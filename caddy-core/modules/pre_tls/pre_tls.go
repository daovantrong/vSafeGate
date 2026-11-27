package pre_tls

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"context"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

const (
	defaultPeekTimeout   = 5 * time.Second
	maxClientHelloRecord = 16384
)

func init() {
	caddy.RegisterModule(PreTLS{})
}

// Info holds TLS ClientHello metadata extracted before TLS termination.
type Info struct {
	SNI        string
	JA4Light   string
	ALPN       string
	TLSVersion string
	RemoteIP   string
}

type infoContextKey struct{}
type connContextKey struct{}

// WithInfo stores PreTLS Info into ctx.
func WithInfo(ctx context.Context, info Info) context.Context {
	return context.WithValue(ctx, infoContextKey{}, info)
}

// WithConn stores the *PreTLSConn into ctx so downstream HTTP handlers can read
// ClientHello metadata after the TLS handshake completes.
func WithConn(ctx context.Context, pc *PreTLSConn) context.Context {
	if pc == nil {
		return ctx
	}
	return context.WithValue(ctx, connContextKey{}, pc)
}

// FromContext retrieves PreTLS Info stored in ctx (either directly via WithInfo
// or lazily from the connection registered via WithConn).
func FromContext(ctx context.Context) (Info, bool) {
	if ctx == nil {
		return Info{}, false
	}
	if v, ok := ctx.Value(infoContextKey{}).(Info); ok {
		return v, true
	}
	if pc, ok := ctx.Value(connContextKey{}).(*PreTLSConn); ok && pc != nil {
		info := pc.Info()
		if info.JA4Light != "" || info.SNI != "" || info.TLSVersion != "" || info.RemoteIP != "" {
			return info, true
		}
	}
	return Info{}, false
}

// PreTLS is a caddy.listeners wrapper placed BEFORE caddy.listeners.tls.
// It inspects TLS ClientHello to extract SNI & JA4-light fingerprints, optionally enforces
// strict Cloudflare/NAT origin CIDRs globally or per-SNI, and silently aborts raw-IP or
// unrecognized SNI connections before a TLS handshake or certificate is sent.
type PreTLS struct {
	AllowedSNIs            []string       `json:"allowed_snis,omitempty"`
	DropMissingSNI         bool           `json:"drop_missing_sni,omitempty"`
	DropUnknownSNI         bool           `json:"drop_unknown_sni,omitempty"`
	StrictCloudflareOrigin bool           `json:"strict_cloudflare_origin,omitempty"`
	StrictOriginSNIs       []string       `json:"strict_origin_snis,omitempty"`
	TrustedCIDRs           []string       `json:"trusted_cidrs,omitempty"`
	HandshakePeekTimeout   caddy.Duration `json:"handshake_peek_timeout,omitempty"`

	logger            *zap.Logger
	exactSNIs         map[string]struct{}
	wildcardSNI       []string
	strictExactSNIs   map[string]struct{}
	strictWildcardSNI []string
	trustedNets       []netip.Prefix
	timeout           time.Duration
}

// CaddyModule implements caddy.Module.
func (PreTLS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.vsafegate_pre_tls",
		New: func() caddy.Module { return new(PreTLS) },
	}
}

func compileSNIList(rawList []string) (map[string]struct{}, []string) {
	exact := make(map[string]struct{}, len(rawList))
	var wild []string
	for _, raw := range rawList {
		host := normalizeHost(raw)
		if host == "" {
			continue
		}
		if strings.HasPrefix(host, "*.") && len(host) > 2 {
			wild = append(wild, host[1:]) // ".example.com"
		} else {
			exact[host] = struct{}{}
		}
	}
	return exact, wild
}

func matchesCompiledSNI(sni string, exact map[string]struct{}, wild []string) bool {
	host := normalizeHost(sni)
	if host == "" {
		return false
	}
	if _, ok := exact[host]; ok {
		return true
	}
	for _, suffix := range wild {
		// Match single-label wildcard (*.example.com matches a.example.com, not a.b.example.com).
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			prefix := host[:len(host)-len(suffix)]
			if prefix != "" && !strings.Contains(prefix, ".") {
				return true
			}
		}
	}
	return false
}

// Provision implements caddy.Provisioner.
func (p *PreTLS) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger()

	p.exactSNIs, p.wildcardSNI = compileSNIList(p.AllowedSNIs)
	p.strictExactSNIs, p.strictWildcardSNI = compileSNIList(p.StrictOriginSNIs)

	p.trustedNets = p.trustedNets[:0]
	for _, raw := range p.TrustedCIDRs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return fmt.Errorf("invalid trusted_cidr %q: %w", raw, err)
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			p.trustedNets = append(p.trustedNets, netip.PrefixFrom(addr, bits))
			continue
		}
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("invalid trusted_cidr %q: %w", raw, err)
		}
		p.trustedNets = append(p.trustedNets, pfx.Masked())
	}

	p.timeout = time.Duration(p.HandshakePeekTimeout)
	if p.timeout <= 0 {
		p.timeout = defaultPeekTimeout
	}

	return nil
}

// Validate implements caddy.Validator.
func (p *PreTLS) Validate() error {
	hasStrictSNIs := len(p.strictExactSNIs) > 0 || len(p.strictWildcardSNI) > 0 || len(p.StrictOriginSNIs) > 0
	if (p.StrictCloudflareOrigin || hasStrictSNIs) && len(p.trustedNets) == 0 {
		return errors.New("strict_cloudflare_origin and strict_origin_snis require at least one entry in trusted_cidrs")
	}
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (p *PreTLS) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "allowed_snis":
				p.AllowedSNIs = append(p.AllowedSNIs, d.RemainingArgs()...)
			case "drop_missing_sni":
				p.DropMissingSNI = true
			case "drop_unknown_sni":
				p.DropUnknownSNI = true
			case "strict_cloudflare_origin":
				p.StrictCloudflareOrigin = true
			case "strict_origin_snis":
				p.StrictOriginSNIs = append(p.StrictOriginSNIs, d.RemainingArgs()...)
			case "trusted_cidrs":
				p.TrustedCIDRs = append(p.TrustedCIDRs, d.RemainingArgs()...)
			case "handshake_peek_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid handshake_peek_timeout: %v", err)
				}
				p.HandshakePeekTimeout = caddy.Duration(dur)
			default:
				return d.Errf("unrecognized subdirective %q", d.Val())
			}
		}
	}
	return nil
}

// WrapListener implements caddy.ListenerWrapper.
func (p *PreTLS) WrapListener(l net.Listener) net.Listener {
	return &preTLSListener{
		Listener: l,
		cfg:      p,
	}
}

type preTLSListener struct {
	net.Listener
	cfg *PreTLS
}

func (l *preTLSListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		remoteIP := extractRemoteIP(c.RemoteAddr())
		if l.cfg.StrictCloudflareOrigin && !l.cfg.isTrustedIP(remoteIP) {
			if l.cfg.logger != nil {
				l.cfg.logger.Debug("pre_tls silent drop: untrusted peer IP",
					zap.String("remote_ip", remoteIP.String()),
				)
			}
			silentAbort(c)
			continue
		}

		return &PreTLSConn{
			Conn:     c,
			cfg:      l.cfg,
			remoteIP: remoteIP,
		}, nil
	}
}

// PreTLSConn wraps a net.Conn to peek the initial TLS ClientHello on the first Read
// without blocking Accept() or consuming handshake bytes.
type PreTLSConn struct {
	net.Conn
	cfg      *PreTLS
	remoteIP netip.Addr

	once sync.Once
	mu   sync.Mutex
	buf  []byte
	off  int
	info Info
	err  error
}

// NetConn exposes the wrapped net.Conn for standard unwrappers.
func (c *PreTLSConn) NetConn() net.Conn {
	return c.Conn
}

// Info returns the extracted ClientHello metadata (populated once first Read completes).
func (c *PreTLSConn) Info() Info {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.info
}

// UnwrapConn walks nested NetConn() / tlsNetConn() wrappers to retrieve *PreTLSConn if present.
func UnwrapConn(c net.Conn) (*PreTLSConn, bool) {
	cur := c
	for cur != nil {
		if pc, ok := cur.(*PreTLSConn); ok {
			return pc, true
		}
		if tn, ok := cur.(interface{ tlsNetConn() net.Conn }); ok {
			cur = tn.tlsNetConn()
			continue
		}
		u, ok := cur.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		cur = u.NetConn()
	}
	return nil, false
}

// UnwrapInfo walks nested NetConn() wrappers to retrieve PreTLS Info if present.
func UnwrapInfo(c net.Conn) (Info, bool) {
	if pc, ok := UnwrapConn(c); ok {
		return pc.Info(), true
	}
	return Info{}, false
}

func (c *PreTLSConn) Read(p []byte) (int, error) {
	c.once.Do(func() {
		c.peekClientHello()
	})

	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return 0, err
	}
	if c.off < len(c.buf) {
		n := copy(p, c.buf[c.off:])
		c.off += n
		if c.off >= len(c.buf) {
			c.buf = nil
			c.off = 0
		}
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	return c.Conn.Read(p)
}

func (c *PreTLSConn) peekClientHello() {
	timeout := defaultPeekTimeout
	if c.cfg != nil && c.cfg.timeout > 0 {
		timeout = c.cfg.timeout
	}
	_ = c.Conn.SetReadDeadline(time.Now().Add(timeout))

	var hdr [5]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		silentAbort(c.Conn)
		c.err = io.EOF
		return
	}

	// TLS record ContentType must be 0x16 (Handshake), legacy major version 0x03.
	if hdr[0] != 0x16 || hdr[1] != 0x03 {
		_ = c.Conn.SetReadDeadline(time.Time{})
		if c.cfg != nil && (c.cfg.DropMissingSNI || c.cfg.DropUnknownSNI) {
			silentAbort(c.Conn)
			c.err = io.EOF
			return
		}
		c.buf = hdr[:]
		return
	}

	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen < 4 || recLen > maxClientHelloRecord {
		silentAbort(c.Conn)
		c.err = io.EOF
		return
	}

	fullBuf := make([]byte, 5+recLen)
	copy(fullBuf[:5], hdr[:])
	if _, err := io.ReadFull(c.Conn, fullBuf[5:]); err != nil {
		silentAbort(c.Conn)
		c.err = io.EOF
		return
	}
	_ = c.Conn.SetReadDeadline(time.Time{})

	parsed, err := ParseClientHello(fullBuf[5:])
	if c.remoteIP.IsValid() {
		parsed.RemoteIP = c.remoteIP.String()
	}

	if err != nil {
		if c.cfg != nil && (c.cfg.DropMissingSNI || c.cfg.DropUnknownSNI) {
			silentAbort(c.Conn)
			c.err = io.EOF
			return
		}
	} else if c.cfg != nil {
		if parsed.SNI == "" {
			if c.cfg.DropMissingSNI {
				silentAbort(c.Conn)
				c.err = io.EOF
				return
			}
		} else if !c.cfg.isAllowedSNI(parsed.SNI) {
			if c.cfg.logger != nil {
				c.cfg.logger.Debug("pre_tls silent drop: unrecognized SNI",
					zap.String("sni", parsed.SNI),
					zap.String("remote_ip", parsed.RemoteIP),
				)
			}
			silentAbort(c.Conn)
			c.err = io.EOF
			return
		} else if c.cfg.isStrictOriginSNI(parsed.SNI) && !c.cfg.isTrustedIP(c.remoteIP) {
			if c.cfg.logger != nil {
				c.cfg.logger.Debug("pre_tls silent drop: per-SNI strict origin untrusted peer IP",
					zap.String("sni", parsed.SNI),
					zap.String("remote_ip", parsed.RemoteIP),
				)
			}
			silentAbort(c.Conn)
			c.err = io.EOF
			return
		}
	}

	c.mu.Lock()
	c.buf = fullBuf
	c.info = parsed
	c.mu.Unlock()
}

func (p *PreTLS) isTrustedIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, pfx := range p.trustedNets {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

func (p *PreTLS) isStrictOriginSNI(sni string) bool {
	if len(p.strictExactSNIs) == 0 && len(p.strictWildcardSNI) == 0 {
		return false
	}
	return matchesCompiledSNI(sni, p.strictExactSNIs, p.strictWildcardSNI)
}

func (p *PreTLS) isAllowedSNI(sni string) bool {
	if !p.DropUnknownSNI {
		return true
	}
	return matchesCompiledSNI(sni, p.exactSNIs, p.wildcardSNI)
}

func extractRemoteIP(addr net.Addr) netip.Addr {
	if addr == nil {
		return netip.Addr{}
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		ip, err2 := netip.ParseAddr(addr.String())
		if err2 != nil {
			return netip.Addr{}
		}
		return ip.Unmap()
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

func silentAbort(c net.Conn) {
	if c == nil {
		return
	}
	cur := c
	for cur != nil {
		if tc, ok := cur.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
			break
		}
		u, ok := cur.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		cur = u.NetConn()
	}
	_ = c.Close()
}

func normalizeHost(raw string) string {
	h := strings.TrimSpace(strings.ToLower(raw))
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return ""
	}
	if strings.ContainsAny(h, " \t\r\n/\\:@") || strings.Contains(h, "..") {
		return ""
	}
	// Reject literal IP addresses passed as SNI (RFC 6066 §3).
	if net.ParseIP(h) != nil {
		return ""
	}
	return h
}

func isGREASE(v uint16) bool {
	return (v & 0x0f0f) == 0x0a0a
}

// ParseClientHello parses the payload inside a TLS Handshake record (after the 5-byte record header)
// and returns extracted SNI, ALPN, TLS version, and deterministic JA4-light fingerprint.
func ParseClientHello(handshake []byte) (Info, error) {
	var out Info
	if len(handshake) < 4 {
		return out, errors.New("truncated handshake")
	}
	if handshake[0] != 0x01 { // HandshakeType ClientHello
		return out, fmt.Errorf("not ClientHello: 0x%02x", handshake[0])
	}
	msgLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if msgLen < 38 || 4+msgLen > len(handshake) {
		return out, errors.New("truncated ClientHello body")
	}
	body := handshake[4 : 4+msgLen]

	if len(body) < 34 {
		return out, errors.New("short ClientHello header")
	}
	legacyVer := binary.BigEndian.Uint16(body[0:2])
	off := 34 // 2B legacy_version + 32B random

	// Session ID
	if off >= len(body) {
		return out, errors.New("missing session id")
	}
	sessLen := int(body[off])
	off++
	if off+sessLen > len(body) {
		return out, errors.New("invalid session id length")
	}
	off += sessLen

	// Cipher Suites
	if off+2 > len(body) {
		return out, errors.New("missing cipher suites")
	}
	cipherBytes := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if cipherBytes == 0 || cipherBytes%2 != 0 || off+cipherBytes > len(body) {
		return out, errors.New("invalid cipher suites length")
	}
	var ciphers []uint16
	for i := 0; i < cipherBytes; i += 2 {
		cs := binary.BigEndian.Uint16(body[off+i : off+i+2])
		if !isGREASE(cs) {
			ciphers = append(ciphers, cs)
		}
	}
	off += cipherBytes

	// Compression Methods
	if off >= len(body) {
		return out, errors.New("missing compression methods")
	}
	compLen := int(body[off])
	off++
	if off+compLen > len(body) {
		return out, errors.New("invalid compression methods")
	}
	off += compLen

	// Extensions (optional)
	var exts []uint16
	var supportedMaxVer uint16
	if off+2 <= len(body) {
		extTotal := int(binary.BigEndian.Uint16(body[off : off+2]))
		off += 2
		if off+extTotal > len(body) {
			return out, errors.New("invalid extensions length")
		}
		extEnd := off + extTotal
		for off+4 <= extEnd {
			extType := binary.BigEndian.Uint16(body[off : off+2])
			extLen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
			off += 4
			if off+extLen > extEnd {
				return out, errors.New("truncated extension")
			}
			extData := body[off : off+extLen]
			off += extLen

			if !isGREASE(extType) {
				if extType != 0x0000 && extType != 0x0010 {
					exts = append(exts, extType)
				}
			}

			switch extType {
			case 0x0000: // server_name
				if sni := parseSNIExtension(extData); sni != "" {
					out.SNI = sni
				}
			case 0x0010: // application_layer_protocol_negotiation
				if alpn := parseALPNExtension(extData); alpn != "" {
					out.ALPN = alpn
				}
			case 0x002b: // supported_versions
				if v := parseSupportedVersions(extData); v > supportedMaxVer {
					supportedMaxVer = v
				}
			}
		}
	}

	ver := supportedMaxVer
	if ver == 0 {
		ver = legacyVer
	}
	out.TLSVersion = tlsVersionCode(ver)
	out.JA4Light = buildJA4Light(out.TLSVersion, out.SNI != "", ciphers, exts)
	return out, nil
}

func parseSNIExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) {
		return ""
	}
	off := 2
	end := 2 + listLen
	for off+3 <= end {
		nameType := data[off]
		nameLen := int(binary.BigEndian.Uint16(data[off+1 : off+3]))
		off += 3
		if off+nameLen > end {
			return ""
		}
		if nameType == 0x00 { // host_name
			return normalizeHost(string(data[off : off+nameLen]))
		}
		off += nameLen
	}
	return ""
}

func parseALPNExtension(data []byte) string {
	if len(data) < 3 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) || listLen == 0 {
		return ""
	}
	pLen := int(data[2])
	if pLen == 0 || 3+pLen > 2+listLen {
		return ""
	}
	return string(data[3 : 3+pLen])
}

func parseSupportedVersions(data []byte) uint16 {
	if len(data) < 3 {
		return 0
	}
	listLen := int(data[0])
	if listLen < 2 || listLen%2 != 0 || 1+listLen > len(data) {
		return 0
	}
	var maxVer uint16
	for i := 1; i+1 < 1+listLen; i += 2 {
		v := binary.BigEndian.Uint16(data[i : i+2])
		if isGREASE(v) {
			continue
		}
		if v > maxVer {
			maxVer = v
		}
	}
	return maxVer
}

func tlsVersionCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	default:
		return "00"
	}
}

func buildJA4Light(ver string, hasSNI bool, ciphers, exts []uint16) string {
	sniFlag := "i"
	if hasSNI {
		sniFlag = "d"
	}
	cCount := len(ciphers)
	if cCount > 99 {
		cCount = 99
	}
	eCount := len(exts)
	if eCount > 99 {
		eCount = 99
	}

	cHash := hashUint16List(ciphers)
	eHash := hashUint16List(exts)
	return fmt.Sprintf("t%s%s%02d%02d_%s_%s", ver, sniFlag, cCount, eCount, cHash, eHash)
}

func hashUint16List(vals []uint16) string {
	if len(vals) == 0 {
		return "000000000000"
	}
	sorted := make([]uint16, len(vals))
	copy(sorted, vals)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var b strings.Builder
	for i, v := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%04x", v)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])[:12]
}

var (
	_ caddy.Module          = (*PreTLS)(nil)
	_ caddy.Provisioner     = (*PreTLS)(nil)
	_ caddy.Validator       = (*PreTLS)(nil)
	_ caddy.ListenerWrapper = (*PreTLS)(nil)
	_ caddyfile.Unmarshaler = (*PreTLS)(nil)
)
