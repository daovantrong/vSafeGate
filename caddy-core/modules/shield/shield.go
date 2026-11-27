package shield

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/cespare/xxhash/v2"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"caddy-core/modules/pre_tls"
)

const (
	numShards                = 256
	maxIPEntriesPerShard     = 4096
	maxSubnetEntriesPerShard = 2048
	maxRouteEntriesPerShard  = 4096
	maxBotCachePerShard      = 1024

	clearanceCookieName = "_clearance"
	verifyEndpointPath  = "/.well-known/sec-verify"
	acmePrefix          = "/.well-known/acme-challenge/"

	defaultRateLimitRPS        = 60.0
	defaultRateLimitBurst      = 120
	defaultSubnetRPS           = 250.0
	defaultSubnetBurst         = 500
	defaultMaxConcurrentPerIP  = 40
	defaultHardDropMultiplier  = 3.0
	defaultAnomalyChallenge    = 50
	defaultAnomalyDrop         = 100
	defaultChallengeDifficulty = 14
	defaultChallengeTTLSec     = 1800
	defaultBanDurationSec      = 600
	defaultEntryTTL            = 10 * time.Minute
)

func init() {
	caddy.RegisterModule(Shield{})
}

var (
	registeredServersMu sync.Mutex
	registeredServers   = make(map[*caddyhttp.Server]struct{})
)

// SensitiveRouteRule overrides rate limits for sensitive prefixes like /login or /api/auth.
type SensitiveRouteRule struct {
	PathPrefix string  `json:"path_prefix,omitempty"`
	RPS        float64 `json:"rps,omitempty"`
	Burst      int     `json:"burst,omitempty"`
}

// ShieldEvent is emitted asynchronously over a Unix domain socket to the management plane.
type ShieldEvent struct {
	Type               string  `json:"type"` // "challenge", "drop", "ban", "stats"
	Timestamp          int64   `json:"ts"`
	Host               string  `json:"host,omitempty"`
	SiteID             string  `json:"site_id,omitempty"`
	ClientIP           string  `json:"client_ip,omitempty"`
	PeerIP             string  `json:"peer_ip,omitempty"`
	BehindTrustedProxy bool    `json:"behind_trusted_proxy,omitempty"`
	URI                string  `json:"uri,omitempty"`
	Method             string  `json:"method,omitempty"`
	UserAgent          string  `json:"user_agent,omitempty"`
	Reason             string  `json:"reason,omitempty"`
	Action             string  `json:"action,omitempty"`
	RPS                float64 `json:"rps,omitempty"`
	DropPS             float64 `json:"drop_ps,omitempty"`
}

// Shield implements L7 DDoS protection, multi-dimensional rate limiting, concurrency limits,
// behavioral + JA4-light bot scoring, verified search bot bypass, and stateless HMAC-SHA256 PoW challenges.
type Shield struct {
	Mode                  string               `json:"mode,omitempty"` // "normal", "under_attack", "off"
	UnderAttackMode       bool                 `json:"under_attack_mode,omitempty"`
	TrustedProxies        []string             `json:"trusted_proxies,omitempty"`
	RateLimitRPS          float64              `json:"rate_limit_rps,omitempty"`
	RateLimitBurst        int                  `json:"rate_limit_burst,omitempty"`
	SubnetRateLimitRPS    float64              `json:"subnet_rate_limit_rps,omitempty"`
	SubnetRateLimitBurst  int                  `json:"subnet_rate_limit_burst,omitempty"`
	HostRateLimitRPS      float64              `json:"host_rate_limit_rps,omitempty"`
	HostRateLimitBurst    int                  `json:"host_rate_limit_burst,omitempty"`
	MaxConcurrentPerIP    int                  `json:"max_concurrent_per_ip,omitempty"`
	HardDropMultiplier    float64              `json:"hard_drop_multiplier,omitempty"`
	AnomalyScoreChallenge int                  `json:"anomaly_score_challenge,omitempty"`
	AnomalyScoreDrop      int                  `json:"anomaly_score_drop,omitempty"`
	ChallengeDifficulty   int                  `json:"challenge_difficulty,omitempty"`
	ChallengeTTLSeconds   int                  `json:"challenge_ttl_seconds,omitempty"`
	ChallengeSecret       string               `json:"challenge_secret,omitempty"`
	BanDurationSeconds    int                  `json:"ban_duration_seconds,omitempty"`
	SensitiveRoutes       []SensitiveRouteRule `json:"sensitive_routes,omitempty"`
	ExemptPaths           []string             `json:"exempt_paths,omitempty"`
	APIPaths              []string             `json:"api_paths,omitempty"`
	VerifySearchBots      *bool                `json:"verify_search_bots,omitempty"`
	EventsSocketPath      string               `json:"events_socket_path,omitempty"`
	SiteID                string               `json:"site_id,omitempty"`
	BannedIPs             []string             `json:"banned_ips,omitempty"`

	logger       *zap.Logger
	trustedNets  []netip.Prefix
	staticBanned map[string]struct{}
	secretKey    []byte
	verifyBots   bool
	rt           *shieldRuntime

	// Injectable hooks for deterministic unit testing
	nowFn        func() time.Time
	lookupAddrFn func(ctx context.Context, addr string) ([]string, error)
	lookupHostFn func(ctx context.Context, host string) ([]string, error)
}

type shieldRuntime struct {
	shards         [numShards]shieldShard
	hostLimitersMu sync.Mutex
	hostLimiters   map[string]*hostStats
	eventCh        chan ShieldEvent
	stopCh         chan struct{}
	stopOnce       sync.Once
	wg             sync.WaitGroup
}

type shieldShard struct {
	mu      sync.Mutex
	ips     map[string]*ipState
	subnets map[string]*subnetState
	routes  map[string]*routeState
	bots    map[string]*botCacheEntry
}

type ipState struct {
	limiter            *rate.Limiter
	hardLimiter        *rate.Limiter
	inFlight           int64
	softViolations     int
	notFoundCount      int
	notFoundWindowFrom time.Time
	anomalyScore       int
	anomalyWindowFrom  time.Time
	bannedUntil        time.Time
	lastSeen           time.Time
}

type subnetState struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type routeState struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type botCacheEntry struct {
	verified  bool
	botName   string
	expiresAt time.Time
}

type hostStats struct {
	limiter *rate.Limiter
	reqs    atomic.Int64
	drops   atomic.Int64
}

// CaddyModule implements caddy.Module.
func (Shield) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.vsafegate_shield",
		New: func() caddy.Module { return new(Shield) },
	}
}

func (s *Shield) now() time.Time {
	if s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now()
}

// Provision implements caddy.Provisioner.
func (s *Shield) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger()
	if s.nowFn == nil {
		s.nowFn = time.Now
	}
	if s.lookupAddrFn == nil {
		s.lookupAddrFn = net.DefaultResolver.LookupAddr
	}
	if s.lookupHostFn == nil {
		s.lookupHostFn = net.DefaultResolver.LookupHost
	}

	s.Mode = strings.ToLower(strings.TrimSpace(s.Mode))
	if s.Mode == "" {
		if s.UnderAttackMode {
			s.Mode = "under_attack"
		} else {
			s.Mode = "normal"
		}
	}
	if s.Mode == "under_attack" {
		s.UnderAttackMode = true
	}

	if s.RateLimitRPS <= 0 {
		s.RateLimitRPS = defaultRateLimitRPS
	}
	if s.RateLimitBurst <= 0 {
		s.RateLimitBurst = max(int(s.RateLimitRPS*2), defaultRateLimitBurst)
	}
	if s.SubnetRateLimitRPS <= 0 {
		s.SubnetRateLimitRPS = defaultSubnetRPS
	}
	if s.SubnetRateLimitBurst <= 0 {
		s.SubnetRateLimitBurst = max(int(s.SubnetRateLimitRPS*2), defaultSubnetBurst)
	}
	if s.HostRateLimitRPS > 0 && s.HostRateLimitBurst <= 0 {
		s.HostRateLimitBurst = max(int(s.HostRateLimitRPS*2), 10)
	}
	if s.MaxConcurrentPerIP <= 0 {
		s.MaxConcurrentPerIP = defaultMaxConcurrentPerIP
	}
	if s.HardDropMultiplier <= 1.0 {
		s.HardDropMultiplier = defaultHardDropMultiplier
	}
	if s.AnomalyScoreChallenge <= 0 {
		s.AnomalyScoreChallenge = defaultAnomalyChallenge
	}
	if s.AnomalyScoreDrop <= 0 {
		s.AnomalyScoreDrop = defaultAnomalyDrop
	}
	if s.ChallengeDifficulty <= 0 {
		s.ChallengeDifficulty = defaultChallengeDifficulty
	}
	if s.ChallengeDifficulty < 8 {
		s.ChallengeDifficulty = 8
	}
	if s.ChallengeDifficulty > 22 {
		s.ChallengeDifficulty = 22
	}
	if s.ChallengeTTLSeconds <= 0 {
		s.ChallengeTTLSeconds = defaultChallengeTTLSec
	}
	if s.BanDurationSeconds <= 0 {
		s.BanDurationSeconds = defaultBanDurationSec
	}
	if s.VerifySearchBots != nil {
		s.verifyBots = *s.VerifySearchBots
	} else {
		s.verifyBots = true
	}

	if s.ChallengeSecret != "" {
		if raw, err := hex.DecodeString(strings.TrimSpace(s.ChallengeSecret)); err == nil && len(raw) >= 16 {
			s.secretKey = raw
		} else {
			sum := sha256.Sum256([]byte(s.ChallengeSecret))
			s.secretKey = sum[:]
		}
	} else {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		s.secretKey = key
	}

	s.trustedNets = s.trustedNets[:0]
	for _, raw := range s.TrustedProxies {
		str := strings.TrimSpace(raw)
		if str == "" {
			continue
		}
		if !strings.Contains(str, "/") {
			addr, err := netip.ParseAddr(str)
			if err != nil {
				return fmt.Errorf("shield invalid trusted_proxy %q: %w", raw, err)
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			s.trustedNets = append(s.trustedNets, netip.PrefixFrom(addr.Unmap(), bits))
			continue
		}
		pfx, err := netip.ParsePrefix(str)
		if err != nil {
			return fmt.Errorf("shield invalid trusted_proxy %q: %w", raw, err)
		}
		if pfx.Bits() == 0 {
			continue // ignore unsafe 0.0.0.0/0 or ::/0
		}
		s.trustedNets = append(s.trustedNets, pfx.Masked())
	}

	for i := range s.SensitiveRoutes {
		if s.SensitiveRoutes[i].RPS <= 0 {
			s.SensitiveRoutes[i].RPS = 5
		}
		if s.SensitiveRoutes[i].Burst <= 0 {
			s.SensitiveRoutes[i].Burst = max(int(s.SensitiveRoutes[i].RPS*2), 5)
		}
	}

	if s.EventsSocketPath == "" && runtime.GOOS == "linux" {
		s.EventsSocketPath = "/run/vsafegate/events.sock"
	}

	s.staticBanned = make(map[string]struct{}, len(s.BannedIPs))
	for _, rawIP := range s.BannedIPs {
		if addr, ok := parseAddrNormalized(rawIP); ok {
			s.staticBanned[addr.String()] = struct{}{}
		}
	}

	rt := &shieldRuntime{
		hostLimiters: make(map[string]*hostStats),
		eventCh:      make(chan ShieldEvent, 4096),
		stopCh:       make(chan struct{}),
	}
	for i := 0; i < numShards; i++ {
		rt.shards[i].ips = make(map[string]*ipState)
		rt.shards[i].subnets = make(map[string]*subnetState)
		rt.shards[i].routes = make(map[string]*routeState)
		rt.shards[i].bots = make(map[string]*botCacheEntry)
	}
	s.rt = rt

	// Hook PreTLS ConnContext once per *caddyhttp.Server so ServeHTTP can inspect JA4-light & SNI.
	if ctx.Context != nil {
		if srv, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server); ok && srv != nil {
			registeredServersMu.Lock()
			if _, exists := registeredServers[srv]; !exists {
				registeredServers[srv] = struct{}{}
				srv.RegisterConnContext(func(connCtx context.Context, c net.Conn) context.Context {
					if pc, found := pre_tls.UnwrapConn(c); found {
						return pre_tls.WithConn(connCtx, pc)
					}
					return connCtx
				})
				srv.RegisterOnStop(func(context.Context) error {
					registeredServersMu.Lock()
					delete(registeredServers, srv)
					registeredServersMu.Unlock()
					return nil
				})
			}
			registeredServersMu.Unlock()
		}
	}

	rt.wg.Add(3)
	go s.reaperLoop(rt)
	go s.statsLoop(rt)
	go s.eventEmitterLoop(rt)

	return nil
}

// Validate implements caddy.Validator.
func (s *Shield) Validate() error {
	switch s.Mode {
	case "", "normal", "under_attack", "off":
	default:
		return fmt.Errorf("invalid shield mode %q", s.Mode)
	}
	return nil
}

// Cleanup implements caddy.CleanerUpper.
func (s *Shield) Cleanup() error {
	if s.rt == nil {
		return nil
	}
	s.rt.stopOnce.Do(func() {
		if s.rt.stopCh != nil {
			close(s.rt.stopCh)
		}
	})
	s.rt.wg.Wait()
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler (JSON is primary).
func (s *Shield) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "mode":
				if !d.NextArg() {
					return d.ArgErr()
				}
				s.Mode = d.Val()
			case "under_attack_mode":
				s.UnderAttackMode = true
			default:
				return d.Errf("unrecognized subdirective %q", d.Val())
			}
		}
	}
	return nil
}

func shardIndex(key string) uint8 {
	return uint8(xxhash.Sum64String(key) & 0xFF)
}

func (s *Shield) reaperLoop(rt *shieldRuntime) {
	defer rt.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rt.stopCh:
			return
		case <-ticker.C:
			now := s.now()
			for i := 0; i < numShards; i++ {
				sh := &rt.shards[i]
				sh.mu.Lock()
				for k, v := range sh.ips {
					if v.inFlight <= 0 && (v.bannedUntil.IsZero() || now.After(v.bannedUntil)) && now.Sub(v.lastSeen) > defaultEntryTTL {
						delete(sh.ips, k)
					}
				}
				for k, v := range sh.subnets {
					if now.Sub(v.lastSeen) > defaultEntryTTL {
						delete(sh.subnets, k)
					}
				}
				for k, v := range sh.routes {
					if now.Sub(v.lastSeen) > defaultEntryTTL {
						delete(sh.routes, k)
					}
				}
				for k, v := range sh.bots {
					if now.After(v.expiresAt) {
						delete(sh.bots, k)
					}
				}
				sh.mu.Unlock()
			}
		}
	}
}

func (s *Shield) statsLoop(rt *shieldRuntime) {
	defer rt.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	lastTick := s.now()
	for {
		select {
		case <-rt.stopCh:
			return
		case <-ticker.C:
			now := s.now()
			elapsed := now.Sub(lastTick).Seconds()
			if elapsed <= 0 {
				elapsed = 2.0
			}
			lastTick = now

			rt.hostLimitersMu.Lock()
			snapshot := make(map[string]*hostStats, len(rt.hostLimiters))
			for h, st := range rt.hostLimiters {
				snapshot[h] = st
			}
			rt.hostLimitersMu.Unlock()

			for h, st := range snapshot {
				reqs := st.reqs.Swap(0)
				drops := st.drops.Swap(0)
				if reqs == 0 && drops == 0 {
					continue
				}
				s.emitEvent(ShieldEvent{
					Type:      "stats",
					Timestamp: now.Unix(),
					Host:      h,
					SiteID:    s.SiteID,
					RPS:       float64(reqs) / elapsed,
					DropPS:    float64(drops) / elapsed,
				})
			}
		}
	}
}

func (s *Shield) emitEvent(ev ShieldEvent) {
	if s.EventsSocketPath == "" || s.rt == nil || s.rt.eventCh == nil {
		return
	}
	select {
	case <-s.rt.stopCh:
		return
	case s.rt.eventCh <- ev:
	default:
		// Bounded queue full under extreme flood: drop telemetry event rather than blocking HTTP workers
	}
}

func (s *Shield) eventEmitterLoop(rt *shieldRuntime) {
	defer rt.wg.Done()
	if s.EventsSocketPath == "" {
		return
	}

	var conn net.Conn
	var bw *bufio.Writer
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	dial := func() bool {
		if conn != nil {
			return true
		}
		c, err := net.DialTimeout("unix", s.EventsSocketPath, 500*time.Millisecond)
		if err != nil {
			return false
		}
		conn = c
		bw = bufio.NewWriterSize(c, 8192)
		return true
	}

	flushTicker := time.NewTicker(250 * time.Millisecond)
	defer flushTicker.Stop()

	for {
		select {
		case <-rt.stopCh:
			return
		case <-flushTicker.C:
			if bw != nil && bw.Buffered() > 0 {
				_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
				if err := bw.Flush(); err != nil {
					_ = conn.Close()
					conn = nil
					bw = nil
				}
			}
		case ev := <-rt.eventCh:
			if !dial() {
				continue
			}
			line, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			_, werr := bw.Write(append(line, '\n'))
			if werr == nil && len(rt.eventCh) == 0 {
				werr = bw.Flush()
			}
			if werr != nil {
				_ = conn.Close()
				conn = nil
				bw = nil
			}
		}
	}
}

func (s *Shield) isTrustedProxy(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, pfx := range s.trustedNets {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

func parseAddrNormalized(raw string) (netip.Addr, bool) {
	str := strings.TrimSpace(raw)
	if str == "" {
		return netip.Addr{}, false
	}
	if host, _, err := net.SplitHostPort(str); err == nil {
		str = host
	}
	str, _, _ = strings.Cut(str, "%")
	addr, err := netip.ParseAddr(strings.TrimSpace(str))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func (s *Shield) resolveClientIP(r *http.Request) (realIP netip.Addr, peerIP netip.Addr, behindTrustedProxy bool) {
	peerIP, _ = parseAddrNormalized(r.RemoteAddr)

	if peerIP.IsValid() && s.isTrustedProxy(peerIP) {
		behindTrustedProxy = true
	}
	if vars, ok := r.Context().Value(caddyhttp.VarsCtxKey).(map[string]any); ok {
		if tp, ok2 := vars[caddyhttp.TrustedProxyVarKey].(bool); ok2 && tp {
			behindTrustedProxy = true
		}
		if behindTrustedProxy {
			if cipStr, ok2 := vars[caddyhttp.ClientIPVarKey].(string); ok2 {
				if parsed, ok3 := parseAddrNormalized(cipStr); ok3 {
					realIP = parsed
				}
			}
		}
	}

	if behindTrustedProxy && (!realIP.IsValid() || realIP == peerIP) {
		// 1. Prefer CF-Connecting-IP when request came via Cloudflare/trusted proxy
		if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" {
			if parsed, ok := parseAddrNormalized(cfIP); ok {
				return parsed, peerIP, true
			}
		}
		// 2. Fallback to right-to-left untrusted X-Forwarded-For walk
		if xffVals := r.Header.Values("X-Forwarded-For"); len(xffVals) > 0 {
			joined := strings.Join(xffVals, ",")
			parts := strings.Split(joined, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				if parsed, ok := parseAddrNormalized(parts[i]); ok {
					if !s.isTrustedProxy(parsed) {
						return parsed, peerIP, true
					}
					realIP = parsed
				}
			}
		}
	}

	if !realIP.IsValid() {
		realIP = peerIP
	}
	return realIP, peerIP, behindTrustedProxy
}

func subnetKeyForIP(addr netip.Addr) string {
	if !addr.IsValid() {
		return "unknown"
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return netip.PrefixFrom(addr, 24).Masked().String()
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}

func (s *Shield) getHostStats(host string) *hostStats {
	norm := strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(norm); err == nil {
		norm = h
	}
	if norm == "" {
		norm = "default"
	}
	s.rt.hostLimitersMu.Lock()
	defer s.rt.hostLimitersMu.Unlock()
	st, ok := s.rt.hostLimiters[norm]
	if !ok {
		st = &hostStats{}
		if s.HostRateLimitRPS > 0 {
			st.limiter = rate.NewLimiter(rate.Limit(s.HostRateLimitRPS), s.HostRateLimitBurst)
		}
		s.rt.hostLimiters[norm] = st
	}
	return st
}

func matchesPathPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func (s *Shield) matchSensitiveRoute(path string) *SensitiveRouteRule {
	for i := range s.SensitiveRoutes {
		p := strings.TrimSpace(s.SensitiveRoutes[i].PathPrefix)
		if p != "" && strings.HasPrefix(path, p) {
			return &s.SensitiveRoutes[i]
		}
	}
	return nil
}

func detectClaimedSearchBot(ua string) (botName string, allowedSuffixes []string, claimed bool) {
	low := strings.ToLower(ua)
	switch {
	case strings.Contains(low, "googlebot") || strings.Contains(low, "adsbot-google") || strings.Contains(low, "google-inspectiontool"):
		return "Googlebot", []string{".googlebot.com", ".google.com"}, true
	case strings.Contains(low, "bingbot") || strings.Contains(low, "msnbot"):
		return "Bingbot", []string{".search.msn.com"}, true
	case strings.Contains(low, "duckduckbot"):
		return "DuckDuckBot", []string{".duckduckgo.com"}, true
	case strings.Contains(low, "applebot"):
		return "Applebot", []string{".applebot.apple.com"}, true
	default:
		return "", nil, false
	}
}

func (s *Shield) verifySearchBot(reqCtx context.Context, ip netip.Addr, ua string) (verified bool, claimedSpoofed bool, botName string) {
	if !s.verifyBots || !ip.IsValid() {
		return false, false, ""
	}
	name, suffixes, claimed := detectClaimedSearchBot(ua)
	if !claimed {
		return false, false, ""
	}

	ipStr := ip.Unmap().String()
	idx := shardIndex(ipStr)
	sh := &s.rt.shards[idx]
	now := s.now()

	sh.mu.Lock()
	if cached, ok := sh.bots[ipStr]; ok && now.Before(cached.expiresAt) {
		v := cached.verified
		bn := cached.botName
		sh.mu.Unlock()
		return v, !v, bn
	}
	sh.mu.Unlock()

	lookupCtx, cancel := context.WithTimeout(reqCtx, 800*time.Millisecond)
	defer cancel()

	okVerified := false
	names, err := s.lookupAddrFn(lookupCtx, ipStr)
	if err == nil {
		for _, rawName := range names {
			host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rawName)), ".")
			matchedSuffix := false
			for _, sfx := range suffixes {
				if strings.HasSuffix(host, sfx) {
					matchedSuffix = true
					break
				}
			}
			if !matchedSuffix {
				continue
			}
			fwdIPs, ferr := s.lookupHostFn(lookupCtx, host)
			if ferr != nil {
				continue
			}
			for _, fipStr := range fwdIPs {
				if fAddr, ok := parseAddrNormalized(fipStr); ok && fAddr == ip.Unmap() {
					okVerified = true
					break
				}
			}
			if okVerified {
				break
			}
		}
	}

	ttl := 10 * time.Minute
	if okVerified {
		ttl = 1 * time.Hour
	}

	sh.mu.Lock()
	if len(sh.bots) >= maxBotCachePerShard {
		for k := range sh.bots {
			delete(sh.bots, k)
			break
		}
	}
	sh.bots[ipStr] = &botCacheEntry{
		verified:  okVerified,
		botName:   name,
		expiresAt: now.Add(ttl),
	}
	sh.mu.Unlock()

	return okVerified, !okVerified, name
}

func parseJA4LightCounts(fp string) (ver string, cCount int, eCount int, ok bool) {
	// Format: t13dCCEE_...
	if len(fp) < 8 || fp[0] != 't' {
		return "", 0, 0, false
	}
	ver = fp[1:3]
	cc, err1 := strconv.Atoi(fp[4:6])
	ec, err2 := strconv.Atoi(fp[6:8])
	if err1 != nil || err2 != nil {
		return "", 0, 0, false
	}
	return ver, cc, ec, true
}

func isModernBrowserUA(ua string) bool {
	if !strings.Contains(ua, "Mozilla/5.0") {
		return false
	}
	return strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Firefox/") || strings.Contains(ua, "Edg/") || strings.Contains(ua, "Safari/")
}

func calcAnomalyScore(r *http.Request, preInfo pre_tls.Info, hasPreInfo bool, claimedSpoofedBot bool) int {
	score := 0
	ua := strings.TrimSpace(r.Header.Get("User-Agent"))
	if ua == "" {
		score += 25
	}
	if claimedSpoofedBot {
		score += 60
	}

	if isModernBrowserUA(ua) {
		if r.Header.Get("Accept") == "" {
			score += 15
		}
		if r.Header.Get("Accept-Language") == "" {
			score += 15
		}
		if r.TLS != nil && (strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Firefox/") || strings.Contains(ua, "Edg/")) {
			if r.Header.Get("Sec-Fetch-Mode") == "" && r.Header.Get("Sec-Fetch-Site") == "" {
				score += 15
			}
		}
		if hasPreInfo && preInfo.JA4Light != "" {
			ver, cCount, eCount, ok := parseJA4LightCounts(preInfo.JA4Light)
			if ok {
				if ver == "10" || ver == "11" || ver == "00" {
					score += 25
				}
				if cCount <= 4 || eCount <= 4 {
					score += 25
				}
			}
			if (strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Firefox/")) && r.ProtoMajor == 1 && preInfo.ALPN != "h2" {
				score += 10
			}
		}
	}
	return score
}

func (s *Shield) signString(msg string) string {
	mac := hmac.New(sha256.New, s.secretKey)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Shield) verifyHMAC(msg, sigHex string) bool {
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sig) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, s.secretKey)
	mac.Write([]byte(msg))
	return hmac.Equal(mac.Sum(nil), sig)
}

func clientFPComponents(r *http.Request, realIP netip.Addr, preInfo pre_tls.Info) (subnet, uaHash, tlsFP string) {
	subnet = subnetKeyForIP(realIP)
	uaSum := sha256.Sum256([]byte(r.Header.Get("User-Agent")))
	uaHash = hex.EncodeToString(uaSum[:8])
	tlsFP = preInfo.JA4Light
	if tlsFP == "" {
		if r.TLS != nil {
			tlsFP = fmt.Sprintf("tls%x", r.TLS.Version)
		} else {
			tlsFP = "plain"
		}
	}
	return subnet, uaHash, tlsFP
}

func (s *Shield) hasValidClearanceCookie(r *http.Request, realIP netip.Addr, preInfo pre_tls.Info) bool {
	c, err := r.Cookie(clearanceCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return false
	}
	expUnix, err := strconv.ParseInt(parts[0], 16, 64)
	if err != nil || s.now().Unix() > expUnix {
		return false
	}
	subnet, uaHash, tlsFP := clientFPComponents(r, realIP, preInfo)
	msg := fmt.Sprintf("clr|%s.%s|%s|%s|%s", parts[0], parts[1], subnet, uaHash, tlsFP)
	return s.verifyHMAC(msg, parts[2])
}

func (s *Shield) buildClearanceCookie(r *http.Request, realIP netip.Addr, preInfo pre_tls.Info) *http.Cookie {
	exp := s.now().Add(time.Duration(s.ChallengeTTLSeconds) * time.Second).Unix()
	expHex := strconv.FormatInt(exp, 16)
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	nonceHex := hex.EncodeToString(nonce[:])

	subnet, uaHash, tlsFP := clientFPComponents(r, realIP, preInfo)
	msg := fmt.Sprintf("clr|%s.%s|%s|%s|%s", expHex, nonceHex, subnet, uaHash, tlsFP)
	sig := s.signString(msg)

	return &http.Cookie{
		Name:     clearanceCookieName,
		Value:    fmt.Sprintf("%s.%s.%s", expHex, nonceHex, sig),
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   s.ChallengeTTLSeconds,
	}
}

func (s *Shield) issueChallengeToken(r *http.Request, realIP netip.Addr, preInfo pre_tls.Info) string {
	tsHex := strconv.FormatInt(s.now().Unix(), 16)
	diffHex := strconv.FormatInt(int64(s.ChallengeDifficulty), 16)
	var nonce [12]byte
	_, _ = rand.Read(nonce[:])
	nonceHex := hex.EncodeToString(nonce[:])

	subnet, uaHash, tlsFP := clientFPComponents(r, realIP, preInfo)
	payload := fmt.Sprintf("%s.%s.%s", tsHex, diffHex, nonceHex)
	sig := s.signString(fmt.Sprintf("chl|%s|%s|%s|%s", payload, subnet, uaHash, tlsFP))
	return payload + "." + sig
}

func (s *Shield) verifyChallengeSolution(r *http.Request, realIP netip.Addr, preInfo pre_tls.Info, token, solution string) bool {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 4 || strings.TrimSpace(solution) == "" || len(solution) > 64 {
		return false
	}
	tsUnix, err1 := strconv.ParseInt(parts[0], 16, 64)
	diff64, err2 := strconv.ParseInt(parts[1], 16, 64)
	if err1 != nil || err2 != nil {
		return false
	}
	diff := int(diff64)
	if diff < 8 || diff > 24 {
		return false
	}
	nowUnix := s.now().Unix()
	if nowUnix-tsUnix > 180 || tsUnix-nowUnix > 30 {
		return false
	}

	subnet, uaHash, tlsFP := clientFPComponents(r, realIP, preInfo)
	payload := fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
	if !s.verifyHMAC(fmt.Sprintf("chl|%s|%s|%s|%s", payload, subnet, uaHash, tlsFP), parts[3]) {
		return false
	}

	sum := sha256.Sum256([]byte(token + ":" + strings.TrimSpace(solution)))
	return HasLeadingZeroBits(sum[:], diff)
}

// HasLeadingZeroBits checks whether hash has at least bits leading zero bits.
func HasLeadingZeroBits(hash []byte, bits int) bool {
	if bits <= 0 {
		return true
	}
	fullBytes := bits / 8
	remBits := bits % 8
	if fullBytes > len(hash) {
		return false
	}
	for i := 0; i < fullBytes; i++ {
		if hash[i] != 0 {
			return false
		}
	}
	if remBits > 0 {
		if fullBytes >= len(hash) {
			return false
		}
		mask := byte(0xFF << (8 - remBits))
		if (hash[fullBytes] & mask) != 0 {
			return false
		}
	}
	return true
}

func (s *Shield) handleChallengeVerify(w http.ResponseWriter, r *http.Request, realIP netip.Addr, preInfo pre_tls.Info) error {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}

	var token, sol, nextURL string
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var req struct {
			Token    string `json:"token"`
			Solution string `json:"solution"`
			Next     string `json:"next"`
		}
		if json.Unmarshal(body, &req) == nil {
			token, sol, nextURL = req.Token, req.Solution, req.Next
		}
	} else {
		vals, _ := url.ParseQuery(string(body))
		token = vals.Get("token")
		sol = vals.Get("solution")
		nextURL = vals.Get("next")
	}

	if !s.verifyChallengeSolution(r, realIP, preInfo, token, sol) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_proof"}`))
		return nil
	}

	http.SetCookie(w, s.buildClearanceCookie(r, realIP, preInfo))
	if !strings.Contains(ct, "application/json") && strings.HasPrefix(nextURL, "/") && !strings.HasPrefix(nextURL, "//") {
		http.Redirect(w, r, nextURL, http.StatusSeeOther)
		return nil
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
	return nil
}

func (s *Shield) writeChallengeResponse(w http.ResponseWriter, r *http.Request, realIP netip.Addr, preInfo pre_tls.Info) {
	token := s.issueChallengeToken(r, realIP, preInfo)
	diff := s.ChallengeDifficulty

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Retry-After", "5")
	w.WriteHeader(http.StatusTooManyRequests)

	// Intentionally minimal, neutral HTML/JS PoW challenge with zero gateway/product branding.
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Just a moment...</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0f172a;color:#e2e8f0}
.box{max-width:420px;width:92%%;padding:28px;border-radius:14px;background:#1e293b;border:1px solid #334155;text-align:center;box-shadow:0 16px 40px rgba(0,0,0,.35)}
.spin{width:34px;height:34px;margin:0 auto 16px;border:3px solid #334155;border-top-color:#38bdf8;border-radius:50%%;animation:s .8s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
h1{font-size:18px;margin:0 0 8px;font-weight:600}
p{font-size:13px;color:#94a3b8;margin:0}
</style>
</head>
<body>
<div class="box">
  <div class="spin"></div>
  <h1>Checking your browser...</h1>
  <p id="st">Verifying connection security. You will be redirected shortly.</p>
  <noscript><p style="color:#f87171;margin-top:12px">JavaScript is required to continue.</p></noscript>
</div>
<script>
(async function(){
  const tok = %q;
  const diff = %d;
  const enc = new TextEncoder();

  function zerosOk(bytes, bits){
    const full = bits >> 3, rem = bits & 7;
    for(let i=0;i<full;i++){ if(bytes[i]!==0) return false; }
    if(rem>0){ const mask = (0xff << (8 - rem)) & 0xff; if((bytes[full] & mask)!==0) return false; }
    return true;
  }

  function sha256Fallback(msgBytes){
    const K = new Uint32Array([
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ]);
    let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    const len = msgBytes.length, bitLen = len * 8;
    const padLen = ((len + 9 + 63) >> 6) << 6;
    const buf = new Uint8Array(padLen);
    buf.set(msgBytes);
    buf[len] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(padLen - 4, bitLen >>> 0, false);
    dv.setUint32(padLen - 8, Math.floor(bitLen / 4294967296), false);
    const w = new Uint32Array(64);
    for(let off=0; off<padLen; off+=64){
      for(let i=0;i<16;i++) w[i]=dv.getUint32(off+i*4,false);
      for(let i=16;i<64;i++){
        const x=w[i-15], y=w[i-2];
        const s0=((x>>>7)|(x<<25))^((x>>>18)|(x<<14))^(x>>>3);
        const s1=((y>>>17)|(y<<15))^((y>>>19)|(y<<13))^(y>>>10);
        w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;
      }
      let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
      for(let i=0;i<64;i++){
        const S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
        const ch=(e&f)^((~e)&g);
        const t1=(h+S1+ch+K[i]+w[i])>>>0;
        const S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
        const maj=(a&b)^(a&c)^(b&c);
        const t2=(S0+maj)>>>0;
        h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
      }
      h0=(h0+a)>>>0;h1=(h1+b)>>>0;h2=(h2+c)>>>0;h3=(h3+d)>>>0;
      h4=(h4+e)>>>0;h5=(h5+f)>>>0;h6=(h6+g)>>>0;h7=(h7+h)>>>0;
    }
    const out = new Uint8Array(32), od = new DataView(out.buffer);
    [h0,h1,h2,h3,h4,h5,h6,h7].forEach((v,i)=>od.setUint32(i*4,v,false));
    return out;
  }

  async function digest(str){
    const bytes = enc.encode(str);
    if(window.crypto && window.crypto.subtle){
      return new Uint8Array(await window.crypto.subtle.digest('SHA-256', bytes));
    }
    return sha256Fallback(bytes);
  }

  for(let n=0; n<5000000; n++){
    const h = await digest(tok + ":" + n);
    if(zerosOk(h, diff)){
      const r = await fetch(%q, {
        method:'POST',
        credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({token:tok,solution:String(n)})
      });
      if(r.ok){
        window.location.replace(window.location.href);
        return;
      }
    }
  }
  document.getElementById('st').textContent='Verification failed. Please reload.';
})();
</script>
</body>
</html>`, token, diff, verifyEndpointPath)
}

func writeNeutral429(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "10")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte("Too Many Requests"))
}

type statusCaptureWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusCaptureWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusCaptureWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func (w *statusCaptureWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusCaptureWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (s *Shield) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if s.Mode == "off" {
		return next.ServeHTTP(w, r)
	}

	reqPath := r.URL.Path
	if strings.HasPrefix(reqPath, acmePrefix) || matchesPathPrefix(reqPath, s.ExemptPaths) {
		return next.ServeHTTP(w, r)
	}

	realIP, peerIP, behindTrustedProxy := s.resolveClientIP(r)
	preInfo, hasPreInfo := pre_tls.FromContext(r.Context())

	hst := s.getHostStats(r.Host)
	hst.reqs.Add(1)

	ipStr := realIP.String()
	if !realIP.IsValid() {
		ipStr = "unknown"
	}
	peerStr := ""
	if peerIP.IsValid() {
		peerStr = peerIP.String()
	}

	if _, banned := s.staticBanned[ipStr]; banned {
		hst.drops.Add(1)
		panic(http.ErrAbortHandler)
	}

	// Verify Search Bots (rDNS + fDNS + TTL cache)
	ua := r.Header.Get("User-Agent")
	verifiedBot, claimedSpoofedBot, _ := s.verifySearchBot(r.Context(), realIP, ua)
	if verifiedBot {
		return next.ServeHTTP(w, r)
	}

	now := s.now()
	idx := shardIndex(ipStr)
	sh := &s.rt.shards[idx]

	sh.mu.Lock()
	entry, ok := sh.ips[ipStr]
	if !ok {
		if len(sh.ips) >= maxIPEntriesPerShard {
			for k, v := range sh.ips {
				if v.inFlight <= 0 && (v.bannedUntil.IsZero() || now.After(v.bannedUntil)) {
					delete(sh.ips, k)
					break
				}
			}
		}
		entry = &ipState{
			limiter:           rate.NewLimiter(rate.Limit(s.RateLimitRPS), s.RateLimitBurst),
			hardLimiter:       rate.NewLimiter(rate.Limit(s.RateLimitRPS*s.HardDropMultiplier), max(int(float64(s.RateLimitBurst)*s.HardDropMultiplier), s.RateLimitBurst*2)),
			anomalyWindowFrom: now,
			notFoundWindowFrom: now,
		}
		sh.ips[ipStr] = entry
	}
	entry.lastSeen = now

	// 1. Active L7 Ban check (zero-overhead abort)
	if !entry.bannedUntil.IsZero() && now.Before(entry.bannedUntil) {
		sh.mu.Unlock()
		hst.drops.Add(1)
		panic(http.ErrAbortHandler)
	}

	// 2. Per-IP In-Flight Concurrency limit (HTTP/2 & HTTP/3 stream flood mitigation)
	if entry.inFlight >= int64(s.MaxConcurrentPerIP) {
		entry.softViolations++
		shouldBan := entry.softViolations >= 5
		if shouldBan {
			entry.bannedUntil = now.Add(time.Duration(s.BanDurationSeconds) * time.Second)
		}
		sh.mu.Unlock()
		hst.drops.Add(1)
		if shouldBan {
			s.emitEvent(ShieldEvent{
				Type:               "ban",
				Timestamp:          now.Unix(),
				Host:               r.Host,
				SiteID:             s.SiteID,
				ClientIP:           ipStr,
				PeerIP:             peerStr,
				BehindTrustedProxy: behindTrustedProxy,
				URI:                r.RequestURI,
				Method:             r.Method,
				UserAgent:          ua,
				Reason:             fmt.Sprintf("[Shield] Concurrent stream flood (>%d in-flight)", s.MaxConcurrentPerIP),
				Action:             "L7_BAN_ABORT",
			})
			panic(http.ErrAbortHandler)
		}
		writeNeutral429(w)
		return nil
	}

	// 3. Hard Rate Ceiling -> L7 Ban + Abort + Async Kernel Event (only direct traffic goes to ipset)
	if !entry.hardLimiter.AllowN(now, 1) {
		entry.bannedUntil = now.Add(time.Duration(s.BanDurationSeconds) * time.Second)
		sh.mu.Unlock()
		hst.drops.Add(1)
		s.emitEvent(ShieldEvent{
			Type:               "ban",
			Timestamp:          now.Unix(),
			Host:               r.Host,
			SiteID:             s.SiteID,
			ClientIP:           ipStr,
			PeerIP:             peerStr,
			BehindTrustedProxy: behindTrustedProxy,
			URI:                r.RequestURI,
			Method:             r.Method,
			UserAgent:          ua,
			Reason:             fmt.Sprintf("[Shield] HTTP flood hard threshold exceeded (%.0f req/s)", s.RateLimitRPS*s.HardDropMultiplier),
			Action:             "L7_BAN_ABORT",
		})
		panic(http.ErrAbortHandler)
	}

	// 4. Soft Per-IP Rate Limit
	softLimited := !entry.limiter.AllowN(now, 1)

	// Reset rolling anomaly window every 60s
	if now.Sub(entry.anomalyWindowFrom) > 60*time.Second {
		entry.anomalyScore = 0
		entry.softViolations = 0
		entry.anomalyWindowFrom = now
	}
	reqAnomaly := calcAnomalyScore(r, preInfo, hasPreInfo, claimedSpoofedBot)
	totalAnomaly := entry.anomalyScore + reqAnomaly
	if softLimited {
		entry.softViolations++
		totalAnomaly += 30
	}

	// Escalate repeat offenders to hard L7 ban + abort
	if totalAnomaly >= s.AnomalyScoreDrop || entry.softViolations >= 20 {
		entry.bannedUntil = now.Add(time.Duration(s.BanDurationSeconds) * time.Second)
		sh.mu.Unlock()
		hst.drops.Add(1)
		s.emitEvent(ShieldEvent{
			Type:               "ban",
			Timestamp:          now.Unix(),
			Host:               r.Host,
			SiteID:             s.SiteID,
			ClientIP:           ipStr,
			PeerIP:             peerStr,
			BehindTrustedProxy: behindTrustedProxy,
			URI:                r.RequestURI,
			Method:             r.Method,
			UserAgent:          ua,
			Reason:             fmt.Sprintf("[Shield] Behavioral/flood anomaly score=%d", totalAnomaly),
			Action:             "L7_BAN_ABORT",
		})
		panic(http.ErrAbortHandler)
	}

	// Reserve in-flight slot before releasing ip shard lock
	entry.inFlight++
	sh.mu.Unlock()

	defer func() {
		sh.mu.Lock()
		if cur, ok := sh.ips[ipStr]; ok && cur.inFlight > 0 {
			cur.inFlight--
		}
		sh.mu.Unlock()
	}()

	if reqPath == verifyEndpointPath {
		return s.handleChallengeVerify(w, r, realIP, preInfo)
	}

	// 5. Subnet (/24 v4 /64 v6) Rate Limit
	subKey := subnetKeyForIP(realIP)
	subIdx := shardIndex(subKey)
	subSh := &s.rt.shards[subIdx]
	subSh.mu.Lock()
	subSt, ok := subSh.subnets[subKey]
	if !ok {
		if len(subSh.subnets) >= maxSubnetEntriesPerShard {
			for k := range subSh.subnets {
				delete(subSh.subnets, k)
				break
			}
		}
		subSt = &subnetState{limiter: rate.NewLimiter(rate.Limit(s.SubnetRateLimitRPS), s.SubnetRateLimitBurst)}
		subSh.subnets[subKey] = subSt
	}
	subSt.lastSeen = now
	subnetLimited := !subSt.limiter.AllowN(now, 1)
	subSh.mu.Unlock()

	// 6. Sensitive Route Prefix Rate Limit
	routeLimited := false
	if sr := s.matchSensitiveRoute(reqPath); sr != nil {
		rKey := ipStr + "\x00" + sr.PathPrefix
		rIdx := shardIndex(rKey)
		rSh := &s.rt.shards[rIdx]
		rSh.mu.Lock()
		rst, ok := rSh.routes[rKey]
		if !ok {
			if len(rSh.routes) >= maxRouteEntriesPerShard {
				for k := range rSh.routes {
					delete(rSh.routes, k)
					break
				}
			}
			rst = &routeState{limiter: rate.NewLimiter(rate.Limit(sr.RPS), sr.Burst)}
			rSh.routes[rKey] = rst
		}
		rst.lastSeen = now
		routeLimited = !rst.limiter.AllowN(now, 1)
		rSh.mu.Unlock()
	}

	// 7. Per-Host Rate Limit
	hostLimited := false
	if hst.limiter != nil {
		hostLimited = !hst.limiter.AllowN(now, 1)
	}

	isAPI := matchesPathPrefix(reqPath, s.APIPaths)
	hasClearance := s.hasValidClearanceCookie(r, realIP, preInfo)

	// 8. Under Attack Mode / Soft Threshold / Anomaly Challenge
	if softLimited || subnetLimited || routeLimited || hostLimited {
		hst.drops.Add(1)
		s.emitEvent(ShieldEvent{
			Type:               "drop",
			Timestamp:          now.Unix(),
			Host:               r.Host,
			SiteID:             s.SiteID,
			ClientIP:           ipStr,
			PeerIP:             peerStr,
			BehindTrustedProxy: behindTrustedProxy,
			URI:                r.RequestURI,
			Method:             r.Method,
			UserAgent:          ua,
			Reason:             "[Shield] Rate limit threshold exceeded",
			Action:             "RATE_LIMIT_429",
		})
		if !isAPI && !hasClearance && (s.UnderAttackMode || strings.Contains(r.Header.Get("Accept"), "text/html")) {
			s.writeChallengeResponse(w, r, realIP, preInfo)
			return nil
		}
		writeNeutral429(w)
		return nil
	}

	needChallenge := false
	if !isAPI && !hasClearance {
		if s.UnderAttackMode {
			needChallenge = true
		} else if totalAnomaly >= s.AnomalyScoreChallenge {
			needChallenge = true
		}
	}
	if needChallenge {
		hst.drops.Add(1)
		s.emitEvent(ShieldEvent{
			Type:               "challenge",
			Timestamp:          now.Unix(),
			Host:               r.Host,
			SiteID:             s.SiteID,
			ClientIP:           ipStr,
			PeerIP:             peerStr,
			BehindTrustedProxy: behindTrustedProxy,
			URI:                r.RequestURI,
			Method:             r.Method,
			UserAgent:          ua,
			Reason:             fmt.Sprintf("[Shield] Challenge issued (under_attack=%v score=%d)", s.UnderAttackMode, totalAnomaly),
			Action:             "CHALLENGE_POW",
		})
		s.writeChallengeResponse(w, r, realIP, preInfo)
		return nil
	}

	// Pass to next handler (Coraza WAF / Reverse Proxy) and track 404 storms
	sw := &statusCaptureWriter{ResponseWriter: w}
	err := next.ServeHTTP(sw, r)
	if sw.status == http.StatusNotFound || sw.status == http.StatusBadRequest {
		sh.mu.Lock()
		if cur, ok := sh.ips[ipStr]; ok {
			if now.Sub(cur.notFoundWindowFrom) > 60*time.Second {
				cur.notFoundCount = 0
				cur.notFoundWindowFrom = now
			}
			cur.notFoundCount++
			if cur.notFoundCount >= 15 {
				cur.anomalyScore += 25
			}
		}
		sh.mu.Unlock()
	}
	return err
}

var (
	_ caddy.Module                = (*Shield)(nil)
	_ caddy.Provisioner           = (*Shield)(nil)
	_ caddy.Validator             = (*Shield)(nil)
	_ caddy.CleanerUpper          = (*Shield)(nil)
	_ caddyhttp.MiddlewareHandler = (*Shield)(nil)
	_ caddyfile.Unmarshaler       = (*Shield)(nil)
)
