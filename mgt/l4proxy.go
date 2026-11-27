package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	l4ShardsCount          = 64
	l4RateMaxShardEntries  = 4096
	l4RateEntryTTL         = 60 * time.Second
	l4RateSweepInterval    = 30 * time.Second
	l4DefaultDialTimeout   = 5 * time.Second
	l4DefaultTCPIdle       = 300 * time.Second
	l4DefaultUDPIdle       = 60 * time.Second
	l4DefaultHealthInt     = 10 * time.Second
	l4UDPReplyBufSize      = 65535
	l4UDPDefaultMaxSessCap = 65536
)

// l4BackendState holds live health and connection load for a single L4 backend endpoint.
type l4BackendState struct {
	addr        string
	healthy     atomic.Bool
	activeConns atomic.Int64
}

// l4ServiceSnapshot is an immutable configuration view read lock-free by worker goroutines.
type l4ServiceSnapshot struct {
	ID                  string
	Name                string
	Protocol            string // "tcp" or "udp"
	ListenPort          int
	Backends            []*l4BackendState
	LBPolicy            string // "round_robin", "least_conn", "ip_hash"
	ProxyProtocol       string // "", "off", "v1", "v2"
	Enabled             bool
	MaxConns            int
	MaxConnsPerIP       int
	RateLimit           int
	DialTimeout         time.Duration
	IdleTimeout         time.Duration
	HealthCheckInterval time.Duration
}

type l4ServiceRuntime struct {
	snap       atomic.Pointer[l4ServiceSnapshot]
	counters   *L4Service
	limiter    *l4ShardedRateLimiter
	ipConns    *l4PerIPConnTracker
	rrCounter  atomic.Uint64
	healthMu   sync.Mutex
	healthStop chan struct{}
	healthKey  string
}

type l4ListenerMeta struct {
	protocol string
	port     int
}

type L4ProxyManager struct {
	mu           sync.Mutex
	listeners    map[string]io.Closer
	listenerMeta map[string]l4ListenerMeta
	services     map[string]*L4Service
	runtimes     map[string]*l4ServiceRuntime
	banMu        sync.RWMutex
	banChecker   func(ip string) bool // optional kernel/config ban check
}

func NewL4ProxyManager() *L4ProxyManager {
	return &L4ProxyManager{
		listeners:    make(map[string]io.Closer),
		listenerMeta: make(map[string]l4ListenerMeta),
		services:     make(map[string]*L4Service),
		runtimes:     make(map[string]*l4ServiceRuntime),
	}
}

var l4Manager = NewL4ProxyManager()

// SetBanChecker attaches an optional IP ban predicate checked on incoming L4 connections.
func (m *L4ProxyManager) SetBanChecker(fn func(ip string) bool) {
	m.banMu.Lock()
	m.banChecker = fn
	m.banMu.Unlock()
}

func (m *L4ProxyManager) isIPBanned(ip string) bool {
	m.banMu.RLock()
	fn := m.banChecker
	m.banMu.RUnlock()
	if fn != nil {
		return fn(ip)
	}
	return false
}

// ListenerAddr returns the bound local address for an active service listener, or nil.
func (m *L4ProxyManager) ListenerAddr(id string) net.Addr {
	m.mu.Lock()
	ln := m.listeners[id]
	m.mu.Unlock()
	if ln == nil {
		return nil
	}
	switch l := ln.(type) {
	case net.Listener:
		return l.Addr()
	case *net.UDPConn:
		return l.LocalAddr()
	default:
		return nil
	}
}

type L4BackendHealth struct {
	ServiceID   string `json:"service_id"`
	ServiceName string `json:"service_name"`
	Protocol    string `json:"protocol"`
	ListenPort  int    `json:"listen_port"`
	Address     string `json:"address"`
	Healthy     bool   `json:"healthy"`
	ActiveConns int64  `json:"active_conns"`
}

func (m *L4ProxyManager) BackendHealthSnapshot() []L4BackendHealth {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	runtimes := make([]*l4ServiceRuntime, 0, len(m.runtimes))
	for _, rt := range m.runtimes {
		runtimes = append(runtimes, rt)
	}
	m.mu.Unlock()

	var out []L4BackendHealth
	for _, rt := range runtimes {
		if rt == nil {
			continue
		}
		snap := rt.snap.Load()
		if snap == nil || !snap.Enabled {
			continue
		}
		for _, b := range snap.Backends {
			if b == nil {
				continue
			}
			out = append(out, L4BackendHealth{
				ServiceID:   snap.ID,
				ServiceName: snap.Name,
				Protocol:    snap.Protocol,
				ListenPort:  snap.ListenPort,
				Address:     b.addr,
				Healthy:     b.healthy.Load(),
				ActiveConns: b.activeConns.Load(),
			})
		}
	}
	return out
}

func normalizeL4Backends(svc *L4Service) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(addr string) {
		addr = strings.TrimSpace(addr)
		if addr == "" || seen[addr] {
			return
		}
		seen[addr] = true
		out = append(out, addr)
	}
	for _, b := range svc.Backends {
		add(b)
	}
	if len(out) == 0 && svc.BackendAddr != "" {
		add(svc.BackendAddr)
	}
	return out
}

func buildL4Snapshot(svc *L4Service, prev *l4ServiceSnapshot) *l4ServiceSnapshot {
	proto := strings.ToLower(strings.TrimSpace(svc.Protocol))
	if proto != "udp" {
		proto = "tcp"
	}
	lb := strings.ToLower(strings.TrimSpace(svc.LBPolicy))
	switch lb {
	case "least_conn", "ip_hash", "round_robin":
	default:
		lb = "round_robin"
	}
	pp := strings.ToLower(strings.TrimSpace(svc.ProxyProtocol))
	if pp != "v1" && pp != "v2" {
		pp = "off"
	}
	if proto == "udp" {
		pp = "off"
	}

	dialTO := l4DefaultDialTimeout
	if svc.DialTimeoutSec > 0 {
		dialTO = time.Duration(svc.DialTimeoutSec) * time.Second
	}
	idleTO := l4DefaultTCPIdle
	if proto == "udp" {
		idleTO = l4DefaultUDPIdle
	}
	if svc.IdleTimeoutSec > 0 {
		idleTO = time.Duration(svc.IdleTimeoutSec) * time.Second
	}

	var hcInt time.Duration
	addrs := normalizeL4Backends(svc)
	if svc.HealthCheckIntervalSec > 0 {
		hcInt = time.Duration(svc.HealthCheckIntervalSec) * time.Second
	} else if len(addrs) > 1 && proto == "tcp" {
		hcInt = l4DefaultHealthInt
	}

	// Preserve existing backend health/activeConns across config updates where possible.
	prevByAddr := make(map[string]*l4BackendState)
	if prev != nil {
		for _, b := range prev.Backends {
			prevByAddr[b.addr] = b
		}
	}
	backends := make([]*l4BackendState, 0, len(addrs))
	for _, addr := range addrs {
		if existing, ok := prevByAddr[addr]; ok {
			backends = append(backends, existing)
			continue
		}
		st := &l4BackendState{addr: addr}
		st.healthy.Store(true)
		backends = append(backends, st)
	}

	return &l4ServiceSnapshot{
		ID:                  svc.ID,
		Name:                svc.Name,
		Protocol:            proto,
		ListenPort:          svc.ListenPort,
		Backends:            backends,
		LBPolicy:            lb,
		ProxyProtocol:       pp,
		Enabled:             svc.Enabled,
		MaxConns:            svc.MaxConns,
		MaxConnsPerIP:       svc.MaxConnsPerIP,
		RateLimit:           svc.RateLimit,
		DialTimeout:         dialTO,
		IdleTimeout:         idleTO,
		HealthCheckInterval: hcInt,
	}
}

func (m *L4ProxyManager) Sync(services []L4Service) {
	m.mu.Lock()
	defer m.mu.Unlock()

	desiredByID := make(map[string]*L4Service, len(services))
	activeIDs := make(map[string]bool, len(services))
	desiredProto := make(map[string]string, len(services))
	for i := range services {
		svc := &services[i]
		desiredByID[svc.ID] = svc
		proto := strings.ToLower(strings.TrimSpace(svc.Protocol))
		if proto != "udp" {
			proto = "tcp"
		}
		desiredProto[svc.ID] = proto
		if svc.Enabled {
			activeIDs[svc.ID] = true
		}
	}

	// Pass 1: Tear down removed, disabled, or port/protocol-changed listeners FIRST
	// so two services swapping ports or protocol changes release sockets before rebinding.
	for id, ln := range m.listeners {
		svc, inDesired := desiredByID[id]
		meta := m.listenerMeta[id]
		if !inDesired || !svc.Enabled || meta.protocol != desiredProto[id] || meta.port != svc.ListenPort {
			log.Printf("[L4 Proxy] Stopping/restarting listener for service ID %s (%s:%d)", id, meta.protocol, meta.port)
			_ = ln.Close()
			delete(m.listeners, id)
			delete(m.listenerMeta, id)
		}
	}
	for id, rt := range m.runtimes {
		svc, inDesired := desiredByID[id]
		if !inDesired {
			rt.stopHealthProbe()
			delete(m.runtimes, id)
			delete(m.services, id)
		} else if !svc.Enabled {
			rt.stopHealthProbe()
		}
	}

	// Pass 2: Update configs/snapshots and start any missing listeners.
	for i := range services {
		svc := &services[i]
		managed, exists := m.services[svc.ID]
		if !exists {
			managed = &L4Service{
				ID: svc.ID,
			}
			m.services[svc.ID] = managed
		}
		managed.Name = svc.Name
		managed.Protocol = svc.Protocol
		managed.ListenPort = svc.ListenPort
		managed.BackendAddr = svc.BackendAddr
		managed.Backends = append([]string(nil), svc.Backends...)
		managed.LBPolicy = svc.LBPolicy
		managed.ProxyProtocol = svc.ProxyProtocol
		managed.Mode = svc.Mode
		managed.Enabled = svc.Enabled
		managed.MaxConns = svc.MaxConns
		managed.MaxConnsPerIP = svc.MaxConnsPerIP
		managed.RateLimit = svc.RateLimit
		managed.DialTimeoutSec = svc.DialTimeoutSec
		managed.IdleTimeoutSec = svc.IdleTimeoutSec
		managed.HealthCheckIntervalSec = svc.HealthCheckIntervalSec
		managed.Description = svc.Description

		rt, ok := m.runtimes[svc.ID]
		if !ok {
			rt = &l4ServiceRuntime{
				counters: managed,
				limiter:  newL4ShardedRateLimiter(),
				ipConns:  newL4PerIPConnTracker(),
			}
			m.runtimes[svc.ID] = rt
		}

		snap := buildL4Snapshot(svc, rt.snap.Load())
		rt.snap.Store(snap)
		rt.syncHealthProbe(snap)

		if snap.Enabled {
			if _, lnExists := m.listeners[svc.ID]; !lnExists {
				switch snap.Protocol {
				case "udp":
					uConn, bindAddr, err := listenDualStackUDP(snap.ListenPort)
					if err != nil {
						log.Printf("[L4 Proxy] Failed to bind UDP %s (Port %d): %v", snap.Name, snap.ListenPort, err)
						continue
					}
					m.listeners[svc.ID] = uConn
					m.listenerMeta[svc.ID] = l4ListenerMeta{protocol: "udp", port: snap.ListenPort}
					log.Printf("[L4 Proxy] Started UDP listening for %s on %s -> %v", snap.Name, bindAddr, backendAddrs(snap.Backends))
					go m.handleUDPListener(svc.ID, uConn, rt)
				default:
					newLn, bindAddr, err := listenDualStackTCP(snap.ListenPort)
					if err != nil {
						log.Printf("[L4 Proxy] Failed to bind TCP %s (Port %d): %v", snap.Name, snap.ListenPort, err)
						continue
					}
					m.listeners[svc.ID] = newLn
					m.listenerMeta[svc.ID] = l4ListenerMeta{protocol: "tcp", port: snap.ListenPort}
					log.Printf("[L4 Proxy] Started TCP listening for %s on %s -> %v", snap.Name, bindAddr, backendAddrs(snap.Backends))
					go m.handleTCPListener(svc.ID, newLn, rt)
				}
			}
		}
	}
	_ = activeIDs
}

func backendAddrs(backends []*l4BackendState) []string {
	out := make([]string, len(backends))
	for i, b := range backends {
		out[i] = b.addr
	}
	return out
}

func listenDualStackTCP(port int) (net.Listener, string, error) {
	v6Addr := fmt.Sprintf("[::]:%d", port)
	if ln, err := net.Listen("tcp", v6Addr); err == nil {
		return ln, ln.Addr().String(), nil
	}
	v4Addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp4", v4Addr)
	if err != nil {
		return nil, "", err
	}
	return ln, ln.Addr().String(), nil
}

func listenDualStackUDP(port int) (*net.UDPConn, string, error) {
	v6Addr := fmt.Sprintf("[::]:%d", port)
	if uAddr, err := net.ResolveUDPAddr("udp", v6Addr); err == nil {
		if conn, err := net.ListenUDP("udp", uAddr); err == nil {
			return conn, conn.LocalAddr().String(), nil
		}
	}
	v4Addr := fmt.Sprintf("0.0.0.0:%d", port)
	uAddr, err := net.ResolveUDPAddr("udp4", v4Addr)
	if err != nil {
		return nil, "", err
	}
	conn, err := net.ListenUDP("udp4", uAddr)
	if err != nil {
		return nil, "", err
	}
	return conn, conn.LocalAddr().String(), nil
}

func (rt *l4ServiceRuntime) syncHealthProbe(snap *l4ServiceSnapshot) {
	rt.healthMu.Lock()
	defer rt.healthMu.Unlock()

	if !snap.Enabled || snap.Protocol != "tcp" || snap.HealthCheckInterval <= 0 || len(snap.Backends) == 0 {
		if rt.healthStop != nil {
			close(rt.healthStop)
			rt.healthStop = nil
			rt.healthKey = ""
		}
		return
	}

	key := fmt.Sprintf("%s|%s", snap.HealthCheckInterval.String(), strings.Join(backendAddrs(snap.Backends), ","))
	if rt.healthStop != nil && rt.healthKey == key {
		return
	}
	if rt.healthStop != nil {
		close(rt.healthStop)
	}
	stopCh := make(chan struct{})
	rt.healthStop = stopCh
	rt.healthKey = key

	go runL4HealthProbeLoop(snap, stopCh)
}

func (rt *l4ServiceRuntime) stopHealthProbe() {
	rt.healthMu.Lock()
	defer rt.healthMu.Unlock()
	if rt.healthStop != nil {
		close(rt.healthStop)
		rt.healthStop = nil
		rt.healthKey = ""
	}
}

func runL4HealthProbeLoop(snap *l4ServiceSnapshot, stopCh <-chan struct{}) {
	probeTimeout := snap.DialTimeout
	if probeTimeout <= 0 || probeTimeout > 3*time.Second {
		probeTimeout = 3 * time.Second
	}
	probeOnce := func() {
		for _, b := range snap.Backends {
			conn, err := net.DialTimeout("tcp", b.addr, probeTimeout)
			if err != nil {
				b.healthy.Store(false)
			} else {
				_ = conn.Close()
				b.healthy.Store(true)
			}
		}
	}

	probeOnce()
	ticker := time.NewTicker(snap.HealthCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			probeOnce()
		}
	}
}

func selectL4Backends(snap *l4ServiceSnapshot, clientIP string, rrCounter *atomic.Uint64) []*l4BackendState {
	n := len(snap.Backends)
	if n == 0 {
		return nil
	}
	if n == 1 {
		return snap.Backends
	}

	healthy := make([]*l4BackendState, 0, n)
	unhealthy := make([]*l4BackendState, 0, n)
	for _, b := range snap.Backends {
		if b.healthy.Load() {
			healthy = append(healthy, b)
		} else {
			unhealthy = append(unhealthy, b)
		}
	}

	orderGroup := func(group []*l4BackendState) []*l4BackendState {
		m := len(group)
		if m <= 1 {
			return group
		}
		out := make([]*l4BackendState, m)
		switch snap.LBPolicy {
		case "ip_hash":
			h := fnv.New32a()
			_, _ = h.Write([]byte(clientIP))
			start := int(h.Sum32()) % m
			for i := 0; i < m; i++ {
				out[i] = group[(start+i)%m]
			}
		case "least_conn":
			copy(out, group)
			tieStart := int(rrCounter.Add(1)-1) % m
			// Rotate first so ties distribute round-robin, then selection-sort by activeConns.
			rotated := make([]*l4BackendState, m)
			for i := 0; i < m; i++ {
				rotated[i] = out[(tieStart+i)%m]
			}
			for i := 0; i < m-1; i++ {
				minIdx := i
				minConns := rotated[i].activeConns.Load()
				for j := i + 1; j < m; j++ {
					if c := rotated[j].activeConns.Load(); c < minConns {
						minIdx = j
						minConns = c
					}
				}
				if minIdx != i {
					rotated[i], rotated[minIdx] = rotated[minIdx], rotated[i]
				}
			}
			return rotated
		default: // round_robin
			start := int((rrCounter.Add(1) - 1) % uint64(m))
			for i := 0; i < m; i++ {
				out[i] = group[(start+i)%m]
			}
		}
		return out
	}

	ordered := orderGroup(healthy)
	if len(unhealthy) > 0 {
		ordered = append(ordered, orderGroup(unhealthy)...)
	}
	return ordered
}

func extractNormalizedClientIP(addr net.Addr) (string, uint16, netip.Addr) {
	if addr == nil {
		return "", 0, netip.Addr{}
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		if na, ok := netip.AddrFromSlice(a.IP); ok {
			na = na.Unmap()
			return na.String(), uint16(a.Port), na
		}
	case *net.UDPAddr:
		if na, ok := netip.AddrFromSlice(a.IP); ok {
			na = na.Unmap()
			return na.String(), uint16(a.Port), na
		}
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		if na, parseErr := netip.ParseAddr(addr.String()); parseErr == nil {
			na = na.Unmap()
			return na.String(), 0, na
		}
		return addr.String(), 0, netip.Addr{}
	}
	p, _ := strconv.Atoi(portStr)
	if na, parseErr := netip.ParseAddr(host); parseErr == nil {
		na = na.Unmap()
		return na.String(), uint16(p), na
	}
	return host, uint16(p), netip.Addr{}
}

// buildProxyProtocolHeader encodes HAProxy PROXY Protocol v1 or v2 header bytes.
func buildProxyProtocolHeader(version string, srcAddr, dstAddr net.Addr) ([]byte, error) {
	_, srcPort, srcIP := extractNormalizedClientIP(srcAddr)
	_, dstPort, dstIP := extractNormalizedClientIP(dstAddr)

	switch version {
	case "v1":
		if !srcIP.IsValid() {
			return []byte("PROXY UNKNOWN\r\n"), nil
		}
		if srcIP.Is4() {
			if !dstIP.IsValid() || !dstIP.Is4() {
				dstIP = netip.IPv4Unspecified()
			}
			return []byte(fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", srcIP.String(), dstIP.String(), srcPort, dstPort)), nil
		}
		if !dstIP.IsValid() || !dstIP.Is6() {
			dstIP = netip.IPv6Unspecified()
		}
		return []byte(fmt.Sprintf("PROXY TCP6 %s %s %d %d\r\n", srcIP.String(), dstIP.String(), srcPort, dstPort)), nil

	case "v2":
		var buf bytes.Buffer
		// 12-byte signature
		buf.Write([]byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a})
		buf.WriteByte(0x21) // Version 2 (0x20) | PROXY command (0x01)
		if !srcIP.IsValid() {
			buf.WriteByte(0x00) // AF_UNSPEC
			_ = binary.Write(&buf, binary.BigEndian, uint16(0))
			return buf.Bytes(), nil
		}
		if srcIP.Is4() {
			if !dstIP.IsValid() || !dstIP.Is4() {
				dstIP = netip.IPv4Unspecified()
			}
			buf.WriteByte(0x11) // AF_INET | STREAM
			_ = binary.Write(&buf, binary.BigEndian, uint16(12))
			s4 := srcIP.As4()
			d4 := dstIP.As4()
			buf.Write(s4[:])
			buf.Write(d4[:])
		} else {
			if !dstIP.IsValid() || !dstIP.Is6() {
				dstIP = netip.IPv6Unspecified()
			}
			buf.WriteByte(0x21) // AF_INET6 | STREAM
			_ = binary.Write(&buf, binary.BigEndian, uint16(36))
			s16 := srcIP.As16()
			d16 := dstIP.As16()
			buf.Write(s16[:])
			buf.Write(d16[:])
		}
		_ = binary.Write(&buf, binary.BigEndian, srcPort)
		_ = binary.Write(&buf, binary.BigEndian, dstPort)
		return buf.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported proxy protocol version %q", version)
	}
}

type l4IdleConn struct {
	net.Conn
	idleTimeout  time.Duration
	lastActivity *atomic.Int64
}

func (c *l4IdleConn) Read(p []byte) (int, error) {
	deadlineTO := c.idleTimeout
	for {
		if deadlineTO > 0 {
			_ = c.Conn.SetReadDeadline(time.Now().Add(deadlineTO))
		}
		n, err := c.Conn.Read(p)
		if n > 0 {
			c.lastActivity.Store(time.Now().UnixNano())
			return n, err
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && c.idleTimeout > 0 {
				remaining := c.idleTimeout - time.Since(time.Unix(0, c.lastActivity.Load()))
				if remaining > 5*time.Millisecond {
					deadlineTO = remaining
					continue
				}
			}
			return n, err
		}
	}
}

func (c *l4IdleConn) Write(p []byte) (int, error) {
	if c.idleTimeout > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idleTimeout))
	}
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.lastActivity.Store(time.Now().UnixNano())
	}
	return n, err
}

func (m *L4ProxyManager) handleTCPListener(_ string, ln net.Listener, rt *l4ServiceRuntime) {
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			// Listener was closed (Sync stopped or restart) -> exit cleanly
			return
		}

		snap := rt.snap.Load()
		if snap == nil || !snap.Enabled || len(snap.Backends) == 0 {
			_ = clientConn.Close()
			continue
		}

		clientIP, _, _ := extractNormalizedClientIP(clientConn.RemoteAddr())
		if clientIP != "" && m.isIPBanned(clientIP) {
			_ = clientConn.Close()
			continue
		}

		if snap.RateLimit > 0 && !rt.limiter.Allow(clientIP, snap.RateLimit) {
			_ = clientConn.Close()
			continue
		}

		if snap.MaxConns > 0 && atomic.LoadInt64(&rt.counters.ActiveConns) >= int64(snap.MaxConns) {
			log.Printf("[L4 Proxy] Max connections reached for %s (%d), dropping", snap.Name, snap.MaxConns)
			_ = clientConn.Close()
			continue
		}

		trackedPerIP := false
		if snap.MaxConnsPerIP > 0 {
			if !rt.ipConns.TryAcquire(clientIP, snap.MaxConnsPerIP) {
				_ = clientConn.Close()
				continue
			}
			trackedPerIP = true
		}

		atomic.AddInt64(&rt.counters.ActiveConns, 1)
		atomic.AddInt64(&rt.counters.TotalConns, 1)

		go m.serveTCPConn(clientConn, clientIP, trackedPerIP, snap, rt)
	}
}

func (m *L4ProxyManager) serveTCPConn(clientConn net.Conn, clientIP string, trackedPerIP bool, snap *l4ServiceSnapshot, rt *l4ServiceRuntime) {
	defer func() {
		_ = clientConn.Close()
		atomic.AddInt64(&rt.counters.ActiveConns, -1)
		if trackedPerIP {
			rt.ipConns.Release(clientIP)
		}
	}()

	candidates := selectL4Backends(snap, clientIP, &rt.rrCounter)
	var (
		backendConn net.Conn
		chosen      *l4BackendState
		dialErr     error
	)
	for _, b := range candidates {
		backendConn, dialErr = net.DialTimeout("tcp", b.addr, snap.DialTimeout)
		if dialErr == nil {
			b.healthy.Store(true)
			chosen = b
			break
		}
		b.healthy.Store(false)
	}
	if backendConn == nil || chosen == nil {
		log.Printf("[L4 Proxy] Failed to connect to backends for %s: %v", snap.Name, dialErr)
		return
	}
	chosen.activeConns.Add(1)
	defer func() {
		chosen.activeConns.Add(-1)
		_ = backendConn.Close()
	}()

	if snap.ProxyProtocol == "v1" || snap.ProxyProtocol == "v2" {
		hdr, hdrErr := buildProxyProtocolHeader(snap.ProxyProtocol, clientConn.RemoteAddr(), clientConn.LocalAddr())
		if hdrErr != nil {
			log.Printf("[L4 Proxy] Failed to encode PROXY %s header for %s: %v", snap.ProxyProtocol, snap.Name, hdrErr)
			return
		}
		if snap.DialTimeout > 0 {
			_ = backendConn.SetWriteDeadline(time.Now().Add(snap.DialTimeout))
		}
		if _, werr := backendConn.Write(hdr); werr != nil {
			log.Printf("[L4 Proxy] Failed to write PROXY %s header to %s for %s: %v", snap.ProxyProtocol, chosen.addr, snap.Name, werr)
			return
		}
		_ = backendConn.SetWriteDeadline(time.Time{})
	}

	if tc, ok := clientConn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	if tb, ok := backendConn.(*net.TCPConn); ok {
		_ = tb.SetKeepAlive(true)
		_ = tb.SetKeepAlivePeriod(30 * time.Second)
	}

	var lastAct atomic.Int64
	lastAct.Store(time.Now().UnixNano())
	wrappedClient := &l4IdleConn{Conn: clientConn, idleTimeout: snap.IdleTimeout, lastActivity: &lastAct}
	wrappedBackend := &l4IdleConn{Conn: backendConn, idleTimeout: snap.IdleTimeout, lastActivity: &lastAct}

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Backend
	go func() {
		defer wg.Done()
		n, _ := io.Copy(wrappedBackend, wrappedClient)
		atomic.AddInt64(&rt.counters.BytesIn, n)
		if tcpConn, ok := backendConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()

	// Backend -> Client
	go func() {
		defer wg.Done()
		n, _ := io.Copy(wrappedClient, wrappedBackend)
		atomic.AddInt64(&rt.counters.BytesOut, n)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
}

type l4UDPSession struct {
	key          string
	clientIP     string
	clientAddr   *net.UDPAddr
	backend      *l4BackendState
	backendConn  *net.UDPConn
	trackedPerIP bool
	lastActivity atomic.Int64
	closed       atomic.Bool
}

func (m *L4ProxyManager) handleUDPListener(_ string, listener *net.UDPConn, rt *l4ServiceRuntime) {
	var sessMu sync.Mutex
	sessions := make(map[string]*l4UDPSession)
	stopReaper := make(chan struct{})

	closeSession := func(s *l4UDPSession) {
		if !s.closed.CompareAndSwap(false, true) {
			return
		}
		_ = s.backendConn.Close()
		atomic.AddInt64(&rt.counters.ActiveConns, -1)
		s.backend.activeConns.Add(-1)
		if s.trackedPerIP {
			rt.ipConns.Release(s.clientIP)
		}
	}

	defer func() {
		close(stopReaper)
		sessMu.Lock()
		for k, s := range sessions {
			delete(sessions, k)
			closeSession(s)
		}
		sessMu.Unlock()
	}()

	// Idle session reaper
	go func() {
		tickInterval := 250 * time.Millisecond
		ticker := time.NewTicker(tickInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopReaper:
				return
			case now := <-ticker.C:
				snap := rt.snap.Load()
				idleTO := l4DefaultUDPIdle
				if snap != nil && snap.IdleTimeout > 0 {
					idleTO = snap.IdleTimeout
				}
				cutoff := now.Add(-idleTO).UnixNano()
				var expired []*l4UDPSession
				sessMu.Lock()
				for k, s := range sessions {
					if s.lastActivity.Load() < cutoff {
						delete(sessions, k)
						expired = append(expired, s)
					}
				}
				sessMu.Unlock()
				for _, s := range expired {
					closeSession(s)
				}
			}
		}
	}()

	buf := make([]byte, l4UDPReplyBufSize)
	for {
		n, clientAddr, err := listener.ReadFromUDP(buf)
		if err != nil {
			return
		}

		snap := rt.snap.Load()
		if snap == nil || !snap.Enabled || len(snap.Backends) == 0 {
			continue
		}

		clientIP, clientPort, _ := extractNormalizedClientIP(clientAddr)
		if clientIP != "" && m.isIPBanned(clientIP) {
			continue
		}
		if snap.RateLimit > 0 && !rt.limiter.Allow(clientIP, snap.RateLimit) {
			continue
		}

		sessKey := clientIP + ":" + strconv.Itoa(int(clientPort))

		sessMu.Lock()
		sess, exists := sessions[sessKey]
		if exists && sess.closed.Load() {
			delete(sessions, sessKey)
			exists = false
		}
		sessMu.Unlock()

		if !exists {
			if snap.MaxConns > 0 && atomic.LoadInt64(&rt.counters.ActiveConns) >= int64(snap.MaxConns) {
				continue
			}
			sessCap := snap.MaxConns
			if sessCap <= 0 || sessCap > l4UDPDefaultMaxSessCap {
				sessCap = l4UDPDefaultMaxSessCap
			}

			candidates := selectL4Backends(snap, clientIP, &rt.rrCounter)
			var (
				bConn  *net.UDPConn
				chosen *l4BackendState
			)
			for _, b := range candidates {
				rAddr, rErr := net.ResolveUDPAddr("udp", b.addr)
				if rErr != nil {
					b.healthy.Store(false)
					continue
				}
				c, dErr := net.DialUDP("udp", nil, rAddr)
				if dErr != nil {
					b.healthy.Store(false)
					continue
				}
				bConn = c
				chosen = b
				b.healthy.Store(true)
				break
			}
			if bConn == nil || chosen == nil {
				continue
			}

			trackedPerIP := false
			if snap.MaxConnsPerIP > 0 {
				if !rt.ipConns.TryAcquire(clientIP, snap.MaxConnsPerIP) {
					_ = bConn.Close()
					continue
				}
				trackedPerIP = true
			}

			sess = &l4UDPSession{
				key:          sessKey,
				clientIP:     clientIP,
				clientAddr:   clientAddr,
				backend:      chosen,
				backendConn:  bConn,
				trackedPerIP: trackedPerIP,
			}
			sess.lastActivity.Store(time.Now().UnixNano())

			sessMu.Lock()
			if len(sessions) >= sessCap {
				sessMu.Unlock()
				_ = bConn.Close()
				if trackedPerIP {
					rt.ipConns.Release(clientIP)
				}
				continue
			}
			if existing, dup := sessions[sessKey]; dup && !existing.closed.Load() {
				sessMu.Unlock()
				_ = bConn.Close()
				if trackedPerIP {
					rt.ipConns.Release(clientIP)
				}
				sess = existing
			} else {
				sessions[sessKey] = sess
				sessMu.Unlock()

				chosen.activeConns.Add(1)
				atomic.AddInt64(&rt.counters.ActiveConns, 1)
				atomic.AddInt64(&rt.counters.TotalConns, 1)

				go func(s *l4UDPSession) {
					rBuf := make([]byte, l4UDPReplyBufSize)
					for {
						rn, err := s.backendConn.Read(rBuf)
						if err != nil {
							sessMu.Lock()
							if cur, ok := sessions[s.key]; ok && cur == s {
								delete(sessions, s.key)
							}
							sessMu.Unlock()
							closeSession(s)
							return
						}
						s.lastActivity.Store(time.Now().UnixNano())
						if _, werr := listener.WriteToUDP(rBuf[:rn], s.clientAddr); werr == nil {
							atomic.AddInt64(&rt.counters.BytesOut, int64(rn))
						}
					}
				}(sess)
			}
		}

		sess.lastActivity.Store(time.Now().UnixNano())
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if _, werr := sess.backendConn.Write(pkt); werr == nil {
			atomic.AddInt64(&rt.counters.BytesIn, int64(n))
		}
	}
}

// --- Pure stdlib 64-shard Token Bucket Rate Limiter ---

type l4RateBucket struct {
	tokens float64
	last   time.Time
}

type l4RateShard struct {
	mu        sync.Mutex
	entries   map[string]*l4RateBucket
	lastSweep time.Time
}

type l4ShardedRateLimiter struct {
	shards [l4ShardsCount]l4RateShard
}

func newL4ShardedRateLimiter() *l4ShardedRateLimiter {
	rl := &l4ShardedRateLimiter{}
	now := time.Now()
	for i := range rl.shards {
		rl.shards[i].entries = make(map[string]*l4RateBucket)
		rl.shards[i].lastSweep = now
	}
	return rl
}

func fnv32ShardIdx(key string) int {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	var h uint32 = offset32
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= prime32
	}
	return int(h & (l4ShardsCount - 1))
}

func (rl *l4ShardedRateLimiter) Allow(key string, ratePerSec int) bool {
	if ratePerSec <= 0 || key == "" {
		return true
	}
	now := time.Now()
	burst := float64(ratePerSec)
	shard := &rl.shards[fnv32ShardIdx(key)]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if now.Sub(shard.lastSweep) > l4RateSweepInterval || len(shard.entries) >= l4RateMaxShardEntries {
		for k, b := range shard.entries {
			if now.Sub(b.last) > l4RateEntryTTL {
				delete(shard.entries, k)
			}
		}
		shard.lastSweep = now
		if len(shard.entries) >= l4RateMaxShardEntries {
			// Hard evict a batch if under heavy IP-spoof flood.
			evicted := 0
			for k := range shard.entries {
				delete(shard.entries, k)
				evicted++
				if evicted >= l4RateMaxShardEntries/4 {
					break
				}
			}
		}
	}

	b, ok := shard.entries[key]
	if !ok {
		shard.entries[key] = &l4RateBucket{
			tokens: burst - 1.0,
			last:   now,
		}
		return true
	}

	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * float64(ratePerSec)
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}
	return false
}

// --- Pure stdlib 64-shard Per-IP Active Connection Tracker ---

type l4ConnShard struct {
	mu     sync.Mutex
	counts map[string]int
}

type l4PerIPConnTracker struct {
	shards [l4ShardsCount]l4ConnShard
}

func newL4PerIPConnTracker() *l4PerIPConnTracker {
	t := &l4PerIPConnTracker{}
	for i := range t.shards {
		t.shards[i].counts = make(map[string]int)
	}
	return t
}

func (t *l4PerIPConnTracker) TryAcquire(ip string, limit int) bool {
	if limit <= 0 || ip == "" {
		return true
	}
	shard := &t.shards[fnv32ShardIdx(ip)]
	shard.mu.Lock()
	cur := shard.counts[ip]
	if cur >= limit {
		shard.mu.Unlock()
		return false
	}
	shard.counts[ip] = cur + 1
	shard.mu.Unlock()
	return true
}

func (t *l4PerIPConnTracker) Release(ip string) {
	if ip == "" {
		return
	}
	shard := &t.shards[fnv32ShardIdx(ip)]
	shard.mu.Lock()
	if cur := shard.counts[ip]; cur <= 1 {
		delete(shard.counts, ip)
	} else {
		shard.counts[ip] = cur - 1
	}
	shard.mu.Unlock()
}
