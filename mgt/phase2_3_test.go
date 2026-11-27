package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPhase2_ShieldUnixSocketEvents_AntiSelfDoS_And_AutoProxy(t *testing.T) {
	shortDir, err := os.MkdirTemp("", "vsg*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortDir) })
	sockPath := filepath.Join(shortDir, "ev.sock")

	s := &AppState{
		configPath:       filepath.Join(shortDir, "config.json"),
		eventsSocketPath: sockPath,
		bannedMap:        make(map[string]*BannedIPEntry),
		sessions:         make(map[string]Session),
		offenseCount:     make(map[string]int),
		config: Config{
			DefaultBanTTL: 24,
			Sites: []Site{
				{
					ID:                       "s-ap",
					Domain:                   "app.example.com",
					Upstream:                 "127.0.0.1:8080",
					AutoProxyEnabled:         true,
					AutoProxyZoneID:          "z1",
					AutoProxyRecordIDs:       []string{"r1"},
					AutoProxyThresholdRPS:    100,
					AutoProxyThresholdDropPS: 10,
					AutoProxyWindowSec:       10,
					AutoProxyHoldMinutes:     5,
				},
			},
			Cloudflare: CloudflareConfig{
				APIToken:   "tok-123",
				CachedIPv4: []string{"173.245.48.0/20"},
			},
			WhitelistIPs: []WhitelistIPEntry{
				{IP: "203.0.113.5", Note: "Admin"},
			},
		},
	}

	var cfPatched atomic.Int32
	cfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"r1","type":"A","name":"app.example.com","content":"1.2.3.4","proxied":false}],"result_info":{"page":1,"per_page":100,"total_pages":1,"count":1}}`))
			return
		}
		cfPatched.Add(1)
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"r1","type":"A","name":"app.example.com","content":"1.2.3.4","proxied":true}}`))
	}))
	defer cfSrv.Close()

	s.autoProxyCtrl = newAutoProxyController(s)
	s.autoProxyCtrl.baseURL = cfSrv.URL

	if err := s.startShieldEventReceiver(); err != nil {
		t.Fatalf("startShieldEventReceiver failed: %v", err)
	}
	defer s.stopShieldEventReceiver()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial unix socket %s failed: %v", sockPath, err)
	}
	defer conn.Close()

	sendEv := func(ev ShieldEvent) {
		t.Helper()
		b, _ := json.Marshal(ev)
		_, werr := conn.Write(append(b, '\n'))
		if werr != nil {
			t.Fatalf("write event failed: %v", werr)
		}
	}

	// 1. Direct abuser -> kernel bannedMap ONLY (not ShieldBannedIPs)
	sendEv(ShieldEvent{
		Type:               "ban",
		ClientIP:           "198.51.100.10",
		PeerIP:             "198.51.100.10",
		BehindTrustedProxy: false,
		Host:               "app.example.com",
		SiteID:             "s-ap",
		Reason:             "direct flood",
	})

	// 2. Abuser behind Cloudflare -> ShieldBannedIPs ONLY (NEVER kernel bannedMap and NEVER ban CF PeerIP!)
	sendEv(ShieldEvent{
		Type:               "ban",
		ClientIP:           "198.51.100.20",
		PeerIP:             "173.245.48.5",
		BehindTrustedProxy: true,
		Host:               "app.example.com",
		SiteID:             "s-ap",
		Reason:             "behind-CF flood",
		URI:                "/login",
		Method:             "POST",
	})

	// 3. Event whose ClientIP itself is Cloudflare Edge -> completely ignored
	sendEv(ShieldEvent{
		Type:     "ban",
		ClientIP: "173.245.48.9",
		PeerIP:   "173.245.48.9",
		Reason:   "must be ignored",
	})

	// 4. Whitelisted IP -> ignored
	sendEv(ShieldEvent{
		Type:     "ban",
		ClientIP: "203.0.113.5",
		PeerIP:   "203.0.113.5",
	})

	// 5. Drop event -> logged in recentLogs
	sendEv(ShieldEvent{
		Type:     "drop",
		ClientIP: "198.51.100.30",
		Host:     "app.example.com",
		URI:      "/api/search",
		Method:   "GET",
		Reason:   "rate exceeded",
	})

	// 6. Stats event feeding high RPS & DropPS into AutoProxyController
	sendEv(ShieldEvent{
		Type:   "stats",
		SiteID: "s-ap",
		Host:   "app.example.com",
		RPS:    150,
		DropPS: 25,
	})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		_, hasDirect := s.bannedMap["198.51.100.10"]
		_, hasProxyClientInKernel := s.bannedMap["198.51.100.20"]
		_, hasCFInKernel := s.bannedMap["173.245.48.5"]
		_, hasCF9InKernel := s.bannedMap["173.245.48.9"]
		_, hasWL := s.bannedMap["203.0.113.5"]
		l7Bans := append([]ShieldBanEntry(nil), s.config.ShieldBannedIPs...)
		logsLen := len(s.recentLogs)
		s.mu.RUnlock()

		rps, dropPS := s.autoProxyCtrl.metricsForSite(s.config.Sites[0], time.Now(), 0)
		if hasDirect && len(l7Bans) == 1 && logsLen >= 1 && rps == 150 && dropPS == 25 {
			if hasProxyClientInKernel || hasCFInKernel || hasCF9InKernel || hasWL {
				t.Fatalf("anti-self-DoS / separation invariant violated: proxyClientKernel=%v cfKernel=%v cf9Kernel=%v wl=%v",
					hasProxyClientInKernel, hasCFInKernel, hasCF9InKernel, hasWL)
			}
			if l7Bans[0].IP != "198.51.100.20" {
				t.Fatalf("expected 198.51.100.20 in L7 ShieldBannedIPs, got %+v", l7Bans)
			}
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	s.mu.RLock()
	if _, ok := s.bannedMap["198.51.100.10"]; !ok {
		t.Fatal("expected direct abuser 198.51.100.10 in kernel bannedMap")
	}
	if _, ok := s.bannedMap["198.51.100.20"]; ok {
		t.Fatal("abuser behind Cloudflare must NOT be kernel-banned")
	}
	if _, ok := s.bannedMap["173.245.48.5"]; ok {
		t.Fatal("Cloudflare peer IP must NEVER be kernel-banned")
	}
	if len(s.config.ShieldBannedIPs) != 1 || s.config.ShieldBannedIPs[0].IP != "198.51.100.20" {
		t.Fatalf("expected 198.51.100.20 in ShieldBannedIPs, got %+v", s.config.ShieldBannedIPs)
	}
	s.mu.RUnlock()

	// Trigger AutoProxy evaluation directly using Shield-fed telemetry
	now := time.Now()
	s.autoProxyCtrl.EvaluateFromTelemetry(context.Background(), 0)
	s.autoProxyCtrl.mu.Lock()
	if tr := s.autoProxyCtrl.trackers["s-ap"]; tr != nil {
		tr.overloadSince = now.Add(-15 * time.Second)
	}
	s.autoProxyCtrl.mu.Unlock()
	s.autoProxyCtrl.EvaluateFromTelemetry(context.Background(), 0)

	if cfPatched.Load() == 0 {
		t.Fatal("expected AutoProxyController.EvaluateFromTelemetry to activate Cloudflare proxy via Shield stats")
	}
}

func TestPhase2_ShieldBansAndUnderAttackAPI(t *testing.T) {
	dir := t.TempDir()
	s := &AppState{
		configPath: filepath.Join(dir, "cfg.json"),
		bannedMap:  make(map[string]*BannedIPEntry),
		sessions: map[string]Session{
			"sess1": {Username: "admin", ExpiresAt: time.Now().Add(time.Hour)},
		},
		offenseCount: make(map[string]int),
		config: Config{
			MgmtHTTPSPort: 4438,
			MgmtHTTPPort:  8088,
			Sites: []Site{
				{ID: "s1", Domain: "one.example.com", Upstream: "127.0.0.1:8080"},
				{ID: "s2", Domain: "two.example.com", Upstream: "127.0.0.1:8081"},
			},
			ShieldBannedIPs: []ShieldBanEntry{
				{IP: "198.51.100.50", Host: "one.example.com", Reason: "L7 bot", BannedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
				{IP: "198.51.100.51", Host: "two.example.com", Reason: "L7 flood", BannedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
			},
		},
	}
	handler := setupRouter(s)
	authedReq := func(method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Host = "127.0.0.1:4438"
		req.Header.Set("Origin", "https://127.0.0.1:4438")
		req.AddCookie(&http.Cookie{Name: "vsafegate_session", Value: "sess1"})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	// GET /api/shield/bans
	rr := authedReq(http.MethodGet, "/api/shield/bans", "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "198.51.100.50") {
		t.Fatalf("GET /api/shield/bans failed (%d): %s", rr.Code, rr.Body.String())
	}

	// DELETE /api/shield/bans?ip=...
	rr = authedReq(http.MethodDelete, "/api/shield/bans?ip=198.51.100.50", "")
	if rr.Code != 200 {
		t.Fatalf("DELETE single shield ban failed (%d): %s", rr.Code, rr.Body.String())
	}
	if len(s.getShieldBannedIPList()) != 1 {
		t.Fatalf("expected 1 remaining shield ban, got %d", len(s.getShieldBannedIPList()))
	}

	// DELETE /api/shield/bans?clear=all
	rr = authedReq(http.MethodDelete, "/api/shield/bans?clear=all", "")
	if rr.Code != 200 || len(s.getShieldBannedIPList()) != 0 {
		t.Fatalf("DELETE clear=all failed: code=%d remaining=%d", rr.Code, len(s.getShieldBannedIPList()))
	}

	// Whitelist normalization + cross-clearing ShieldBannedIPs & kernel ban + preserving RFC1918 defaults
	s.addShieldL7Ban("198.51.100.77", "app.example.com", "s1", "test-l7-ban", "/login", "GET", "bot")
	if len(s.getShieldBannedIPList()) != 1 {
		t.Fatalf("expected 1 shield ban before whitelist, got %d", len(s.getShieldBannedIPList()))
	}
	if err := s.addWhitelistIP("::ffff:198.51.100.77", "trusted-admin"); err != nil {
		t.Fatalf("addWhitelistIP failed: %v", err)
	}
	if len(s.getShieldBannedIPList()) != 0 {
		t.Fatalf("expected addWhitelistIP to clear normalized IP from ShieldBannedIPs")
	}
	if len(s.config.WhitelistIPs) == 0 || s.config.WhitelistIPs[len(s.config.WhitelistIPs)-1].IP != "198.51.100.77" {
		t.Fatalf("expected normalized IPv4 198.51.100.77 in WhitelistIPs, got %+v", s.config.WhitelistIPs)
	}
	if err := s.removeWhitelistIP("10.0.0.0/8"); err != nil {
		t.Fatalf("removeWhitelistIP failed: %v", err)
	}
	wlEntries := collectWhitelistIPv4Entries(s.config)
	hasRFC1918 := false
	for _, e := range wlEntries {
		if e == "10.0.0.0/8" {
			hasRFC1918 = true
			break
		}
	}
	if !hasRFC1918 {
		t.Fatalf("expected RFC1918 10.0.0.0/8 to remain protected in collectWhitelistIPv4Entries, got %v", wlEntries)
	}

	// POST /api/sites/under-attack single site
	rr = authedReq(http.MethodPost, "/api/sites/under-attack", `{"site_id":"s1","enabled":true}`)
	if rr.Code != 200 || !s.config.Sites[0].UnderAttackMode || s.config.Sites[0].ShieldMode != "under_attack" || s.config.Sites[1].UnderAttackMode {
		t.Fatalf("single site under-attack toggle failed (%d): %+v", rr.Code, s.config.Sites)
	}

	// POST /api/sites/under-attack all=true -> false
	rr = authedReq(http.MethodPost, "/api/sites/under-attack", `{"all":true,"enabled":true}`)
	if rr.Code != 200 || !s.config.Sites[1].UnderAttackMode {
		t.Fatalf("all sites under-attack toggle failed (%d): %+v", rr.Code, s.config.Sites)
	}

	// GET /api/mgmt/settings includes effective_mgmt_listen_ips
	rr = authedReq(http.MethodGet, "/api/mgmt/settings", "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"effective_mgmt_listen_ips"`) {
		t.Fatalf("expected effective_mgmt_listen_ips in settings response, got (%d): %s", rr.Code, rr.Body.String())
	}
}

func TestPhase3_API_OriginTLS_L4UDP_DefensePolicy(t *testing.T) {
	dir := t.TempDir()
	var fwTriggers atomic.Int64
	s := &AppState{
		configPath:       filepath.Join(dir, "cfg.json"),
		certsDir:         filepath.Join(dir, "certs"),
		bannedMap:        make(map[string]*BannedIPEntry),
		sessions:         map[string]Session{"sess1": {Username: "admin", ExpiresAt: time.Now().Add(time.Hour)}},
		offenseCount:     make(map[string]int),
		firewallSyncHook: func() { fwTriggers.Add(1) },
		config: Config{
			MgmtHTTPSPort: 4438,
			MgmtHTTPPort:  0,
		},
	}
	handler := setupRouter(s)
	authedReq := func(method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Host = "127.0.0.1:4438"
		req.Header.Set("Origin", "https://127.0.0.1:4438")
		req.AddCookie(&http.Cookie{Name: "vsafegate_session", Value: "sess1"})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	// Generate dummy self-signed cert PEM using existing test helper or invalid check first
	rr := authedReq(http.MethodPost, "/api/sites", `{"domain":"ca.example.com","upstream":"https://10.0.0.1:8443","origin_tls_mode":"custom_ca"}`)
	if rr.Code != 400 {
		t.Fatalf("expected 400 when custom_ca lacks CA PEM, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = authedReq(http.MethodPost, "/api/sites", `{"domain":"badlb.example.com","upstream":"http://10.0.0.1:8080","lb_policy":"bogus"}`)
	if rr.Code != 400 {
		t.Fatalf("expected 400 on invalid lb_policy, got %d", rr.Code)
	}
	rr = authedReq(http.MethodPost, "/api/sites", `{"domain":"badsh.example.com","upstream":"http://10.0.0.1:8080","shield_mode":"invalid"}`)
	if rr.Code != 400 {
		t.Fatalf("expected 400 on invalid shield_mode, got %d", rr.Code)
	}

	// Valid site with Phase 2 & 3 fields (using valid PEM generated on the fly? check site validation pass with origin_tls_mode=system)
	rr = authedReq(http.MethodPost, "/api/sites", `{
		"id":"s-ok","domain":"ok.example.com","upstream":"https://10.0.0.1:8443","upstreams":["https://10.0.0.2:8443"],
		"ssl":true,"waf":true,"shield_mode":"under_attack","rate_limit_rps":25,"rate_limit_burst":40,
		"challenge_difficulty":16,"lb_policy":"least_conn","health_check_path":"/health","health_check_interval":"10s",
		"origin_tls_mode":"system","origin_tls_sni":"origin.internal"
	}`)
	if rr.Code != 200 {
		t.Fatalf("expected 200 creating valid Phase 2/3 site, got %d: %s", rr.Code, rr.Body.String())
	}
	if !s.config.Sites[0].UnderAttackMode || s.config.Sites[0].LBPolicy != "least_conn" || s.config.Sites[0].OriginTLSMode != "system" {
		t.Fatalf("site fields not persisted cleanly: %+v", s.config.Sites[0])
	}

	// L4 TCP + UDP port isolation: allow disabled TCP + disabled UDP on SAME port 5353, reject UDP + proxy_protocol=v2
	rr = authedReq(http.MethodPost, "/api/l4/services", `{"id":"l4-u-bad","name":"BadUDP","protocol":"udp","listen_port":5353,"backend_addr":"127.0.0.1:5353","proxy_protocol":"v2"}`)
	if rr.Code != 400 {
		t.Fatalf("expected 400 rejecting PROXY protocol on UDP, got %d", rr.Code)
	}
	rr = authedReq(http.MethodPost, "/api/l4/services", `{"id":"l4-tcp","name":"TCP5353","protocol":"tcp","listen_port":5353,"backends":["10.0.0.1:5353","10.0.0.2:5353"],"lb_policy":"ip_hash","proxy_protocol":"v2","max_conns_per_ip":10,"idle_timeout_sec":60,"health_check_interval_sec":5,"enabled":false}`)
	if rr.Code != 200 {
		t.Fatalf("expected 200 creating L4 TCP service, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = authedReq(http.MethodPost, "/api/l4/services", `{"id":"l4-udp","name":"UDP5353","protocol":"udp","listen_port":5353,"backend_addr":"10.0.0.1:5353","enabled":false}`)
	if rr.Code != 200 {
		t.Fatalf("expected 200 creating L4 UDP on same port 5353 as TCP, got %d: %s", rr.Code, rr.Body.String())
	}
	// Duplicate TCP on same port MUST fail
	rr = authedReq(http.MethodPost, "/api/l4/services", `{"id":"l4-tcp2","name":"TCPDup","protocol":"tcp","listen_port":5353,"backend_addr":"10.0.0.3:5353","enabled":false}`)
	if rr.Code != 400 {
		t.Fatalf("expected 400 on duplicate TCP:5353 port, got %d", rr.Code)
	}

	// Defense policy with EgressFilterEnabled
	rr = authedReq(http.MethodPost, "/api/defense/policy", `{"default_ban_ttl_hours":12,"ssh_guard_enabled":true,"ssh_max_attempts":5,"egress_filter_enabled":true}`)
	if rr.Code != 200 || !s.config.DefensePolicy.EgressFilterEnabled {
		t.Fatalf("expected egress_filter_enabled saved, got (%d): %+v", rr.Code, s.config.DefensePolicy)
	}

	// Verify firewallSyncHook triggered across Site + L4 POST/PUT/toggle/DELETE + Mgmt Settings,
	// and verify POST /api/mgmt/settings falls back MgmtHTTPPort <= 0 to 808 (not 8088).
	before := fwTriggers.Load()
	if before < 3 {
		t.Fatalf("expected at least 3 firewallSyncHook triggers from Site + 2 L4 creations, got %d", before)
	}
	rr = authedReq(http.MethodPut, "/api/l4/services", `{"id":"l4-tcp","name":"TCP5353","protocol":"tcp","listen_port":5354,"backends":["10.0.0.1:5353"],"enabled":false}`)
	if rr.Code != 200 || fwTriggers.Load() != before+1 {
		t.Fatalf("expected PUT /api/l4/services to trigger firewall sync (code=%d)", rr.Code)
	}
	rr = authedReq(http.MethodPost, "/api/l4/services/toggle?id=l4-tcp", "")
	if rr.Code != 200 || fwTriggers.Load() != before+2 {
		t.Fatalf("expected POST /api/l4/services/toggle to trigger firewall sync (code=%d)", rr.Code)
	}
	// Cleanly disable/delete before test exits so port 5354 doesn't linger
	rr = authedReq(http.MethodDelete, "/api/l4/services?id=l4-tcp", "")
	if rr.Code != 200 || fwTriggers.Load() != before+3 {
		t.Fatalf("expected DELETE /api/l4/services to trigger firewall sync (code=%d)", rr.Code)
	}
	rr = authedReq(http.MethodPost, "/api/mgmt/settings", `{"mgmt_domain":"","mgmt_https_port":4438}`)
	if rr.Code != 200 || s.config.MgmtHTTPPort != 808 || fwTriggers.Load() != before+4 {
		t.Fatalf("expected MgmtHTTPPort fallback to 808 and firewall sync trigger, got code=%d httpPort=%d triggers=%d", rr.Code, s.config.MgmtHTTPPort, fwTriggers.Load())
	}
}

// --- Phase 3 Firewall Mock Runner Tests ---

type mockFirewallRunner struct {
	mu           sync.Mutex
	commands     []string
	stdinScripts []string
	failSysctl   bool
	noIP6Tables  bool
	isLXC        bool
	existingSets map[string]bool
}

func (m *mockFirewallRunner) Run(name string, args ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	line := name + " " + strings.Join(args, " ")
	m.commands = append(m.commands, line)
	if name == "ip6tables" && m.noIP6Tables {
		return errors.New("ip6table_filter missing in LXC")
	}
	if name == "ipset" && len(args) >= 2 && args[0] == "list" && !m.existingSets[args[1]] {
		return errors.New("set does not exist")
	}
	if name == "iptables" && len(args) >= 1 && args[0] == "-C" {
		// Jump not installed yet -> trigger -I parentChain 1 -j chain
		return errors.New("not found")
	}
	if name == "ip6tables" && len(args) >= 1 && args[0] == "-C" {
		return errors.New("not found")
	}
	if name == "iptables" && len(args) >= 1 && args[0] == "-D" {
		return errors.New("no matching rule")
	}
	return nil
}

func (m *mockFirewallRunner) Output(name string, args ...string) ([]byte, error) {
	return nil, m.Run(name, args...)
}

func (m *mockFirewallRunner) RunStdin(stdinData string, name string, args ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.commands = append(m.commands, name+" "+strings.Join(args, " "))
	m.stdinScripts = append(m.stdinScripts, stdinData)
	// Mark created set as existing
	for _, line := range strings.Split(stdinData, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "create" && !strings.HasSuffix(f[1], "-tmp") {
			if m.existingSets == nil {
				m.existingSets = make(map[string]bool)
			}
			m.existingSets[f[1]] = true
		}
	}
	return nil
}

func (m *mockFirewallRunner) WriteFile(path string, data []byte, perm os.FileMode) error {
	if strings.HasPrefix(path, "/proc/sys/") && m.failSysctl {
		return errors.New("read-only file system")
	}
	return nil
}

func (m *mockFirewallRunner) ReadFile(path string) ([]byte, error) {
	if path == "/proc/1/environ" && m.isLXC {
		return []byte("container=lxc\x00"), nil
	}
	if path == "/proc/sys/net/ipv4/tcp_syncookies" {
		return []byte("1\n"), nil
	}
	return nil, os.ErrNotExist
}

func (m *mockFirewallRunner) LookPath(file string) (string, error) {
	if file == "ip6tables" && m.noIP6Tables {
		return "", errors.New("not found")
	}
	return "/sbin/" + file, nil
}

func TestPhase3_FirewallRulesOrdering_IPv6Drop_Egress_AtomicSwap_LXC(t *testing.T) {
	cfg := Config{
		GeoIPMode:        "whitelist",
		MgmtHTTPSPort:    4438,
		MgmtHTTPPort:     8088,
		MgmtAllowedCIDRs: []string{"10.99.0.0/24"},
		WhitelistIPs:     []WhitelistIPEntry{{IP: "198.51.100.4"}},
		Cloudflare:       CloudflareConfig{CachedIPv4: []string{"173.245.48.0/20"}},
		L4Services: []L4Service{
			{ID: "udp53", Name: "DNS", Protocol: "udp", ListenPort: 5353, Enabled: true},
			{ID: "tcp25565", Name: "MC", Protocol: "tcp", ListenPort: 25565, Enabled: true},
		},
		DefensePolicy: DefensePolicy{EgressFilterEnabled: true},
	}

	runner := &mockFirewallRunner{
		existingSets: map[string]bool{
			"vsafegate-threatintel": true,
		},
	}
	s := &AppState{config: cfg}
	s.applyIptablesRulesWith(runner)

	// 1. Atomic ipset swap script check
	if len(runner.stdinScripts) < 2 {
		t.Fatalf("expected ipset restore scripts for whitelist and trusted sets, got %d", len(runner.stdinScripts))
	}
	wlScript := runner.stdinScripts[0]
	if !strings.Contains(wlScript, "create vsafegate-whitelist-tmp hash:net") ||
		!strings.Contains(wlScript, "swap vsafegate-whitelist-tmp vsafegate-whitelist") ||
		!strings.Contains(wlScript, "destroy vsafegate-whitelist-tmp") {
		t.Fatalf("expected atomic swap script for vsafegate-whitelist, got:\n%s", wlScript)
	}

	joined := strings.Join(runner.commands, "\n")

	// 2. Custom chain VSAFEGATE_INPUT rule ordering checks
	wlIdx := strings.Index(joined, "-A VSAFEGATE_INPUT -m set --match-set vsafegate-whitelist src -j ACCEPT")
	blIdx := strings.Index(joined, "-A VSAFEGATE_INPUT -m set --match-set vsafegate-blacklist src -j DROP")
	tiIdx := strings.Index(joined, "-A VSAFEGATE_INPUT -m set --match-set vsafegate-threatintel src -j DROP")
	geoIdx := strings.Index(joined, "-A VSAFEGATE_INPUT ! -i tailscale+ ! -i zt+ ! -i lo -m conntrack --ctstate NEW -m set ! --match-set vsafegate-trusted src -m set ! --match-set vsafegate-allowed src -j DROP")
	httpIdx := strings.Index(joined, "-A VSAFEGATE_INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT")

	if wlIdx < 0 || blIdx < 0 || tiIdx < 0 || geoIdx < 0 || httpIdx < 0 {
		t.Fatalf("missing required VSAFEGATE_INPUT rules in:\n%s", joined)
	}
	if !(wlIdx < blIdx && blIdx < tiIdx && tiIdx < geoIdx && geoIdx < httpIdx) {
		t.Fatalf("rule ordering bug (whitelist < blacklist < threatintel < geoip < http80/443): indices wl=%d bl=%d ti=%d geo=%d http=%d",
			wlIdx, blIdx, tiIdx, geoIdx, httpIdx)
	}
	if strings.Contains(joined, "-A VSAFEGATE_INPUT -p tcp --dport 80 -j ACCEPT") {
		t.Fatal("regression: unfiltered port 80 ACCEPT must NOT exist before GeoIP/Blacklist")
	}

	// 3. Trusted Proxy exclusion from kernel hashlimit/connlimit (anti-self-DoS)
	if !strings.Contains(joined, "-p tcp --syn -m set ! --match-set vsafegate-trusted src -m hashlimit") ||
		!strings.Contains(joined, "--match-set vsafegate-trusted src -m connlimit") {
		t.Fatalf("expected vsafegate-trusted exclusion on hashlimit/connlimit:\n%s", joined)
	}

	// 4. L4 TCP & UDP active ports + isolated Mgmt CIDR allow then DROP
	if !strings.Contains(joined, "-p udp -m multiport --dports 5353 -j ACCEPT") ||
		!strings.Contains(joined, "-p tcp -m multiport --dports 25565 -j ACCEPT") ||
		!strings.Contains(joined, "-s 10.99.0.0/24 -m multiport --dports 4438,8088 -j ACCEPT") {
		t.Fatalf("expected L4 ports and MgmtAllowedCIDRs rules:\n%s", joined)
	}

	// 5. VSAFEGATE_OUTPUT egress chain + VSAFEGATE6_INPUT drop all non-link-local IPv6
	if !strings.Contains(joined, "-A VSAFEGATE_OUTPUT -m set --match-set vsafegate-blacklist dst -j DROP") ||
		!strings.Contains(joined, "ip6tables -A VSAFEGATE6_INPUT -s fe80::/10 -j ACCEPT") ||
		!strings.Contains(joined, "ip6tables -A VSAFEGATE6_INPUT -j DROP") {
		t.Fatalf("expected VSAFEGATE_OUTPUT and VSAFEGATE6_INPUT link-local-only + DROP:\n%s", joined)
	}

	// 6. LXC capability tolerance: read-only sysctl & missing ip6tables should NOT fail/panic, and disabling Egress removes chain
	s.config.DefensePolicy.EgressFilterEnabled = false
	lxcRunner := &mockFirewallRunner{
		isLXC:        true,
		failSysctl:   true,
		noIP6Tables:  true,
		existingSets: map[string]bool{},
	}
	s.applyIptablesRulesWith(lxcRunner)
	lxcCmds := strings.Join(lxcRunner.commands, "\n")
	if !strings.Contains(lxcCmds, "iptables -X VSAFEGATE_OUTPUT") {
		t.Fatalf("expected VSAFEGATE_OUTPUT cleanup when EgressFilterEnabled=false, got:\n%s", lxcCmds)
	}
	caps := detectFirewallCapabilitiesWith(lxcRunner)
	if !caps.IsLXC || !caps.SysctlReadOnly || caps.HasIP6Tables {
		t.Fatalf("unexpected LXC capability detection: %+v", caps)
	}

	// 7. GeoIP blacklist mode also exempts vsafegate-trusted when present, and empty atomic blacklist flush works
	s.config.GeoIPMode = "blacklist"
	blGeoRunner := &mockFirewallRunner{existingSets: map[string]bool{}}
	s.applyIptablesRulesWith(blGeoRunner)
	blCmds := strings.Join(blGeoRunner.commands, "\n")
	if !strings.Contains(blCmds, "-A VSAFEGATE_INPUT ! -i tailscale+ ! -i zt+ ! -i lo -m set ! --match-set vsafegate-trusted src -m set --match-set vsafegate-countries src -j DROP") {
		t.Fatalf("expected GeoIP blacklist mode to exempt vsafegate-trusted:\n%s", blCmds)
	}
	emptyBLScript := buildAtomicIpsetSwapScript("vsafegate-blacklist", 65536, nil)
	if !strings.Contains(emptyBLScript, "flush vsafegate-blacklist-tmp") || !strings.Contains(emptyBLScript, "swap vsafegate-blacklist-tmp vsafegate-blacklist") {
		t.Fatalf("expected empty blacklist atomic flush script, got:\n%s", emptyBLScript)
	}
}

// --- Phase 3 L4 Proxy Comprehensive Tests ---

func startTestTCPEcho(t *testing.T, tag string, firstConnReadHook func([]byte)) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var hookOnce sync.Once
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						payload := append([]byte(nil), buf[:n]...)
						if firstConnReadHook != nil {
							hookOnce.Do(func() { firstConnReadHook(payload) })
						}
						_, _ = conn.Write([]byte(tag + ":" + string(payload)))
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestPhase3_L4Proxy_RaceFreeSync_RateLimit_MaxConns_Idle_ProxyProto_LB_UDP(t *testing.T) {
	mgr := NewL4ProxyManager()
	t.Cleanup(func() { mgr.Sync(nil) })

	// 1. Race-free concurrent Sync() + active TCP traffic + Multi-Backend LB & Active Health Failover
	be1Addr, stopBE1 := startTestTCPEcho(t, "B1", nil)
	be2Addr, stopBE2 := startTestTCPEcho(t, "B2", nil)
	defer stopBE1()
	defer stopBE2()

	svcLB := L4Service{
		ID:                     "svc-lb",
		Name:                   "LB TCP",
		Protocol:               "tcp",
		ListenPort:             0,
		Backends:               []string{be1Addr, be2Addr},
		LBPolicy:               "round_robin",
		Enabled:                true,
		HealthCheckIntervalSec: 1,
		DialTimeoutSec:         1,
	}
	mgr.Sync([]L4Service{svcLB})
	lbProxyAddr := mgr.ListenerAddr("svc-lb").String()

	// Concurrent Sync updates while hammering connections (verified cleanly under -race)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 15; i++ {
			svcCopy := svcLB
			svcCopy.MaxConns = 100 + i
			mgr.Sync([]L4Service{svcCopy})
			time.Sleep(5 * time.Millisecond)
		}
	}()
	seenB1, seenB2 := 0, 0
	for i := 0; i < 8; i++ {
		c, err := net.DialTimeout("tcp", lbProxyAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial lb failed: %v", err)
		}
		_, _ = c.Write([]byte("ping"))
		buf := make([]byte, 64)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, rerr := c.Read(buf)
		_ = c.Close()
		if rerr != nil {
			t.Fatalf("read lb failed: %v", rerr)
		}
		msg := string(buf[:n])
		if strings.HasPrefix(msg, "B1:") {
			seenB1++
		} else if strings.HasPrefix(msg, "B2:") {
			seenB2++
		}
	}
	wg.Wait()
	if seenB1 == 0 || seenB2 == 0 {
		t.Fatalf("expected round_robin traffic split across B1 & B2, got B1=%d B2=%d", seenB1, seenB2)
	}

	// Kill backend B1 -> health check / failover should route cleanly to B2
	stopBE1()
	time.Sleep(1200 * time.Millisecond)
	for i := 0; i < 4; i++ {
		c, err := net.DialTimeout("tcp", lbProxyAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("failover dial %d failed: %v", i, err)
		}
		_, _ = c.Write([]byte("after"))
		buf := make([]byte, 64)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, rerr := c.Read(buf)
		_ = c.Close()
		if rerr != nil || !strings.HasPrefix(string(buf[:n]), "B2:") {
			t.Fatalf("expected B2 failover response, got n=%d %q err=%v", n, string(buf[:n]), rerr)
		}
	}

	// 2. PROXY Protocol v1 + RateLimit + MaxConnsPerIP + IdleTimeoutSec=1
	var capturedV1 []byte
	pp1Backend, stopPP1 := startTestTCPEcho(t, "PP1", func(b []byte) { capturedV1 = b })
	defer stopPP1()

	// Test PROXY Protocol v1 cleanly first without rate limit interfering
	mgr.Sync([]L4Service{
		{
			ID:             "svc-pp1",
			Name:           "PP1",
			Protocol:       "tcp",
			ListenPort:     0,
			BackendAddr:    pp1Backend,
			ProxyProtocol:  "v1",
			Enabled:        true,
			MaxConnsPerIP:  2,
			IdleTimeoutSec: 1,
		},
	})
	pp1Addr := mgr.ListenerAddr("svc-pp1").String()

	c1, err := net.Dial("tcp", pp1Addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c1.Write([]byte("hi"))
	buf := make([]byte, 256)
	var acc bytes.Buffer
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	for !bytes.Contains(acc.Bytes(), []byte("hi")) {
		n, rerr := c1.Read(buf)
		if n > 0 {
			acc.Write(buf[:n])
		}
		if rerr != nil {
			t.Fatalf("pp1 echo failed (got %q): %v", acc.String(), rerr)
		}
	}
	_ = c1.SetReadDeadline(time.Time{})
	if !strings.HasPrefix(string(capturedV1), "PROXY TCP4 127.0.0.1 ") && !strings.HasPrefix(string(capturedV1), "PROXY TCP6 ") {
		t.Fatalf("expected valid PROXY Protocol v1 header on backend, got %q (echo %q)", string(capturedV1), acc.String())
	}

	// Enforce MaxConnsPerIP=2 (c1 open, c2 open, c3 rejected/closed immediately)
	c2, err := net.Dial("tcp", pp1Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	c3, err := net.Dial("tcp", pp1Addr)
	if err == nil {
		_ = c3.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err3 := c3.Read(make([]byte, 16))
		_ = c3.Close()
		if err3 == nil {
			t.Fatal("expected 3rd concurrent connection from same IP to be dropped by MaxConnsPerIP=2")
		}
	}

	// IdleTimeoutSec=1 should close c1 after ~1s inactivity
	_ = c1.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	_, idleErr := c1.Read(make([]byte, 16))
	_ = c1.Close()
	if idleErr == nil {
		t.Fatal("expected idle connection c1 to be closed after IdleTimeoutSec=1")
	}

	// 3. PROXY Protocol v2 binary signature & IPv4 address check
	var capturedV2 []byte
	pp2Backend, stopPP2 := startTestTCPEcho(t, "PP2", func(b []byte) { capturedV2 = b })
	defer stopPP2()
	mgr.Sync([]L4Service{
		{ID: "svc-pp2", Name: "PP2", Protocol: "tcp", ListenPort: 0, BackendAddr: pp2Backend, ProxyProtocol: "v2", Enabled: true},
	})
	pp2Addr := mgr.ListenerAddr("svc-pp2").String()
	cv2, err := net.Dial("tcp", pp2Addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = cv2.Write([]byte("v2body"))
	_ = cv2.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = cv2.Read(buf)
	_ = cv2.Close()
	v2Magic := []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}
	if len(capturedV2) < 16 || !bytes.HasPrefix(capturedV2, v2Magic) || capturedV2[12] != 0x21 {
		t.Fatalf("expected HAProxy PROXY v2 binary header, got %x", capturedV2)
	}
	if capturedV2[13] == 0x11 && binary.BigEndian.Uint16(capturedV2[14:16]) != 12 {
		t.Fatalf("expected IPv4 v2 payload length 12, got %d", binary.BigEndian.Uint16(capturedV2[14:16]))
	}

	// 4. Sharded RateLimit unit & integration check
	mgr.Sync([]L4Service{
		{ID: "svc-rl", Name: "RL", Protocol: "tcp", ListenPort: 0, BackendAddr: be2Addr, RateLimit: 2, Enabled: true},
	})
	rlAddr := mgr.ListenerAddr("svc-rl").String()
	dropped := 0
	for i := 0; i < 8; i++ {
		c, err := net.DialTimeout("tcp", rlAddr, time.Second)
		if err != nil {
			dropped++
			continue
		}
		_, _ = c.Write([]byte("rl"))
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, rerr := c.Read(make([]byte, 32))
		_ = c.Close()
		if rerr != nil {
			dropped++
		}
	}
	if dropped == 0 {
		t.Fatal("expected sharded RateLimit=2/s to drop burst connections beyond 2")
	}

	// 5. End-to-End UDP Proxy + Idle Session Expiry
	udpBE, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpBE.Close()
	go func() {
		rb := make([]byte, 2048)
		for {
			n, addr, err := udpBE.ReadFrom(rb)
			if err != nil {
				return
			}
			_, _ = udpBE.WriteTo([]byte(fmt.Sprintf("UDP-OK:%s", string(rb[:n]))), addr)
		}
	}()

	mgr.Sync([]L4Service{
		{ID: "svc-udp", Name: "UDP Echo", Protocol: "udp", ListenPort: 0, BackendAddr: udpBE.LocalAddr().String(), IdleTimeoutSec: 1, Enabled: true},
	})
	udpProxyAddr := mgr.ListenerAddr("svc-udp").String()
	uClient, err := net.Dial("udp", udpProxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer uClient.Close()
	_, _ = uClient.Write([]byte("hello-udp"))
	_ = uClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	uBuf := make([]byte, 128)
	un, uerr := uClient.Read(uBuf)
	if uerr != nil || string(uBuf[:un]) != "UDP-OK:hello-udp" {
		t.Fatalf("UDP proxy echo failed: n=%d %q err=%v", un, string(uBuf[:un]), uerr)
	}

	// Verify counters updated and UDP session reaps cleanly after 1s idle
	mgr.mu.Lock()
	udpCounters := mgr.services["svc-udp"]
	mgr.mu.Unlock()
	byteDeadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(byteDeadline) {
		if atomic.LoadInt64(&udpCounters.BytesIn) > 0 && atomic.LoadInt64(&udpCounters.BytesOut) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt64(&udpCounters.BytesIn) == 0 || atomic.LoadInt64(&udpCounters.BytesOut) == 0 {
		t.Fatalf("expected non-zero UDP BytesIn/BytesOut, got in=%d out=%d",
			atomic.LoadInt64(&udpCounters.BytesIn), atomic.LoadInt64(&udpCounters.BytesOut))
	}
	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&udpCounters.ActiveConns) == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := atomic.LoadInt64(&udpCounters.ActiveConns); got != 0 {
		t.Fatalf("expected idle UDP session to expire after 1s, ActiveConns=%d", got)
	}

	// 6. Sync Port Swap + Prune Deleted Service Maps
	// Reserve two unused ephemeral TCP ports and immediately release them to test deterministic port swap.
	reservePort := func() int {
		l, err := net.Listen("tcp", "[::]:0")
		if err != nil {
			l, err = net.Listen("tcp", "0.0.0.0:0")
			if err != nil {
				t.Fatal(err)
			}
		}
		p := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		return p
	}
	pA := reservePort()
	pB := reservePort()
	if pA == pB {
		pB = reservePort()
	}
	mgr.Sync([]L4Service{
		{ID: "swap-1", Name: "Swap1", Protocol: "tcp", ListenPort: pA, BackendAddr: be1Addr, Enabled: true},
		{ID: "swap-2", Name: "Swap2", Protocol: "tcp", ListenPort: pB, BackendAddr: be2Addr, Enabled: true},
	})
	if mgr.ListenerAddr("swap-1") == nil || mgr.ListenerAddr("swap-2") == nil {
		t.Fatalf("expected both swap listeners active on %d and %d", pA, pB)
	}
	// Swap ports pA <-> pB AND delete svc-udp in a single Sync!
	mgr.Sync([]L4Service{
		{ID: "swap-1", Name: "Swap1", Protocol: "tcp", ListenPort: pB, BackendAddr: be1Addr, Enabled: true},
		{ID: "swap-2", Name: "Swap2", Protocol: "tcp", ListenPort: pA, BackendAddr: be2Addr, Enabled: true},
	})
	if mgr.ListenerAddr("swap-1") == nil || mgr.ListenerAddr("swap-2") == nil {
		t.Fatalf("expected port swap between swap-1 (%d->%d) and swap-2 (%d->%d) to succeed cleanly", pA, pB, pB, pA)
	}
	if _, p1, _ := net.SplitHostPort(mgr.ListenerAddr("swap-1").String()); p1 != fmt.Sprintf("%d", pB) {
		t.Fatalf("expected swap-1 on port %d, got %s", pB, p1)
	}
	if _, p2, _ := net.SplitHostPort(mgr.ListenerAddr("swap-2").String()); p2 != fmt.Sprintf("%d", pA) {
		t.Fatalf("expected swap-2 on port %d, got %s", pA, p2)
	}
	mgr.mu.Lock()
	_, udpStillInServices := mgr.services["svc-udp"]
	_, udpStillInRuntimes := mgr.runtimes["svc-udp"]
	mgr.mu.Unlock()
	if udpStillInServices || udpStillInRuntimes {
		t.Fatalf("expected deleted service svc-udp to be pruned from services/runtimes")
	}
}

var _ = io.EOF
