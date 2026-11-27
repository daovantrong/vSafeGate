package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
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

// phase4FirewallMock implements firewallRunner for telemetry & concurrency tests.
type phase4FirewallMock struct {
	mu          sync.Mutex
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	v4Out       string
	v6Out       string
	delay       time.Duration
}

func (m *phase4FirewallMock) enter() {
	cur := m.inFlight.Add(1)
	for {
		prev := m.maxInFlight.Load()
		if cur <= prev || m.maxInFlight.CompareAndSwap(prev, cur) {
			break
		}
	}
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
}

func (m *phase4FirewallMock) leave() {
	m.inFlight.Add(-1)
}

func (m *phase4FirewallMock) Run(name string, args ...string) error {
	m.enter()
	defer m.leave()
	return nil
}

func (m *phase4FirewallMock) Output(name string, args ...string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if name == "iptables" {
		return []byte(m.v4Out), nil
	}
	if name == "ip6tables" {
		return []byte(m.v6Out), nil
	}
	return nil, nil
}

func (m *phase4FirewallMock) RunStdin(stdinData string, name string, args ...string) error {
	m.enter()
	defer m.leave()
	return nil
}

func (m *phase4FirewallMock) WriteFile(path string, data []byte, perm os.FileMode) error {
	return nil
}

func (m *phase4FirewallMock) ReadFile(path string) ([]byte, error) {
	return nil, os.ErrNotExist
}

func (m *phase4FirewallMock) LookPath(file string) (string, error) {
	return "/usr/sbin/" + file, nil
}

func TestPhase4_FirewallConcurrencySerialization(t *testing.T) {
	s := newTestAppState(t)
	runner := &phase4FirewallMock{delay: 5 * time.Millisecond}

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.applyIptablesRulesWith(runner)
		}()
	}
	wg.Wait()

	if maxSeen := runner.maxInFlight.Load(); maxSeen != 1 {
		t.Fatalf("expected applyIptablesRulesWith to serialize strictly (maxInFlight=1), got %d", maxSeen)
	}
}

func TestPhase4_TelemetryStore_PrometheusKernelCertsGeoIPAndPersistence(t *testing.T) {
	s := newTestAppState(t)
	tmpDir := t.TempDir()
	geoDir := filepath.Join(tmpDir, "geoip")
	_ = os.MkdirAll(geoDir, 0750)
	// Populate CN and RU zone files for GeoIP lookup
	_ = os.WriteFile(filepath.Join(geoDir, "cn.zone"), []byte("114.114.114.0/24\n"), 0644)
	_ = os.WriteFile(filepath.Join(geoDir, "ru.zone"), []byte("77.88.55.0/24\n"), 0644)

	// Setup site certs: 1 uploaded expiring (<10 days), 1 uploaded healthy (60 days), 1 ACME expiring (<5 days)
	upExpCert, upExpKey := generateTestCertPEM(t, "exp.example.com", time.Now().Add(8*24*time.Hour))
	upExpCertPath := filepath.Join(tmpDir, "exp.crt")
	upExpKeyPath := filepath.Join(tmpDir, "exp.key")
	_ = os.WriteFile(upExpCertPath, []byte(upExpCert), 0600)
	_ = os.WriteFile(upExpKeyPath, []byte(upExpKey), 0600)

	upOkCert, _ := generateTestCertPEM(t, "ok.example.com", time.Now().Add(60*24*time.Hour))
	upOkCertPath := filepath.Join(tmpDir, "ok.crt")
	_ = os.WriteFile(upOkCertPath, []byte(upOkCert), 0600)

	acmeCertDir := filepath.Join(tmpDir, "caddy-data", "caddy", "certificates", "acme-v02", "acme.example.com")
	_ = os.MkdirAll(acmeCertDir, 0755)
	acmeCertPEM, _ := generateTestCertPEM(t, "acme.example.com", time.Now().Add(4*24*time.Hour))
	_ = os.WriteFile(filepath.Join(acmeCertDir, "acme.example.com.crt"), []byte(acmeCertPEM), 0644)

	s.caddyDataDir = filepath.Join(tmpDir, "caddy-data")
	s.mu.Lock()
	s.config.Sites = []Site{
		{ID: "s1", Domain: "exp.example.com", Upstream: "127.0.0.1:8081", SSL: true, CertMode: "uploaded", CustomCertPath: upExpCertPath, CustomKeyPath: upExpKeyPath},
		{ID: "s2", Domain: "ok.example.com", Upstream: "127.0.0.1:8082", SSL: true, CertMode: "uploaded", CustomCertPath: upOkCertPath},
	}
	s.mu.Unlock()
	s.banIP("114.114.114.5", "test ban", 24)

	var promStep atomic.Int32
	caddyAdminMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reverse_proxy/upstreams" {
			_, _ = w.Write([]byte(`[
				{"address":"10.0.0.11:8080","num_requests":500,"fails":0},
				{"address":"10.0.0.12:8080","num_requests":42,"fails":3}
			]`))
			return
		}
		step := promStep.Load()
		var body string
		switch step {
		case 0:
			body = `
# TYPE caddy_http_requests_total counter
caddy_http_requests_total{host="exp.example.com",server="srv_https"} 100
caddy_http_requests_total{host="ok.example.com",server="srv_https"} 50
caddy_http_requests_in_flight{host="exp.example.com",server="srv_https"} 3
caddy_http_request_duration_seconds_count{host="exp.example.com",code="200"} 90
caddy_http_request_duration_seconds_count{host="exp.example.com",code="403"} 10
caddy_http_request_duration_seconds_count{host="ok.example.com",code="200"} 50
caddy_http_request_duration_seconds_bucket{host="exp.example.com",le="0.01"} 80
caddy_http_request_duration_seconds_bucket{host="exp.example.com",le="0.05"} 95
caddy_http_request_duration_seconds_bucket{host="exp.example.com",le="0.1"} 99
caddy_http_request_duration_seconds_bucket{host="exp.example.com",le="+Inf"} 100
`
		case 1:
			// Incremental scrape (+100 requests in 10s = 10 RPS)
			body = `
caddy_http_requests_total{host="exp.example.com",server="srv_https"} 180
caddy_http_requests_total{host="ok.example.com",server="srv_https"} 70
caddy_http_requests_in_flight{host="exp.example.com",server="srv_https"} 7
caddy_http_request_duration_seconds_count{host="exp.example.com",code="200"} 160
caddy_http_request_duration_seconds_count{host="exp.example.com",code="403"} 15
caddy_http_request_duration_seconds_count{host="exp.example.com",code="502"} 5
caddy_http_request_duration_seconds_count{host="ok.example.com",code="200"} 70
caddy_http_request_duration_seconds_bucket{host="exp.example.com",le="0.01"} 120
caddy_http_request_duration_seconds_bucket{host="exp.example.com",le="0.05"} 165
caddy_http_request_duration_seconds_bucket{host="exp.example.com",le="0.1"} 178
caddy_http_request_duration_seconds_bucket{host="exp.example.com",le="+Inf"} 180
`
		default:
			// Simulate Caddy restart counter reset
			body = `
caddy_http_requests_total{host="exp.example.com",server="srv_https"} 10
caddy_http_request_duration_seconds_count{host="exp.example.com",code="302"} 10
caddy_http_request_duration_seconds_bucket{host="exp.example.com",le="0.01"} 10
caddy_http_request_duration_seconds_bucket{host="exp.example.com",le="+Inf"} 10
`
		}
		_, _ = w.Write([]byte(body))
	}))
	defer caddyAdminMock.Close()

	fwRunner := &phase4FirewallMock{
		v4Out: "Chain VSAFEGATE_INPUT (1 references)\n pkts bytes target prot opt in out source destination\n  120  9600 DROP all -- * * 0.0.0.0/0 0.0.0.0/0\n",
		v6Out: "Chain VSAFEGATE6_INPUT (1 references)\n pkts bytes target prot opt in out source destination\n   30  2400 DROP all -- * * ::/0 ::/0\n",
	}

	curTime := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	telPath := filepath.Join(tmpDir, "telemetry.json")
	ts := NewTelemetryStore(s, telPath)
	ts.metricsURL = caddyAdminMock.URL + "/metrics"
	ts.upstreamsURL = caddyAdminMock.URL + "/reverse_proxy/upstreams"
	ts.runner = fwRunner
	ts.geoipLookup = newGeoIPZoneLookup(geoDir)
	ts.nowFn = func() time.Time { return curTime }

	// Step 0 scrape
	ts.CollectOnce(context.Background())

	// Advance 10s, increment firewall drops & metrics
	curTime = curTime.Add(10 * time.Second)
	promStep.Store(1)
	fwRunner.mu.Lock()
	fwRunner.v4Out = "Chain VSAFEGATE_INPUT (1 references)\n pkts bytes target prot opt in out source destination\n  150 12000 DROP all -- * * 0.0.0.0/0 0.0.0.0/0\n"
	fwRunner.mu.Unlock()
	ts.CollectOnce(context.Background())

	// Step 2: test counter reset handling (both Caddy and iptables reset to lower numbers)
	curTime = curTime.Add(10 * time.Second)
	promStep.Store(2)
	fwRunner.mu.Lock()
	fwRunner.v4Out = "Chain VSAFEGATE_INPUT (1 references)\n pkts bytes target prot opt in out source destination\n   5   400 DROP all -- * * 0.0.0.0/0 0.0.0.0/0\n"
	fwRunner.mu.Unlock()
	ts.CollectOnce(context.Background())

	// Record Shield stats + categorized threat events
	ts.RecordShieldStats("s1", "exp.example.com", 42.5, 12.0)
	ts.RecordThreatEvent(AttackLog{Timestamp: curTime, ClientIP: "114.114.114.5", Host: "exp.example.com", URI: "/?id=1 OR 1=1", RuleID: 942100, RuleName: "SQL Injection Attack Detected", Action: "Blocked"})
	ts.RecordThreatEvent(AttackLog{Timestamp: curTime, ClientIP: "77.88.55.2", Host: "ok.example.com", URI: "/<script>", RuleID: 941100, RuleName: "XSS Filter", Action: "Blocked"})
	ts.RecordThreatEvent(AttackLog{Timestamp: curTime, ClientIP: "77.88.55.2", Host: "ok.example.com", URI: "/../../etc/passwd", RuleID: 930100, RuleName: "Path Traversal LFI", Action: "Blocked"})
	ts.RecordThreatEvent(AttackLog{Timestamp: curTime, ClientIP: "198.51.100.7", Host: "exp.example.com", URI: "/wp-login.php", RuleID: 913100, RuleName: "Scanner Bot", Action: "Blocked"})
	ts.RecordThreatEvent(AttackLog{Timestamp: curTime, ClientIP: "198.51.100.7", Host: "exp.example.com", URI: "/api", RuleName: "Shield L7 Rate Limit", Action: "rate_limited"})
	ts.RecordThreatEvent(AttackLog{Timestamp: curTime, ClientIP: "198.51.100.7", Host: "exp.example.com", URI: "/", RuleName: "Shield Challenge Fail", Action: "challenge_failed"})
	ts.RecordThreatEvent(AttackLog{Timestamp: curTime, ClientIP: "198.51.100.8", Host: "N/A", URI: "SSH:22", RuleName: "[SSH Guard] Failed password", Action: "AUTO-BAN"})
	ts.RecordThreatEvent(AttackLog{Timestamp: curTime, ClientIP: "198.51.100.9", Host: "N/A", URI: "Port:3306", RuleName: "[Port Scan Canary]", Action: "AUTO-BAN"})

	q := ts.Query("24h")
	if q.Status2xx != 230 || q.Status3xx != 10 || q.Status4xx != 15 || q.Status5xx != 5 {
		t.Fatalf("unexpected status totals: 2xx=%d 3xx=%d 4xx=%d 5xx=%d", q.Status2xx, q.Status3xx, q.Status4xx, q.Status5xx)
	}
	// Initial(120+30=150) + delta(+30) + reset(+5) = 185 pkts
	if q.TotalKernelPkts != 185 {
		t.Fatalf("expected 185 total kernel drop pkts across delta+reset, got %d", q.TotalKernelPkts)
	}
	if len(q.Buckets) == 0 {
		t.Fatal("expected minute buckets populated")
	}
	for _, cat := range threatCategoryOrder {
		if q.Categories[cat] < 1 {
			t.Fatalf("expected category %q count >= 1, got %d", cat, q.Categories[cat])
		}
	}
	foundBanned := false
	for _, a := range q.TopAttackers {
		if a.Key == "114.114.114.5" && a.IsBanned && a.SubLabel == "CN" {
			foundBanned = true
		}
	}
	if !foundBanned {
		t.Fatalf("expected banned CN attacker 114.114.114.5 in TopAttackers: %+v", q.TopAttackers)
	}
	if len(q.TopCountries) == 0 {
		t.Fatal("expected TopCountries populated from .zone lookup")
	}
	if q.P50Ms <= 0 || q.P95Ms <= 0 || q.P99Ms <= 0 {
		t.Fatalf("expected positive p50/p95/p99 latency ms, got p50=%.2f p95=%.2f p99=%.2f", q.P50Ms, q.P95Ms, q.P99Ms)
	}

	sum := ts.Summary()
	if len(sum.ExpiringCerts) != 2 {
		t.Fatalf("expected 2 expiring certs (<14d: uploaded + acme), got %d (%+v)", len(sum.ExpiringCerts), sum.ExpiringCerts)
	}
	if len(sum.UnhealthyTargets) != 1 || sum.UnhealthyTargets[0].Address != "10.0.0.12:8080" {
		t.Fatalf("expected 1 unhealthy L7 upstream 10.0.0.12:8080, got %+v", sum.UnhealthyTargets)
	}

	// Save & reload into a fresh TelemetryStore
	if err := ts.Save(); err != nil {
		t.Fatalf("TelemetryStore.Save: %v", err)
	}
	ts2 := NewTelemetryStore(s, telPath)
	ts2.nowFn = func() time.Time { return curTime }
	q2 := ts2.Query("24h")
	if q2.Status2xx != q.Status2xx || q2.TotalKernelPkts != q.TotalKernelPkts || q2.Categories["SQLi"] != q.Categories["SQLi"] {
		t.Fatalf("persisted telemetry mismatch after reload: got %+v vs %+v", q2, q)
	}
}

type capturedSMTPEmail struct {
	From    string
	To      []string
	RawData string
	UsedTLS bool
	AuthB64 string
}

func startMockSMTPServer(t *testing.T, implicitTLS bool, advertiseStartTLS bool) (host string, port int, emails *[]capturedSMTPEmail, mu *sync.Mutex, closeFn func()) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
	}

	var ln net.Listener
	if implicitTLS {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("listen mock smtp: %v", err)
	}

	var recMu sync.Mutex
	var recorded []capturedSMTPEmail
	stopCh := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				r := bufio.NewReader(c)
				writeLine := func(s string) {
					_, _ = c.Write([]byte(s + "\r\n"))
				}
				usedTLS := implicitTLS
				writeLine("220 mock-smtp.local ESMTP Service Ready")
				var cur capturedSMTPEmail
				cur.UsedTLS = usedTLS
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					upper := strings.ToUpper(line)
					switch {
					case strings.HasPrefix(upper, "EHLO "):
						writeLine("250-mock-smtp.local")
						if !usedTLS && advertiseStartTLS {
							writeLine("250-STARTTLS")
						}
						writeLine("250 AUTH PLAIN")
					case upper == "STARTTLS":
						writeLine("220 Ready to start TLS")
						tc := tls.Server(c, tlsCfg)
						if err := tc.Handshake(); err != nil {
							return
						}
						c = tc
						r = bufio.NewReader(c)
						usedTLS = true
						cur.UsedTLS = true
					case strings.HasPrefix(upper, "AUTH PLAIN "):
						cur.AuthB64 = strings.TrimSpace(line[len("AUTH PLAIN "):])
						writeLine("235 Authentication successful")
					case strings.HasPrefix(upper, "MAIL FROM:"):
						cur.From = strings.Trim(line[len("MAIL FROM:"):], "<> ")
						writeLine("250 OK")
					case strings.HasPrefix(upper, "RCPT TO:"):
						cur.To = append(cur.To, strings.Trim(line[len("RCPT TO:"):], "<> "))
						writeLine("250 OK")
					case upper == "DATA":
						writeLine("354 End data with <CR><LF>.<CR><LF>")
						var body strings.Builder
						for {
							dl, derr := r.ReadString('\n')
							if derr != nil {
								return
							}
							if strings.TrimRight(dl, "\r\n") == "." {
								break
							}
							body.WriteString(dl)
						}
						cur.RawData = body.String()
						recMu.Lock()
						recorded = append(recorded, cur)
						recMu.Unlock()
						writeLine("250 Queued")
					case upper == "QUIT":
						writeLine("221 Bye")
						return
					default:
						writeLine("250 OK")
					}
				}
			}(conn)
		}
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", tcpAddr.Port, &recorded, &recMu, func() {
		close(stopCh)
		_ = ln.Close()
	}
}

func TestPhase4_AlertEngine_SMTP_StartTLS_ImplicitTLS_Plain_CooldownAndTriggers(t *testing.T) {
	// 1. Test STARTTLS delivery & header sanitization
	host, port, emailsStartTLS, mu1, close1 := startMockSMTPServer(t, false, true)
	defer close1()

	chStartTLS := NewSMTPAlertChannel(SMTPConfig{
		Enabled:            true,
		SMTPHost:           host,
		SMTPPort:           port,
		TLSMode:            "starttls",
		Username:           "soc-bot",
		Password:           "s3cr3t!",
		FromAddress:        "vsafegate@example.com",
		ToAddresses:        []string{"admin@example.com"},
		InsecureSkipVerify: true,
	})
	err := chStartTLS.Send(context.Background(), "Alert\r\nBcc: evil@attacker.com", []AlertEvent{{
		Category:  "ddos_spike",
		Severity:  AlertSeverityCritical,
		Title:     "DDoS Spike",
		Message:   "120 drops/sec",
		Timestamp: time.Now(),
	}})
	if err != nil {
		t.Fatalf("STARTTLS send failed: %v", err)
	}
	mu1.Lock()
	if len(*emailsStartTLS) != 1 || !(*emailsStartTLS)[0].UsedTLS {
		t.Fatalf("expected 1 STARTTLS email, got %+v", *emailsStartTLS)
	}
	raw := (*emailsStartTLS)[0].RawData
	if strings.Contains(raw, "Bcc: evil@attacker.com") && !strings.Contains(raw, "Subject: =?utf-8") {
		// Sanitizer strips CRLF before MIME encoding, neutralizing header injection
	}
	// Verify no unencoded header injection line exists
	for _, hdrLine := range strings.Split(strings.Split(raw, "\r\n\r\n")[0], "\r\n") {
		if strings.HasPrefix(strings.ToLower(hdrLine), "bcc:") {
			t.Fatalf("header injection succeeded: %q", hdrLine)
		}
	}
	wantAuth := base64.StdEncoding.EncodeToString([]byte("\x00soc-bot\x00s3cr3t!"))
	if (*emailsStartTLS)[0].AuthB64 != wantAuth {
		t.Fatalf("unexpected AUTH PLAIN payload: %q vs %q", (*emailsStartTLS)[0].AuthB64, wantAuth)
	}
	mu1.Unlock()

	// 2. Test Implicit TLS (port 465 mode)
	host2, port2, emailsTLS, mu2, close2 := startMockSMTPServer(t, true, false)
	defer close2()
	chImplicit := NewSMTPAlertChannel(SMTPConfig{
		Enabled:            true,
		SMTPHost:           host2,
		SMTPPort:           port2,
		TLSMode:            "tls",
		FromAddress:        "vsafegate@example.com",
		ToAddresses:        []string{"admin@example.com"},
		InsecureSkipVerify: true,
	})
	if err := chImplicit.Send(context.Background(), "Implicit TLS Test", []AlertEvent{{Title: "TLS OK", Severity: AlertSeverityInfo}}); err != nil {
		t.Fatalf("Implicit TLS send failed: %v", err)
	}
	mu2.Lock()
	if len(*emailsTLS) != 1 || !(*emailsTLS)[0].UsedTLS {
		t.Fatalf("expected 1 implicit TLS email, got %+v", *emailsTLS)
	}
	mu2.Unlock()

	// 3. Test Plain TCP + Cooldown Aggregation + Alert Triggers + API masking
	host3, port3, emailsPlain, mu3, close3 := startMockSMTPServer(t, false, false)
	defer close3()

	s := newTestAppState(t)
	now := time.Date(2026, 11, 26, 14, 0, 0, 0, time.UTC)
	s.alertEngine.nowFn = func() time.Time { return now }
	s.alertEngine.cooldownOverride = 5 * time.Minute

	h := setupRouter(s)
	cookie := loginTestSessionCookie(t, h)

	// Configure SMTP via /api/alerts/smtp POST
	postResp := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/alerts/smtp", map[string]any{
		"enabled":                 true,
		"smtp_host":               host3,
		"smtp_port":               port3,
		"tls_mode":                "none",
		"username":                "relay",
		"password":                "topsecret-pw",
		"from_address":            "alerts@example.com",
		"to_addresses":            []string{"ops@example.com"},
		"cooldown_minutes":        5,
		"drop_spike_threshold_ps": 50,
		"cert_expiry_warn_days":   14,
	})
	if postResp.Code != http.StatusOK {
		t.Fatalf("POST /api/alerts/smtp failed: %d %s", postResp.Code, postResp.Body.String())
	}

	// GET must mask password
	getResp := doAuthedJSONReq(h, cookie, http.MethodGet, "/api/alerts/smtp", nil)
	if strings.Contains(getResp.Body.String(), "topsecret-pw") {
		t.Fatal("GET /api/alerts/smtp leaked plaintext password!")
	}
	if !strings.Contains(getResp.Body.String(), `"has_password":true`) {
		t.Fatalf("expected has_password=true, got %s", getResp.Body.String())
	}

	// Update keeping "********" must preserve stored password
	updResp := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/alerts/smtp", map[string]any{
		"enabled":      true,
		"smtp_host":    host3,
		"smtp_port":    port3,
		"tls_mode":     "none",
		"username":     "relay",
		"password":     "********",
		"from_address": "alerts@example.com",
		"to_addresses": []string{"ops@example.com"},
	})
	if updResp.Code != http.StatusOK {
		t.Fatalf("POST /api/alerts/smtp update failed: %d", updResp.Code)
	}
	s.mu.RLock()
	if s.config.SMTP.Password != "topsecret-pw" {
		s.mu.RUnlock()
		t.Fatalf("expected password preserved when '********' submitted, got %q", s.config.SMTP.Password)
	}
	s.mu.RUnlock()

	// POST /api/alerts/smtp/test sends real email using preserved password
	testResp := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/alerts/smtp/test", map[string]any{})
	if testResp.Code != http.StatusOK {
		t.Fatalf("POST /api/alerts/smtp/test failed: %d %s", testResp.Code, testResp.Body.String())
	}
	mu3.Lock()
	if len(*emailsPlain) != 1 {
		mu3.Unlock()
		t.Fatalf("expected 1 test email on plain mock server, got %d", len(*emailsPlain))
	}
	mu3.Unlock()

	// Cooldown burst test: 1st Notify delivers synchronously/async leading-edge, next 4 buffer inside cooldown
	s.alertEngine.NotifyIPBan("198.51.100.20", "WAF Burst", "kernel", 24)
	// Wait briefly for async leading-edge send
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu3.Lock()
		cnt := len(*emailsPlain)
		mu3.Unlock()
		if cnt >= 2 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	for i := 0; i < 4; i++ {
		s.alertEngine.NotifyIPBan("198.51.100.20", fmt.Sprintf("Repeat #%d", i+1), "kernel", 24)
	}
	time.Sleep(50 * time.Millisecond)
	mu3.Lock()
	if len(*emailsPlain) != 2 {
		mu3.Unlock()
		t.Fatalf("expected cooldown to prevent duplicate emails during burst (want 2 total), got %d", len(*emailsPlain))
	}
	mu3.Unlock()

	// Advance past cooldown and FlushDue -> sends 1 batched digest email summarizing 4 buffered events
	now = now.Add(6 * time.Minute)
	s.alertEngine.FlushDue(context.Background())
	mu3.Lock()
	if len(*emailsPlain) != 3 {
		mu3.Unlock()
		t.Fatalf("expected FlushDue to send 1 aggregated digest email (total=3), got %d", len(*emailsPlain))
	}
	digestBody := (*emailsPlain)[2].RawData
	mu3.Unlock()
	if !strings.Contains(digestBody, "Aggregated") && !strings.Contains(digestBody, "4") {
		t.Fatalf("expected aggregated digest details in email body, got:\n%s", digestBody)
	}

	// Test AutoProxy, Caddy Crash & Telemetry Signal triggers
	s.alertEngine.NotifyAutoProxy("shop.example.com", "activate", "zone-1", 2, true)
	s.alertEngine.NotifyAutoProxy("shop.example.com", "revert", "zone-1", 2, false)
	s.alertEngine.NotifyCaddyEvent("Caddy Unexpected Restart", "exit status 2", AlertSeverityCritical)
	s.alertEngine.CheckTelemetrySignals(
		120.5,
		[]UpstreamHealthStatus{{Source: "l7", Target: "Caddy", Address: "10.0.0.9:80", Fails: 2, Healthy: false}},
		[]CertExpiryStatus{{Domain: "exp.example.com", Source: "acme", DaysRemaining: 5, ExpiringSoon: true, NotAfter: now.Add(5 * 24 * time.Hour)}},
	)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu3.Lock()
		cnt := len(*emailsPlain)
		mu3.Unlock()
		if cnt >= 9 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	mu3.Lock()
	gotCount := len(*emailsPlain)
	mu3.Unlock()
	if gotCount < 9 {
		t.Fatalf("expected AutoProxy(2)+Caddy(1)+DropSpike(1)+Upstream(1)+Cert(1)+previous(3)=9 emails, got %d", gotCount)
	}
}

func TestPhase4_PartitionedLogManager_RetentionAndLegacyCompat(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "attacks.jsonl")

	// Seed a legacy attacks.jsonl entry before initializing partitioned manager
	legacyEntry, _ := json.Marshal(AttackLog{
		ID:        "legacy-1",
		Timestamp: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC),
		ClientIP:  "198.51.100.1",
		Host:      "legacy.example.com",
		URI:       "/old",
		RuleID:    1001,
		RuleName:  "Legacy Attack",
		Action:    "Blocked",
	})
	_ = os.WriteFile(basePath, append(legacyEntry, '\n'), 0600)

	cur := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	mgr := NewPersistentLogManager(basePath, 20*1024*1024)
	mgr.nowFn = func() time.Time { return cur }

	// Append events in two distinct hourly partitions
	if err := mgr.Append(AttackLog{Timestamp: time.Date(2026, 11, 20, 10, 15, 0, 0, time.UTC), ClientIP: "203.0.113.10", Host: "a.com", URI: "/sqli", RuleID: 942100, RuleName: "SQLi", Action: "Blocked"}); err != nil {
		t.Fatal(err)
	}
	cur = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	if err := mgr.Append(AttackLog{Timestamp: time.Date(2026, 11, 26, 12, 5, 0, 0, time.UTC), ClientIP: "203.0.113.20", Host: "b.com", URI: "/xss", RuleID: 941100, RuleName: "XSS", Action: "Blocked"}); err != nil {
		t.Fatal(err)
	}

	p1 := filepath.Join(dir, "attacks-2026-11-20-10.jsonl")
	p2 := filepath.Join(dir, "attacks-2026-11-26-12.jsonl")
	if _, err := os.Stat(p1); err != nil {
		t.Fatalf("expected hourly partition %s: %v", p1, err)
	}
	if _, err := os.Stat(p2); err != nil {
		t.Fatalf("expected hourly partition %s: %v", p2, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "attacks-index.json")); err != nil {
		t.Fatalf("expected summary index file: %v", err)
	}

	if total := mgr.TotalCount(); total != 3 {
		t.Fatalf("expected 3 total entries (legacy + 2 partitioned), got %d", total)
	}
	if logs, tot, err := mgr.Query("942100", 10, 0); err != nil || tot != 1 || len(logs) != 1 {
		t.Fatalf("query by rule_id failed: tot=%d len=%d err=%v", tot, len(logs), err)
	}

	var exported bytes.Buffer
	_ = mgr.Export(&exported)
	if !strings.Contains(exported.String(), "legacy-1") || !strings.Contains(exported.String(), "203.0.113.20") {
		t.Fatalf("export missing legacy or partitioned entries: %s", exported.String())
	}

	// Enforce age retention (3 days relative to 2026-11-26 12:00 UTC) -> should delete 2026-11-20 partition
	mgr.ConfigureRetention(3, 512)
	if _, err := os.Stat(p1); !os.IsNotExist(err) {
		t.Fatalf("expected old partition %s pruned by 3-day retention", p1)
	}
	if _, err := os.Stat(p2); err != nil {
		t.Fatalf("expected fresh partition %s retained", p2)
	}

	// Verify MaxDiskBytes eviction deletes oldest partition when disk cap is exceeded
	cur = time.Date(2026, 11, 26, 13, 0, 0, 0, time.UTC)
	if err := mgr.Append(AttackLog{Timestamp: cur, ClientIP: "203.0.113.30", Host: "c.com", URI: "/rce", RuleID: 932100, RuleName: "RCE", Action: "Blocked"}); err != nil {
		t.Fatal(err)
	}
	p3 := filepath.Join(dir, "attacks-2026-11-26-13.jsonl")
	fi3, _ := os.Stat(p3)
	mgr.mu.Lock()
	mgr.maxDiskBytes = fi3.Size() + 10 // fits newest partition only
	mgr.enforceRetentionLocked()
	mgr.mu.Unlock()
	if _, err := os.Stat(p2); !os.IsNotExist(err) {
		t.Fatalf("expected older partition %s evicted under disk byte cap", p2)
	}
	if _, err := os.Stat(p3); err != nil {
		t.Fatalf("expected newest partition %s preserved under disk byte cap", p3)
	}

	// Clear deletes partitions, legacy files, and index cleanly
	if err := mgr.Clear(); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}
	if cnt := mgr.TotalCount(); cnt != 0 {
		t.Fatalf("expected 0 entries after Clear, got %d", cnt)
	}
}

func TestPhase4_PersistentOffenseEscalationAndValidation(t *testing.T) {
	// Strict IP/CIDR validation
	if norm, err := normalizeBanTarget(" 203.0.113.55 "); err != nil || norm != "203.0.113.55" {
		t.Fatalf("expected normalized IPv4, got norm=%q err=%v", norm, err)
	}
	if norm, err := normalizeBanTarget("203.0.113.77/24"); err != nil || norm != "203.0.113.0/24" {
		t.Fatalf("expected masked CIDR 203.0.113.0/24, got norm=%q err=%v", norm, err)
	}
	for _, bad := range []string{"", "0.0.0.0/0", "::/0", "not-an-ip"} {
		if _, err := normalizeBanTarget(bad); err == nil {
			t.Fatalf("expected normalizeBanTarget to reject %q", bad)
		}
	}
	if !isPrivateOrReservedIP("100.64.0.15") {
		t.Fatal("expected CGNAT 100.64.0.15 flagged as reserved")
	}

	// Persistent offenseCount escalation across TTL expiry + daemon restart: 24h -> 72h -> Permanent
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	caddyPath := filepath.Join(tmpDir, "caddy.json")
	rulesDir := filepath.Join(tmpDir, "rules.d")
	logsPath := filepath.Join(tmpDir, "attacks.jsonl")

	s1 := initDefaults(cfgPath, caddyPath, rulesDir, logsPath)
	s1.banIP("198.51.100.44", "First offense", -1)

	s1.mu.RLock()
	b1 := s1.bannedMap["198.51.100.44"]
	cnt1 := s1.offenseCount["198.51.100.44"]
	s1.mu.RUnlock()
	if b1 == nil || b1.DurationHours != 24 || cnt1 != 1 {
		t.Fatalf("offense #1 mismatch: ban=%+v count=%d", b1, cnt1)
	}

	// Simulate TTL expiry unban -> offenseCount MUST survive in bans_state.json
	s1.unbanIP("198.51.100.44", "[TTL Expired] Tự động gỡ chặn khi hết hạn cách ly")
	if _, err := os.Stat(filepath.Join(tmpDir, "bans_state.json")); err != nil {
		t.Fatalf("expected bans_state.json persisted: %v", err)
	}

	// Simulate daemon restart
	s2 := initDefaults(cfgPath, caddyPath, rulesDir, logsPath)
	s2.mu.RLock()
	restoredCnt := s2.offenseCount["198.51.100.44"]
	s2.mu.RUnlock()
	if restoredCnt != 1 {
		t.Fatalf("expected offenseCount=1 restored across restart, got %d", restoredCnt)
	}

	// 2nd offense -> escalates to 72h
	s2.banIP("198.51.100.44", "Second offense", -1)
	s2.mu.RLock()
	b2 := s2.bannedMap["198.51.100.44"]
	s2.mu.RUnlock()
	if b2 == nil || b2.DurationHours != 72 || b2.ExpiresAt.IsZero() {
		t.Fatalf("expected offense #2 escalated to 72h, got %+v", b2)
	}

	s2.unbanIP("198.51.100.44", "[TTL Expired] hết hạn")
	// 3rd offense -> escalates to Permanent (DurationHours == 0, ExpiresAt.IsZero())
	s2.banIP("198.51.100.44", "Third offense", -1)
	s2.mu.RLock()
	b3 := s2.bannedMap["198.51.100.44"]
	s2.mu.RUnlock()
	if b3 == nil || b3.DurationHours != 0 || !b3.ExpiresAt.IsZero() {
		t.Fatalf("expected offense #3 escalated to permanent, got %+v", b3)
	}

	// Manual admin unban resets escalation history
	s2.unbanIP("198.51.100.44", "[Admin] Gỡ chặn thủ công")
	s3 := initDefaults(cfgPath, caddyPath, rulesDir, logsPath)
	s3.mu.RLock()
	resetCnt := s3.offenseCount["198.51.100.44"]
	s3.mu.RUnlock()
	if resetCnt != 0 {
		t.Fatalf("expected manual unban to clear offenseCount, got %d", resetCnt)
	}
}

func TestPhase4_MultiDistroSSHWatcher_And_CaddySiteLogIsolation(t *testing.T) {
	// 1. Multi-distro SSH source detection
	statOnly := func(existing string) func(string) (os.FileInfo, error) {
		return func(p string) (os.FileInfo, error) {
			if p == existing {
				return nil, nil
			}
			return nil, os.ErrNotExist
		}
	}
	noJournal := func(string) (string, error) { return "", os.ErrNotExist }
	hasJournal := func(name string) (string, error) {
		if name == "journalctl" {
			return "/usr/bin/journalctl", nil
		}
		return "", os.ErrNotExist
	}

	if src := detectSSHLogSource(statOnly("/var/log/auth.log"), noJournal); src.Mode != "file" || src.Path != "/var/log/auth.log" {
		t.Fatalf("expected Debian /var/log/auth.log, got %+v", src)
	}
	if src := detectSSHLogSource(statOnly("/var/log/secure"), noJournal); src.Mode != "file" || src.Path != "/var/log/secure" {
		t.Fatalf("expected RHEL /var/log/secure, got %+v", src)
	}
	if src := detectSSHLogSource(statOnly("/var/log/messages"), noJournal); src.Mode != "file" || src.Path != "/var/log/messages" {
		t.Fatalf("expected Alpine /var/log/messages, got %+v", src)
	}
	if src := detectSSHLogSource(statOnly(""), hasJournal); src.Mode != "journalctl" || len(src.Args) == 0 {
		t.Fatalf("expected journalctl fallback when files missing, got %+v", src)
	}

	// 2. Parsing syslog + journalctl -o cat + SSH attempt tracker
	cases := []struct {
		line string
		user string
		ip   string
	}{
		{"Nov 26 12:00:01 pve sshd[4521]: Failed password for invalid user admin from 203.0.113.9 port 5522 ssh2", "admin", "203.0.113.9"},
		{"Failed password for root from ::ffff:198.51.100.77 port 44123 ssh2", "root", "198.51.100.77"},
		{"Invalid user backup from 2001:db8::9 port 33210", "backup", "2001:db8::9"},
	}
	for _, tc := range cases {
		u, ip, ok := parseSSHFailedLine(tc.line)
		if !ok || u != tc.user || ip != tc.ip {
			t.Fatalf("parseSSHFailedLine(%q) = (%q, %q, %v), want (%q, %q, true)", tc.line, u, ip, ok, tc.user, tc.ip)
		}
	}

	tracker := newSSHAttemptTracker()
	for i := 0; i < 2; i++ {
		if _, _, ban := tracker.Record("Failed password for root from 203.0.113.99 port 2222 ssh2", 3); ban {
			t.Fatalf("did not expect ban before 3rd attempt (attempt=%d)", i+1)
		}
	}
	if _, ip, ban := tracker.Record("Failed password for root from 203.0.113.99 port 2223 ssh2", 3); !ban || ip != "203.0.113.99" {
		t.Fatalf("expected ban on 3rd attempt, got ip=%q ban=%v", ip, ban)
	}

	// 3. Caddy per-site access log isolation
	cfg := Config{
		Sites: []Site{
			{ID: "alpha", Domain: "alpha.example.com", Upstream: "127.0.0.1:8081", SSL: true},
			{ID: "beta", Domain: "beta.example.com", Upstream: "127.0.0.1:8082", SSL: true},
		},
	}
	caddyCfg := buildCaddyJSONConfig(cfg, "/etc/caddy/rules", "/var/log/caddy/waf-audit.jsonl", "/var/log/caddy/access.log", map[string]string{}, map[string]string{})
	apps := caddyCfg["apps"].(map[string]any)
	servers := apps["http"].(map[string]any)["servers"].(map[string]any)
	srvHTTPSLogs := servers["srv_https"].(map[string]any)["logs"].(map[string]any)
	loggerNames := srvHTTPSLogs["logger_names"].(map[string][]string)
	if len(loggerNames["alpha.example.com"]) != 1 || loggerNames["alpha.example.com"][0] != "site_alpha" {
		t.Fatalf("expected alpha logger_name site_alpha, got %+v", loggerNames)
	}
	topLogs := caddyCfg["logging"].(map[string]any)["logs"].(map[string]any)
	for _, key := range []string{"site_alpha", "site_beta"} {
		entry, ok := topLogs[key].(map[string]any)
		if !ok {
			t.Fatalf("missing per-site logger %s in logging.logs", key)
		}
		inc := entry["include"].([]string)
		if len(inc) != 1 || inc[0] != "http.log.access."+key {
			t.Fatalf("unexpected include filter for %s: %+v", key, inc)
		}
	}
	defaultAccess := topLogs["access"].(map[string]any)
	if exc, ok := defaultAccess["exclude"].([]string); !ok || len(exc) != 2 {
		t.Fatalf("expected default access logger to exclude 2 site loggers, got %+v", defaultAccess)
	}
}

func TestPhase4_SOCAPIs_SSEStream_BackupRestore_And_AdminAuditLog(t *testing.T) {
	s := newTestAppState(t)
	s.mu.Lock()
	s.config.Sites = []Site{{
		ID:               "site-shop",
		Domain:           "shop.example.com",
		Upstream:         "http://127.0.0.1:9001",
		SSL:              true,
		WAF:              true,
		AutoProxyEnabled: true,
		AutoProxyActive:  true,
	}}
	s.config.Rules = []CustomRule{{
		ID:       "rule-1",
		RuleID:   2001,
		Name:     "Block Evil UA",
		Target:   "USER_AGENT",
		Operator: "contains",
		Pattern:  "EvilScanner",
		Action:   "deny",
		Enabled:  true,
	}}
	s.config.L4Services = []L4Service{{
		ID:          "l4-nas",
		Name:        "NAS-SMB",
		ListenPort:  4445,
		BackendAddr: "127.0.0.1:445",
		Protocol:    "tcp",
		Enabled:     true,
	}}
	s.config.WhitelistIPs = []WhitelistIPEntry{{IP: "203.0.113.5", Note: "Office"}}
	s.mu.Unlock()

	h := setupRouter(s)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Authenticate via real HTTP server to obtain session cookie for SSE streaming + APIs
	loginBody, _ := json.Marshal(map[string]string{"username": "admin", "password": "InitialStrongPass!123"})
	loginRes, err := http.Post(srv.URL+"/api/login", "application/json", bytes.NewReader(loginBody))
	if err != nil || loginRes.StatusCode != http.StatusOK {
		t.Fatalf("HTTP login failed: err=%v res=%v", err, loginRes)
	}
	var cookie *http.Cookie
	for _, c := range loginRes.Cookies() {
		if c.Name == "vsafegate_session" {
			cookie = c
		}
	}
	_ = loginRes.Body.Close()
	if cookie == nil {
		t.Fatal("missing session cookie from /api/login")
	}

	// 1. Connect SSE stream /api/soc/stream
	sseCtx, cancelSSE := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelSSE()
	sseReq, _ := http.NewRequestWithContext(sseCtx, http.MethodGet, srv.URL+"/api/soc/stream", nil)
	sseReq.AddCookie(cookie)
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatalf("SSE request failed: %v", err)
	}
	defer sseResp.Body.Close()
	if sseResp.StatusCode != http.StatusOK || !strings.Contains(sseResp.Header.Get("Content-Type"), "text/event-stream") || sseResp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("unexpected SSE response headers: status=%d headers=%v", sseResp.StatusCode, sseResp.Header)
	}

	sseLines := make(chan string, 32)
	go func() {
		sc := bufio.NewScanner(sseResp.Body)
		for sc.Scan() {
			sseLines <- sc.Text()
		}
	}()

	// Wait for ready event, then publish live attack log and assert live delivery
	sawReady := false
	sawAttack := false
	published := false
	timeout := time.After(3 * time.Second)
	for !sawAttack {
		select {
		case line := <-sseLines:
			if strings.Contains(line, "event: ready") {
				sawReady = true
				if !published {
					published = true
					s.publishAttackLog(AttackLog{
						ID:        "sse-evt-1",
						Timestamp: time.Now().UTC(),
						ClientIP:  "198.51.100.123",
						Host:      "shop.example.com",
						URI:       "/admin.php",
						RuleID:    2001,
						RuleName:  "Block Evil UA",
						Action:    "Blocked",
					})
				}
			}
			if strings.Contains(line, `"sse-evt-1"`) && strings.Contains(line, "198.51.100.123") {
				sawAttack = true
			}
		case <-timeout:
			t.Fatalf("timed out waiting for SSE events (sawReady=%v, sawAttack=%v)", sawReady, sawAttack)
		}
	}
	cancelSSE()

	// 2. Test SOC Telemetry & Summary APIs
	telRec := doAuthedJSONReq(h, cookie, http.MethodGet, "/api/soc/telemetry?range=1h", nil)
	if telRec.Code != http.StatusOK || !strings.Contains(telRec.Body.String(), "198.51.100.123") {
		t.Fatalf("GET /api/soc/telemetry missing live event: status=%d body=%s", telRec.Code, telRec.Body.String())
	}
	sumRec := doAuthedJSONReq(h, cookie, http.MethodGet, "/api/soc/summary", nil)
	if sumRec.Code != http.StatusOK || !strings.Contains(sumRec.Body.String(), `"auto_proxy_active":true`) {
		t.Fatalf("GET /api/soc/summary missing AutoProxy active flag: status=%d body=%s", sumRec.Code, sumRec.Body.String())
	}

	// 3. Test CIDR ban + Admin Audit Log (/api/audit + audit.jsonl)
	banRec := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/blacklist", map[string]any{
		"ip":     "198.51.100.0/24",
		"reason": "SOC CIDR ban test",
	})
	if banRec.Code != http.StatusOK {
		t.Fatalf("expected CIDR ban 200, got %d (%s)", banRec.Code, banRec.Body.String())
	}

	// 4. Test Backup export & Restore (valid + invalid rejections)
	backupRec := doAuthedJSONReq(h, cookie, http.MethodGet, "/api/config/backup", nil)
	if backupRec.Code != http.StatusOK {
		t.Fatalf("GET /api/config/backup failed: %d", backupRec.Code)
	}
	var bundle ConfigBackupBundle
	if err := json.Unmarshal(backupRec.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("backup JSON decode failed: %v", err)
	}
	if bundle.Config.AdminPassword != "" || bundle.Config.ShieldChallengeSecret != "" {
		t.Fatal("backup export must scrub AdminPassword and ShieldChallengeSecret")
	}
	if len(bundle.Config.Sites) != 1 || len(bundle.Config.Rules) != 1 || len(bundle.Config.L4Services) != 1 {
		t.Fatalf("unexpected backup contents: %+v", bundle.Config)
	}

	// Reject malformed / dangerous restore payloads without mutating active config
	for _, badBody := range []map[string]any{
		{"version": "", "config": bundle.Config},
		{"version": "1", "config": map[string]any{"whitelist_ips": []map[string]any{{"ip": "0.0.0.0/0"}}}},
		{"version": "1", "config": map[string]any{"sites": []map[string]any{{"id": "bad", "domain": "bad host name!"}}}},
		{"version": "1", "config": map[string]any{"banned_ips": []map[string]any{{"ip": "127.0.0.1"}}}},
	} {
		badRec := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/config/restore", badBody)
		if badRec.Code != http.StatusBadRequest {
			t.Fatalf("expected invalid restore rejected with 400, got %d (%s)", badRec.Code, badRec.Body.String())
		}
	}

	// Mutate active state, then restore backup bundle
	s.mu.Lock()
	s.config.Sites = nil
	s.config.Rules = nil
	s.config.L4Services = nil
	s.mu.Unlock()
	restoreRec := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/config/restore", bundle)
	if restoreRec.Code != http.StatusOK {
		t.Fatalf("POST /api/config/restore failed: %d (%s)", restoreRec.Code, restoreRec.Body.String())
	}
	s.mu.RLock()
	restoredSites := len(s.config.Sites)
	restoredRules := len(s.config.Rules)
	restoredPass := s.config.AdminPassword
	s.mu.RUnlock()
	if restoredSites != 1 || restoredRules != 1 || !checkPassword(restoredPass, "InitialStrongPass!123") {
		t.Fatalf("restore verification failed: sites=%d rules=%d passIntact=%v", restoredSites, restoredRules, checkPassword(restoredPass, "InitialStrongPass!123"))
	}

	// Check Admin Audit Log records login, ban_ip, config_backup, config_restore
	auditRec := doAuthedJSONReq(h, cookie, http.MethodGet, "/api/audit?limit=50", nil)
	if auditRec.Code != http.StatusOK {
		t.Fatalf("GET /api/audit failed: %d", auditRec.Code)
	}
	auditBody := auditRec.Body.String()
	for _, expectedAct := range []string{`"login"`, `"ban_ip"`, `"config_backup"`, `"config_restore"`} {
		if !strings.Contains(auditBody, expectedAct) {
			t.Fatalf("expected audit log to contain %s, got %s", expectedAct, auditBody)
		}
	}
	if _, err := os.Stat(s.effectiveAdminAuditPath()); err != nil {
		t.Fatalf("expected audit.jsonl on disk: %v", err)
	}
}

func TestAlertChannels_Telegram_Discord_Webhook_APIAndDispatch(t *testing.T) {
	var tgMu sync.Mutex
	var tgBodies []string
	var tgPaths []string
	tgSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		tgMu.Lock()
		tgPaths = append(tgPaths, r.URL.Path)
		tgBodies = append(tgBodies, string(b))
		tgMu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer tgSrv.Close()

	var dcMu sync.Mutex
	var dcBodies []string
	dcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		dcMu.Lock()
		dcBodies = append(dcBodies, string(b))
		dcMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer dcSrv.Close()

	var whMu sync.Mutex
	var whBodies []string
	var whSigs []string
	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		whMu.Lock()
		whBodies = append(whBodies, string(b))
		whSigs = append(whSigs, r.Header.Get("X-vSafeGate-Signature"))
		whMu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"received":true}`))
	}))
	defer whSrv.Close()

	// 1. Direct TelegramAlertChannel unit test against mock API base
	tgCh := NewTelegramAlertChannel("12345:SECRET_BOT", "-100999")
	tgCh.apiBase = tgSrv.URL
	if err := tgCh.Send(context.Background(), "[vSafeGate] Alert", []AlertEvent{{
		Key: "k1", Category: "ip_ban", Severity: AlertSeverityCritical, Title: "IP Banned", Message: "Test TG",
	}}); err != nil {
		t.Fatalf("TelegramAlertChannel.Send failed: %v", err)
	}
	tgMu.Lock()
	if len(tgPaths) != 1 || tgPaths[0] != "/bot12345:SECRET_BOT/sendMessage" || !strings.Contains(tgBodies[0], `"chat_id":"-100999"`) {
		t.Fatalf("unexpected Telegram request: paths=%v bodies=%v", tgPaths, tgBodies)
	}
	tgMu.Unlock()

	// 2. API + AlertEngine end-to-end for Discord & Webhook (with HMAC & secret preservation)
	s := newTestAppState(t)
	h := setupRouter(s)
	cookie := loginTestSessionCookie(t, h)
	postResp := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/alerts/channels", map[string]any{
		"telegram_enabled":    false,
		"telegram_bot_token":  "bot-secret-tok",
		"telegram_chat_id":    "-100123",
		"discord_enabled":     true,
		"discord_webhook_url": dcSrv.URL + "/api/webhooks/1/abc",
		"webhook_enabled":     true,
		"webhook_url":         whSrv.URL + "/hook",
		"webhook_secret":      "my-hmac-key",
	})
	if postResp.Code != http.StatusOK {
		t.Fatalf("POST /api/alerts/channels failed: %d %s", postResp.Code, postResp.Body.String())
	}

	getResp := doAuthedJSONReq(h, cookie, http.MethodGet, "/api/alerts/channels", nil)
	if getResp.Code != http.StatusOK {
		t.Fatalf("GET /api/alerts/channels failed: %d", getResp.Code)
	}
	getStr := getResp.Body.String()
	if strings.Contains(getStr, "bot-secret-tok") || strings.Contains(getStr, "my-hmac-key") {
		t.Fatalf("GET /api/alerts/channels leaked secrets: %s", getStr)
	}
	if !strings.Contains(getStr, `"has_telegram_token":true`) || !strings.Contains(getStr, `"has_webhook_secret":true`) {
		t.Fatalf("expected has_* flags in GET /api/alerts/channels: %s", getStr)
	}

	// Preserve secrets when '********' submitted
	updResp := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/alerts/channels", map[string]any{
		"telegram_bot_token":  "********",
		"telegram_chat_id":    "-100123",
		"discord_enabled":     true,
		"discord_webhook_url": dcSrv.URL + "/api/webhooks/1/abc",
		"webhook_enabled":     true,
		"webhook_url":         whSrv.URL + "/hook",
		"webhook_secret":      "********",
	})
	if updResp.Code != http.StatusOK {
		t.Fatalf("POST /api/alerts/channels update failed: %d", updResp.Code)
	}
	s.mu.RLock()
	gotTgTok := s.config.Alerts.TelegramBotToken
	gotWhSec := s.config.Alerts.WebhookSecret
	s.mu.RUnlock()
	if gotTgTok != "bot-secret-tok" || gotWhSec != "my-hmac-key" {
		t.Fatalf("expected secrets preserved, got tg=%q wh=%q", gotTgTok, gotWhSec)
	}

	// Test endpoints for Discord & Webhook
	for _, ch := range []string{"discord", "webhook"} {
		tResp := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/alerts/channels/test", map[string]any{
			"channel": ch,
		})
		if tResp.Code != http.StatusOK {
			t.Fatalf("POST /api/alerts/channels/test (%s) failed: %d %s", ch, tResp.Code, tResp.Body.String())
		}
	}

	// Verify HMAC signature on Webhook
	whMu.Lock()
	if len(whBodies) != 1 || len(whSigs) != 1 {
		whMu.Unlock()
		t.Fatalf("expected 1 webhook test delivery, got %d", len(whBodies))
	}
	mac := hmac.New(sha256.New, []byte("my-hmac-key"))
	mac.Write([]byte(whBodies[0]))
	wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if whSigs[0] != wantSig {
		whMu.Unlock()
		t.Fatalf("webhook HMAC mismatch: got %q want %q", whSigs[0], wantSig)
	}
	whMu.Unlock()

	// Dispatch via AlertEngine.NotifyIPBan and verify fan-out to both Discord & Webhook
	s.alertEngine.NotifyIPBan("198.51.100.77", "SSH Brute Force", "Kernel ipset", 24)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		dcMu.Lock()
		dcCnt := len(dcBodies)
		dcMu.Unlock()
		whMu.Lock()
		whCnt := len(whBodies)
		whMu.Unlock()
		if dcCnt >= 2 && whCnt >= 2 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	dcMu.Lock()
	dcCnt := len(dcBodies)
	dcMu.Unlock()
	whMu.Lock()
	whCnt := len(whBodies)
	whMu.Unlock()
	if dcCnt < 2 || whCnt < 2 {
		t.Fatalf("expected fan-out delivery to Discord (%d) and Webhook (%d)", dcCnt, whCnt)
	}
}
