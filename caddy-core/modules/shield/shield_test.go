package shield

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"caddy-core/modules/pre_tls"
)

func okNextHandler(status int) caddyhttp.Handler {
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("ok"))
		return nil
	})
}

func makeBrowserReq(method, target, remoteAddr string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = remoteAddr
	req.Host = "app.example.com"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	return req
}

func TestShield_SafeRealClientIPResolution(t *testing.T) {
	sh := &Shield{
		TrustedProxies: []string{"173.245.48.0/20", "10.0.0.0/8"},
	}
	if err := sh.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer sh.Cleanup()

	// 1. Untrusted peer spoofing CF-Connecting-IP & XFF MUST be ignored
	reqUntrusted := makeBrowserReq(http.MethodGet, "https://app.example.com/", "203.0.113.5:55555")
	reqUntrusted.Header.Set("CF-Connecting-IP", "1.1.1.1")
	reqUntrusted.Header.Set("X-Forwarded-For", "8.8.8.8")
	realIP, peerIP, behind := sh.resolveClientIP(reqUntrusted)
	if behind || realIP.String() != "203.0.113.5" || peerIP.String() != "203.0.113.5" {
		t.Fatalf("expected untrusted peer IP 203.0.113.5, got real=%s peer=%s behind=%v", realIP, peerIP, behind)
	}

	// 2. Trusted Cloudflare peer with CF-Connecting-IP resolves real visitor IP
	reqCF := makeBrowserReq(http.MethodGet, "https://app.example.com/", "173.245.48.12:44321")
	reqCF.Header.Set("CF-Connecting-IP", "198.51.100.42")
	reqCF.Header.Set("X-Forwarded-For", "198.51.100.42, 173.245.48.12")
	realIP, peerIP, behind = sh.resolveClientIP(reqCF)
	if !behind || realIP.String() != "198.51.100.42" || peerIP.String() != "173.245.48.12" {
		t.Fatalf("expected CF realIP 198.51.100.42 & behind=true, got real=%s peer=%s behind=%v", realIP, peerIP, behind)
	}

	// 3. Trusted internal proxy with XFF chain resolves right-most untrusted IP
	reqXFF := makeBrowserReq(http.MethodGet, "https://app.example.com/", "10.0.0.2:12345")
	reqXFF.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.99, 10.0.0.5")
	realIP, _, behind = sh.resolveClientIP(reqXFF)
	if !behind || realIP.String() != "198.51.100.99" {
		t.Fatalf("expected XFF right-most untrusted 198.51.100.99, got real=%s behind=%v", realIP, behind)
	}
}

func TestShield_MultiDimensionalRateLimitsAndHardAbortEvents(t *testing.T) {
	sockDir, err := os.MkdirTemp("", "sh*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "e.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("unix listen (%s): %v", sockPath, err)
	}
	defer ln.Close()

	eventsCh := make(chan ShieldEvent, 32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				sc := bufio.NewScanner(conn)
				for sc.Scan() {
					var ev ShieldEvent
					if json.Unmarshal(sc.Bytes(), &ev) == nil {
						eventsCh <- ev
					}
				}
			}(c)
		}
	}()

	sh := &Shield{
		TrustedProxies:       []string{"173.245.48.0/20"},
		RateLimitRPS:         2,
		RateLimitBurst:       2,
		SubnetRateLimitRPS:   5,
		SubnetRateLimitBurst: 5,
		HostRateLimitRPS:     20,
		HostRateLimitBurst:   20,
		HardDropMultiplier:   2.0, // hard burst = 4
		EventsSocketPath:     sockPath,
		SiteID:               "site-test",
		SensitiveRoutes: []SensitiveRouteRule{
			{PathPrefix: "/login", RPS: 1, Burst: 1},
		},
		APIPaths:    []string{"/api/"},
		ExemptPaths: []string{"/healthz"},
	}
	if err := sh.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer sh.Cleanup()

	next := okNextHandler(http.StatusOK)

	// 1. Exempt path passes regardless
	for i := 0; i < 10; i++ {
		req := makeBrowserReq(http.MethodGet, "https://app.example.com/healthz", "203.0.113.10:1000")
		rec := httptest.NewRecorder()
		if err := sh.ServeHTTP(rec, req, next); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("exempt path failed at %d: code=%d err=%v", i, rec.Code, err)
		}
	}

	// 2. Sensitive route /login allows 1 burst then returns 429 on 2nd
	reqLogin1 := makeBrowserReq(http.MethodPost, "https://app.example.com/login", "203.0.113.20:1000")
	recL1 := httptest.NewRecorder()
	_ = sh.ServeHTTP(recL1, reqLogin1, next)
	if recL1.Code != http.StatusOK {
		t.Fatalf("first /login expected 200, got %d", recL1.Code)
	}
	reqLogin2 := makeBrowserReq(http.MethodPost, "https://app.example.com/login", "203.0.113.20:1000")
	reqLogin2.Header.Set("Accept", "application/json")
	recL2 := httptest.NewRecorder()
	_ = sh.ServeHTTP(recL2, reqLogin2, next)
	if recL2.Code != http.StatusTooManyRequests {
		t.Fatalf("second /login expected 429, got %d", recL2.Code)
	}

	// 3. Per-Subnet /24 limit across distinct IPs in 198.51.100.0/24 (5 burst total)
	subnet429 := false
	for i := 1; i <= 10; i++ {
		req := makeBrowserReq(http.MethodGet, "https://app.example.com/api/items", "198.51.100."+strconv.Itoa(i)+":2000")
		rec := httptest.NewRecorder()
		_ = sh.ServeHTTP(rec, req, next)
		if rec.Code == http.StatusTooManyRequests {
			subnet429 = true
			if strings.Contains(rec.Body.String(), "<html") {
				t.Fatal("APIPath /api/ should get neutral text 429, not HTML JS challenge")
			}
			break
		}
	}
	if !subnet429 {
		t.Fatal("expected /24 subnet rate limit to trigger 429 across distinct IPs")
	}

	// 4. Hard flood via Cloudflare Trusted Proxy triggers ErrAbortHandler + async event with BehindTrustedProxy=true
	aborted := false
	for i := 0; i < 10; i++ {
		func() {
			defer func() {
				if r := recover(); r == http.ErrAbortHandler {
					aborted = true
				}
			}()
			req := makeBrowserReq(http.MethodGet, "https://app.example.com/flood", "173.245.48.99:44300")
			req.Header.Set("CF-Connecting-IP", "192.0.2.88")
			rec := httptest.NewRecorder()
			_ = sh.ServeHTTP(rec, req, next)
		}()
		if aborted {
			break
		}
	}
	if !aborted {
		t.Fatal("expected hard flood to panic(http.ErrAbortHandler)")
	}

	// Wait for ban event over Unix socket
	deadline := time.After(3 * time.Second)
	var gotBan ShieldEvent
	for {
		select {
		case ev := <-eventsCh:
			if ev.Type == "ban" {
				gotBan = ev
				goto verifiedEvent
			}
		case <-deadline:
			t.Fatal("timeout waiting for shield ban event on Unix domain socket")
		}
	}
verifiedEvent:
	if !gotBan.BehindTrustedProxy || gotBan.ClientIP != "192.0.2.88" || gotBan.PeerIP != "173.245.48.99" {
		t.Fatalf("unexpected shield ban event: %+v", gotBan)
	}
}

func TestShield_PerIPConcurrencyLimit(t *testing.T) {
	sh := &Shield{
		RateLimitRPS:       100,
		RateLimitBurst:     100,
		MaxConcurrentPerIP: 2,
	}
	if err := sh.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer sh.Cleanup()

	started := make(chan struct{}, 2)
	release := make(chan struct{})
	slowNext := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		started <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
		return nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := makeBrowserReq(http.MethodGet, "https://app.example.com/slow", "203.0.113.55:1111")
			rec := httptest.NewRecorder()
			_ = sh.ServeHTTP(rec, req, slowNext)
		}()
	}
	<-started
	<-started

	// 3rd concurrent request from same IP MUST be rejected immediately
	req3 := makeBrowserReq(http.MethodGet, "https://app.example.com/slow", "203.0.113.55:2222")
	rec3 := httptest.NewRecorder()
	_ = sh.ServeHTTP(rec3, req3, okNextHandler(http.StatusOK))
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when exceeding MaxConcurrentPerIP=2, got %d", rec3.Code)
	}

	close(release)
	wg.Wait()

	// After release, requests succeed again
	req4 := makeBrowserReq(http.MethodGet, "https://app.example.com/slow", "203.0.113.55:3333")
	rec4 := httptest.NewRecorder()
	_ = sh.ServeHTTP(rec4, req4, okNextHandler(http.StatusOK))
	if rec4.Code != http.StatusOK {
		t.Fatalf("expected 200 after concurrent slots released, got %d", rec4.Code)
	}
}

func TestShield_UnderAttackStatelessHMACPoW_ZeroBranding_And_Difficulty16(t *testing.T) {
	sh := &Shield{
		Mode:                "under_attack",
		UnderAttackMode:     true,
		ChallengeDifficulty: 16, // exercises hex "10" parsing edge case!
		ChallengeSecret:     "0123456789abcdef0123456789abcdef",
	}
	if err := sh.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer sh.Cleanup()

	next := okNextHandler(http.StatusOK)
	preCtx := pre_tls.WithInfo(context.Background(), pre_tls.Info{
		SNI:        "app.example.com",
		JA4Light:   "t13d1516_0123456789ab_cdef01234567",
		ALPN:       "h2",
		TLSVersion: "13",
	})

	// 1. Initial request receives PoW challenge HTML with ZERO vSafeGate/Caddy/Coraza branding
	req1 := makeBrowserReq(http.MethodGet, "https://app.example.com/dashboard", "198.51.100.77:5000").WithContext(preCtx)
	req1.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	rec1 := httptest.NewRecorder()
	if err := sh.ServeHTTP(rec1, req1, next); err != nil {
		t.Fatalf("ServeHTTP challenge: %v", err)
	}
	if rec1.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 challenge response, got %d", rec1.Code)
	}
	html := rec1.Body.String()
	lowHTML := strings.ToLower(html)
	for _, bannedBrand := range []string{"vsafegate", "caddy", "coraza"} {
		if strings.Contains(lowHTML, bannedBrand) {
			t.Fatalf("challenge HTML leaked forbidden brand %q", bannedBrand)
		}
	}

	// Extract token from `const tok = "..."`
	m := regexp.MustCompile(`const tok = "([^"]+)"`).FindStringSubmatch(html)
	if len(m) != 2 {
		t.Fatalf("could not extract PoW token from challenge HTML:\n%s", html)
	}
	token := m[1]

	// Solve PoW (difficulty 16 bits -> ~65k hashes on average, < 50ms in Go)
	var solution string
	for n := 0; n < 2000000; n++ {
		cand := strconv.Itoa(n)
		sum := sha256.Sum256([]byte(token + ":" + cand))
		if HasLeadingZeroBits(sum[:], 16) {
			solution = cand
			break
		}
	}
	if solution == "" {
		t.Fatal("failed to solve 16-bit PoW within 2M iterations")
	}

	// 2. Submit PoW solution to /.well-known/sec-verify -> receives HttpOnly _clearance cookie
	payload, _ := json.Marshal(map[string]string{
		"token":    token,
		"solution": solution,
	})
	reqVerify := makeBrowserReq(http.MethodPost, "https://app.example.com"+verifyEndpointPath, "198.51.100.77:5001").WithContext(preCtx)
	reqVerify.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	reqVerify.Header.Set("Content-Type", "application/json")
	reqVerify.Body = http.NoBody
	reqVerify = httptest.NewRequest(http.MethodPost, "https://app.example.com"+verifyEndpointPath, bytes.NewReader(payload)).WithContext(preCtx)
	reqVerify.RemoteAddr = "198.51.100.77:5001"
	reqVerify.Host = "app.example.com"
	reqVerify.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	reqVerify.Header.Set("User-Agent", req1.Header.Get("User-Agent"))
	reqVerify.Header.Set("Content-Type", "application/json")

	recVerify := httptest.NewRecorder()
	if err := sh.ServeHTTP(recVerify, reqVerify, next); err != nil {
		t.Fatalf("ServeHTTP verify: %v", err)
	}
	if recVerify.Code != http.StatusOK {
		t.Fatalf("expected 200 on valid PoW verify, got %d (%s)", recVerify.Code, recVerify.Body.String())
	}

	var clearance *http.Cookie
	for _, c := range recVerify.Result().Cookies() {
		if c.Name == clearanceCookieName {
			clearance = c
		}
	}
	if clearance == nil || !clearance.HttpOnly || !clearance.Secure || clearance.SameSite != http.SameSiteLaxMode {
		t.Fatalf("invalid clearance cookie attributes: %+v", clearance)
	}

	// 3. Subsequent request with valid cookie & matching subnet/UA/TLS FP passes through!
	req2 := makeBrowserReq(http.MethodGet, "https://app.example.com/dashboard", "198.51.100.88:5002").WithContext(preCtx) // same /24 subnet
	req2.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	req2.AddCookie(clearance)
	rec2 := httptest.NewRecorder()
	if err := sh.ServeHTTP(rec2, req2, next); err != nil || rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid clearance cookie on same /24, got code=%d err=%v", rec2.Code, err)
	}

	// 4. Stolen cookie from different subnet OR different User-Agent MUST be rejected!
	reqStolenSubnet := makeBrowserReq(http.MethodGet, "https://app.example.com/dashboard", "203.0.113.99:5003").WithContext(preCtx)
	reqStolenSubnet.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	reqStolenSubnet.AddCookie(clearance)
	recStolen := httptest.NewRecorder()
	_ = sh.ServeHTTP(recStolen, reqStolenSubnet, next)
	if recStolen.Code == http.StatusOK {
		t.Fatal("clearance cookie stolen from different /24 subnet must not be accepted")
	}

	reqStolenFP := makeBrowserReq(http.MethodGet, "https://app.example.com/dashboard", "198.51.100.88:5004").WithContext(
		pre_tls.WithInfo(context.Background(), pre_tls.Info{JA4Light: "t12d0202_deadbeef_000000000000"}),
	)
	reqStolenFP.TLS = &tls.ConnectionState{Version: tls.VersionTLS12}
	reqStolenFP.AddCookie(clearance)
	recStolenFP := httptest.NewRecorder()
	_ = sh.ServeHTTP(recStolenFP, reqStolenFP, next)
	if recStolenFP.Code == http.StatusOK {
		t.Fatal("clearance cookie replayed with mismatched JA4-light fingerprint must not be accepted")
	}
}

func TestShield_JA4MismatchBehavioralAndVerifiedBotBypass(t *testing.T) {
	sh := &Shield{
		Mode:                  "normal",
		AnomalyScoreChallenge: 45,
		AnomalyScoreDrop:      100,
		lookupAddrFn: func(ctx context.Context, addr string) ([]string, error) {
			if addr == "66.249.66.1" {
				return []string{"crawl-66-249-66-1.googlebot.com."}, nil
			}
			return []string{"evil-vps.example.net."}, nil
		},
		lookupHostFn: func(ctx context.Context, host string) ([]string, error) {
			if host == "crawl-66-249-66-1.googlebot.com" {
				return []string{"66.249.66.1"}, nil
			}
			return []string{"198.51.100.123"}, nil
		},
	}
	if err := sh.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer sh.Cleanup()

	next := okNextHandler(http.StatusOK)

	// 1. Verified Googlebot bypasses challenge cleanly
	botReq := httptest.NewRequest(http.MethodGet, "https://app.example.com/robots.txt", nil)
	botReq.RemoteAddr = "66.249.66.1:40000"
	botReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	botRec := httptest.NewRecorder()
	if err := sh.ServeHTTP(botRec, botReq, next); err != nil || botRec.Code != http.StatusOK {
		t.Fatalf("verified Googlebot should bypass challenge, got code=%d err=%v", botRec.Code, err)
	}

	// 2. Spoofed Googlebot fails rDNS/fDNS and gets penalized/challenged
	fakeBotReq := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	fakeBotReq.RemoteAddr = "198.51.100.123:40001"
	fakeBotReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	fakeBotReq.Header.Set("Accept", "text/html")
	fakeBotRec := httptest.NewRecorder()
	_ = sh.ServeHTTP(fakeBotRec, fakeBotReq, next)
	if fakeBotRec.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed Googlebot expected 429 challenge, got %d", fakeBotRec.Code)
	}

	// 3. Browser UA + TLS JA4-light mismatch (TLS 1.0 + 2 ciphers + missing Accept-Language/Sec-Fetch)
	mismatchCtx := pre_tls.WithInfo(context.Background(), pre_tls.Info{
		SNI:        "app.example.com",
		JA4Light:   "t10d0202_000000000000_000000000000",
		ALPN:       "http/1.1",
		TLSVersion: "10",
	})
	botMimic := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil).WithContext(mismatchCtx)
	botMimic.RemoteAddr = "203.0.113.44:40002"
	botMimic.TLS = &tls.ConnectionState{Version: tls.VersionTLS10}
	botMimic.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0.0.0 Safari/537.36")
	botMimic.Header.Set("Accept", "text/html")
	mismatchRec := httptest.NewRecorder()
	_ = sh.ServeHTTP(mismatchRec, botMimic, next)
	if mismatchRec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected JA4-light/UA mismatch to trigger 429 challenge, got %d", mismatchRec.Code)
	}

	// 4. Clean IP check helper sanity
	if got := subnetKeyForIP(netip.MustParseAddr("2001:db8:1:2:3:4:5:6")); got != "2001:db8:1:2::/64" {
		t.Fatalf("unexpected IPv6 subnet key: %q", got)
	}
}

func TestShield_StaticBannedIPsBehindTrustedProxy(t *testing.T) {
	sh := &Shield{
		Mode:           "normal",
		TrustedProxies: []string{"173.245.48.0/20"},
		BannedIPs:      []string{"192.0.2.55", "::ffff:198.51.100.66"},
	}
	if err := sh.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer sh.Cleanup()

	next := okNextHandler(http.StatusOK)

	// Clean visitor via Cloudflare Edge passes
	cleanReq := makeBrowserReq(http.MethodGet, "https://app.example.com/", "173.245.48.10:443")
	cleanReq.Header.Set("CF-Connecting-IP", "203.0.113.10")
	cleanRec := httptest.NewRecorder()
	if err := sh.ServeHTTP(cleanRec, cleanReq, next); err != nil || cleanRec.Code != http.StatusOK {
		t.Fatalf("expected clean visitor via Cloudflare to pass, got code=%d err=%v", cleanRec.Code, err)
	}

	// Banned real visitor behind Cloudflare Edge is aborted (while CF peer remains unbanned)
	for _, badIP := range []string{"192.0.2.55", "198.51.100.66"} {
		aborted := false
		func() {
			defer func() {
				if r := recover(); r == http.ErrAbortHandler {
					aborted = true
				}
			}()
			badReq := makeBrowserReq(http.MethodGet, "https://app.example.com/", "173.245.48.10:443")
			badReq.Header.Set("CF-Connecting-IP", badIP)
			badRec := httptest.NewRecorder()
			_ = sh.ServeHTTP(badRec, badReq, next)
		}()
		if !aborted {
			t.Fatalf("expected staticBanned IP %s behind Cloudflare to abort", badIP)
		}
	}
}

func TestShield_SoftViolationsResetOnWindowExpiry(t *testing.T) {
	var nowMu sync.Mutex
	curNow := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	sh := &Shield{
		Mode:               "normal",
		RateLimitRPS:       1,
		RateLimitBurst:     1,
		HardDropMultiplier: 100,
		AnomalyScoreDrop:   1000,
		nowFn: func() time.Time {
			nowMu.Lock()
			defer nowMu.Unlock()
			return curNow
		},
	}
	if err := sh.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer sh.Cleanup()

	next := okNextHandler(http.StatusOK)

	// Hit soft limit 10 times in window 1 (stays well below softViolations >= 20)
	for i := 0; i < 11; i++ {
		req := makeBrowserReq(http.MethodGet, "https://app.example.com/", "198.51.100.88:50000")
		rec := httptest.NewRecorder()
		if err := sh.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("window 1 req %d unexpected err: %v", i, err)
		}
	}

	// Advance > 60s so anomalyWindowFrom expires, then trigger 15 more soft violations.
	// Without softViolations reset, 10 + 15 >= 20 would hard-abort and ban the shared NAT IP.
	nowMu.Lock()
	curNow = curNow.Add(65 * time.Second)
	nowMu.Unlock()
	for i := 0; i < 16; i++ {
		req := makeBrowserReq(http.MethodGet, "https://app.example.com/", "198.51.100.88:50001")
		rec := httptest.NewRecorder()
		if err := sh.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("window 2 req %d should NOT hard-abort after 60s window reset: %v", i, err)
		}
	}
}
