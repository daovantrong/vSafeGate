package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loginTestSessionCookie(t *testing.T, handler http.Handler) *http.Cookie {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "InitialStrongPass!123",
	})
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/login", bytes.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "vsafegate_session" {
			return c
		}
	}
	t.Fatal("missing session cookie")
	return nil
}

func doAuthedJSONReq(handler http.Handler, cookie *http.Cookie, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, &buf)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestPhase01_GeoIPTriStateAndAtomicCustom(t *testing.T) {
	s := newTestAppState(t)
	h := setupRouter(s)
	cookie := loginTestSessionCookie(t, h)

	// Default GeoIP mode must be disabled (not forcing VN whitelist)
	rec := doAuthedJSONReq(h, cookie, http.MethodGet, "/api/geoip", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/geoip failed: %d", rec.Code)
	}
	var geoResp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &geoResp)
	if geoResp["geoip_mode"] != "disabled" {
		t.Fatalf("expected default geoip_mode=disabled, got %v", geoResp["geoip_mode"])
	}

	// Switch to whitelist, blacklist, and reject invalid
	if r := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/geoip/mode?mode=whitelist", nil); r.Code != http.StatusOK {
		t.Fatalf("expected 200 for whitelist mode, got %d", r.Code)
	}
	if r := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/geoip/mode?mode=bogus", nil); r.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bogus mode, got %d", r.Code)
	}

	// Atomic /api/geoip/custom switches mode + adds country in one request
	rCustom := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/geoip/custom", map[string]string{
		"code": "sg",
		"mode": "blacklist",
	})
	if rCustom.Code != http.StatusOK {
		t.Fatalf("expected 200 on atomic /api/geoip/custom, got %d (%s)", rCustom.Code, rCustom.Body.String())
	}
	s.mu.RLock()
	gotMode := s.config.GeoIPMode
	gotBlocked := strings.Join(s.config.BlockedCountries, ",")
	s.mu.RUnlock()
	if gotMode != "blacklist" || !strings.Contains(gotBlocked, "SG") {
		t.Fatalf("expected mode=blacklist & SG blocked, got mode=%q blocked=%q", gotMode, gotBlocked)
	}
}

func TestPhase01_AntiSelfDoS_CloudflareAndTrustedProxy(t *testing.T) {
	s := newTestAppState(t)
	s.mu.Lock()
	s.config.TrustedProxies = []string{"192.0.2.10/32"}
	s.config.Cloudflare.CachedIPv4 = []string{"173.245.48.0/20", "104.16.0.0/13"}
	s.mu.Unlock()
	h := setupRouter(s)
	cookie := loginTestSessionCookie(t, h)

	// 1. banIP must NEVER kernel-ban Cloudflare Edge, TrustedProxy, or ::ffff:-mapped Cloudflare IPs
	for _, protectedIP := range []string{"173.245.48.5", "::ffff:173.245.48.5", "192.0.2.10", "127.0.0.1", "0.0.0.0"} {
		s.banIP(protectedIP, "test anti-self-dos", 24)
		s.mu.RLock()
		_, exists := s.bannedMap[protectedIP]
		_, mappedExists := s.bannedMap["173.245.48.5"]
		s.mu.RUnlock()
		if exists || mappedExists {
			t.Fatalf("protected/reserved/proxy IP %q was illegally banned!", protectedIP)
		}
	}

	// 2. HTTP POST /api/blacklist rejects Cloudflare / TrustedProxy IPs with 400
	recCF := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/blacklist", map[string]any{
		"ip":             "104.16.0.5",
		"reason":         "Admin mistake",
		"duration_hours": 1,
	})
	if recCF.Code != http.StatusBadRequest {
		t.Fatalf("expected POST /api/blacklist to reject Cloudflare IP with 400, got %d", recCF.Code)
	}

	recTP := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/blacklist", map[string]any{
		"ip":             "192.0.2.10",
		"reason":         "Admin mistake",
		"duration_hours": 1,
	})
	if recTP.Code != http.StatusBadRequest {
		t.Fatalf("expected POST /api/blacklist to reject TrustedProxy IP with 400, got %d", recTP.Code)
	}

	// 3. Real attacker public IP succeeds
	recBad := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/blacklist", map[string]any{
		"ip":             "198.51.100.77",
		"reason":         "Verified flooder",
		"duration_hours": 24,
	})
	if recBad.Code != http.StatusOK {
		t.Fatalf("expected 200 banning public IP, got %d (%s)", recBad.Code, recBad.Body.String())
	}
	s.mu.RLock()
	_, ok := s.bannedMap["198.51.100.77"]
	s.mu.RUnlock()
	if !ok {
		t.Fatal("expected 198.51.100.77 in bannedMap")
	}
}

func TestPhase01_SitesCertExclusions_L4Validation_MgmtSettings(t *testing.T) {
	s := newTestAppState(t)
	h := setupRouter(s)
	cookie := loginTestSessionCookie(t, h)

	// 1. Sites CRUD + validation + AppPreset + duplicate rejection
	badSite := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/sites", map[string]any{
		"domain":     "app.example.com",
		"upstream":   "http://10.0.0.10:8080",
		"app_preset": "invalid_preset",
	})
	if badSite.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid app_preset, got %d", badSite.Code)
	}

	createSite := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/sites", map[string]any{
		"domain":          "app.example.com",
		"upstream":        "http://10.0.0.10:8080",
		"ssl":             true,
		"waf":             true,
		"waf_mode":        "on",
		"paranoia_level":  2,
		"app_preset":      "wordpress",
		"hide_alt_svc":    true,
		"trusted_proxies": []string{"192.168.1.1/32"},
	})
	if createSite.Code != http.StatusOK {
		t.Fatalf("expected 200 creating site, got %d (%s)", createSite.Code, createSite.Body.String())
	}
	var created Site
	_ = json.Unmarshal(createSite.Body.Bytes(), &created)

	// Duplicate domain check on PUT as well as POST
	dupPost := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/sites", map[string]any{
		"domain":   "app.example.com",
		"upstream": "http://10.0.0.11:8080",
	})
	if dupPost.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 duplicate domain POST, got %d", dupPost.Code)
	}

	// 2. Upload & Delete custom cert via /api/sites/cert
	certPEM, keyPEM := generateTestCertPEM(t, "app.example.com", time.Now().Add(24*time.Hour))
	upCert := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/sites/cert", map[string]string{
		"site_id":  created.ID,
		"cert_pem": certPEM,
		"key_pem":  keyPEM,
	})
	if upCert.Code != http.StatusOK {
		t.Fatalf("expected 200 uploading valid cert, got %d (%s)", upCert.Code, upCert.Body.String())
	}

	// 3. Add WAF exclusion and verify PUT /api/sites preserves CustomCertPath + Exclusions
	addExcl := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/waf/exclusions", map[string]any{
		"site_id":   created.ID,
		"rule_id":   942100,
		"match_uri": "/wp-json/wp/v2/posts",
		"comment":   "WP REST",
	})
	if addExcl.Code != http.StatusOK {
		t.Fatalf("expected 200 adding exclusion, got %d (%s)", addExcl.Code, addExcl.Body.String())
	}

	putSite := doAuthedJSONReq(h, cookie, http.MethodPut, "/api/sites", map[string]any{
		"id":       created.ID,
		"domain":   "app.example.com",
		"upstream": "http://10.0.0.12:8080",
		"ssl":      true,
		"waf":      true,
	})
	if putSite.Code != http.StatusOK {
		t.Fatalf("expected 200 on PUT /api/sites, got %d (%s)", putSite.Code, putSite.Body.String())
	}
	var updated Site
	_ = json.Unmarshal(putSite.Body.Bytes(), &updated)
	if updated.CustomCertPath == "" || len(updated.Exclusions) != 1 {
		t.Fatalf("PUT /api/sites must preserve cert path and exclusions, got cert=%q excls=%d", updated.CustomCertPath, len(updated.Exclusions))
	}

	// Delete cert resets CertMode back to auto_http
	delCert := doAuthedJSONReq(h, cookie, http.MethodDelete, "/api/sites/cert?site_id="+created.ID, nil)
	if delCert.Code != http.StatusOK {
		t.Fatalf("expected 200 deleting cert, got %d", delCert.Code)
	}

	// 4. L4 Services PUT validation (rate_limit >= 0 & port bounds)
	badL4 := doAuthedJSONReq(h, cookie, http.MethodPut, "/api/l4/services", map[string]any{
		"id":           "l4-smb",
		"name":         "Bad Rate",
		"protocol":     "tcp",
		"listen_port":  8445,
		"backend_addr": "192.168.1.50:445",
		"rate_limit":   -5,
	})
	if badL4.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative rate_limit, got %d", badL4.Code)
	}

	goodL4 := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/l4/services", map[string]any{
		"name":         "SMB Test",
		"protocol":     "tcp",
		"listen_port":  18445,
		"backend_addr": "127.0.0.1:445",
		"max_conns":    25,
		"rate_limit":   15,
		"enabled":      false,
	})
	if goodL4.Code != http.StatusOK {
		t.Fatalf("expected 200 creating L4 service with rate_limit, got %d (%s)", goodL4.Code, goodL4.Body.String())
	}

	// 5. /api/mgmt/settings rejects 0.0.0.0/0, ::/0, and invalid listen IPs; accepts valid isolation
	badMgmt := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/mgmt/settings", map[string]any{
		"mgmt_allowed_cidrs": []string{"0.0.0.0/0"},
	})
	if badMgmt.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 rejecting 0.0.0.0/0 in mgmt_allowed_cidrs, got %d", badMgmt.Code)
	}
	badTP := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/mgmt/settings", map[string]any{
		"trusted_proxies": []string{"::/0"},
	})
	if badTP.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 rejecting ::/0 in trusted_proxies, got %d", badTP.Code)
	}
	goodMgmt := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/mgmt/settings", map[string]any{
		"mgmt_domain":        "panel.example.com",
		"mgmt_https_port":    4439,
		"mgmt_http_port":     809,
		"mgmt_listen_ips":    []string{"192.168.10.2"},
		"mgmt_allowed_cidrs": []string{"127.0.0.1/32", "192.168.10.0/24"},
		"trusted_proxies":    []string{"192.168.10.1/32"},
	})
	if goodMgmt.Code != http.StatusOK {
		t.Fatalf("expected 200 saving valid mgmt settings, got %d (%s)", goodMgmt.Code, goodMgmt.Body.String())
	}

	// 6. /api/status exposes mgmt_https_port & mgmt_http_port
	st := doAuthedJSONReq(h, cookie, http.MethodGet, "/api/status", nil)
	if st.Code != http.StatusOK || !strings.Contains(st.Body.String(), `"mgmt_https_port":4439`) {
		t.Fatalf("expected mgmt_https_port=4439 in /api/status, got %s", st.Body.String())
	}
}

func TestPhase01_SiteTrustedProxyAntiSelfDoS_UnbanNormalization_And_ParseAuditAction(t *testing.T) {
	s := newTestAppState(t)
	s.mu.Lock()
	s.config.Sites = append(s.config.Sites, Site{
		ID:             "site-tp",
		Domain:         "app.example.com",
		Upstream:       "10.0.0.5:80",
		TrustedProxies: []string{"198.51.100.77", "203.0.113.0/24"},
	})
	s.mu.Unlock()

	if !isTrustedProxyOrCloudflareIP("198.51.100.77", s.config) {
		t.Fatal("expected site TrustedProxies single IP 198.51.100.77 to be protected")
	}
	if !isTrustedProxyOrCloudflareIP("::ffff:198.51.100.77", s.config) {
		t.Fatal("expected ::ffff:198.51.100.77 unmapped site proxy IP to be protected")
	}
	if !isTrustedProxyOrCloudflareIP("203.0.113.42", s.config) {
		t.Fatal("expected site TrustedProxies CIDR 203.0.113.0/24 to be protected")
	}

	h := setupRouter(s)
	cookie := loginTestSessionCookie(t, h)
	banSiteProxy := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/blacklist", map[string]any{
		"ip":     "198.51.100.77",
		"reason": "test",
	})
	if banSiteProxy.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 rejecting site trusted proxy ban, got %d (%s)", banSiteProxy.Code, banSiteProxy.Body.String())
	}

	// Verify unbanIP normalizes IPv4-mapped IPv6 addresses
	s.banIP("192.0.2.55", "test-unmap", 1)
	s.mu.RLock()
	_, isBanned := s.bannedMap["192.0.2.55"]
	s.mu.RUnlock()
	if !isBanned {
		t.Fatal("expected 192.0.2.55 to be banned")
	}
	s.unbanIP("::ffff:192.0.2.55", "manual unban")
	s.mu.RLock()
	_, stillBanned := s.bannedMap["192.0.2.55"]
	s.mu.RUnlock()
	if stillBanned {
		t.Fatal("expected ::ffff:192.0.2.55 unbanIP to remove normalized 192.0.2.55")
	}

	// Verify parseCorazaAuditLine distinguishes Phase 1 deny (403) from drop even when status==0,
	// and falls back to error_message when K part is absent.
	denyLine := `{"transaction":{"id":"tx1","client_ip":"198.51.100.99","is_interrupted":true,"response":{"status":0},"request":{"method":"GET","uri":"/.env","headers":{"Host":["app.example.com"]}}},"messages":[{"actionset":"","message":"","error_message":"[client \"198.51.100.99\"] Coraza: Access denied (phase 1). vSafeGate 403 Test [id \"990002\"] [msg \"Blocked Sensitive Env\"] [data \"Matched /.env\"]","data":null}]}`
	parsedDeny, ok := parseCorazaAuditLine(denyLine)
	if !ok {
		t.Fatal("expected deny audit line to parse")
	}
	if parsedDeny.Action != "BLOCKED (403)" || parsedDeny.RuleID != 990002 || parsedDeny.RuleName != "Blocked Sensitive Env" || parsedDeny.MatchedVar != "Matched /.env" || parsedDeny.Phase != 1 {
		t.Fatalf("unexpected parsed deny audit entry: %+v", parsedDeny)
	}

	dropLine := `{"transaction":{"id":"tx2","client_ip":"::ffff:198.51.100.88","is_interrupted":true,"response":{"status":0},"request":{"method":"GET","uri":"/drop","headers":{"Host":["app.example.com"]}}},"messages":[{"actionset":"OWASP_CRS/4.25.0","message":"Drop Test","error_message":"[client \"198.51.100.88\"] Coraza: Access dropped (phase 1). Drop Test [id \"990001\"]","data":{"id":990001,"msg":"Drop Test","severity":-1,"raw":"SecRule REQUEST_URI \"@beginsWith /drop\" \"id:990001,phase:1,drop\""}}]}`
	parsedDrop, ok := parseCorazaAuditLine(dropLine)
	if !ok {
		t.Fatal("expected drop audit line to parse")
	}
	if parsedDrop.Action != "DROPPED" || parsedDrop.ClientIP != "198.51.100.88" || parsedDrop.Severity == "-1" {
		t.Fatalf("unexpected parsed drop audit entry: %+v", parsedDrop)
	}
}

func TestPhase01_MethodEnforcement_Exclusions_Rules_And_MgmtValidation(t *testing.T) {
	s := newTestAppState(t)
	h := setupRouter(s)
	cookie := loginTestSessionCookie(t, h)

	// 1. Mutating endpoints MUST reject GET (CSRF bypass protection)
	mutatingPaths := []string{
		"/api/logout",
		"/api/geoip/mode?mode=whitelist",
		"/api/geoip/toggle?code=VN",
		"/api/geoip/custom",
		"/api/l4/services/toggle?id=l4-1",
		"/api/rules/toggle?id=r-1",
		"/api/reload",
		"/api/network/interfaces/apply",
	}
	for _, p := range mutatingPaths {
		rec := doAuthedJSONReq(h, cookie, http.MethodGet, p, nil)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s expected 405 Method Not Allowed, got %d", p, rec.Code)
		}
	}

	// 2. POST /api/rules honors enabled:false and rejects invalid ipMatch
	ruleRec := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/rules", map[string]any{
		"name":     "Disabled Initially",
		"target":   "URI",
		"operator": "contains",
		"pattern":  "/healthz",
		"action":   "allow",
		"enabled":  false,
	})
	if ruleRec.Code != http.StatusOK {
		t.Fatalf("POST /api/rules failed: %d (%s)", ruleRec.Code, ruleRec.Body.String())
	}
	var createdRule CustomRule
	if err := json.Unmarshal(ruleRec.Body.Bytes(), &createdRule); err != nil || createdRule.Enabled {
		t.Fatalf("expected created rule Enabled=false, got %+v (err=%v)", createdRule, err)
	}

	badIPMatch := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/rules", map[string]any{
		"name":     "Bad ipMatch",
		"target":   "IP",
		"operator": "ipMatch",
		"pattern":  "not-an-ip",
		"action":   "drop",
	})
	if badIPMatch.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid ipMatch pattern, got %d", badIPMatch.Code)
	}

	// 3. POST /api/sites rejects path-traversal site ID
	badSiteID := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/sites", map[string]any{
		"id":       "../evil",
		"domain":   "ok.example.com",
		"upstream": "127.0.0.1:8080",
	})
	if badSiteID.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for path-traversal site ID, got %d", badSiteID.Code)
	}

	// Add wildcard site and test /api/waf/exclusions host:port matching + sanitization
	addSite := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/sites", map[string]any{
		"domain":   "*.example.com",
		"upstream": "10.0.0.2:80",
	})
	if addSite.Code != http.StatusOK {
		t.Fatalf("POST /api/sites failed: %d (%s)", addSite.Code, addSite.Body.String())
	}

	badExclArg := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/waf/exclusions", map[string]any{
		"host":        "app.example.com:8443",
		"rule_id":     941100,
		"match_uri":   "/comment",
		"remove_args": []string{"ARGS:bio,deny"},
	})
	if badExclArg.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for injection in remove_args, got %d", badExclArg.Code)
	}

	badExclURI := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/waf/exclusions", map[string]any{
		"host":      "app.example.com",
		"rule_id":   941100,
		"match_uri": "no-leading-slash",
	})
	if badExclURI.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for match_uri missing leading slash, got %d", badExclURI.Code)
	}

	goodExcl := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/waf/exclusions", map[string]any{
		"host":        "app.example.com:8443",
		"rule_id":     941100,
		"match_uri":   "/comment",
		"remove_args": []string{"ARGS:bio"},
	})
	if goodExcl.Code != http.StatusOK || !strings.Contains(goodExcl.Body.String(), `"sites_updated":1`) {
		t.Fatalf("expected wildcard host:port exclusion to match 1 site, got %d (%s)", goodExcl.Code, goodExcl.Body.String())
	}

	// 4. POST /api/mgmt/settings rejects invalid MgmtDomain and colliding/out-of-range ports
	badMgmtCases := []map[string]any{
		{"mgmt_domain": "*.wild.example.com"},
		{"mgmt_domain": "bad host"},
		{"mgmt_https_port": 443},
		{"mgmt_http_port": 80},
		{"mgmt_https_port": 70000},
		{"mgmt_https_port": 8443, "mgmt_http_port": 8443},
	}
	for _, payload := range badMgmtCases {
		rec := doAuthedJSONReq(h, cookie, http.MethodPost, "/api/mgmt/settings", payload)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("mgmt settings %v expected 400, got %d (%s)", payload, rec.Code, rec.Body.String())
		}
	}
}

func writeTestLeafCertPEM(t *testing.T, outPath, domain, issuerCN string, notAfter time.Time, selfSigned bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		t.Fatalf("mkdir %s: %v", outPath, err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: issuerCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent := caTmpl
	signer := caKey
	if selfSigned {
		parent = leafTmpl
		signer = leafKey
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTmpl, parent, &leafKey.PublicKey, signer)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(outPath, pemBytes, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
}

func TestPhase01_MgmtDomainCertProvisioningAndRollback(t *testing.T) {
	s := newTestAppState(t)
	s.mu.Lock()
	s.caddyDataDir = filepath.Join(t.TempDir(), "caddy-data")
	s.config.Cloudflare.APIToken = "cf-test-token"
	s.config.MgmtDomain = "old.example.com"
	s.mu.Unlock()

	// 1. Self-signed / local CA certs must be ignored by findValidPublicCertForDomain
	localCert := filepath.Join(s.caddyDataDir, "caddy", "certificates", "local", "old.example.com", "old.example.com.crt")
	writeTestLeafCertPEM(t, localCert, "old.example.com", "Caddy Local Authority - ECC Intermediate", time.Now().Add(90*24*time.Hour), false)
	if ok, _, _ := findValidPublicCertForDomain(s.caddyDataDir, "old.example.com"); ok {
		t.Fatal("expected local Caddy CA cert to be ignored as non-public")
	}

	var provisionCalls int
	var nextErr error
	s.mgmtCertProvisioner = func(ctx context.Context, cfgSnapshot Config) (string, string, time.Time, error) {
		provisionCalls++
		if nextErr != nil {
			return "", "", time.Time{}, nextErr
		}
		exp := time.Now().Add(90 * 24 * time.Hour).UTC()
		crtPath := filepath.Join(s.caddyDataDir, "caddy", "certificates", "acme-v02.api.letsencrypt.org-directory", cfgSnapshot.MgmtDomain, cfgSnapshot.MgmtDomain+".crt")
		writeTestLeafCertPEM(t, crtPath, cfgSnapshot.MgmtDomain, "R11", exp, false)
		return "issued", "R11", exp, nil
	}

	handler := setupRouter(s)
	cookie := loginTestSessionCookie(t, handler)
	doPost := func(payload map[string]any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/mgmt/settings", bytes.NewReader(raw))
		req.Host = "127.0.0.1:8080"
		req.Header.Set("Origin", "http://127.0.0.1:8080")
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// 2. Failed issuance (e.g., Let's Encrypt rate limit) must auto-fallback to self-signed cert so access never breaks
	nextErr = errors.New("cấp chứng chỉ SSL cho bad.example.com thất bại: rateLimited")
	recFail := doPost(map[string]any{
		"mgmt_domain":          "bad.example.com",
		"mgmt_use_letsencrypt": true,
		"mgmt_https_port":      4438,
		"mgmt_http_port":       808,
	})
	if recFail.Code != http.StatusOK {
		t.Fatalf("expected 200 internal_fallback on rateLimited failure, got %d (%s)", recFail.Code, recFail.Body.String())
	}
	if !strings.Contains(recFail.Body.String(), `"cert_status":"internal_fallback"`) {
		t.Fatalf("expected cert_status=internal_fallback, got %s", recFail.Body.String())
	}
	s.mu.RLock()
	curDom := s.config.MgmtDomain
	curInternal := s.config.MgmtCertInternal
	s.mu.RUnlock()
	if curDom != "bad.example.com" || !curInternal {
		t.Fatalf("expected MgmtDomain=bad.example.com with MgmtCertInternal=true fallback, got domain=%q internal=%v", curDom, curInternal)
	}

	// 3. Successful issuance commits new MgmtDomain with MgmtCertInternal=false and puts it into dual-issuer policy [acme, internal]
	nextErr = nil
	recOK := doPost(map[string]any{
		"mgmt_domain":          "pve.trong.pro",
		"mgmt_use_letsencrypt": true,
		"mgmt_https_port":      4438,
		"mgmt_http_port":       808,
	})
	if recOK.Code != http.StatusOK {
		t.Fatalf("expected 200 on valid issuance, got %d (%s)", recOK.Code, recOK.Body.String())
	}
	if !strings.Contains(recOK.Body.String(), `"cert_status":"issued"`) {
		t.Fatalf("expected cert_status=issued, got %s", recOK.Body.String())
	}
	if provisionCalls != 2 {
		t.Fatalf("expected 2 provision attempts, got %d", provisionCalls)
	}

	// 4. Saving again with unchanged domain & valid cached cert reuses it without calling ACME again
	recReuse := doPost(map[string]any{
		"mgmt_domain":     "pve.trong.pro",
		"mgmt_https_port": 4438,
		"mgmt_http_port":  808,
	})
	if recReuse.Code != http.StatusOK {
		t.Fatalf("expected 200 on reuse, got %d (%s)", recReuse.Code, recReuse.Body.String())
	}
	if !strings.Contains(recReuse.Body.String(), `"cert_status":"reused"`) {
		t.Fatalf("expected cert_status=reused, got %s", recReuse.Body.String())
	}
	if provisionCalls != 2 {
		t.Fatalf("expected cached cert reuse without re-provisioning, got %d calls", provisionCalls)
	}

	// 5. Verify buildCaddyJSONConfig places pve.trong.pro in DNS-01 automation
	s.mu.RLock()
	cfgSnap := s.config
	s.mu.RUnlock()
	caddyJSON := buildCaddyJSONConfig(cfgSnap, "/etc/caddy/rules", "/var/log/caddy/waf-audit.jsonl", "/var/log/caddy/access.log", nil, nil)
	rawJSON, _ := json.Marshal(caddyJSON)
	jsonStr := string(rawJSON)
	if !strings.Contains(jsonStr, `"name":"cloudflare"`) || !strings.Contains(jsonStr, `"pve.trong.pro"`) {
		t.Fatalf("expected cloudflare dns-01 policy for pve.trong.pro, got %s", jsonStr)
	}

	// 5b. Renewal failure fallback: if domain has no non-expired public cert (e.g. expired), watchdog flips MgmtCertInternal=true
	expiredPath := filepath.Join(s.caddyDataDir, "caddy", "certificates", "acme-v02.api.letsencrypt.org-directory", "expired.example.com", "expired.example.com.crt")
	writeTestLeafCertPEM(t, expiredPath, "expired.example.com", "R11", time.Now().Add(-2*time.Hour), false)
	s.mu.Lock()
	s.config.MgmtDomain = "expired.example.com"
	s.config.MgmtCertInternal = false
	s.mu.Unlock()
	if !s.checkMgmtCertRenewalFallback(time.Now()) {
		t.Fatal("expected checkMgmtCertRenewalFallback to trigger for expired cert")
	}
	s.mu.RLock()
	expFallback := s.config.MgmtCertInternal
	s.mu.RUnlock()
	if !expFallback {
		t.Fatal("expected MgmtCertInternal=true after renewal fallback")
	}
	// Restore pve.trong.pro for step 6
	s.mu.Lock()
	s.config.MgmtDomain = "pve.trong.pro"
	s.config.MgmtCertInternal = false
	s.mu.Unlock()

	// 6. Unchecking Let's Encrypt switches MgmtCertInternal=true and skips ACME provisioning
	recSelf := doPost(map[string]any{
		"mgmt_domain":          "pve.trong.pro",
		"mgmt_use_letsencrypt": false,
		"mgmt_https_port":      4438,
		"mgmt_http_port":       808,
	})
	if recSelf.Code != http.StatusOK {
		t.Fatalf("expected 200 on self-signed switch, got %d (%s)", recSelf.Code, recSelf.Body.String())
	}
	if !strings.Contains(recSelf.Body.String(), `"cert_status":"internal"`) {
		t.Fatalf("expected cert_status=internal, got %s", recSelf.Body.String())
	}
	if provisionCalls != 2 {
		t.Fatalf("expected no ACME call when mgmt_use_letsencrypt=false, got %d", provisionCalls)
	}
	s.mu.RLock()
	cfgSelf := s.config
	s.mu.RUnlock()
	if !cfgSelf.MgmtCertInternal {
		t.Fatal("expected MgmtCertInternal=true")
	}
	selfJSON := buildCaddyJSONConfig(cfgSelf, "/etc/caddy/rules", "/var/log/caddy/waf-audit.jsonl", "/var/log/caddy/access.log", nil, nil)
	selfRaw, _ := json.Marshal(selfJSON)
	if strings.Contains(string(selfRaw), `"name":"cloudflare"`) {
		t.Fatalf("expected no cloudflare issuer when MgmtCertInternal=true, got %s", string(selfRaw))
	}
}

func TestPhase01_MgmtPanelSSL_CustomCert_Inspect_And_Modes(t *testing.T) {
	s := newTestAppState(t)
	s.mu.Lock()
	s.caddyDataDir = filepath.Join(t.TempDir(), "caddy-data")
	s.config.Cloudflare.APIToken = "cf-test-token"
	s.config.MgmtDomain = "panel.example.com"
	s.mu.Unlock()

	handler := setupRouter(s)
	cookie := loginTestSessionCookie(t, handler)
	doReq := func(method, path string, payload map[string]any) *httptest.ResponseRecorder {
		var body []byte
		if payload != nil {
			body, _ = json.Marshal(payload)
		}
		req := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, bytes.NewReader(body))
		req.Host = "127.0.0.1:8080"
		req.Header.Set("Origin", "http://127.0.0.1:8080")
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// 1. Reject mismatched/invalid custom PEM
	recBad := doReq(http.MethodPost, "/api/mgmt/ssl", map[string]any{
		"mode":     "custom",
		"cert_pem": "not-a-cert",
		"key_pem":  "not-a-key",
	})
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid custom PEM, got %d (%s)", recBad.Code, recBad.Body.String())
	}

	// 2. Generate valid cert + key pair and save as custom Panel SSL
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	notAfter := time.Now().Add(180 * 24 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "*.example.com"},
		DNSNames:     []string{"*.example.com", "panel.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	recCustom := doReq(http.MethodPost, "/api/mgmt/ssl", map[string]any{
		"mode":     "custom",
		"cert_pem": certPEM,
		"key_pem":  keyPEM,
	})
	if recCustom.Code != http.StatusOK {
		t.Fatalf("expected 200 saving custom Panel SSL, got %d (%s)", recCustom.Code, recCustom.Body.String())
	}

	// 3. GET /api/mgmt/ssl returns full details including PEMs and calculated days_remaining
	recGet := doReq(http.MethodGet, "/api/mgmt/ssl", nil)
	if recGet.Code != http.StatusOK {
		t.Fatalf("expected 200 on GET /api/mgmt/ssl, got %d", recGet.Code)
	}
	var info MgmtPanelSSLInfo
	if err := json.Unmarshal(recGet.Body.Bytes(), &info); err != nil {
		t.Fatalf("unmarshal ssl info: %v", err)
	}
	if info.Mode != "custom" || info.DaysRemaining < 175 || !strings.Contains(info.Domain, "*.example.com") {
		t.Fatalf("unexpected ssl info: %+v", info)
	}
	if !strings.Contains(info.CertPEM, "BEGIN CERTIFICATE") || !strings.Contains(info.KeyPEM, "BEGIN EC PRIVATE KEY") {
		t.Fatalf("expected cert_pem and key_pem in GET /api/mgmt/ssl")
	}

	// 4. Verify Caddy JSON uses load_files for custom Panel SSL
	s.mu.RLock()
	cfgSnap := s.config
	s.mu.RUnlock()
	caddyJSON := buildCaddyJSONConfig(cfgSnap, "/etc/caddy/rules", "/var/log/caddy/waf-audit.jsonl", "/var/log/caddy/access.log", nil, nil)
	rawJSON, _ := json.Marshal(caddyJSON)
	if !strings.Contains(string(rawJSON), `"load_files"`) || !strings.Contains(string(rawJSON), `mgmt-panel.crt`) {
		t.Fatalf("expected load_files with mgmt-panel.crt in Caddy JSON, got %s", string(rawJSON))
	}

	// 5. Switch to internal via /api/mgmt/ssl
	recInt := doReq(http.MethodPost, "/api/mgmt/ssl", map[string]any{"mode": "internal"})
	if recInt.Code != http.StatusOK || !strings.Contains(recInt.Body.String(), `"cert_status":"internal"`) {
		t.Fatalf("expected switch to internal, got %d %s", recInt.Code, recInt.Body.String())
	}
}
