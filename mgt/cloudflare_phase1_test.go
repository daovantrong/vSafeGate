package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func generateTestCertPEM(t *testing.T, dnsName string, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: dnsName},
		Issuer:       pkix.Name{CommonName: "vSafeGate Test CA"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certOut), string(keyOut)
}

func TestCloudflarePhase1_APICRUD_Pagination_AndIPs(t *testing.T) {
	var mu sync.Mutex
	var patchCalls []string
	var deletedID string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/user/tokens/verify" && r.Method == http.MethodGet:
			if r.Header.Get("Authorization") != "Bearer good-tok" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"Invalid token"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"result":{"status":"active"}}`))

		case r.URL.Path == "/zones" && r.Method == http.MethodGet:
			page := r.URL.Query().Get("page")
			if page == "1" {
				_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"z1","name":"one.example.com","status":"active"}],"result_info":{"page":1,"total_pages":2}}`))
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"z2","name":"two.example.com","status":"active"}],"result_info":{"page":2,"total_pages":2}}`))

		case r.URL.Path == "/zones/z1/dns_records" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"rec-a","type":"A","name":"app.one.example.com","content":"203.0.113.1","ttl":1,"proxied":false}],"result_info":{"page":1,"total_pages":1}}`))

		case r.URL.Path == "/zones/z1/dns_records" && r.Method == http.MethodPost:
			var rec CFDNSRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			rec.ID = "rec-created"
			resp, _ := json.Marshal(map[string]any{"success": true, "result": rec})
			_, _ = w.Write(resp)

		case r.URL.Path == "/zones/z1/dns_records/rec-a" && r.Method == http.MethodPut:
			var rec CFDNSRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			rec.ID = "rec-a"
			resp, _ := json.Marshal(map[string]any{"success": true, "result": rec})
			_, _ = w.Write(resp)

		case r.URL.Path == "/zones/z1/dns_records/rec-a" && r.Method == http.MethodPatch:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			if body["proxied"] == true {
				patchCalls = append(patchCalls, "on")
			} else {
				patchCalls = append(patchCalls, "off")
			}
			mu.Unlock()
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"rec-a","type":"A","name":"app.one.example.com","content":"203.0.113.1","ttl":1,"proxied":true}}`))

		case r.URL.Path == "/zones/z1/dns_records/rec-a" && r.Method == http.MethodDelete:
			mu.Lock()
			deletedID = "rec-a"
			mu.Unlock()
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"rec-a"}}`))

		case r.URL.Path == "/ips" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"success":true,"result":{"ipv4_cidrs":["173.245.48.0/20"],"ipv6_cidrs":["2400:cb00::/32"]}}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cf := newCloudflareClient("good-tok")
	cf.BaseURL = srv.URL

	ctx := context.Background()
	status, err := cf.VerifyToken(ctx)
	if err != nil || status != "active" {
		t.Fatalf("VerifyToken failed: status=%q err=%v", status, err)
	}

	zones, err := cf.ListZones(ctx)
	if err != nil || len(zones) != 2 {
		t.Fatalf("expected 2 paginated zones, got len=%d err=%v", len(zones), err)
	}

	created, err := cf.CreateDNSRecord(ctx, "z1", CFDNSRecord{Type: "a", Name: "sub", Content: "203.0.113.2"})
	if err != nil || created.Type != "A" || created.TTL != 1 {
		t.Fatalf("CreateDNSRecord normalization failed: %+v err=%v", created, err)
	}

	if _, err := cf.CreateDNSRecord(ctx, "z1", CFDNSRecord{Type: "MX", Name: "@", Content: "mail.example.com", Proxied: true}); err == nil {
		t.Fatal("expected proxied MX record to fail validation")
	}

	updated, err := cf.UpdateDNSRecord(ctx, "z1", "rec-a", CFDNSRecord{Type: "A", Name: "app.one.example.com", Content: "203.0.113.99"})
	if err != nil || updated.Content != "203.0.113.99" || updated.TTL != 1 {
		t.Fatalf("UpdateDNSRecord failed: %+v err=%v", updated, err)
	}

	if _, err := cf.PatchDNSRecordProxied(ctx, "z1", "rec-a", true); err != nil {
		t.Fatalf("PatchDNSRecordProxied failed: %v", err)
	}
	if err := cf.DeleteDNSRecord(ctx, "z1", "rec-a"); err != nil {
		t.Fatalf("DeleteDNSRecord failed: %v", err)
	}
	v4, v6, err := cf.FetchCloudflareIPs(ctx)
	if err != nil || len(v4) != 1 || len(v6) != 1 {
		t.Fatalf("FetchCloudflareIPs failed: v4=%v v6=%v err=%v", v4, v6, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(patchCalls) != 1 || patchCalls[0] != "on" || deletedID != "rec-a" {
		t.Fatalf("unexpected patch/delete audit: patch=%v deleted=%q", patchCalls, deletedID)
	}
}

func TestCloudflarePhase1_SyncIPsWithBase(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("ENV", "dev")
	origWD, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	defer func() { _ = os.Chdir(origWD) }()

	s := newTestAppState(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":{"ipv4_cidrs":["104.16.0.0/13"],"ipv6_cidrs":["2606:4700::/32"]}}`))
	}))
	defer srv.Close()

	if err := s.syncCloudflareIPsWithBase(context.Background(), srv.URL); err != nil {
		t.Fatalf("syncCloudflareIPsWithBase failed: %v", err)
	}
	if len(s.config.Cloudflare.CachedIPv4) != 1 || s.config.Cloudflare.IPSyncSource != "cloudflare_api" {
		t.Fatalf("unexpected Cloudflare cache state: %+v", s.config.Cloudflare)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "cf_ips.json")); err != nil {
		t.Fatalf("expected cf_ips.json cache file in temp workdir: %v", err)
	}
}

func TestCloudflarePhase1_SaveUploadedSiteCert(t *testing.T) {
	s := newTestAppState(t)
	s.mu.Lock()
	s.config.Sites = []Site{{ID: "site-1", Domain: "cert.example.com", Upstream: "http://127.0.0.1:9000", SSL: true}}
	s.mu.Unlock()

	validCert, validKey := generateTestCertPEM(t, "cert.example.com", time.Now().Add(48*time.Hour))
	_, wrongKey := generateTestCertPEM(t, "other.example.com", time.Now().Add(48*time.Hour))
	expiredCert, expiredKey := generateTestCertPEM(t, "expired.example.com", time.Now().Add(-time.Hour))

	// Invalid cases
	if _, err := s.saveUploadedSiteCert("../evil", validCert, validKey); err == nil {
		t.Fatal("expected path-traversal site_id rejection")
	}
	if _, err := s.saveUploadedSiteCert("site-1", validCert, wrongKey); err == nil {
		t.Fatal("expected mismatched cert/key rejection")
	}
	if _, err := s.saveUploadedSiteCert("site-1", expiredCert, expiredKey); err == nil {
		t.Fatal("expected expired certificate rejection")
	}
	if _, err := s.saveUploadedSiteCert("missing-site", validCert, validKey); err == nil {
		t.Fatal("expected non-existent site error")
	}

	// Valid upload
	meta, err := s.saveUploadedSiteCert("site-1", validCert, validKey)
	if err != nil {
		t.Fatalf("valid cert upload failed: %v", err)
	}
	if meta.Subject != "cert.example.com" || meta.Issuer != "cert.example.com" {
		t.Fatalf("unexpected cert metadata: %+v", meta)
	}
	if _, err := os.Stat(meta.CertPath); err != nil {
		t.Fatalf("cert file not written: %v", err)
	}
	if _, err := os.Stat(meta.KeyPath); err != nil {
		t.Fatalf("key file not written: %v", err)
	}
	s.mu.RLock()
	updated := s.config.Sites[0]
	s.mu.RUnlock()
	if updated.CertMode != "uploaded" || updated.CustomCertPath != meta.CertPath || !updated.SSL {
		t.Fatalf("site config not updated after cert upload: %+v", updated)
	}
}

func TestCloudflarePhase1_AutoProxyControllerHysteresisAndSafety(t *testing.T) {
	s := newTestAppState(t)
	s.mu.Lock()
	s.config.Cloudflare.APIToken = "ap-tok"
	s.config.Sites = []Site{{
		ID:                       "site-ap",
		Domain:                   "ap.example.com",
		Upstream:                 "http://127.0.0.1:9001",
		SSL:                      true,
		AutoProxyEnabled:         true,
		AutoProxyZoneID:          "z-ap",
		AutoProxyRecordIDs:       []string{"rec-a", "rec-mx"}, // MX MUST be skipped!
		AutoProxyThresholdRPS:    500,
		AutoProxyThresholdDropPS: 30,
		AutoProxyWindowSec:       15,
		AutoProxyHoldMinutes:     60,
		AutoProxyAutoRevert:      true,
		AutoProxyUnderAttack:     true,
	}}
	s.mu.Unlock()

	var mu sync.Mutex
	var patched []string
	var secLevels []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/zones/z-ap/dns_records" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"rec-a","type":"A","name":"ap.example.com","content":"203.0.113.10","ttl":1,"proxied":false},{"id":"rec-mx","type":"MX","name":"ap.example.com","content":"mail.example.com","ttl":1,"proxied":false}],"result_info":{"page":1,"total_pages":1}}`))
		case strings.HasPrefix(r.URL.Path, "/zones/z-ap/dns_records/") && r.Method == http.MethodPatch:
			recID := strings.TrimPrefix(r.URL.Path, "/zones/z-ap/dns_records/")
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			patched = append(patched, recID+":"+map[bool]string{true: "true", false: "false"}[body["proxied"] == true])
			mu.Unlock()
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"rec-a","type":"A","name":"ap.example.com","content":"203.0.113.10","ttl":1,"proxied":true}}`))
		case r.URL.Path == "/zones/z-ap/settings/security_level" && r.Method == http.MethodPatch:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			secLevels = append(secLevels, body["value"])
			mu.Unlock()
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ctrl := newAutoProxyController(s)
	ctrl.baseURL = srv.URL
	cur := time.Date(2026, 11, 25, 14, 0, 0, 0, time.UTC)
	ctrl.nowFn = func() time.Time { return cur }

	ctx := context.Background()

	// Step 1: overload begins -> NOT triggered before 15s hysteresis window
	ctrl.Evaluate(ctx, 700, 0)
	cur = cur.Add(10 * time.Second)
	ctrl.Evaluate(ctx, 700, 0)
	mu.Lock()
	if len(patched) != 0 {
		t.Fatalf("triggered too early before hysteresis window: %v", patched)
	}
	mu.Unlock()

	// Step 2: 15s elapsed -> activates A record ONLY (never MX), sets under_attack
	cur = cur.Add(6 * time.Second)
	ctrl.Evaluate(ctx, 700, 0)

	mu.Lock()
	if len(patched) != 1 || patched[0] != "rec-a:true" {
		t.Fatalf("expected only rec-a patched true, got %v", patched)
	}
	if len(secLevels) != 1 || secLevels[0] != "under_attack" {
		t.Fatalf("expected security_level=under_attack, got %v", secLevels)
	}
	mu.Unlock()

	s.mu.RLock()
	if !s.config.Sites[0].AutoProxyActive {
		t.Fatal("expected AutoProxyActive=true")
	}
	s.mu.RUnlock()

	// Step 3: calm traffic BEFORE holdMinutes (60m) must NOT revert
	cur = cur.Add(30 * time.Minute)
	ctrl.Evaluate(ctx, 10, 0)
	cur = cur.Add(20 * time.Second)
	ctrl.Evaluate(ctx, 10, 0)
	s.mu.RLock()
	if !s.config.Sites[0].AutoProxyActive {
		t.Fatal("must NOT auto-revert before holdMinutes elapsed")
	}
	s.mu.RUnlock()

	// Step 4: after holdMinutes + calm window -> reverts proxied=false & security_level=medium
	cur = cur.Add(35 * time.Minute)
	ctrl.Evaluate(ctx, 10, 0)
	cur = cur.Add(20 * time.Second)
	ctrl.Evaluate(ctx, 10, 0)

	mu.Lock()
	if len(patched) != 2 || patched[1] != "rec-a:false" {
		t.Fatalf("expected rec-a revert to false, got %v", patched)
	}
	if len(secLevels) != 2 || secLevels[1] != "medium" {
		t.Fatalf("expected security_level revert to medium, got %v", secLevels)
	}
	mu.Unlock()

	s.mu.RLock()
	if s.config.Sites[0].AutoProxyActive {
		t.Fatal("expected AutoProxyActive=false after auto-revert")
	}
	s.mu.RUnlock()
}
