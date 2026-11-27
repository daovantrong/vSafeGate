package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/corazawaf/coraza-caddy/v2"
	"github.com/corazawaf/coraza/v3"

	_ "caddy-core/modules/cf_dns"
	_ "caddy-core/modules/pre_tls"
	_ "caddy-core/modules/shield"
)

func writeSelfSignedCert(t *testing.T, dir, dnsName string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
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

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	var certBuf bytes.Buffer
	_ = pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certBuf.Bytes(), 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	var keyBuf bytes.Buffer
	_ = pem.Encode(&keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyBuf.Bytes(), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func TestCaddyCore_PreTLS_CorazaDrop_SharedAuditLog_NoServerHeader(t *testing.T) {
	tmpDir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, tmpDir, "safe.local")
	auditPath := filepath.Join(tmpDir, "waf-audit.jsonl")

	// Mock backend that optionally adds X-Drop-Resp on /drop-phase3
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/drop-phase3" {
			w.Header().Set("X-Drop-Resp", "1")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok-upstream"))
	}))
	defer backend.Close()
	upstreamAddr := strings.TrimPrefix(backend.URL, "http://")

	port := freeTCPPort(t)
	auditSlash := filepath.ToSlash(auditPath)
	certSlash := filepath.ToSlash(certPath)
	keySlash := filepath.ToSlash(keyPath)

	directives := fmt.Sprintf(`
SecRuleEngine On
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus ^$
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLog %s
SecRule REQUEST_URI "@contains /drop-phase1" "id:1001,phase:1,drop,log,auditlog,msg:'phase1 drop'"
SecRule RESPONSE_HEADERS:X-Drop-Resp "@streq 1" "id:1003,phase:3,drop,log,auditlog,msg:'phase3 drop'"
`, auditSlash)

	cfg := map[string]any{
		"admin": map[string]any{"disabled": true},
		"apps": map[string]any{
			"tls": map[string]any{
				"certificates": map[string]any{
					"load_files": []map[string]any{
						{"certificate": certSlash, "key": keySlash, "format": "pem"},
					},
				},
			},
			"http": map[string]any{
				"servers": map[string]any{
					"srv0": map[string]any{
						"listen": []string{fmt.Sprintf("127.0.0.1:%d", port)},
						"listener_wrappers": []map[string]any{
							{
								"wrapper":          "vsafegate_pre_tls",
								"allowed_snis":     []string{"safe.local"},
								"drop_missing_sni": true,
								"drop_unknown_sni": true,
							},
							{"wrapper": "tls"},
						},
						"tls_connection_policies": []map[string]any{
							{"match": map[string]any{"sni": []string{"safe.local"}}},
						},
						"automatic_https": map[string]any{"disable": true},
						"routes": []map[string]any{
							{
								"match": []map[string]any{{"host": []string{"safe.local"}}},
								"handle": []map[string]any{
									{
										"handler":    "waf",
										"directives": directives,
									},
									{
										"handler": "reverse_proxy",
										"upstreams": []map[string]any{
											{"dial": upstreamAddr},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	rawCfg, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal cfg: %v", err)
	}
	if err := caddy.Load(rawCfg, true); err != nil {
		t.Fatalf("caddy.Load: %v", err)
	}
	t.Cleanup(func() {
		_ = caddy.Stop()
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "safe.local",
			},
		},
	}

	doTLSGet := func(path string) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, "https://"+addr+path, nil)
		if err != nil {
			return nil, err
		}
		req.Host = "safe.local"
		return client.Do(req)
	}

	// 1. Valid request succeeds with zero Server header
	resp, err := doTLSGet("/hello")
	if err != nil {
		t.Fatalf("valid HTTPS request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok-upstream" {
		t.Fatalf("unexpected response: status=%d body=%q", resp.StatusCode, string(body))
	}
	if srvHdr := resp.Header.Get("Server"); srvHdr != "" {
		t.Fatalf("expected empty Server header, got %q", srvHdr)
	}

	// 2. Unrecognized SNI dropped silently before TLS cert is sent
	badSNIConn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "attacker.invalid",
	})
	if err == nil {
		_ = badSNIConn.Close()
		t.Fatal("expected TLS handshake failure for unrecognized SNI")
	}

	// 3. Coraza Phase 1 drop aborts connection with zero HTTP response bytes
	p1Resp, err := doTLSGet("/drop-phase1")
	if err == nil {
		_ = p1Resp.Body.Close()
		t.Fatalf("expected Phase 1 drop to abort connection, got status %d", p1Resp.StatusCode)
	}

	// 4. Coraza Phase 3 drop aborts connection with zero HTTP response bytes
	p3Resp, err := doTLSGet("/drop-phase3")
	if err == nil {
		_ = p3Resp.Body.Close()
		t.Fatalf("expected Phase 3 drop to abort connection, got status %d", p3Resp.StatusCode)
	}

	// 5. Verify JSON audit log lines were written for both dropped transactions
	time.Sleep(100 * time.Millisecond)
	auditData, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(auditData)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 audit log JSON lines, got %d (%q)", len(lines), string(auditData))
	}
	for i, ln := range lines {
		var parsed map[string]any
		if uerr := json.Unmarshal([]byte(ln), &parsed); uerr != nil {
			t.Fatalf("audit line %d is not valid JSON: %v (%s)", i, uerr, ln)
		}
	}

	// 6. Stop Caddy and verify audit log file handle is closed cleanly (no FD leak; Windows Remove succeeds)
	if err := caddy.Stop(); err != nil {
		t.Fatalf("caddy.Stop: %v", err)
	}
	if err := os.Remove(auditPath); err != nil {
		t.Fatalf("expected audit log FD to be closed after caddy.Stop, Remove failed: %v", err)
	}
}

func TestCaddyCore_MgmtAutomateInternalTLS_And_TrustedProxiesRealIP(t *testing.T) {
	tmpDir := t.TempDir()
	storageDir := filepath.Join(tmpDir, "caddy-data")
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		t.Fatalf("MkdirAll storageDir: %v", err)
	}
	certPath, keyPath := writeSelfSignedCert(t, tmpDir, "proxy.local")

	var gotRealIP, gotXFF string
	appBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRealIP = r.Header.Get("X-Real-Ip")
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxy-ok"))
	}))
	defer appBackend.Close()
	appUpstream := strings.TrimPrefix(appBackend.URL, "http://")

	mgmtBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("mgmt-ok"))
	}))
	defer mgmtBackend.Close()
	mgmtUpstream := strings.TrimPrefix(mgmtBackend.URL, "http://")

	mgmtPort := freeTCPPort(t)
	httpsPort := freeTCPPort(t)
	adminPort := freeTCPPort(t)

	cfgJSON := fmt.Sprintf(`{
  "admin": { "listen": "127.0.0.1:%d" },
  "storage": { "module": "file_system", "root": %q },
  "apps": {
    "pki": {
      "certificate_authorities": {
        "local": { "install_trust": false }
      }
    },
    "http": {
      "servers": {
        "srv_mgmt": {
          "listen": ["127.0.0.1:%d"],
          "automatic_https": { "disable": true },
          "tls_connection_policies": [{ "default_sni": "127.0.0.1" }],
          "routes": [{
            "match": [{ "remote_ip": { "ranges": ["127.0.0.1/32", "::1/128"] } }],
            "handle": [{
              "handler": "reverse_proxy",
              "upstreams": [{ "dial": %q }]
            }]
          }]
        },
        "srv_https": {
          "listen": ["127.0.0.1:%d"],
          "automatic_https": { "disable": true },
          "trusted_proxies": {
            "source": "static",
            "ranges": ["127.0.0.1/32"]
          },
          "client_ip_headers": ["CF-Connecting-IP", "X-Forwarded-For"],
          "tls_connection_policies": [{ "default_sni": "proxy.local" }],
          "routes": [{
            "match": [{ "host": ["proxy.local"] }],
            "handle": [{
              "handler": "reverse_proxy",
              "upstreams": [{ "dial": %q }],
              "headers": {
                "request": {
                  "set": {
                    "X-Real-IP": ["{http.vars.client_ip}"]
                  }
                }
              }
            }]
          }]
        }
      }
    },
    "tls": {
      "certificates": {
        "load_files": [{ "certificate": %q, "key": %q }],
        "automate": ["127.0.0.1", "mgmt.local"]
      },
      "automation": {
        "policies": [{
          "subjects": ["127.0.0.1", "mgmt.local"],
          "issuers": [{ "module": "internal" }]
        }]
      }
    }
  }
}`, adminPort, storageDir, mgmtPort, mgmtUpstream, httpsPort, appUpstream, certPath, keyPath)

	if err := caddy.Load([]byte(cfgJSON), true); err != nil {
		t.Fatalf("caddy.Load failed: %v", err)
	}
	defer func() { _ = caddy.Stop() }()

	// 1. Verify srv_mgmt serves internal TLS without explicit SNI (using default_sni=127.0.0.1 + tls.certificates.automate).
	// Cert issuance for tls.certificates.automate completes asynchronously just after caddy.Load returns.
	mgmtClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	var mgmtResp *http.Response
	var err error
	deadline := time.Now().Add(6 * time.Second)
	for {
		mgmtResp, err = mgmtClient.Get(fmt.Sprintf("https://127.0.0.1:%d/", mgmtPort))
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("srv_mgmt TLS request failed (automate/internal TLS check): %v", err)
	}
	mgmtBody, _ := io.ReadAll(mgmtResp.Body)
	_ = mgmtResp.Body.Close()
	if mgmtResp.StatusCode != http.StatusOK || string(mgmtBody) != "mgmt-ok" {
		t.Fatalf("unexpected srv_mgmt response: status=%d body=%q", mgmtResp.StatusCode, string(mgmtBody))
	}

	// 2. Verify trusted_proxies + CF-Connecting-IP sets {http.vars.client_ip} -> X-Real-IP and preserves XFF
	proxyClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "proxy.local",
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/whoami", httpsPort), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = "proxy.local"
	req.Header.Set("CF-Connecting-IP", "198.51.100.42")
	req.Header.Set("X-Forwarded-For", "198.51.100.42")
	resp, err := proxyClient.Do(req)
	if err != nil {
		t.Fatalf("srv_https proxy request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from srv_https, got %d", resp.StatusCode)
	}
	if gotRealIP != "198.51.100.42" {
		t.Fatalf("expected X-Real-Ip=198.51.100.42 from {http.vars.client_ip}, got %q", gotRealIP)
	}
	if !strings.Contains(gotXFF, "198.51.100.42") {
		t.Fatalf("expected X-Forwarded-For to retain trusted CF-Connecting-IP 198.51.100.42, got %q", gotXFF)
	}
}

func TestCaddyCore_CRSv4_Presets_AuditStatus_And_SecLangEscaping(t *testing.T) {
	// 1. Verify Coraza SecLang quote/backslash parsing semantics directly
	testCases := []struct {
		name      string
		directive string
		wantErr   bool
	}{
		{"regex_dot_env", `SecRule REQUEST_URI "@rx \.env" "id:910001,phase:1,deny,status:403"`, false},
		{"escaped_quote", `SecRule ARGS "@contains foo\"bar" "id:910002,phase:2,deny,status:403"`, false},
		{"raw_trailing_backslash_breaks_quote", `SecRule ARGS "@contains foo\" "id:910003,phase:2,deny,status:403"`, true},
		{"doubled_trailing_backslash", `SecRule ARGS "@contains foo\\" "id:910004,phase:2,deny,status:403"`, false},
		{"even_backslash_before_quote_breaks", `SecRule ARGS "@contains foo\\"bar" "id:910006,phase:2,deny,status:403"`, true},
		{"quoted_backslash_literal_then_quote", `SecRule ARGS "@contains foo\\\"bar" "id:910005,phase:2,deny,status:403"`, false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On\n" + tc.directive))
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %s (%s), got nil", tc.name, tc.directive)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %s (%s): %v", tc.name, tc.directive, err)
			}
		})
	}

	// 2. Load real Coraza + CRS v4 with wordpress/api/nas presets in Caddy and inspect 403 vs drop audit logs
	tmpDir := t.TempDir()
	auditPath := filepath.ToSlash(filepath.Join(tmpDir, "waf-audit.log"))

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()
	upstream := strings.TrimPrefix(backend.URL, "http://")

	port := freeTCPPort(t)
	adminPort := freeTCPPort(t)

	directives := fmt.Sprintf(`Include @coraza.conf-recommended
SecRuleEngine On
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus ^$
SecAuditLogParts ABIJDEFHKZ
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLog %s
SecAction "id:900099,phase:1,pass,t:none,nolog,setvar:tx.crs_setup_version=4250"
SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4,setvar:tx.blocking_paranoia_level=1"
SecAction "id:900201,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE',ctl:ruleRemoveTargetById=941100;ARGS:content,ctl:ruleRemoveTargetById=941160;ARGS:content"
SecAction "id:900202,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=GET HEAD POST PUT PATCH DELETE OPTIONS',setvar:'tx.allowed_request_content_type=|application/json|application/x-www-form-urlencoded|multipart/form-data|text/plain|'"
SecAction "id:900203,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=GET HEAD POST PUT DELETE OPTIONS PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK'"
SecRule REQUEST_URI "@beginsWith /remote.php/dav/" "id:900204,phase:1,pass,nolog,ctl:ruleRemoveById=920350,ctl:ruleRemoveById=932100-932299"
Include @owasp_crs/*.conf
SecRule REQUEST_URI "@beginsWith /force-drop" "id:990001,phase:1,drop,log,auditlog,msg:'vSafeGate Drop Test'"
SecRule REQUEST_URI "@rx \.env" "id:990002,phase:1,deny,status:403,log,auditlog,msg:'vSafeGate 403 Test'"`, auditPath)

	cfg := map[string]any{
		"admin": map[string]any{"listen": fmt.Sprintf("127.0.0.1:%d", adminPort)},
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"srv_http": map[string]any{
						"listen": []string{fmt.Sprintf("127.0.0.1:%d", port)},
						"routes": []any{
							map[string]any{
								"handle": []any{
									map[string]any{
										"handler":        "waf",
										"load_owasp_crs": true,
										"directives":     directives,
									},
									map[string]any{
										"handler":   "reverse_proxy",
										"upstreams": []any{map[string]any{"dial": upstream}},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	rawCfg, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal cfg: %v", err)
	}
	if err := caddy.Load(rawCfg, true); err != nil {
		t.Fatalf("caddy.Load with CRS v4 + presets failed: %v", err)
	}
	t.Cleanup(func() {
		_ = caddy.Stop()
	})

	client := &http.Client{Timeout: 5 * time.Second}
	respOK, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/ok", port))
	if err != nil {
		t.Fatalf("GET /ok failed: %v", err)
	}
	_ = respOK.Body.Close()
	if respOK.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /ok, got %d", respOK.StatusCode)
	}

	resp403, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/.env", port))
	if err != nil {
		t.Fatalf("GET /.env failed: %v", err)
	}
	_ = resp403.Body.Close()
	if resp403.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on /.env, got %d", resp403.StatusCode)
	}

	respDrop, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/force-drop", port))
	if err == nil {
		_ = respDrop.Body.Close()
		t.Fatalf("expected drop connection abort on /force-drop, got status %d", respDrop.StatusCode)
	}

	time.Sleep(100 * time.Millisecond)
	auditBytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	t.Logf("audit log:\n%s", string(auditBytes))
	lines := strings.Split(strings.TrimSpace(string(auditBytes)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected 2 audit lines, got %d", len(lines))
	}
	sawDeny990002 := false
	sawDrop990001 := false
	for i, ln := range lines {
		var row struct {
			Transaction struct {
				IsInterrupted bool `json:"is_interrupted"`
			} `json:"transaction"`
			Messages []struct {
				ErrorMessage string `json:"error_message"`
				Data         *struct {
					ID int `json:"id"`
				} `json:"data"`
			} `json:"messages"`
		}
		if err := json.Unmarshal([]byte(ln), &row); err != nil {
			t.Fatalf("invalid audit JSON line %d: %v", i, err)
		}
		if !row.Transaction.IsInterrupted {
			t.Fatalf("expected audit line %d to be interrupted", i)
		}
		for _, m := range row.Messages {
			if m.Data == nil || m.Data.ID == 0 {
				t.Fatalf("expected part K Data.ID populated in audit line %d (%s)", i, ln)
			}
			if m.Data.ID == 990002 && strings.Contains(m.ErrorMessage, "Access denied") {
				sawDeny990002 = true
			}
			if m.Data.ID == 990001 && strings.Contains(m.ErrorMessage, "Access dropped") {
				sawDrop990001 = true
			}
		}
	}
	if !sawDeny990002 || !sawDrop990001 {
		t.Fatalf("expected both deny 990002 (%v) and drop 990001 (%v) in audit log", sawDeny990002, sawDrop990001)
	}
}

func TestCaddyCore_ShieldBeforeCorazaPipeline_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, tmpDir, "shield.local")

	var upstreamHits int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("shield-upstream-ok"))
	}))
	defer backend.Close()
	upstreamAddr := strings.TrimPrefix(backend.URL, "http://")

	port := freeTCPPort(t)
	adminPort := freeTCPPort(t)

	cfg := map[string]any{
		"admin": map[string]any{"listen": fmt.Sprintf("127.0.0.1:%d", adminPort)},
		"apps": map[string]any{
			"tls": map[string]any{
				"certificates": map[string]any{
					"load_files": []map[string]any{
						{"certificate": filepath.ToSlash(certPath), "key": filepath.ToSlash(keyPath), "format": "pem"},
					},
				},
			},
			"http": map[string]any{
				"servers": map[string]any{
					"srv0": map[string]any{
						"listen":          []string{fmt.Sprintf("127.0.0.1:%d", port)},
						"automatic_https": map[string]any{"disable": true},
						"listener_wrappers": []map[string]any{
							{
								"wrapper":          "vsafegate_pre_tls",
								"allowed_snis":     []string{"shield.local"},
								"drop_missing_sni": true,
								"drop_unknown_sni": true,
							},
							{"wrapper": "tls"},
						},
						"tls_connection_policies": []map[string]any{
							{"match": map[string]any{"sni": []string{"shield.local"}}},
						},
						"routes": []map[string]any{
							{
								"match": []map[string]any{{"host": []string{"shield.local"}}},
								"handle": []map[string]any{
									{
										"handler":           "vsafegate_shield",
										"mode":              "under_attack",
										"under_attack_mode": true,
										"site_id":           "site-shield-int",
										"api_paths":         []string{"/api/"},
									},
									{
										"handler":    "waf",
										"directives": "SecRuleEngine On\nSecRule REQUEST_URI \"@contains /sqli\" \"id:991001,phase:1,deny,status:403\"",
									},
									{
										"handler":   "reverse_proxy",
										"upstreams": []map[string]any{{"dial": upstreamAddr}},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := caddy.Load(raw, true); err != nil {
		t.Fatalf("caddy.Load with vsafegate_shield before waf failed: %v", err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "shield.local",
			},
		},
	}

	// 1. HTML path in under_attack_mode is challenged by Shield (429) BEFORE hitting Coraza or upstream
	reqChallenge, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/sqli", port), nil)
	reqChallenge.Host = "shield.local"
	reqChallenge.Header.Set("User-Agent", "Mozilla/5.0 Chrome/130.0.0.0")
	reqChallenge.Header.Set("Accept", "text/html")
	reqChallenge.Header.Set("Accept-Language", "en-US")
	respCh, err := client.Do(reqChallenge)
	if err != nil {
		t.Fatalf("GET /sqli failed: %v", err)
	}
	chBody, _ := io.ReadAll(respCh.Body)
	_ = respCh.Body.Close()
	if respCh.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected Shield (429) to intercept BEFORE Coraza (403) on /sqli in under_attack mode, got %d", respCh.StatusCode)
	}
	if strings.Contains(strings.ToLower(string(chBody)), "caddy") || respCh.Header.Get("Server") != "" {
		t.Fatalf("expected zero branding and empty Server header")
	}

	// 2. API path bypasses HTML PoW and reaches Coraza/upstream cleanly
	reqAPI, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/api/ping", port), nil)
	reqAPI.Host = "shield.local"
	reqAPI.Header.Set("User-Agent", "curl/8.0")
	respAPI, err := client.Do(reqAPI)
	if err != nil {
		t.Fatalf("GET /api/ping failed: %v", err)
	}
	apiBody, _ := io.ReadAll(respAPI.Body)
	_ = respAPI.Body.Close()
	if respAPI.StatusCode != http.StatusOK || string(apiBody) != "shield-upstream-ok" {
		t.Fatalf("expected 200 OK from upstream via /api/ping, got %d (%q)", respAPI.StatusCode, string(apiBody))
	}
	if upstreamHits != 1 {
		t.Fatalf("expected 1 upstream hit, got %d", upstreamHits)
	}
}

func writeCAAndSignedLeaf(t *testing.T, dir, caCN, leafDNS string) (caPEMPath string, leafCert tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey CA: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: caCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caPEMPath = filepath.Join(dir, caCN+".pem")
	if err := os.WriteFile(caPEMPath, caPEM, 0600); err != nil {
		t.Fatalf("WriteFile CA: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey leaf: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: leafDNS},
		DNSNames:     []string{leafDNS},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate leaf: %v", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	leafCert, err = tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return caPEMPath, leafCert
}

func TestCaddyCore_Phase2And3_CustomOriginCA_LB_HealthCheck_ShieldSocketEvents(t *testing.T) {
	tmpDir := t.TempDir()
	edgeCertPath, edgeKeyPath := writeSelfSignedCert(t, tmpDir, "*.edge.local")

	// Create two independent Origin CAs: trustedCA for good backends, untrustedCA for bad route
	trustedCAPath, goodLeaf := writeCAAndSignedLeaf(t, tmpDir, "trusted-origin-ca", "origin.internal")
	_, rogueLeaf := writeCAAndSignedLeaf(t, tmpDir, "rogue-origin-ca", "origin.internal")

	var hitsB1, hitsB2, hcHits atomic.Int64
	makeTLSUpstream := func(name string, cert tls.Certificate, counter *atomic.Int64) *httptest.Server {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				hcHits.Add(1)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
				return
			}
			counter.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("origin-" + name + "-" + strings.Repeat("payload-", 64)))
		}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		srv.StartTLS()
		return srv
	}

	up1 := makeTLSUpstream("u1", goodLeaf, &hitsB1)
	defer up1.Close()
	up2 := makeTLSUpstream("u2", goodLeaf, &hitsB2)
	defer up2.Close()
	rogueUp := makeTLSUpstream("rogue", rogueLeaf, &hitsB1)
	defer rogueUp.Close()

	// Short AF_UNIX directory (<108 bytes on Windows/Linux)
	sockDir, err := os.MkdirTemp("", "sh*")
	if err != nil {
		t.Fatalf("MkdirTemp sockDir: %v", err)
	}
	defer os.RemoveAll(sockDir)
	sockPath := filepath.Join(sockDir, "e.sock")
	sockLn, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen unix %s: %v", sockPath, err)
	}
	defer sockLn.Close()

	eventsCh := make(chan map[string]any, 64)
	go func() {
		for {
			c, err := sockLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				sc := bufio.NewScanner(conn)
				for sc.Scan() {
					var ev map[string]any
					if json.Unmarshal(sc.Bytes(), &ev) == nil {
						select {
						case eventsCh <- ev:
						default:
						}
					}
				}
			}(c)
		}
	}()

	port := freeTCPPort(t)
	adminPort := freeTCPPort(t)

	cfg := map[string]any{
		"admin": map[string]any{"listen": fmt.Sprintf("127.0.0.1:%d", adminPort)},
		"apps": map[string]any{
			"tls": map[string]any{
				"certificates": map[string]any{
					"load_files": []map[string]any{
						{"certificate": filepath.ToSlash(edgeCertPath), "key": filepath.ToSlash(edgeKeyPath), "format": "pem"},
					},
				},
			},
			"http": map[string]any{
				"servers": map[string]any{
					"srv0": map[string]any{
						"listen":          []string{fmt.Sprintf("127.0.0.1:%d", port)},
						"automatic_https": map[string]any{"disable": true},
						"tls_connection_policies": []map[string]any{
							{"match": map[string]any{"sni": []string{"lb.edge.local", "badca.edge.local"}}},
							{},
						},
						"routes": []map[string]any{
							{
								"match": []map[string]any{{"host": []string{"lb.edge.local"}}},
								"handle": []map[string]any{
									{
										"handler":            "vsafegate_shield",
										"mode":               "normal",
										"site_id":            "site-lb-tls",
										"events_socket_path": filepath.ToSlash(sockPath),
										"rate_limit_rps":     5,
										"rate_limit_burst":   5,
										"anomaly_score_drop": 100,
										"api_paths":          []string{"/api/"},
									},
									{
										"handler": "encode",
										"encodings": map[string]any{
											"zstd": map[string]any{},
											"gzip": map[string]any{},
										},
										"prefer": []string{"zstd", "gzip"},
									},
									{
										"handler": "reverse_proxy",
										"upstreams": []map[string]any{
											{"dial": strings.TrimPrefix(up1.URL, "https://")},
											{"dial": strings.TrimPrefix(up2.URL, "https://")},
										},
										"load_balancing": map[string]any{
											"selection_policy": map[string]any{"policy": "least_conn"},
										},
										"health_checks": map[string]any{
											"active": map[string]any{
												"uri":      "/healthz",
												"interval": "100ms",
												"timeout":  "2s",
											},
											"passive": map[string]any{
												"fail_duration": "10s",
												"max_fails":     2,
											},
										},
										"transport": map[string]any{
											"protocol": "http",
											"tls": map[string]any{
												"server_name": "origin.internal",
												"ca": map[string]any{
													"provider":  "file",
													"pem_files": []string{filepath.ToSlash(trustedCAPath)},
												},
											},
										},
									},
								},
							},
							{
								"match": []map[string]any{{"host": []string{"badca.edge.local"}}},
								"handle": []map[string]any{
									{
										"handler": "reverse_proxy",
										"upstreams": []map[string]any{
											{"dial": strings.TrimPrefix(rogueUp.URL, "https://")},
										},
										"transport": map[string]any{
											"protocol": "http",
											"tls": map[string]any{
												"server_name": "origin.internal",
												"ca": map[string]any{
													"provider":  "file",
													"pem_files": []string{filepath.ToSlash(trustedCAPath)},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := caddy.Load(raw, true); err != nil {
		t.Fatalf("caddy.Load Phase 2/3 config failed: %v", err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableCompression: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, p, _ := net.SplitHostPort(addr)
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", p))
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// 1. Custom Origin CA route succeeds + compresses response when Accept-Encoding: gzip is sent
	reqGood, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://lb.edge.local:%d/api/data", port), nil)
	reqGood.Header.Set("Accept-Encoding", "gzip")
	reqGood.Header.Set("User-Agent", "Mozilla/5.0 Chrome/130.0.0.0")
	respGood, err := client.Do(reqGood)
	if err != nil {
		t.Fatalf("GET lb.edge.local failed: %v", err)
	}
	_ = respGood.Body.Close()
	if respGood.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK through custom Origin CA + LB, got %d", respGood.StatusCode)
	}
	if respGood.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected gzip encoding from encode handler, got %q", respGood.Header.Get("Content-Encoding"))
	}

	// 2. Rogue CA upstream is rejected by custom CA verification (502 Bad Gateway)
	reqBadCA, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://badca.edge.local:%d/", port), nil)
	respBadCA, err := client.Do(reqBadCA)
	if err != nil {
		t.Fatalf("GET badca.edge.local failed: %v", err)
	}
	_ = respBadCA.Body.Close()
	if respBadCA.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway when upstream presents untrusted CA cert, got %d", respBadCA.StatusCode)
	}

	// 3. Trigger hard flood past 2x burst (10 reqs on /api/) so Shield emits a ban event over Unix socket
	for i := 0; i < 16; i++ {
		r, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://lb.edge.local:%d/api/flood?i=%d", port, i), nil)
		r.Header.Set("User-Agent", "curl/8.0")
		resp, err := client.Do(r)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			// Expected ErrAbortHandler / EOF once hard-banned
			break
		}
	}

	// Verify active health check actually ran and Unix socket received at least one ban/stats event
	deadline := time.After(5 * time.Second)
	sawBanEvent := false
	for !sawBanEvent {
		select {
		case ev := <-eventsCh:
			if ev["type"] == "ban" && ev["site_id"] == "site-lb-tls" {
				sawBanEvent = true
			}
		case <-deadline:
			t.Fatalf("timed out waiting for Shield ban event on Unix socket %s (hcHits=%d)", sockPath, hcHits.Load())
		}
	}
	if hcHits.Load() == 0 {
		t.Fatalf("expected active health checks to probe upstreams at least once")
	}
}
