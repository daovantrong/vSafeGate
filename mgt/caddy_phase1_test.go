package main

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCaddyPhase1_CorazaCRSv4OrderAndTuning(t *testing.T) {
	cfg := Config{
		BannedIPs: []BannedIPEntry{
			{IP: "203.0.113.50", Reason: "Scanner"},
			{IP: "198.51.100.10", Reason: "Bot"},
		},
		Rules: []CustomRule{
			{
				ID:       "r-enabled",
				RuleID:   1005,
				Name:     "Block Admin Drop",
				Target:   "REQUEST_URI",
				Operator: "beginsWith",
				Pattern:  "/secret",
				Action:   "drop",
				Enabled:  true,
			},
			{
				ID:       "r-disabled",
				RuleID:   1006,
				Name:     "Disabled Rule Must Omit",
				Target:   "REQUEST_URI",
				Operator: "beginsWith",
				Pattern:  "/should-not-exist",
				Action:   "deny",
				Enabled:  false,
			},
		},
	}

	site := &Site{
		ID:                       "site-wp",
		Domain:                   "blog.example.com",
		Upstream:                 "http://10.0.0.10:8080",
		SSL:                      true,
		WAF:                      true,
		WAFMode:                  "detection",
		ParanoiaLevel:            3,
		InboundAnomalyThreshold:  12,
		OutboundAnomalyThreshold: 9,
		RequestBodyMaxMB:         999, // clamped to 500
		AppPreset:                "wordpress",
		Exclusions: []WAFExclusion{
			{ID: "ex-uri", RuleID: 942100, MatchURI: "/wp-admin/admin-ajax.php", Comment: "AJAX", Enabled: true},
			{ID: "ex-global", RuleID: 941130, Comment: "Global FP", Enabled: true},
			{ID: "ex-disabled", RuleID: 999999, Comment: "Off", Enabled: false},
		},
	}

	out := buildSiteCorazaRuleset(cfg, site, "/var/log/vsafegate/waf-audit.jsonl")

	// Verify exact CRS v4 directive ordering
	markers := []string{
		"Include @coraza.conf-recommended",
		"SecRuleEngine DetectionOnly",
		`SecRequestBodyLimit 524288000`,
		`SecAction "id:900099,phase:1,pass,t:none,nolog,setvar:tx.crs_setup_version=4250"`,
		`setvar:tx.blocking_paranoia_level=3,setvar:tx.detection_paranoia_level=3,setvar:tx.inbound_anomaly_score_threshold=12,setvar:tx.outbound_anomaly_score_threshold=9`,
		`SecRule REMOTE_ADDR "@ipMatch `,
		`SecRule REQUEST_URI "@rx ^/\.well-known/acme-challenge/[A-Za-z0-9_-]{1,128}$" "id:900,phase:1,allow,nolog"`,
		`# AppPreset: wordpress`,
		`REQUEST_URI "@beginsWith /wp-admin/admin-ajax.php" "id:900300,phase:1,pass,nolog,ctl:ruleRemoveById=942100"`,
		"Include @owasp_crs/*.conf",
		"SecRuleRemoveById 941130",
		"SecRule REQUEST_URI \"@beginsWith /secret\" \\\n    \"id:1005,phase:1,drop,auditlog,msg:'[vSafeGate] Block Admin Drop'\"",
	}

	prevIdx := -1
	for _, m := range markers {
		idx := strings.Index(out, m)
		if idx < 0 {
			t.Fatalf("missing expected directive %q in:\n%s", m, out)
		}
		if idx <= prevIdx {
			t.Fatalf("directive out of order: %q at %d <= previous %d", m, idx, prevIdx)
		}
		prevIdx = idx
	}

	if strings.Contains(out, "/should-not-exist") {
		t.Fatal("disabled custom rule must not be emitted in Coraza ruleset")
	}
	if strings.Contains(out, "999999") {
		t.Fatal("disabled exclusion must not be emitted")
	}
	if !strings.Contains(out, "198.51.100.10") || !strings.Contains(out, "203.0.113.50") {
		t.Fatal("rule 999 blacklist must include BannedIPs")
	}
	legacyOut := buildSiteCorazaRuleset(Config{BlacklistIP: []string{"192.0.2.99"}}, nil, "/var/log/vsafegate/waf-audit.jsonl")
	if !strings.Contains(legacyOut, "192.0.2.99") {
		t.Fatal("expected legacy BlacklistIP fallback in rule 999 when BannedIPs empty")
	}
}

func TestCaddyPhase1_BuildCaddyJSON_HTTPFallback_TrustedProxies_MgmtIsolation(t *testing.T) {
	cfg := Config{
		MgmtDomain:       "mgmt.example.com",
		MgmtHTTPSPort:    4438,
		MgmtHTTPPort:     808,
		MgmtListenIPs:    []string{"192.168.10.2", "127.0.0.1"},
		MgmtAllowedCIDRs: []string{"127.0.0.1/32", "192.168.10.0/24", "0.0.0.0/0"}, // 0.0.0.0/0 must be filtered? Note buildTrustedProxyCIDRs filters 0.0.0.0/0!
		TrustedProxies:   []string{"10.10.0.1/32", "0.0.0.0/0", "::/0"},
		Cloudflare: CloudflareConfig{
			APIToken:   "cf-test-token",
			CachedIPv4: []string{"173.245.48.0/20"},
			CachedIPv6: []string{"2400:cb00::/32"},
		},
		Sites: []Site{
			{
				ID:        "s-http",
				Domain:    "plain.example.com",
				Upstream:  "http://10.0.0.5:8080",
				Upstreams: []string{"http://10.0.0.5:8080", "http://10.0.0.6:8080"},
				SSL:       false,
				WAF:       false,
			},
			{
				ID:             "s-dns01",
				Domain:         "*.wild.example.com",
				Upstream:       "http://10.0.0.7:8443",
				SSL:            true,
				CertMode:       "cloudflare_dns01",
				HideAltSvc:     true,
				WAF:            true,
				TrustedProxies: []string{"192.168.99.1/32"},
			},
			{
				ID:             "s-uploaded",
				Domain:         "origin.example.com",
				Upstream:       "https://10.0.0.8:443",
				SSL:            true,
				CertMode:       "uploaded",
				CustomCertPath: "/etc/vsafegate/certs/s-uploaded.crt",
				CustomKeyPath:  "/etc/vsafegate/certs/s-uploaded.key",
				WAF:            true,
			},
		},
	}

	raw := buildCaddyJSONConfig(cfg, "/etc/vsafegate/rules.d", "/var/log/vsafegate/waf-audit.jsonl", "/var/log/vsafegate/access.jsonl",
		map[string]string{
			"s-dns01":    "/etc/vsafegate/rules.d/site_s-dns01.conf",
			"s-uploaded": "/etc/vsafegate/rules.d/site_s-uploaded.conf",
		},
		nil,
	)

	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	jsonStr := string(data)

	// 1. Check Site.SSL == false lives in srv_http WITHOUT redirect, and NOT in srv_https
	apps := raw["apps"].(map[string]any)
	httpApp := apps["http"].(map[string]any)
	servers := httpApp["servers"].(map[string]any)

	srvHTTPS := servers["srv_https"].(map[string]any)
	srvHTTP := servers["srv_http"].(map[string]any)
	srvMgmt := servers["srv_mgmt"].(map[string]any)

	httpsRoutes := srvHTTPS["routes"].([]map[string]any)
	httpRoutes := srvHTTP["routes"].([]map[string]any)

	// plain.example.com should be handled directly in srv_http (reverse_proxy) and NOT in srv_https
	foundPlainInHTTPProxy := false
	for _, rt := range httpRoutes {
		if b, _ := json.Marshal(rt); strings.Contains(string(b), "plain.example.com") {
			if strings.Contains(string(b), "reverse_proxy") && !strings.Contains(string(b), "301") {
				foundPlainInHTTPProxy = true
			}
		}
	}
	if !foundPlainInHTTPProxy {
		t.Fatal("expected Site.SSL=false domain plain.example.com to run reverse_proxy directly on srv_http")
	}
	for _, rt := range httpsRoutes {
		if b, _ := json.Marshal(rt); strings.Contains(string(b), "plain.example.com") {
			t.Fatal("Site.SSL=false domain must not be in srv_https")
		}
	}

	// 2. Check catch-all abort on both srv_https and srv_http (no legacy fake 200 banner)
	lastHTTPS, _ := json.Marshal(httpsRoutes[len(httpsRoutes)-1])
	lastHTTP, _ := json.Marshal(httpRoutes[len(httpRoutes)-1])
	if !strings.Contains(string(lastHTTPS), `"abort":true`) || !strings.Contains(string(lastHTTP), `"abort":true`) {
		t.Fatalf("expected catch-all abort on srv_https and srv_http, got https=%s http=%s", lastHTTPS, lastHTTP)
	}

	// 3. Check handle_errors close on srv_https/srv_http and Slowloris timeouts
	if !strings.Contains(jsonStr, `"read_header_timeout":"5s"`) || !strings.Contains(jsonStr, `"errors":{"routes":[{"handle":[{"close":true`) {
		t.Fatal("expected Slowloris read_header_timeout and errors.routes close in server JSON")
	}

	// 4. Check trusted_proxies rejected 0.0.0.0/0 & ::/0, kept real CIDRs, and X-Real-IP uses {http.vars.client_ip}
	tp := srvHTTPS["trusted_proxies"].(map[string]any)
	ranges := tp["ranges"].([]string)
	for _, r := range ranges {
		if r == "0.0.0.0/0" || r == "::/0" {
			t.Fatalf("trusted_proxies must NEVER include catch-all CIDR %q", r)
		}
	}
	if !strings.Contains(jsonStr, `"X-Real-IP":["{http.vars.client_ip}"]`) {
		t.Fatal("expected reverse_proxy to forward X-Real-IP: {http.vars.client_ip}")
	}
	if strings.Contains(jsonStr, `"X-Forwarded-For":["{http.request.remote.host}"]`) {
		t.Fatal("reverse_proxy must NOT manually overwrite X-Forwarded-For with remote.host")
	}

	// 5. Check HideAltSvc disables h3 ALPN and deletes Alt-Svc header
	if !strings.Contains(jsonStr, `"Alt-Svc"`) || !strings.Contains(jsonStr, `"protocols":["h1","h2"]`) {
		t.Fatal("expected HideAltSvc to remove Alt-Svc header and limit srv_https protocols to h1/h2")
	}

	// 6. Check load_files + cloudflare_dns01 + srv_mgmt isolation + automate internal TLS
	if !strings.Contains(jsonStr, `"certificate":"/etc/vsafegate/certs/s-uploaded.crt"`) {
		t.Fatal("expected uploaded custom cert in tls.certificates.load_files")
	}
	if !strings.Contains(jsonStr, `"provider":{"api_token":"cf-test-token","name":"cloudflare"}`) {
		t.Fatal("expected cloudflare DNS-01 challenge issuer when APIToken is set")
	}

	mgmtListen := srvMgmt["listen"].([]string)
	if len(mgmtListen) != 2 || mgmtListen[0] != "127.0.0.1:4438" || mgmtListen[1] != "192.168.10.2:4438" {
		t.Fatalf("unexpected srv_mgmt listen addresses (must deduplicate 127.0.0.1 and bind explicitly): %v", mgmtListen)
	}
	for _, addr := range mgmtListen {
		if strings.HasPrefix(addr, ":") {
			t.Fatalf("srv_mgmt must never bind wildcard %q", addr)
		}
	}

	tlsApp := apps["tls"].(map[string]any)
	certsCfg := tlsApp["certificates"].(map[string]any)
	automate, ok := certsCfg["automate"].([]string)
	if !ok || len(automate) == 0 {
		t.Fatal("expected tls.certificates.automate to list srv_mgmt internal subjects (fixes Caddy automatic_https.disable)")
	}
	if !strings.Contains(jsonStr, `"default_sni":"127.0.0.1"`) {
		t.Fatal("expected srv_mgmt tls_connection_policies default_sni=127.0.0.1")
	}
	if !strings.Contains(jsonStr, `"install_trust":false`) {
		t.Fatal("expected pki local CA install_trust=false to prevent headless/Windows trust-store hangs")
	}
}

func TestCaddyPhase1_SecLangSanitization_WordPressQuotes_And_AutomateDedupe(t *testing.T) {
	// 1. Verify SecLang escaping preserves regex backslashes while neutralizing quotes & odd trailing backslashes
	if got := sanitizeRulePattern(`\.env`); got != `\.env` {
		t.Fatalf("expected \\.env preserved, got %q", got)
	}
	if got := sanitizeRulePattern(`foo\`); got != `foo\\` {
		t.Fatalf("expected trailing backslash doubled to foo\\\\, got %q", got)
	}
	if got := sanitizeRulePattern(`foo"bar`); got != `foo\"bar` {
		t.Fatalf("expected quote escaped to foo\\\"bar, got %q", got)
	}
	if got := sanitizeRulePattern(`foo\"bar`); got != `foo\\\"bar` {
		t.Fatalf("expected backslash+quote escaped to foo\\\\\\\"bar, got %q", got)
	}
	if got := sanitizeRuleMessage(`msg'x\`); got != `msg\'x\\` {
		t.Fatalf("expected message single-quote and trailing backslash escaped, got %q", got)
	}

	// 2. Verify wordpress preset quotes tx.allowed_methods, SecAuditLogParts includes K before Z,
	//    RemoveArgs strips injection characters, and automate excludes ACME-claimed MgmtDomain.
	site := Site{
		ID:        "s-wp",
		Domain:    "panel.example.com",
		Upstream:  "10.0.0.5:8080",
		SSL:       true,
		CertMode:  "auto_http",
		WAF:       true,
		WAFMode:   "on",
		AppPreset: "wordpress",
		Exclusions: []WAFExclusion{
			{
				ID:         "ex1",
				RuleID:     941100,
				MatchURI:   `/submit\`,
				RemoveArgs: []string{`ARGS:bio,deny,status:200`, `ARGS:note;"'`},
				Enabled:    true,
			},
		},
	}
	cfg := Config{
		MgmtDomain:    "panel.example.com",
		MgmtHTTPSPort: 4438,
		Sites:         []Site{site},
	}

	rules := buildSiteCorazaRuleset(cfg, &site, "/var/log/caddy/audit.log")
	if !strings.Contains(rules, "SecAuditLogParts ABIJDEFHKZ") {
		t.Fatal("expected SecAuditLogParts ABIJDEFHKZ (including K for JSON RulesMatched metadata)")
	}
	if !strings.Contains(rules, `setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'`) {
		t.Fatal("expected wordpress SecAction to single-quote tx.allowed_methods")
	}
	if !strings.Contains(rules, `@beginsWith /submit\\`) {
		t.Fatalf("expected exclusion MatchURI trailing backslash escaped safely, got:\n%s", rules)
	}
	if strings.Contains(rules, "ARGS:bio,deny") || strings.Contains(rules, `;ARGS:note;"`) {
		t.Fatalf("expected RemoveArgs commas/quotes/semicolons stripped, got:\n%s", rules)
	}

	raw := buildCaddyJSONConfig(cfg, "/etc/vsafegate/rules.d", "/var/log/vsafegate/waf-audit.jsonl", "/var/log/vsafegate/access.jsonl",
		map[string]string{"s-wp": "/etc/vsafegate/rules.d/site_s-wp.conf"},
		nil,
	)
	tlsApp := raw["apps"].(map[string]any)["tls"].(map[string]any)
	automate := tlsApp["certificates"].(map[string]any)["automate"].([]string)
	for _, a := range automate {
		if a == "panel.example.com" {
			t.Fatalf("expected tls.certificates.automate to exclude ACME-claimed MgmtDomain, got %v", automate)
		}
	}
	foundLoopback := false
	for _, a := range automate {
		if a == "127.0.0.1" {
			foundLoopback = true
		}
	}
	if !foundLoopback {
		t.Fatalf("expected tls.certificates.automate to retain 127.0.0.1, got %v", automate)
	}
}

func TestCaddyPhase1Polish_MgmtListenPrivateFallback_StrictOriginPerSNI(t *testing.T) {
	// 1. Default private/RFC1918 + Tailscale/CGNAT IPv4 fallback excludes public WAN & link-local
	candidates := []netip.Addr{
		netip.MustParseAddr("203.0.113.50"),  // public WAN -> must NEVER bind mgmt panel
		netip.MustParseAddr("169.254.10.20"), // link-local -> skip
		netip.MustParseAddr("10.20.30.40"),   // RFC1918
		netip.MustParseAddr("192.168.50.10"), // RFC1918
		netip.MustParseAddr("100.101.102.3"), // Tailscale CGNAT
	}
	resolved := resolveMgmtListenIPs(nil, candidates)
	got := strings.Join(resolved, ",")
	if strings.Contains(got, "203.0.113.50") || strings.Contains(got, "169.254.10.20") {
		t.Fatalf("resolveMgmtListenIPs leaked non-private IP: %v", resolved)
	}
	for _, want := range []string{"127.0.0.1", "10.20.30.40", "192.168.50.10", "100.101.102.3"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %s in default mgmt listen IPs, got %v", want, resolved)
		}
	}

	// Explicit override must still win
	explicit := resolveMgmtListenIPs([]string{"192.168.99.5"}, candidates)
	if len(explicit) != 2 || explicit[0] != "127.0.0.1" || explicit[1] != "192.168.99.5" {
		t.Fatalf("expected explicit override [127.0.0.1 192.168.99.5], got %v", explicit)
	}

	// 2. Per-SNI strict_origin_snis isolation when mixing strict & non-strict SSL sites
	cfg := Config{
		MgmtHTTPSPort: 4438,
		MgmtHTTPPort:  8088,
		MgmtListenIPs: []string{"127.0.0.1"},
		Sites: []Site{
			{ID: "strict", Domain: "strict.example.com", Upstream: "10.0.0.1:8080", SSL: true, CertMode: "uploaded", CustomCertPath: "/c.crt", CustomKeyPath: "/c.key", StrictCloudflareOrigin: true},
			{ID: "open", Domain: "direct.example.com", Upstream: "10.0.0.2:8080", SSL: true, CertMode: "uploaded", CustomCertPath: "/d.crt", CustomKeyPath: "/d.key", StrictCloudflareOrigin: false},
		},
	}
	raw := buildCaddyJSONConfigWithOptions(cfg, "/rules", "/audit.log", "/access.log", map[string]string{}, map[string]string{}, "")
	jsonBytes, _ := json.Marshal(raw)
	jsonStr := string(jsonBytes)

	if !strings.Contains(jsonStr, `"strict_origin_snis":["strict.example.com"]`) {
		t.Fatalf("expected strict_origin_snis containing only strict.example.com, got:\n%s", jsonStr)
	}
	if strings.Contains(jsonStr, `"strict_origin_snis":["strict.example.com","direct.example.com"]`) ||
		strings.Contains(jsonStr, `"strict_cloudflare_origin":true`) {
		t.Fatalf("strict_cloudflare_origin leaked to non-strict site:\n%s", jsonStr)
	}
}

func TestCaddyPhase2And3_ShieldOrder_MultiUpstreamLB_HealthChecks_OriginTLS(t *testing.T) {
	secFalse := false
	verifyBots := true
	cfg := Config{
		MgmtHTTPSPort:         4438,
		MgmtHTTPPort:          8088,
		MgmtListenIPs:         []string{"127.0.0.1"},
		ShieldChallengeSecret: "deadbeefdeadbeefdeadbeefdeadbeef",
		ShieldBannedIPs: []ShieldBanEntry{
			{IP: "198.51.100.77", Reason: "L7 abuse", ExpiresAt: time.Now().Add(time.Hour)},
			{IP: "198.51.100.88", Reason: "expired", ExpiresAt: time.Now().Add(-time.Minute)},
		},
		Sites: []Site{
			{
				ID:                  "s-lb",
				Domain:              "lb.example.com",
				Upstream:            "https://10.0.0.11:8443",
				Upstreams:           []string{"https://10.0.0.12:8443"},
				SSL:                 true,
				CertMode:            "internal",
				WAF:                 true,
				WAFMode:             "on",
				ShieldMode:          "under_attack",
				UnderAttackMode:     true,
				RateLimitRPS:        15,
				RateLimitBurst:      30,
				ChallengeDifficulty: 16,
				VerifySearchBots:    &verifyBots,
				SensitiveRoutes:     []ShieldSensitiveRoute{{PathPrefix: "/wp-login.php", RPS: 2, Burst: 3}},
				LBPolicy:            "least_conn",
				HealthCheckPath:     "/healthz",
				HealthCheckInterval: "5s",
				HealthCheckTimeout:  "2s",
				OriginTLSMode:       "custom_ca",
				OriginTLSCAPath:     "/etc/vsafegate/certs/s-lb-origin-ca.crt",
				OriginTLSSNI:        "origin.internal",
			},
			{
				ID:              "s-sys",
				Domain:          "sys.example.com",
				Upstream:        "https://backend.local:8443",
				SSL:             true,
				CertMode:        "internal",
				OriginTLSMode:   "system",
				SecurityHeaders: &secFalse,
			},
		},
	}

	raw := buildCaddyJSONConfigWithOptions(cfg, "/rules", "/audit.log", "/access.log",
		map[string]string{"s-lb": "/rules/site-s-lb.conf"},
		map[string]string{"s-lb": "SecRuleEngine On"},
		"/run/vsafegate/events.sock",
	)
	httpsSrv := raw["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["srv_https"].(map[string]any)
	routes := httpsSrv["routes"].([]map[string]any)
	if len(routes) < 2 {
		t.Fatalf("expected 2 site routes + catchall, got %d", len(routes))
	}

	// Verify handler order on s-lb: headers -> vsafegate_shield -> request_body -> waf -> encode -> reverse_proxy
	lbHandlers := routes[0]["handle"].([]map[string]any)
	var names []string
	for _, h := range lbHandlers {
		names = append(names, h["handler"].(string))
	}
	wantOrder := "headers,vsafegate_shield,request_body,waf,encode,reverse_proxy"
	if strings.Join(names, ",") != wantOrder {
		t.Fatalf("unexpected pipeline order: got %v, want %s", names, wantOrder)
	}

	shieldCfg := lbHandlers[1]
	if shieldCfg["under_attack_mode"] != true || shieldCfg["events_socket_path"] != "/run/vsafegate/events.sock" {
		t.Fatalf("unexpected shield config: %+v", shieldCfg)
	}
	banned, _ := shieldCfg["banned_ips"].([]string)
	if len(banned) != 1 || banned[0] != "198.51.100.77" {
		t.Fatalf("expected active L7 ban [198.51.100.77] without expired entry, got %v", banned)
	}

	// Verify Security Headers set on s-lb (default enabled) and skipped when explicitly false on s-sys
	lbHeadersBytes, _ := json.Marshal(lbHandlers[0])
	if !strings.Contains(string(lbHeadersBytes), `"Strict-Transport-Security"`) || !strings.Contains(string(lbHeadersBytes), `"X-Content-Type-Options"`) {
		t.Fatalf("expected security headers on SSL site, got %s", lbHeadersBytes)
	}
	sysHandlers := routes[1]["handle"].([]map[string]any)
	sysHeadersBytes, _ := json.Marshal(sysHandlers[0])
	if strings.Contains(string(sysHeadersBytes), `"Strict-Transport-Security"`) {
		t.Fatalf("expected no security headers set when SecurityHeaders=false, got %s", sysHeadersBytes)
	}

	// Verify Multi-Upstream LB, HealthCheck & Custom CA on reverse_proxy
	rpBytes, _ := json.Marshal(lbHandlers[5])
	rpStr := string(rpBytes)
	if !strings.Contains(rpStr, `"policy":"least_conn"`) || !strings.Contains(rpStr, `"uri":"/healthz"`) || !strings.Contains(rpStr, `"passive":{`) {
		t.Fatalf("expected LB + active & passive health checks in reverse_proxy: %s", rpStr)
	}
	if !strings.Contains(rpStr, `"provider":"file"`) || !strings.Contains(rpStr, `"/etc/vsafegate/certs/s-lb-origin-ca.crt"`) || !strings.Contains(rpStr, `"server_name":"origin.internal"`) {
		t.Fatalf("expected custom_ca file pool + server_name in reverse_proxy: %s", rpStr)
	}
	if strings.Contains(rpStr, `"insecure_skip_verify":true`) {
		t.Fatalf("custom_ca must NOT set insecure_skip_verify=true: %s", rpStr)
	}

	// Verify system CA mode emits transport.tls={} without insecure_skip_verify
	sysRPBytes, _ := json.Marshal(sysHandlers[len(sysHandlers)-1])
	if strings.Contains(string(sysRPBytes), `"insecure_skip_verify"`) || strings.Contains(string(sysRPBytes), `"provider":"file"`) {
		t.Fatalf("system origin TLS mode should verify via system pool without insecure_skip_verify: %s", sysRPBytes)
	}
}

func joinRuleSpecs(specs []firewallRuleSpec) string {
	lines := make([]string, 0, len(specs))
	for _, s := range specs {
		lines = append(lines, strings.Join(s.args, " "))
	}
	return strings.Join(lines, "\n")
}

func TestMgmtAllowPublicInternet_DefaultAndRestricted(t *testing.T) {
	// 1. Default (nil MgmtAllowPublicInternet) -> public internet allowed on :4438 / :808
	cfgDefault := Config{
		MgmtDomain:    "vsg.example.com",
		MgmtHTTPSPort: 4438,
		MgmtHTTPPort:  808,
	}
	if !isMgmtPublicInternetAllowed(cfgDefault) {
		t.Fatalf("expected isMgmtPublicInternetAllowed to default to true")
	}
	rawDefault := buildCaddyJSONConfigWithOptions(cfgDefault, "/rules", "/audit.log", "/access.log", nil, nil, "")
	bDefault, _ := json.Marshal(rawDefault)
	sDefault := string(bDefault)
	if !strings.Contains(sDefault, `"listen":[":4438"]`) || !strings.Contains(sDefault, `"listen":[":808"]`) {
		t.Fatalf("expected default Caddy srv_mgmt to listen on :4438 and :808, got: %s", sDefault)
	}
	fwDefault := joinRuleSpecs(buildIPv4InputRules(cfgDefault, false, false, false))
	if !strings.Contains(fwDefault, "-p tcp -m multiport --dports 4438,808 -j ACCEPT") {
		t.Fatalf("expected default firewall rules to allow public :4438,808, got:\n%s", fwDefault)
	}
	if strings.Contains(fwDefault, "--dports 4438,808 -j DROP") {
		t.Fatalf("expected no DROP rule on :4438,808 when MgmtAllowPublicInternet is default true, got:\n%s", fwDefault)
	}

	// 2. Disabled (false) -> restricted to private/VPN listen + LAN/VPN firewall allow + DROP
	allowFalse := false
	cfgRestricted := Config{
		MgmtDomain:              "vsg.example.com",
		MgmtHTTPSPort:           4438,
		MgmtHTTPPort:            808,
		MgmtAllowPublicInternet: &allowFalse,
	}
	if isMgmtPublicInternetAllowed(cfgRestricted) {
		t.Fatalf("expected isMgmtPublicInternetAllowed to be false")
	}
	rawRestricted := buildCaddyJSONConfigWithOptions(cfgRestricted, "/rules", "/audit.log", "/access.log", nil, nil, "")
	bRestricted, _ := json.Marshal(rawRestricted)
	sRestricted := string(bRestricted)
	if strings.Contains(sRestricted, `"listen":[":4438"]`) || !strings.Contains(sRestricted, `"127.0.0.1:4438"`) {
		t.Fatalf("expected restricted Caddy srv_mgmt to bind private/loopback IPs instead of :4438, got: %s", sRestricted)
	}
	fwRestricted := joinRuleSpecs(buildIPv4InputRules(cfgRestricted, false, false, false))
	if !strings.Contains(fwRestricted, "-p tcp -s 127.0.0.0/8 -m multiport --dports 4438,808 -j ACCEPT") ||
		!strings.Contains(fwRestricted, "-p tcp -m multiport --dports 4438,808 -j DROP") {
		t.Fatalf("expected restricted firewall rules to allow LAN/loopback and DROP public :4438,808, got:\n%s", fwRestricted)
	}

	// 3. Explicit MgmtAllowedCIDRs still overrides even if MgmtAllowPublicInternet is nil/true
	allowTrue := true
	cfgExplicit := Config{
		MgmtHTTPSPort:           4438,
		MgmtHTTPPort:            808,
		MgmtAllowedCIDRs:        []string{"10.99.0.0/24"},
		MgmtAllowPublicInternet: &allowTrue,
	}
	fwExplicit := joinRuleSpecs(buildIPv4InputRules(cfgExplicit, false, false, false))
	if !strings.Contains(fwExplicit, "-p tcp -s 10.99.0.0/24 -m multiport --dports 4438,808 -j ACCEPT") ||
		!strings.Contains(fwExplicit, "-p tcp -m multiport --dports 4438,808 -j DROP") {
		t.Fatalf("expected explicit MgmtAllowedCIDRs to override public allow, got:\n%s", fwExplicit)
	}
}

func TestPanelSSL_HTTP01ChallengeWithoutCFToken(t *testing.T) {
	cfg := Config{
		MgmtDomain:        "panel-http01.example.com",
		MgmtCertMode:      "letsencrypt",
		MgmtCertChallenge: "http01",
		MgmtHTTPSPort:     4438,
		MgmtHTTPPort:      808,
	}
	raw := buildCaddyJSONConfigWithOptions(cfg, "/rules", "/audit.log", "/access.log", nil, nil, "")
	b, _ := json.Marshal(raw)
	s := string(b)
	if !strings.Contains(s, `"subjects":["panel-http01.example.com"]`) {
		t.Fatalf("expected panel-http01.example.com in Caddy automation subjects, got: %s", s)
	}
	if strings.Contains(s, `"internal_subjects"`) && strings.Contains(s, `"issuer":{"module":"internal"}`) {
		// Ensure panel-http01.example.com is NOT forced into internal issuer when http01 is selected
		info := inspectActiveMgmtCert(cfg, t.TempDir())
		if info.Challenge != "http01" || info.Mode != "letsencrypt" {
			t.Fatalf("expected inspectActiveMgmtCert to report mode=letsencrypt challenge=http01, got %+v", info)
		}
	}
}

func TestFirewall_DynamicTrustedInterfacesAndSSHPorts(t *testing.T) {
	cfg := Config{
		TrustedInterfaces: []string{"wg0", "tun+"},
		SSHPorts:          []int{2222, 22},
		GeoIPMode:         "whitelist",
	}
	fw := joinRuleSpecs(buildIPv4InputRules(cfg, false, false, false))
	if !strings.Contains(fw, "-i wg0 -j ACCEPT") || !strings.Contains(fw, "-i tun+ -j ACCEPT") {
		t.Fatalf("expected dynamic trusted interfaces wg0 and tun+, got:\n%s", fw)
	}
	if strings.Contains(fw, "-i tailscale+ -j ACCEPT") {
		t.Fatalf("expected tailscale+ NOT to be added when custom TrustedInterfaces=[wg0 tun+] is set, got:\n%s", fw)
	}
	if !strings.Contains(fw, "! -i wg0 ! -i tun+ ! -i lo -m conntrack --ctstate NEW") {
		t.Fatalf("expected GeoIP rule to exempt wg0 and tun+, got:\n%s", fw)
	}
	if !strings.Contains(fw, "-p tcp -m multiport --dports 2222,22 -j ACCEPT") {
		t.Fatalf("expected dynamic SSHPorts 2222,22, got:\n%s", fw)
	}
}
