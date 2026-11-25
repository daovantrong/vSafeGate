package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

func sanitizeRuleString(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

func sanitizeRulePattern(p string) string {
	p = sanitizeRuleString(p)
	p = strings.ReplaceAll(p, `"`, `\"`)
	return p
}

func sanitizeRuleMessage(m string) string {
	m = sanitizeRuleString(m)
	m = strings.ReplaceAll(m, `'`, `\'`)
	return m
}

var reValidHeader = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func sanitizeHeaderName(h string) string {
	h = strings.TrimSpace(h)
	if reValidHeader.MatchString(h) {
		return h
	}
	return "X-Custom"
}

type ReloadManager struct {
	mu        sync.Mutex
	timer     *time.Timer
	delay     time.Duration
	appState  *AppState
	isQueued  bool
}

func NewReloadManager(s *AppState, delay time.Duration) *ReloadManager {
	if delay <= 0 {
		delay = 2 * time.Second
	}
	return &ReloadManager{
		delay:    delay,
		appState: s,
	}
}

func (rm *ReloadManager) Trigger() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.timer != nil {
		rm.timer.Stop()
	}
	rm.isQueued = true
	rm.timer = time.AfterFunc(rm.delay, func() {
		rm.mu.Lock()
		rm.isQueued = false
		rm.mu.Unlock()
		if rm.appState != nil {
			if err := rm.appState.generateCaddyAndRules(); err != nil {
				log.Printf("[ReloadManager] Error generating Caddy/Rules: %v", err)
			}
		}
	})
}

func (rm *ReloadManager) ForceReload() error {
	rm.mu.Lock()
	if rm.timer != nil {
		rm.timer.Stop()
	}
	rm.isQueued = false
	rm.mu.Unlock()

	if rm.appState != nil {
		return rm.appState.generateCaddyAndRules()
	}
	return nil
}

func (s *AppState) generateCaddyAndRules() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 1. Generate rules/custom-rules.conf
	var ruleBuilder strings.Builder
	ruleBuilder.WriteString("# =========================================================================\n")
	ruleBuilder.WriteString("# vSafeGate Native Rules - Tự do tạo Rule không giới hạn\n")
	ruleBuilder.WriteString("# =========================================================================\n")
	ruleBuilder.WriteString("SecRuleEngine On\n")
	ruleBuilder.WriteString("SecDefaultAction \"phase:2,deny,status:403,log\"\n\n")
	ruleBuilder.WriteString("# CRITICAL: Always Whitelist Let's Encrypt / ZeroSSL ACME Challenges globally\n")
	ruleBuilder.WriteString("# Bypasses WAF & IP filtering for Multi-Perspective Validation\n")
	ruleBuilder.WriteString("SecRule REQUEST_URI \"@beginsWith /.well-known/acme-challenge/\" \"id:900,phase:1,allow,nolog\"\n\n")

	// Blacklist IPs
	allBannedIPs := make([]string, 0, len(s.config.BannedIPs))
	for _, b := range s.config.BannedIPs {
		if b.IP != "" {
			allBannedIPs = append(allBannedIPs, b.IP)
		}
	}
	// Fallback to legacy if empty
	if len(allBannedIPs) == 0 && len(s.config.BlacklistIP) > 0 {
		allBannedIPs = s.config.BlacklistIP
	}

	if len(allBannedIPs) > 0 {
		ruleBuilder.WriteString("# IP Blacklist\n")
		ruleBuilder.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:999,phase:1,deny,status:403,msg:'[vSafeGate] Blacklisted IP Blocked',log\"\n\n", strings.Join(allBannedIPs, ",")))
	}

	for _, r := range s.config.Rules {
		if !r.Enabled {
			continue
		}
		cleanName := sanitizeRuleMessage(r.Name)
		cleanPattern := sanitizeRulePattern(r.Pattern)

		op := "@rx"
		switch r.Operator {
		case "ipMatch":
			op = "@ipMatch"
		case "contains":
			op = "@contains"
		case "beginsWith":
			op = "@beginsWith"
		default:
			op = "@rx"
		}

		if r.RuleID == 1001 {
			ruleBuilder.WriteString(fmt.Sprintf(`# Rule %d: %s
SecRule REQUEST_URI "%s %s" \
    "id:%d,phase:1,deny,status:403,chain,msg:'[vSafeGate] %s',log"
    SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1"

`, r.RuleID, cleanName, op, cleanPattern, r.RuleID, cleanName))
		} else if strings.HasPrefix(r.Target, "HEADER:") {
			hdr := sanitizeHeaderName(strings.TrimPrefix(r.Target, "HEADER:"))
			ruleBuilder.WriteString(fmt.Sprintf(`# Rule %d: %s
SecRule REQUEST_HEADERS:%s "%s %s" \
    "id:%d,phase:1,deny,status:403,msg:'[vSafeGate] %s',log"

`, r.RuleID, cleanName, hdr, op, cleanPattern, r.RuleID, cleanName))
		} else if r.Target == "ARGS" {
			ruleBuilder.WriteString(fmt.Sprintf(`# Rule %d: %s
SecRule ARGS "%s %s" \
    "id:%d,phase:2,deny,status:403,msg:'[vSafeGate] %s',log"

`, r.RuleID, cleanName, op, cleanPattern, r.RuleID, cleanName))
		} else if r.Target == "METHOD" {
			ruleBuilder.WriteString(fmt.Sprintf(`# Rule %d: %s
SecRule REQUEST_METHOD "%s %s" \
    "id:%d,phase:1,deny,status:403,msg:'[vSafeGate] %s',log"

`, r.RuleID, cleanName, op, cleanPattern, r.RuleID, cleanName))
		} else if strings.Contains(r.Target, "ARGS") && strings.Contains(r.Target, "URI") {
			ruleBuilder.WriteString(fmt.Sprintf(`# Rule %d: %s
SecRule ARGS|REQUEST_URI "%s %s" \
    "id:%d,phase:2,deny,status:403,msg:'[vSafeGate] %s',log"

`, r.RuleID, cleanName, op, cleanPattern, r.RuleID, cleanName))
		} else {
			ruleBuilder.WriteString(fmt.Sprintf(`# Rule %d: %s
SecRule REQUEST_URI "%s %s" \
    "id:%d,phase:1,deny,status:403,msg:'[vSafeGate] %s',log"

`, r.RuleID, cleanName, op, cleanPattern, r.RuleID, cleanName))
		}
	}

	os.MkdirAll(filepath.Dir(s.rulesPath), 0755)
	tmpRules := s.rulesPath + ".tmp"
	if err := os.WriteFile(tmpRules, []byte(ruleBuilder.String()), 0644); err != nil {
		return err
	}
	os.Rename(tmpRules, s.rulesPath)

	// 2. Generate Caddyfile
	var caddyBuilder strings.Builder
	caddyBuilder.WriteString("{\n")
	caddyBuilder.WriteString("    order coraza_waf first\n")
	caddyBuilder.WriteString("    cert_issuer acme {\n")
	caddyBuilder.WriteString("        disable_tlsalpn_challenge\n")
	caddyBuilder.WriteString("    }\n")
	caddyBuilder.WriteString("}\n\n")

	// Management Dashboard (Configurable domain & ports)
	mgmtDomain := strings.TrimSpace(s.config.MgmtDomain)
	httpsPort := s.config.MgmtHTTPSPort
	if httpsPort <= 0 {
		httpsPort = 4438
	}
	httpPort := s.config.MgmtHTTPPort
	if httpPort <= 0 {
		httpPort = 808
	}

	var mgmtHosts []string
	if mgmtDomain != "" {
		mgmtHosts = append(mgmtHosts, fmt.Sprintf("%s:%d", mgmtDomain, httpsPort))
	}
	for _, ip := range getHostIPv4s() {
		mgmtHosts = append(mgmtHosts, fmt.Sprintf("%s:%d", ip, httpsPort))
	}
	if len(mgmtHosts) == 0 {
		mgmtHosts = append(mgmtHosts, fmt.Sprintf("127.0.0.1:%d", httpsPort))
	}

	caddyBuilder.WriteString(fmt.Sprintf("# vSafeGate Management Dashboard (HTTPS %d, HTTP %d redirect)\n", httpsPort, httpPort))
	caddyBuilder.WriteString(fmt.Sprintf("%s {\n", strings.Join(mgmtHosts, ", ")))
	caddyBuilder.WriteString("    tls internal\n")
	caddyBuilder.WriteString("    reverse_proxy 127.0.0.1:9444\n")
	caddyBuilder.WriteString("}\n\n")

	if mgmtDomain != "" {
		caddyBuilder.WriteString(fmt.Sprintf(":%d {\n", httpPort))
		caddyBuilder.WriteString(fmt.Sprintf("    redir https://%s:%d{uri}\n", mgmtDomain, httpsPort))
		caddyBuilder.WriteString("}\n\n")
	}

	for _, site := range s.config.Sites {
		upstream := strings.TrimRight(strings.TrimSpace(site.Upstream), "/")
		caddyBuilder.WriteString(fmt.Sprintf("%s {\n", site.Domain))
		if site.WAF {
			caddyBuilder.WriteString("    coraza_waf {\n")
			caddyBuilder.WriteString("        load_owasp_crs\n")
			caddyBuilder.WriteString(fmt.Sprintf("        directives `\n            Include %s\n        `\n", s.rulesPath))
			caddyBuilder.WriteString("    }\n")
		}
		caddyBuilder.WriteString(fmt.Sprintf("    reverse_proxy %s {\n", upstream))
		if strings.Contains(upstream, "192.168.1.1") {
			caddyBuilder.WriteString("        header_up Host {upstream_hostport}\n")
		} else {
			caddyBuilder.WriteString("        header_up Host {host}\n")
		}
		caddyBuilder.WriteString("        header_up X-Real-IP {remote_host}\n")
		caddyBuilder.WriteString("        header_up X-Forwarded-For {remote_host}\n")
		caddyBuilder.WriteString("        header_up X-Forwarded-Proto {scheme}\n")
		caddyBuilder.WriteString("        header_up X-Forwarded-Port {server_port}\n")
		caddyBuilder.WriteString("        header_up X-Forwarded-Host {host}\n")
		if strings.Contains(upstream, ":5001") && !strings.Contains(site.Domain, ":5001") {
			caddyBuilder.WriteString("        header_down Location :5001 \"\"\n")
		}
		if strings.Contains(upstream, ":5000") && !strings.Contains(site.Domain, ":5000") {
			caddyBuilder.WriteString("        header_down Location :5000 \"\"\n")
		}
		if strings.HasPrefix(site.Upstream, "https://") {
			caddyBuilder.WriteString("        transport http {\n")
			caddyBuilder.WriteString("            tls_insecure_skip_verify\n")
			caddyBuilder.WriteString("        }\n")
		}
		caddyBuilder.WriteString("    }\n")
		caddyBuilder.WriteString("    log {\n")
		caddyBuilder.WriteString("        output file /var/log/caddy/access.log {\n")
		caddyBuilder.WriteString("            roll_size 50mb\n")
		caddyBuilder.WriteString("            roll_keep 5\n")
		caddyBuilder.WriteString("        }\n")
		caddyBuilder.WriteString("        format json\n")
		caddyBuilder.WriteString("    }\n")
		caddyBuilder.WriteString("}\n\n")
	}

	// Fallback site for unmatched IPs (prevent raw IP scans)
	caddyBuilder.WriteString(":80, :443 {\n")
	caddyBuilder.WriteString("    respond \"<h1>vSafeGate Protected Gateway</h1><p>Active and Secure.</p>\" 200\n")
	caddyBuilder.WriteString("}\n")

	os.MkdirAll(filepath.Dir(s.caddyPath), 0755)
	tmpCaddy := s.caddyPath + ".tmp"
	if err := os.WriteFile(tmpCaddy, []byte(caddyBuilder.String()), 0644); err != nil {
		return err
	}
	os.Rename(tmpCaddy, s.caddyPath)

	// Reload Caddy safely (Linux: direct reload under CaddySupervisor or external fallback)
	if runtime.GOOS == "linux" {
		if s.caddySupervisor != nil {
			if err := s.caddySupervisor.Reload(); err != nil && s.caddySupervisor.IsRunning() {
				log.Printf("[Caddy] Reload failed: %v", err)
			}
		} else if bin := findCaddyBinary(); bin != "" && isAddrListening("127.0.0.1:2019") {
			exec.Command(bin, "reload", "--config", s.caddyPath, "--force").Run()
		} else if _, err := exec.LookPath("systemctl"); err == nil {
			exec.Command("systemctl", "reload", "caddy").Run()
		} else if _, err := exec.LookPath("rc-service"); err == nil {
			exec.Command("rc-service", "caddy", "reload").Run()
		}
	}
	return nil
}

func getHostIPv4s() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					ips = append(ips, ip4.String())
				}
			}
		}
	}
	ips = append(ips, "127.0.0.1")
	return ips
}

func isHostOrLoopbackIP(ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" || ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return true
	}
	for _, hostIP := range getHostIPv4s() {
		if ip == hostIP {
			return true
		}
	}
	return false
}
