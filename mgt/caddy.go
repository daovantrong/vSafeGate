package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func sanitizeRuleString(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

func sanitizeSecLangQuoted(s string, quote byte) string {
	s = sanitizeRuleString(s)
	var b strings.Builder
	b.Grow(len(s) + 8)
	i := 0
	for i < len(s) {
		if s[i] == '\\' {
			start := i
			for i < len(s) && s[i] == '\\' {
				i++
			}
			count := i - start
			if i < len(s) && s[i] == quote {
				for j := 0; j < count*2; j++ {
					b.WriteByte('\\')
				}
				b.WriteByte('\\')
				b.WriteByte(quote)
				i++
			} else if i == len(s) && count%2 == 1 {
				for j := 0; j < count+1; j++ {
					b.WriteByte('\\')
				}
			} else {
				b.WriteString(s[start:i])
			}
			continue
		}
		if s[i] == quote {
			b.WriteByte('\\')
			b.WriteByte(quote)
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func sanitizeRulePattern(p string) string {
	return sanitizeSecLangQuoted(p, '"')
}

func sanitizeRuleMessage(m string) string {
	return sanitizeSecLangQuoted(m, '\'')
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
	mu       sync.Mutex
	timer    *time.Timer
	delay    time.Duration
	appState *AppState
	isQueued bool
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

func (s *AppState) effectiveWAFAuditLogPath() string {
	if s.wafAuditPath != "" {
		return s.wafAuditPath
	}
	if os.Getenv("ENV") == "dev" {
		return "./waf-audit.jsonl"
	}
	return "/var/log/caddy/waf-audit.jsonl"
}

func (s *AppState) effectiveAccessLogPath() string {
	if s.accessLogPath != "" {
		return s.accessLogPath
	}
	if os.Getenv("ENV") == "dev" {
		return "./access.log"
	}
	return "/var/log/caddy/access.log"
}

func effectiveSiteWAFMode(site Site) string {
	m := strings.ToLower(strings.TrimSpace(site.WAFMode))
	switch m {
	case "off", "detection", "on":
		return m
	default:
		if site.WAF {
			return "on"
		}
		return "off"
	}
}

func effectiveSiteCertMode(site Site) string {
	if !site.SSL {
		return "none"
	}
	m := strings.ToLower(strings.TrimSpace(site.CertMode))
	switch m {
	case "cloudflare_dns01", "uploaded", "internal", "auto_http", "none":
		return m
	default:
		return "auto_http"
	}
}

func effectiveSiteShieldMode(site Site) string {
	if site.UnderAttackMode {
		return "under_attack"
	}
	m := strings.ToLower(strings.TrimSpace(site.ShieldMode))
	switch m {
	case "off", "under_attack", "normal":
		return m
	default:
		return "normal"
	}
}

var (
	cgnatPrefix    = netip.MustParsePrefix("100.64.0.0/10")
	linkLocal4Pref = netip.MustParsePrefix("169.254.0.0/16")
)

func isPrivateMgmtIPv4(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.Is4() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || linkLocal4Pref.Contains(addr) {
		return false
	}
	return addr.IsPrivate() || cgnatPrefix.Contains(addr)
}

func detectPrivateMgmtIPv4s() []netip.Addr {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var addrs []netip.Addr
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		nameLow := strings.ToLower(ifi.Name)
		if strings.HasPrefix(nameLow, "docker") ||
			strings.HasPrefix(nameLow, "veth") ||
			strings.HasPrefix(nameLow, "br-") ||
			strings.HasPrefix(nameLow, "virbr") ||
			strings.HasPrefix(nameLow, "cni") ||
			strings.HasPrefix(nameLow, "flannel") {
			continue
		}
		ifAddrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range ifAddrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if addr, ok2 := netip.AddrFromSlice(ipnet.IP); ok2 {
				addr = addr.Unmap()
				if isPrivateMgmtIPv4(addr) {
					addrs = append(addrs, addr)
				}
			}
		}
	}
	return addrs
}

func resolveMgmtListenIPs(configured []string, fallbackAddrs []netip.Addr) []string {
	ips := []string{"127.0.0.1"}
	seen := map[string]struct{}{"127.0.0.1": {}}

	hasConfigured := false
	for _, rawIP := range configured {
		ipStr := strings.TrimSpace(rawIP)
		if ipStr == "" {
			continue
		}
		hasConfigured = true
		if addr, err := netip.ParseAddr(ipStr); err == nil {
			norm := addr.Unmap().String()
			if _, ok := seen[norm]; !ok {
				seen[norm] = struct{}{}
				ips = append(ips, norm)
			}
		}
	}

	if !hasConfigured {
		var detected []string
		for _, addr := range fallbackAddrs {
			if isPrivateMgmtIPv4(addr) {
				norm := addr.Unmap().String()
				if _, ok := seen[norm]; !ok {
					seen[norm] = struct{}{}
					detected = append(detected, norm)
				}
			}
		}
		sort.Strings(detected)
		ips = append(ips, detected...)
	}

	return ips
}

func collectActiveShieldBannedIPs(cfg Config, now time.Time) []string {
	if len(cfg.ShieldBannedIPs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(cfg.ShieldBannedIPs))
	var out []string
	for _, b := range cfg.ShieldBannedIPs {
		if !b.ExpiresAt.IsZero() && now.After(b.ExpiresAt) {
			continue
		}
		ip := strings.TrimSpace(b.IP)
		if addr, err := netip.ParseAddr(ip); err == nil {
			ip = addr.Unmap().String()
		}
		if ip == "" || isTrustedProxyOrCloudflareIP(ip, cfg) {
			continue
		}
		if _, ok := seen[ip]; !ok {
			seen[ip] = struct{}{}
			out = append(out, ip)
		}
	}
	sort.Strings(out)
	return out
}

func parseUpstreamDialAndScheme(rawUpstream string) (dialAddr string, isHTTPS bool, hostPort string) {
	uStr := strings.TrimRight(strings.TrimSpace(rawUpstream), "/")
	if uStr == "" {
		return "", false, ""
	}
	if !strings.Contains(uStr, "://") {
		uStr = "http://" + uStr
	}
	u, err := url.Parse(uStr)
	if err != nil || u.Host == "" {
		return strings.TrimPrefix(strings.TrimPrefix(rawUpstream, "https://"), "http://"), strings.HasPrefix(rawUpstream, "https://"), ""
	}
	isHTTPS = strings.EqualFold(u.Scheme, "https")
	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		if isHTTPS {
			host = net.JoinHostPort(host, "443")
		} else {
			host = net.JoinHostPort(host, "80")
		}
	}
	return host, isHTTPS, u.Host
}

func collectAllBannedIPs(cfg Config) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, b := range cfg.BannedIPs {
		ip := strings.TrimSpace(b.IP)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; !ok {
			seen[ip] = struct{}{}
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		for _, ip := range cfg.BlacklistIP {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			if _, ok := seen[ip]; !ok {
				seen[ip] = struct{}{}
				out = append(out, ip)
			}
		}
	}
	return out
}

func buildTrustedProxyCIDRs(cfg Config, extra ...[]string) []string {
	cfV4, cfV6 := effectiveCloudflareCIDRs(cfg.Cloudflare)
	privateRanges := []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
	}

	seen := make(map[string]struct{})
	var out []string
	addList := func(items []string) {
		for _, raw := range items {
			s := strings.TrimSpace(raw)
			if s == "" {
				continue
			}
			var normalized string
			if strings.Contains(s, "/") {
				pfx, err := netip.ParsePrefix(s)
				if err != nil || pfx.Bits() == 0 {
					continue
				}
				normalized = pfx.Masked().String()
			} else {
				addr, err := netip.ParseAddr(s)
				if err != nil {
					continue
				}
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				normalized = netip.PrefixFrom(addr.Unmap(), bits).String()
			}
			if _, ok := seen[normalized]; !ok {
				seen[normalized] = struct{}{}
				out = append(out, normalized)
			}
		}
	}

	addList(privateRanges)
	addList(cfV4)
	addList(cfV6)
	addList(cfg.TrustedProxies)
	for _, list := range extra {
		addList(list)
	}
	return out
}

func appendCustomRuleSecLang(b *strings.Builder, r CustomRule) {
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

	actionExpr := "deny,status:403,auditlog"
	switch strings.ToLower(strings.TrimSpace(r.Action)) {
	case "drop":
		actionExpr = "drop,auditlog"
	case "allow":
		actionExpr = "allow,nolog"
	default:
		actionExpr = "deny,status:403,auditlog"
	}

	if r.RuleID == 1001 {
		b.WriteString(fmt.Sprintf(`# Rule %d: %s
SecRule REQUEST_URI "%s %s" \
    "id:%d,phase:1,%s,chain,msg:'[vSafeGate] %s'"
    SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1"

`, r.RuleID, cleanName, op, cleanPattern, r.RuleID, actionExpr, cleanName))
		return
	}

	if strings.HasPrefix(r.Target, "HEADER:") {
		hdr := sanitizeHeaderName(strings.TrimPrefix(r.Target, "HEADER:"))
		b.WriteString(fmt.Sprintf(`# Rule %d: %s
SecRule REQUEST_HEADERS:%s "%s %s" \
    "id:%d,phase:1,%s,msg:'[vSafeGate] %s'"

`, r.RuleID, cleanName, hdr, op, cleanPattern, r.RuleID, actionExpr, cleanName))
	} else if r.Target == "IP" {
		b.WriteString(fmt.Sprintf(`# Rule %d: %s
SecRule REMOTE_ADDR "%s %s" \
    "id:%d,phase:1,%s,msg:'[vSafeGate] %s'"

`, r.RuleID, cleanName, op, cleanPattern, r.RuleID, actionExpr, cleanName))
	} else if r.Target == "USER_AGENT" {
		b.WriteString(fmt.Sprintf(`# Rule %d: %s
SecRule REQUEST_HEADERS:User-Agent "%s %s" \
    "id:%d,phase:1,%s,msg:'[vSafeGate] %s'"

`, r.RuleID, cleanName, op, cleanPattern, r.RuleID, actionExpr, cleanName))
	} else if r.Target == "ARGS" {
		b.WriteString(fmt.Sprintf(`# Rule %d: %s
SecRule ARGS "%s %s" \
    "id:%d,phase:2,%s,msg:'[vSafeGate] %s'"

`, r.RuleID, cleanName, op, cleanPattern, r.RuleID, actionExpr, cleanName))
	} else if r.Target == "METHOD" {
		b.WriteString(fmt.Sprintf(`# Rule %d: %s
SecRule REQUEST_METHOD "%s %s" \
    "id:%d,phase:1,%s,msg:'[vSafeGate] %s'"

`, r.RuleID, cleanName, op, cleanPattern, r.RuleID, actionExpr, cleanName))
	} else if strings.Contains(r.Target, "ARGS") && strings.Contains(r.Target, "URI") {
		b.WriteString(fmt.Sprintf(`# Rule %d: %s
SecRule ARGS|REQUEST_URI "%s %s" \
    "id:%d,phase:2,%s,msg:'[vSafeGate] %s'"

`, r.RuleID, cleanName, op, cleanPattern, r.RuleID, actionExpr, cleanName))
	} else {
		b.WriteString(fmt.Sprintf(`# Rule %d: %s
SecRule REQUEST_URI "%s %s" \
    "id:%d,phase:1,%s,msg:'[vSafeGate] %s'"

`, r.RuleID, cleanName, op, cleanPattern, r.RuleID, actionExpr, cleanName))
	}
}

func buildSiteCorazaRuleset(cfg Config, site *Site, auditLogPath string) string {
	var b strings.Builder
	b.WriteString("# =========================================================================\n")
	b.WriteString("# vSafeGate OWASP CRS v4 + Custom SecLang Policy\n")
	b.WriteString("# =========================================================================\n")

	// 1. Coraza recommended base defaults BEFORE overrides
	b.WriteString("Include @coraza.conf-recommended\n\n")

	// 2. Engine & Audit overrides AFTER @coraza.conf-recommended
	ruleEngine := "On"
	paranoia := 1
	inThresh := 5
	outThresh := 4
	bodyMB := 100
	appPreset := "generic"

	if site != nil {
		if effectiveSiteWAFMode(*site) == "detection" {
			ruleEngine = "DetectionOnly"
		}
		if site.ParanoiaLevel >= 1 && site.ParanoiaLevel <= 4 {
			paranoia = site.ParanoiaLevel
		}
		if site.InboundAnomalyThreshold > 0 {
			inThresh = site.InboundAnomalyThreshold
		}
		if site.OutboundAnomalyThreshold > 0 {
			outThresh = site.OutboundAnomalyThreshold
		}
		if site.RequestBodyMaxMB > 0 {
			bodyMB = site.RequestBodyMaxMB
		}
		if site.AppPreset != "" {
			appPreset = strings.ToLower(strings.TrimSpace(site.AppPreset))
		}
	}
	if bodyMB > 500 {
		bodyMB = 500
	}
	bodyBytes := int64(bodyMB) * 1024 * 1024

	b.WriteString(fmt.Sprintf("SecRuleEngine %s\n", ruleEngine))
	b.WriteString("SecDefaultAction \"phase:1,log,auditlog,pass\"\n")
	b.WriteString("SecDefaultAction \"phase:2,log,auditlog,pass\"\n")
	b.WriteString("SecAuditEngine RelevantOnly\n")
	b.WriteString("SecAuditLogRelevantStatus ^$\n")
	b.WriteString("SecAuditLogParts ABIJDEFHKZ\n")
	b.WriteString("SecAuditLogType Serial\n")
	b.WriteString("SecAuditLogFormat JSON\n")
	b.WriteString(fmt.Sprintf("SecAuditLog %s\n", filepath.ToSlash(auditLogPath)))
	b.WriteString("SecRxPreFilter On\n")
	b.WriteString("SecRequestBodyAccess On\n")
	b.WriteString(fmt.Sprintf("SecRequestBodyLimit %d\n", bodyBytes))
	b.WriteString("SecRequestBodyNoFilesLimit 1048576\n")
	b.WriteString("SecRequestBodyLimitAction Reject\n")
	b.WriteString("SecResponseBodyAccess On\n")
	b.WriteString("SecResponseBodyMimeType text/plain text/html text/xml application/json application/xml\n")
	b.WriteString("SecResponseBodyLimit 524288\n")
	b.WriteString("SecResponseBodyLimitAction ProcessPartial\n\n")

	// CRS v4 initialization MUST precede @owasp_crs/*.conf to avoid rule 901001 500 error
	b.WriteString("# CRS v4 Initialization (prevents 901001 missing setup_version)\n")
	b.WriteString("SecAction \"id:900099,phase:1,pass,t:none,nolog,setvar:tx.crs_setup_version=4250\"\n")
	b.WriteString(fmt.Sprintf(
		"SecAction \"id:900110,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d\"\n\n",
		paranoia, paranoia, inThresh, outThresh,
	))

	// 3. IP Blacklist BEFORE ACME whitelist so banned IPs stay blocked
	allBannedIPs := collectAllBannedIPs(cfg)
	if len(allBannedIPs) > 0 {
		b.WriteString("# IP Blacklist (evaluated before ACME allowlist)\n")
		b.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:999,phase:1,drop,auditlog,msg:'[vSafeGate] Blacklisted IP Blocked'\"\n\n", strings.Join(allBannedIPs, ",")))
	}

	// 4. Strict ACME HTTP-01 challenge allowlist
	b.WriteString("# Strict ACME HTTP-01 Challenge Allowlist\n")
	b.WriteString(`SecRule REQUEST_URI "@rx ^/\.well-known/acme-challenge/[A-Za-z0-9_-]{1,128}$" "id:900,phase:1,allow,nolog"` + "\n\n")

	// 5. App Presets & Pre-CRS Exclusions
	switch appPreset {
	case "wordpress":
		b.WriteString("# AppPreset: wordpress\n")
		b.WriteString("SecAction \"id:900201,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE',ctl:ruleRemoveTargetById=941100;ARGS:content,ctl:ruleRemoveTargetById=941160;ARGS:content\"\n\n")
	case "api":
		b.WriteString("# AppPreset: api\n")
		b.WriteString("SecAction \"id:900202,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=GET HEAD POST PUT PATCH DELETE OPTIONS',setvar:'tx.allowed_request_content_type=|application/json|application/x-www-form-urlencoded|multipart/form-data|text/plain|'\"\n\n")
	case "nextcloud", "nas":
		b.WriteString("# AppPreset: nextcloud/nas (WebDAV methods & DSM upload paths)\n")
		b.WriteString("SecAction \"id:900203,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=GET HEAD POST PUT DELETE OPTIONS PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK'\"\n")
		b.WriteString("SecRule REQUEST_URI \"@beginsWith /remote.php/dav/\" \"id:900204,phase:1,pass,nolog,ctl:ruleRemoveById=920350,ctl:ruleRemoveById=932100-932299\"\n\n")
	}

	var postCRSRemoveIDs []int
	if site != nil && len(site.Exclusions) > 0 {
		b.WriteString("# Site WAF Exclusions\n")
		nextExclRuleID := 900300
		for _, ex := range site.Exclusions {
			if !ex.Enabled || ex.RuleID <= 0 {
				continue
			}
			cleanURI := sanitizeRulePattern(ex.MatchURI)
			if cleanURI == "" && len(ex.RemoveArgs) == 0 {
				postCRSRemoveIDs = append(postCRSRemoveIDs, ex.RuleID)
				continue
			}
			var ctls []string
			if len(ex.RemoveArgs) == 0 {
				ctls = append(ctls, fmt.Sprintf("ctl:ruleRemoveById=%d", ex.RuleID))
			} else {
				argClean := strings.NewReplacer(`"`, "", `'`, "", `;`, "", `,`, "", `\`, "", " ", "", "\t", "")
				for _, arg := range ex.RemoveArgs {
					safeArg := argClean.Replace(sanitizeRuleString(arg))
					if safeArg != "" {
						ctls = append(ctls, fmt.Sprintf("ctl:ruleRemoveTargetById=%d;%s", ex.RuleID, safeArg))
					}
				}
			}
			if len(ctls) == 0 {
				continue
			}
			if cleanURI != "" {
				b.WriteString(fmt.Sprintf("SecRule REQUEST_URI \"@beginsWith %s\" \"id:%d,phase:1,pass,nolog,%s\"\n", cleanURI, nextExclRuleID, strings.Join(ctls, ",")))
			} else {
				b.WriteString(fmt.Sprintf("SecAction \"id:%d,phase:1,pass,nolog,%s\"\n", nextExclRuleID, strings.Join(ctls, ",")))
			}
			nextExclRuleID++
		}
		b.WriteString("\n")
	}

	// 6. OWASP CRS v4 ruleset
	b.WriteString("# OWASP Core Rule Set v4\n")
	b.WriteString("Include @owasp_crs/*.conf\n\n")

	// 7. Post-CRS unconditional rule removals & Site/Global Custom Rules
	if len(postCRSRemoveIDs) > 0 {
		b.WriteString("# Post-CRS Rule Removals\n")
		for _, rid := range postCRSRemoveIDs {
			b.WriteString(fmt.Sprintf("SecRuleRemoveById %d\n", rid))
		}
		b.WriteString("\n")
	}

	b.WriteString("# vSafeGate Custom Rules\n")
	for _, r := range cfg.Rules {
		if !r.Enabled {
			continue
		}
		if r.SiteID != "" && (site == nil || r.SiteID != site.ID) {
			continue
		}
		appendCustomRuleSecLang(&b, r)
	}

	return b.String()
}

func buildReverseProxyHandler(site Site) map[string]any {
	rawUpstreams := make([]string, 0, 1+len(site.Upstreams))
	if strings.TrimSpace(site.Upstream) != "" {
		rawUpstreams = append(rawUpstreams, site.Upstream)
	}
	for _, u := range site.Upstreams {
		u = strings.TrimSpace(u)
		if u != "" && u != strings.TrimSpace(site.Upstream) {
			rawUpstreams = append(rawUpstreams, u)
		}
	}

	upstreams := make([]map[string]any, 0, len(rawUpstreams))
	anyHTTPS := false

	for _, raw := range rawUpstreams {
		dial, isHTTPS, _ := parseUpstreamDialAndScheme(raw)
		if dial == "" {
			continue
		}
		upstreams = append(upstreams, map[string]any{"dial": dial})
		if isHTTPS {
			anyHTTPS = true
		}
	}

	reqSetHeaders := map[string][]string{
		"Host":              {"{http.request.host}"},
		"X-Real-IP":         {"{http.vars.client_ip}"},
		"X-Forwarded-Proto": {"{http.request.scheme}"},
		"X-Forwarded-Port":  {"{http.request.port}"},
		"X-Forwarded-Host":  {"{http.request.host}"},
	}

	headersCfg := map[string]any{
		"request": map[string]any{
			"set": reqSetHeaders,
		},
	}

	rp := map[string]any{
		"handler":        "reverse_proxy",
		"upstreams":      upstreams,
		"flush_interval": -1,
		"headers":        headersCfg,
	}

	if anyHTTPS {
		tlsMode := strings.ToLower(strings.TrimSpace(site.OriginTLSMode))
		if tlsMode == "" {
			tlsMode = "insecure"
		}
		tlsCfg := map[string]any{}
		switch tlsMode {
		case "system":
			// Verify origin cert using OS system CA pool
		case "custom_ca":
			if strings.TrimSpace(site.OriginTLSCAPath) != "" {
				tlsCfg["ca"] = map[string]any{
					"provider":  "file",
					"pem_files": []string{filepath.ToSlash(strings.TrimSpace(site.OriginTLSCAPath))},
				}
			} else {
				tlsCfg["insecure_skip_verify"] = true
			}
		default: // "insecure"
			tlsCfg["insecure_skip_verify"] = true
		}
		if sni := strings.TrimSpace(site.OriginTLSSNI); sni != "" {
			tlsCfg["server_name"] = sni
		}
		rp["transport"] = map[string]any{
			"protocol": "http",
			"tls":      tlsCfg,
		}
	}

	if len(upstreams) > 1 {
		policy := strings.ToLower(strings.TrimSpace(site.LBPolicy))
		switch policy {
		case "round_robin", "least_conn", "ip_hash", "client_ip_hash", "first", "random":
		default:
			policy = "round_robin"
		}
		rp["load_balancing"] = map[string]any{
			"selection_policy": map[string]any{
				"policy": policy,
			},
			"retries":      2,
			"try_duration": "3s",
		}
	}

	healthPath := strings.TrimSpace(site.HealthCheckPath)
	if len(upstreams) > 1 || healthPath != "" {
		hc := map[string]any{}
		if len(upstreams) > 1 {
			hc["passive"] = map[string]any{
				"fail_duration":    "10s",
				"max_fails":        3,
				"unhealthy_status": []int{502, 503, 504},
			}
		}
		if healthPath != "" {
			interval := strings.TrimSpace(site.HealthCheckInterval)
			if interval == "" {
				interval = "10s"
			}
			timeout := strings.TrimSpace(site.HealthCheckTimeout)
			if timeout == "" {
				timeout = "3s"
			}
			hc["active"] = map[string]any{
				"uri":      healthPath,
				"interval": interval,
				"timeout":  timeout,
				"passes":   2,
				"fails":    3,
			}
		}
		rp["health_checks"] = hc
	}

	return rp
}

func buildShieldHandler(cfg Config, site Site, trustedRanges []string, l7BannedIPs []string, eventsSocketPath string) map[string]any {
	mode := effectiveSiteShieldMode(site)
	sh := map[string]any{
		"handler":           "vsafegate_shield",
		"site_id":           site.ID,
		"mode":              mode,
		"under_attack_mode": mode == "under_attack",
		"trusted_proxies":   trustedRanges,
	}
	if strings.TrimSpace(cfg.ShieldChallengeSecret) != "" {
		sh["challenge_secret"] = strings.TrimSpace(cfg.ShieldChallengeSecret)
	}
	if eventsSocketPath != "" {
		sh["events_socket_path"] = eventsSocketPath
	}
	if site.RateLimitRPS > 0 {
		sh["rate_limit_rps"] = site.RateLimitRPS
	}
	if site.RateLimitBurst > 0 {
		sh["rate_limit_burst"] = site.RateLimitBurst
	}
	if site.SubnetRateLimitRPS > 0 {
		sh["subnet_rate_limit_rps"] = site.SubnetRateLimitRPS
	}
	if site.HostRateLimitRPS > 0 {
		sh["host_rate_limit_rps"] = site.HostRateLimitRPS
	}
	if site.MaxConcurrentPerIP > 0 {
		sh["max_concurrent_per_ip"] = site.MaxConcurrentPerIP
	}
	if site.ChallengeDifficulty >= 8 && site.ChallengeDifficulty <= 22 {
		sh["challenge_difficulty"] = site.ChallengeDifficulty
	}
	if len(site.SensitiveRoutes) > 0 {
		routes := make([]map[string]any, 0, len(site.SensitiveRoutes))
		for _, sr := range site.SensitiveRoutes {
			if strings.TrimSpace(sr.PathPrefix) == "" {
				continue
			}
			item := map[string]any{
				"path_prefix": strings.TrimSpace(sr.PathPrefix),
			}
			if sr.RPS > 0 {
				item["rps"] = sr.RPS
			}
			if sr.Burst > 0 {
				item["burst"] = sr.Burst
			}
			routes = append(routes, item)
		}
		if len(routes) > 0 {
			sh["sensitive_routes"] = routes
		}
	}
	if len(site.ExemptPaths) > 0 {
		sh["exempt_paths"] = site.ExemptPaths
	}
	if len(site.APIPaths) > 0 {
		sh["api_paths"] = site.APIPaths
	}
	if site.VerifySearchBots != nil {
		sh["verify_search_bots"] = *site.VerifySearchBots
	}
	if len(l7BannedIPs) > 0 {
		sh["banned_ips"] = l7BannedIPs
	}
	return sh
}

func buildSitePipelineHandlers(cfg Config, site Site, siteRulesPath, siteRulesContent string, siteTrustedRanges []string, l7BannedIPs []string, eventsSocketPath string) []map[string]any {
	deleteHeaders := []string{
		"Server",
		"X-Powered-By",
		"X-AspNet-Version",
		"X-Generator",
		"Via",
	}
	if site.HideAltSvc {
		deleteHeaders = append(deleteHeaders, "Alt-Svc")
	}

	respHeaders := map[string]any{
		"delete": deleteHeaders,
	}
	if site.SecurityHeaders == nil || *site.SecurityHeaders {
		setSec := map[string][]string{
			"X-Content-Type-Options": {"nosniff"},
			"X-Frame-Options":        {"SAMEORIGIN"},
		}
		if site.SSL {
			setSec["Strict-Transport-Security"] = []string{"max-age=31536000; includeSubDomains"}
		}
		respHeaders["set"] = setSec
	}

	handlers := []map[string]any{
		{
			"handler":  "headers",
			"response": respHeaders,
		},
	}

	if effectiveSiteShieldMode(site) != "off" {
		handlers = append(handlers, buildShieldHandler(cfg, site, siteTrustedRanges, l7BannedIPs, eventsSocketPath))
	}

	maxMB := site.RequestBodyMaxMB
	if maxMB <= 0 {
		maxMB = 100
	}
	if maxMB > 500 {
		maxMB = 500
	}
	handlers = append(handlers, map[string]any{
		"handler":  "request_body",
		"max_size": int64(maxMB) * 1024 * 1024,
	})

	if effectiveSiteWAFMode(site) != "off" {
		sum := sha256.Sum256([]byte(siteRulesContent))
		directives := fmt.Sprintf("# sha256:%s\nInclude %s", hex.EncodeToString(sum[:12]), filepath.ToSlash(siteRulesPath))
		handlers = append(handlers, map[string]any{
			"handler":        "waf",
			"load_owasp_crs": true,
			"directives":     directives,
		})
	}

	handlers = append(handlers, map[string]any{
		"handler": "encode",
		"encodings": map[string]any{
			"zstd": map[string]any{},
			"gzip": map[string]any{},
		},
		"prefer": []string{"zstd", "gzip"},
	})

	handlers = append(handlers, buildReverseProxyHandler(site))
	return handlers
}

func buildCaddyJSONConfig(cfg Config, rulesDir, auditLogPath, accessLogPath string, siteRulesPaths map[string]string, siteRulesContents map[string]string) map[string]any {
	return buildCaddyJSONConfigWithOptions(cfg, rulesDir, auditLogPath, accessLogPath, siteRulesPaths, siteRulesContents, "/run/vsafegate/events.sock")
}

func buildCaddyJSONConfigWithOptions(cfg Config, rulesDir, auditLogPath, accessLogPath string, siteRulesPaths map[string]string, siteRulesContents map[string]string, eventsSocketPath string) map[string]any {
	var allowedSNIs []string
	var strictOriginSNIs []string
	var dns01Subjects []string
	var httpACMESubjects []string
	var internalSubjects []string
	var loadFiles []map[string]any
	var extraSiteTrustedProxies [][]string

	anyHideAltSvc := false
	l7BannedIPs := collectActiveShieldBannedIPs(cfg, time.Now())

	httpsRoutes := make([]map[string]any, 0, len(cfg.Sites)+1)
	httpRoutes := make([]map[string]any, 0, len(cfg.Sites)+1)

	loggerNames := make(map[string][]string)
	siteLogsCfg := make(map[string]any)
	usedLoggerKeys := make(map[string]int)
	var excludedSiteLoggers []string
	accessLogDir := filepath.Dir(accessLogPath)

	for _, site := range cfg.Sites {
		domain := strings.TrimSpace(site.Domain)
		if domain == "" {
			continue
		}
		if len(site.TrustedProxies) > 0 {
			extraSiteTrustedProxies = append(extraSiteTrustedProxies, site.TrustedProxies)
		}
		if site.HideAltSvc {
			anyHideAltSvc = true
		}

		safeID := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				return r
			}
			return '-'
		}, site.ID)
		if safeID == "" {
			safeID = "site"
		}
		usedLoggerKeys[safeID]++
		if usedLoggerKeys[safeID] > 1 {
			safeID = fmt.Sprintf("%s-%d", safeID, usedLoggerKeys[safeID])
		}
		loggerKey := "site_" + safeID
		hostKey := strings.ToLower(domain)
		if h, _, err := net.SplitHostPort(hostKey); err == nil && h != "" {
			hostKey = h
		}
		loggerNames[hostKey] = []string{loggerKey}
		excludedSiteLoggers = append(excludedSiteLoggers, "http.log.access."+loggerKey)
		siteLogsCfg[loggerKey] = map[string]any{
			"include": []string{"http.log.access." + loggerKey},
			"writer": map[string]any{
				"output":       "file",
				"filename":     filepath.ToSlash(filepath.Join(accessLogDir, "access-"+safeID+".log")),
				"roll":         true,
				"roll_size_mb": 50,
				"roll_keep":    5,
			},
			"encoder": map[string]any{"format": "json"},
		}

		sRulesPath := siteRulesPaths[site.ID]
		sRulesContent := siteRulesContents[site.ID]
		siteTrustedRanges := buildTrustedProxyCIDRs(cfg, site.TrustedProxies)
		pipeline := buildSitePipelineHandlers(cfg, site, sRulesPath, sRulesContent, siteTrustedRanges, l7BannedIPs, eventsSocketPath)

		if site.SSL {
			allowedSNIs = append(allowedSNIs, domain)
			if site.StrictCloudflareOrigin {
				strictOriginSNIs = append(strictOriginSNIs, domain)
			}
			certMode := effectiveSiteCertMode(site)
			switch certMode {
			case "cloudflare_dns01":
				if strings.TrimSpace(cfg.Cloudflare.APIToken) != "" {
					dns01Subjects = append(dns01Subjects, domain)
				} else {
					httpACMESubjects = append(httpACMESubjects, domain)
				}
			case "uploaded":
				if site.CustomCertPath != "" && site.CustomKeyPath != "" {
					loadFiles = append(loadFiles, map[string]any{
						"certificate": filepath.ToSlash(site.CustomCertPath),
						"key":         filepath.ToSlash(site.CustomKeyPath),
						"format":      "pem",
					})
				} else {
					internalSubjects = append(internalSubjects, domain)
				}
			case "internal":
				internalSubjects = append(internalSubjects, domain)
			default:
				httpACMESubjects = append(httpACMESubjects, domain)
			}

			httpsRoutes = append(httpsRoutes, map[string]any{
				"match":    []map[string]any{{"host": []string{domain}}},
				"terminal": true,
				"handle":   pipeline,
			})

			httpRoutes = append(httpRoutes, map[string]any{
				"match":    []map[string]any{{"host": []string{domain}}},
				"terminal": true,
				"handle": []map[string]any{
					{
						"handler":     "static_response",
						"status_code": 301,
						"headers": map[string][]string{
							"Location": {"https://{http.request.host}{http.request.uri}"},
						},
					},
				},
			})
		} else {
			httpRoutes = append(httpRoutes, map[string]any{
				"match":    []map[string]any{{"host": []string{domain}}},
				"terminal": true,
				"handle":   pipeline,
			})
		}
	}

	// Catch-all silent abort routes (replaces old fake 200 banner)
	catchAllAbort := map[string]any{
		"terminal": true,
		"handle": []map[string]any{
			{"handler": "static_response", "abort": true},
		},
	}
	httpsRoutes = append(httpsRoutes, catchAllAbort)
	httpRoutes = append(httpRoutes, catchAllAbort)

	// Management Isolation: bind 127.0.0.1 + explicit MgmtListenIPs (or private/RFC1918 + Tailscale/CGNAT fallback; never public WAN)
	mgmtDomain := strings.TrimSpace(cfg.MgmtDomain)
	httpsPort := cfg.MgmtHTTPSPort
	if httpsPort <= 0 {
		httpsPort = 4438
	}
	httpPort := cfg.MgmtHTTPPort
	if httpPort <= 0 {
		httpPort = 808
	}

	var fallbackMgmt []netip.Addr
	if len(cfg.MgmtListenIPs) == 0 {
		fallbackMgmt = detectPrivateMgmtIPv4s()
	}
	mgmtIPs := resolveMgmtListenIPs(cfg.MgmtListenIPs, fallbackMgmt)
	var mgmtListenAddrs []string
	var mgmtHTTPListenAddrs []string
	if len(cfg.MgmtListenIPs) == 0 && isMgmtPublicInternetAllowed(cfg) {
		mgmtListenAddrs = []string{fmt.Sprintf(":%d", httpsPort)}
		mgmtHTTPListenAddrs = []string{fmt.Sprintf(":%d", httpPort)}
	} else {
		mgmtListenAddrs = make([]string, 0, len(mgmtIPs))
		mgmtHTTPListenAddrs = make([]string, 0, len(mgmtIPs))
		for _, ip := range mgmtIPs {
			mgmtListenAddrs = append(mgmtListenAddrs, net.JoinHostPort(ip, strconv.Itoa(httpsPort)))
			mgmtHTTPListenAddrs = append(mgmtHTTPListenAddrs, net.JoinHostPort(ip, strconv.Itoa(httpPort)))
		}
	}

	var mgmtAutomateSubjects []string
	sortedMgmtIPs := append([]string(nil), mgmtIPs...)
	sort.Strings(sortedMgmtIPs)
	for _, ip := range sortedMgmtIPs {
		internalSubjects = append(internalSubjects, ip)
		mgmtAutomateSubjects = append(mgmtAutomateSubjects, ip)
	}
	mgmtUsesACME := false
	var mgmtDNS01Subjects []string
	mgmtMode := effectiveMgmtCertMode(cfg)
	mgmtChallenge := strings.ToLower(strings.TrimSpace(cfg.MgmtCertChallenge))
	if mgmtChallenge != "http01" {
		mgmtChallenge = "dns01"
	}
	if mgmtDomain != "" {
		switch mgmtMode {
		case "custom":
			loadFiles = append(loadFiles, map[string]any{
				"certificate": filepath.ToSlash(cfg.MgmtCustomCertPath),
				"key":         filepath.ToSlash(cfg.MgmtCustomKeyPath),
				"format":      "pem",
			})
		case "letsencrypt":
			if net.ParseIP(mgmtDomain) == nil && mgmtChallenge == "http01" {
				httpACMESubjects = append(httpACMESubjects, mgmtDomain)
				mgmtAutomateSubjects = append(mgmtAutomateSubjects, mgmtDomain)
				mgmtUsesACME = true
			} else if net.ParseIP(mgmtDomain) == nil && strings.TrimSpace(cfg.Cloudflare.APIToken) != "" {
				mgmtDNS01Subjects = append(mgmtDNS01Subjects, mgmtDomain)
				mgmtAutomateSubjects = append(mgmtAutomateSubjects, mgmtDomain)
				mgmtUsesACME = true
			} else {
				internalSubjects = append(internalSubjects, mgmtDomain)
				mgmtAutomateSubjects = append(mgmtAutomateSubjects, mgmtDomain)
			}
		default:
			internalSubjects = append(internalSubjects, mgmtDomain)
			mgmtAutomateSubjects = append(mgmtAutomateSubjects, mgmtDomain)
		}
	}

	// Deduplicate subjects across automation policies so caddytls.Validate() never rejects duplicates
	claimedSubjects := make(map[string]struct{})
	dedupSubjects := func(list []string) []string {
		out := make([]string, 0, len(list))
		for _, sub := range list {
			s := strings.ToLower(strings.TrimSpace(sub))
			if s == "" {
				continue
			}
			if _, exists := claimedSubjects[s]; exists {
				continue
			}
			claimedSubjects[s] = struct{}{}
			out = append(out, s)
		}
		return out
	}
	dns01Subjects = dedupSubjects(dns01Subjects)
	mgmtDNS01Subjects = dedupSubjects(mgmtDNS01Subjects)
	httpACMESubjects = dedupSubjects(httpACMESubjects)
	internalSubjects = dedupSubjects(internalSubjects)

	// Filter mgmtAutomateSubjects to exclude site-owned ACME policies (keep mgmtDomain when srv_mgmt uses DNS-01 since automatic_https is disabled on srv_mgmt)
	acmeClaimed := make(map[string]struct{}, len(dns01Subjects)+len(mgmtDNS01Subjects)+len(httpACMESubjects))
	for _, s := range dns01Subjects {
		acmeClaimed[s] = struct{}{}
	}
	for _, s := range mgmtDNS01Subjects {
		acmeClaimed[s] = struct{}{}
	}
	for _, s := range httpACMESubjects {
		acmeClaimed[s] = struct{}{}
	}
	filteredMgmtAutomate := make([]string, 0, len(mgmtAutomateSubjects))
	seenAuto := make(map[string]struct{})
	mgmtDomainLower := strings.ToLower(mgmtDomain)
	for _, sub := range mgmtAutomateSubjects {
		s := strings.ToLower(strings.TrimSpace(sub))
		if s == "" {
			continue
		}
		if _, claimed := acmeClaimed[s]; claimed && !(mgmtUsesACME && s == mgmtDomainLower) {
			continue
		}
		if _, dup := seenAuto[s]; dup {
			continue
		}
		seenAuto[s] = struct{}{}
		filteredMgmtAutomate = append(filteredMgmtAutomate, s)
	}

	mgmtRoutes := make([]map[string]any, 0, 2)
	if len(cfg.MgmtAllowedCIDRs) > 0 {
		mgmtRoutes = append(mgmtRoutes, map[string]any{
			"match": []map[string]any{
				{
					"not": []map[string]any{
						{"remote_ip": map[string]any{"ranges": cfg.MgmtAllowedCIDRs}},
					},
				},
			},
			"terminal": true,
			"handle": []map[string]any{
				{"handler": "static_response", "abort": true},
			},
		})
	}
	mgmtRoutes = append(mgmtRoutes, map[string]any{
		"terminal": true,
		"handle": []map[string]any{
			{
				"handler": "headers",
				"response": map[string]any{
					"delete": []string{"Server", "X-Powered-By", "Via"},
				},
			},
			{
				"handler":   "reverse_proxy",
				"upstreams": []map[string]any{{"dial": "127.0.0.1:9444"}},
			},
		},
	})

	trustedRanges := buildTrustedProxyCIDRs(cfg, extraSiteTrustedProxies...)
	emptyErrors := map[string]any{
		"routes": []map[string]any{
			{
				"handle": []map[string]any{
					{
						"handler":     "static_response",
						"status_code": "{http.error.status_code}",
						"close":       true,
					},
				},
			},
		},
	}

	protocols := []string{"h1", "h2", "h3"}
	if anyHideAltSvc {
		protocols = []string{"h1", "h2"}
	}

	preTLSWrapper := map[string]any{
		"wrapper":                  "vsafegate_pre_tls",
		"allowed_snis":             allowedSNIs,
		"drop_missing_sni":         true,
		"drop_unknown_sni":         true,
		"strict_cloudflare_origin": false,
		"trusted_cidrs":            trustedRanges,
		"handshake_peek_timeout":   "5s",
	}
	if len(strictOriginSNIs) > 0 {
		preTLSWrapper["strict_origin_snis"] = strictOriginSNIs
	}

	httpLogsCfg := map[string]any{"default_logger_name": "access"}
	if len(loggerNames) > 0 {
		httpLogsCfg["logger_names"] = loggerNames
	}

	srvHTTPS := map[string]any{
		"listen":    []string{":443"},
		"protocols": protocols,
		"listener_wrappers": []map[string]any{
			preTLSWrapper,
			{"wrapper": "tls"},
		},
		"read_header_timeout":   "5s",
		"read_timeout":          "30s",
		"write_timeout":         "60s",
		"idle_timeout":          "60s",
		"read_idle_timeout":     "10s",
		"read_min_rate":         512,
		"write_idle_timeout":    "15s",
		"write_min_rate":        512,
		"max_header_bytes":      16384,
		"automatic_https":       map[string]any{"disable_redirects": true},
		"trusted_proxies":       map[string]any{"source": "static", "ranges": trustedRanges},
		"client_ip_headers":     []string{"CF-Connecting-IP", "X-Forwarded-For"},
		"trusted_proxies_strict": 1,
		"errors":                emptyErrors,
		"logs":                  httpLogsCfg,
		"routes":                httpsRoutes,
	}
	if len(allowedSNIs) > 0 {
		srvHTTPS["tls_connection_policies"] = []map[string]any{
			{"match": map[string]any{"sni": allowedSNIs}},
		}
	}

	srvHTTP := map[string]any{
		"listen":                 []string{":80"},
		"read_header_timeout":    "5s",
		"read_timeout":           "30s",
		"write_timeout":          "60s",
		"idle_timeout":           "60s",
		"max_header_bytes":       16384,
		"trusted_proxies":        map[string]any{"source": "static", "ranges": trustedRanges},
		"client_ip_headers":      []string{"CF-Connecting-IP", "X-Forwarded-For"},
		"trusted_proxies_strict": 1,
		"errors":                 emptyErrors,
		"logs":                   httpLogsCfg,
		"routes":                 httpRoutes,
	}

	srvMgmt := map[string]any{
		"listen":                  mgmtListenAddrs,
		"automatic_https":         map[string]any{"disable": true},
		"tls_connection_policies": []map[string]any{{"default_sni": "127.0.0.1"}},
		"errors":                  emptyErrors,
		"routes":                  mgmtRoutes,
	}

	servers := map[string]any{
		"srv_https": srvHTTPS,
		"srv_http":  srvHTTP,
		"srv_mgmt":  srvMgmt,
	}

	if mgmtDomain != "" {
		servers["srv_mgmt_http"] = map[string]any{
			"listen":          mgmtHTTPListenAddrs,
			"automatic_https": map[string]any{"disable": true},
			"errors":          emptyErrors,
			"routes": []map[string]any{
				{
					"terminal": true,
					"handle": []map[string]any{
						{
							"handler":     "static_response",
							"status_code": 301,
							"headers": map[string][]string{
								"Location": {fmt.Sprintf("https://%s:%d{http.request.uri}", mgmtDomain, httpsPort)},
							},
						},
					},
				},
			},
		}
	}

	tlsApp := map[string]any{}
	certsCfg := map[string]any{}
	if len(loadFiles) > 0 {
		certsCfg["load_files"] = loadFiles
	}
	if len(filteredMgmtAutomate) > 0 {
		certsCfg["automate"] = filteredMgmtAutomate
	}
	if len(certsCfg) > 0 {
		tlsApp["certificates"] = certsCfg
	}

	var policies []map[string]any
	if len(mgmtDNS01Subjects) > 0 {
		policies = append(policies, map[string]any{
			"subjects": mgmtDNS01Subjects,
			"issuers": []map[string]any{
				{
					"module": "acme",
					"challenges": map[string]any{
						"dns": map[string]any{
							"provider": map[string]any{
								"name":      "cloudflare",
								"api_token": strings.TrimSpace(cfg.Cloudflare.APIToken),
							},
						},
					},
				},
			},
		})
	}
	if len(dns01Subjects) > 0 {
		policies = append(policies, map[string]any{
			"subjects": dns01Subjects,
			"issuers": []map[string]any{
				{
					"module": "acme",
					"challenges": map[string]any{
						"dns": map[string]any{
							"provider": map[string]any{
								"name":      "cloudflare",
								"api_token": strings.TrimSpace(cfg.Cloudflare.APIToken),
							},
						},
					},
				},
			},
		})
	}
	if len(httpACMESubjects) > 0 {
		policies = append(policies, map[string]any{
			"subjects": httpACMESubjects,
			"issuers": []map[string]any{
				{
					"module": "acme",
					"challenges": map[string]any{
						"tls-alpn": map[string]any{"disabled": true},
					},
				},
			},
		})
	}
	if len(internalSubjects) > 0 {
		policies = append(policies, map[string]any{
			"subjects": internalSubjects,
			"issuers":  []map[string]any{{"module": "internal"}},
		})
	}
	if len(policies) > 0 {
		tlsApp["automation"] = map[string]any{"policies": policies}
	}

	accessLogger := map[string]any{
		"writer": map[string]any{
			"output":       "file",
			"filename":     filepath.ToSlash(accessLogPath),
			"roll":         true,
			"roll_size_mb": 50,
			"roll_keep":    5,
		},
		"encoder": map[string]any{"format": "json"},
	}
	if len(excludedSiteLoggers) > 0 {
		accessLogger["exclude"] = excludedSiteLoggers
	}
	allLoggingLogs := map[string]any{
		"access": accessLogger,
	}
	for k, v := range siteLogsCfg {
		allLoggingLogs[k] = v
	}

	return map[string]any{
		"admin": map[string]any{
			"listen": "127.0.0.1:2019",
		},
		"logging": map[string]any{
			"logs": allLoggingLogs,
		},
		"apps": map[string]any{
			"pki": map[string]any{
				"certificate_authorities": map[string]any{
					"local": map[string]any{
						"install_trust": false,
					},
				},
			},
			"tls": tlsApp,
			"http": map[string]any{
				"http_port":  80,
				"https_port": 443,
				"metrics": map[string]any{
					"per_host":             true,
					"observe_catchall_hosts": false,
				},
				"servers": servers,
			},
		},
	}
}

func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func reloadCaddyViaAdminAPI(adminAddr string, jsonData []byte) error {
	if adminAddr == "" {
		adminAddr = "127.0.0.1:2019"
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+adminAddr+"/load", bytes.NewReader(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("caddy admin /load HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (s *AppState) generateCaddyAndRules() error {
	s.mu.RLock()
	cfgSnapshot := s.config
	cfgSnapshot.Sites = append([]Site(nil), s.config.Sites...)
	cfgSnapshot.Rules = append([]CustomRule(nil), s.config.Rules...)
	cfgSnapshot.BannedIPs = append([]BannedIPEntry(nil), s.config.BannedIPs...)
	cfgSnapshot.ShieldBannedIPs = append([]ShieldBanEntry(nil), s.config.ShieldBannedIPs...)
	cfgSnapshot.BlacklistIP = append([]string(nil), s.config.BlacklistIP...)
	cfgSnapshot.WhitelistIPs = append([]WhitelistIPEntry(nil), s.config.WhitelistIPs...)
	cfgSnapshot.TrustedProxies = append([]string(nil), s.config.TrustedProxies...)
	cfgSnapshot.MgmtListenIPs = append([]string(nil), s.config.MgmtListenIPs...)
	cfgSnapshot.MgmtAllowedCIDRs = append([]string(nil), s.config.MgmtAllowedCIDRs...)
	rulesPath := s.rulesPath
	caddyPath := s.caddyPath
	auditLogPath := s.effectiveWAFAuditLogPath()
	accessLogPath := s.effectiveAccessLogPath()
	eventsSockPath := s.effectiveEventsSocketPath()
	s.mu.RUnlock()

	if rulesPath == "" {
		if os.Getenv("ENV") == "dev" {
			rulesPath = "./rules/custom-rules.conf"
		} else {
			rulesPath = "/etc/caddy/rules/custom-rules.conf"
		}
	}
	if caddyPath == "" {
		if os.Getenv("ENV") == "dev" {
			caddyPath = "./caddy.json"
		} else {
			caddyPath = "/etc/caddy/caddy.json"
		}
	}

	rulesDir := filepath.Dir(rulesPath)
	_ = os.MkdirAll(filepath.Dir(auditLogPath), 0750)
	_ = os.MkdirAll(filepath.Dir(accessLogPath), 0750)

	// 1. Write global custom-rules.conf + per-site CRS v4 configs
	globalConf := buildSiteCorazaRuleset(cfgSnapshot, nil, auditLogPath)
	if err := writeAtomicFile(rulesPath, []byte(globalConf), 0640); err != nil {
		return err
	}

	siteRulesPaths := make(map[string]string, len(cfgSnapshot.Sites))
	siteRulesContents := make(map[string]string, len(cfgSnapshot.Sites))
	for _, site := range cfgSnapshot.Sites {
		if effectiveSiteWAFMode(site) == "off" {
			continue
		}
		p := filepath.Join(rulesDir, "site-"+safeSiteRuleID(site.ID)+".conf")
		content := buildSiteCorazaRuleset(cfgSnapshot, &site, auditLogPath)
		if err := writeAtomicFile(p, []byte(content), 0640); err != nil {
			return err
		}
		siteRulesPaths[site.ID] = p
		siteRulesContents[site.ID] = content
	}

	// 2. Build & write Caddy JSON
	caddyCfg := buildCaddyJSONConfigWithOptions(cfgSnapshot, rulesDir, auditLogPath, accessLogPath, siteRulesPaths, siteRulesContents, eventsSockPath)
	jsonBytes, err := json.MarshalIndent(caddyCfg, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomicFile(caddyPath, jsonBytes, 0600); err != nil {
		return err
	}

	// 3. Reload Caddy safely via Admin API /load with supervisor/CLI fallback
	if runtime.GOOS == "linux" {
		if s.caddySupervisor != nil {
			if err := s.caddySupervisor.Reload(); err != nil && s.caddySupervisor.IsRunning() {
				log.Printf("[Caddy] Reload failed: %v", err)
				if s.alertEngine != nil {
					s.alertEngine.NotifyCaddyEvent("Caddy Reload Failed", err.Error(), AlertSeverityCritical)
				}
			}
		} else if isAddrListening("127.0.0.1:2019") {
			if err := reloadCaddyViaAdminAPI("127.0.0.1:2019", jsonBytes); err != nil {
				if bin := findCaddyBinary(); bin != "" {
					if out, cmdErr := exec.Command(bin, "reload", "--config", caddyPath, "--force").CombinedOutput(); cmdErr != nil {
						log.Printf("[Caddy] CLI reload fallback failed: %v (%s)", cmdErr, strings.TrimSpace(string(out)))
						if s.alertEngine != nil {
							s.alertEngine.NotifyCaddyEvent("Caddy Reload Failed", fmt.Sprintf("%v: %s", cmdErr, strings.TrimSpace(string(out))), AlertSeverityCritical)
						}
					}
				} else if s.alertEngine != nil {
					s.alertEngine.NotifyCaddyEvent("Caddy Reload Failed", err.Error(), AlertSeverityCritical)
				}
			}
		} else if _, err := exec.LookPath("systemctl"); err == nil {
			_ = exec.Command("systemctl", "reload", "caddy").Run()
		} else if _, err := exec.LookPath("rc-service"); err == nil {
			_ = exec.Command("rc-service", "caddy", "reload").Run()
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

// findValidPublicCertForDomain scans Caddy's certificate storage for an active,
// non-self-signed public certificate covering domain with >7 days of validity left.
func findValidPublicCertForDomain(caddyDataDir, domain string) (bool, string, time.Time) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if caddyDataDir == "" || domain == "" || net.ParseIP(domain) != nil {
		return false, "", time.Time{}
	}
	certsRoot := filepath.Join(caddyDataDir, "caddy", "certificates")
	now := time.Now()
	minValidUntil := now.Add(7 * 24 * time.Hour)

	var bestIssuer string
	var bestNotAfter time.Time
	found := false

	_ = filepath.WalkDir(certsRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		lowerName := strings.ToLower(d.Name())
		if !strings.HasSuffix(lowerName, ".crt") && !strings.HasSuffix(lowerName, ".pem") {
			return nil
		}
		// Skip Caddy's internal self-signed CA directories
		slashed := filepath.ToSlash(path)
		if strings.Contains(slashed, "/certificates/local/") || strings.Contains(slashed, "/certificates/internal/") {
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for len(raw) > 0 {
			var block *pem.Block
			block, raw = pem.Decode(raw)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, perr := x509.ParseCertificate(block.Bytes)
			if perr != nil || cert.IsCA {
				continue
			}
			if strings.Contains(cert.Issuer.CommonName, "Caddy Local Authority") || cert.Issuer.String() == cert.Subject.String() {
				continue
			}
			if verr := cert.VerifyHostname(domain); verr != nil {
				continue
			}
			if !cert.NotAfter.After(minValidUntil) {
				continue
			}
			if !found || cert.NotAfter.After(bestNotAfter) {
				found = true
				bestNotAfter = cert.NotAfter
				if cert.Issuer.CommonName != "" {
					bestIssuer = cert.Issuer.CommonName
				} else if len(cert.Issuer.Organization) > 0 {
					bestIssuer = cert.Issuer.Organization[0]
				} else {
					bestIssuer = "ACME Public CA"
				}
			}
		}
		return nil
	})
	return found, bestIssuer, bestNotAfter
}

func (s *AppState) readRecentCaddyACMEError(domain string, since time.Time) string {
	if runtime.GOOS != "linux" {
		return ""
	}
	out, err := exec.Command("journalctl", "-u", "vsafegate", "--since", since.Format("2006-01-02 15:04:05"), "--no-pager", "-n", "60").CombinedOutput()
	if err != nil {
		return ""
	}
	domLower := strings.ToLower(domain)
	lines := strings.Split(string(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := lines[i]
		ll := strings.ToLower(l)
		if !strings.Contains(ll, domLower) && !strings.Contains(ll, "acme") && !strings.Contains(ll, "ratelimit") {
			continue
		}
		if strings.Contains(ll, "ratelimited") || strings.Contains(ll, "too many certificates") {
			return "Let's Encrypt đã giới hạn tần suất cấp chứng chỉ (rateLimited / too many certificates): " + strings.TrimSpace(l)
		}
		if strings.Contains(ll, "urn:ietf:params:acme:error:") || strings.Contains(ll, "failed to obtain certificate") || strings.Contains(ll, "could not get certificate from issuer") {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

func safeSiteRuleID(id string) string {
	safeID := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, id)
	if safeID == "" {
		return "site"
	}
	return safeID
}

// ensureMgmtDomainCert checks whether domain already has a valid public certificate;
// if missing or domain changed, stages a Cloudflare DNS-01 Caddy reload and waits for
// Caddy to obtain & store the certificate before committing.
func (s *AppState) ensureMgmtDomainCert(ctx context.Context, cfgSnapshot Config) (string, string, time.Time, error) {
	if s.mgmtCertProvisioner != nil {
		return s.mgmtCertProvisioner(ctx, cfgSnapshot)
	}
	domain := strings.ToLower(strings.TrimSpace(cfgSnapshot.MgmtDomain))
	if domain == "" || net.ParseIP(domain) != nil {
		return "none", "", time.Time{}, nil
	}
	challenge := strings.ToLower(strings.TrimSpace(cfgSnapshot.MgmtCertChallenge))
	if challenge != "http01" && strings.TrimSpace(cfgSnapshot.Cloudflare.APIToken) == "" {
		return "internal", "Caddy Local Authority (Self-Signed — chưa cấu hình Cloudflare API Token)", time.Time{}, nil
	}
	dataDir := s.effectiveCaddyDataDir()
	if ok, issuer, exp := findValidPublicCertForDomain(dataDir, domain); ok {
		return "reused", issuer, exp, nil
	}

	if runtime.GOOS != "linux" || !isAddrListening("127.0.0.1:2019") {
		return "", "", time.Time{}, fmt.Errorf("Caddy Admin API (127.0.0.1:2019) không hoạt động để cấp chứng chỉ cho %s", domain)
	}

	// Build staged config with MgmtCertInternal=false to trigger Cloudflare DNS-01 issuance
	staged := cfgSnapshot
	staged.MgmtCertInternal = false
	rulesDir := filepath.Dir(s.rulesPath)
	if rulesDir == "" || rulesDir == "." {
		rulesDir = "/etc/caddy/rules"
	}
	siteRulesPaths := make(map[string]string, len(staged.Sites))
	siteRulesContents := make(map[string]string, len(staged.Sites))
	for _, site := range staged.Sites {
		if effectiveSiteWAFMode(site) == "off" {
			continue
		}
		p := filepath.Join(rulesDir, "site-"+safeSiteRuleID(site.ID)+".conf")
		if raw, err := os.ReadFile(p); err == nil {
			siteRulesPaths[site.ID] = p
			siteRulesContents[site.ID] = string(raw)
		}
	}

	stagedJSON := buildCaddyJSONConfig(staged, rulesDir, s.effectiveWAFAuditLogPath(), s.effectiveAccessLogPath(), siteRulesPaths, siteRulesContents)
	jsonBytes, err := json.MarshalIndent(stagedJSON, "", "  ")
	if err != nil {
		return "", "", time.Time{}, err
	}

	startAt := time.Now().Add(-2 * time.Second)
	if err := reloadCaddyViaAdminAPI("127.0.0.1:2019", jsonBytes); err != nil {
		return "", "", time.Time{}, fmt.Errorf("nạp cấu hình SSL cho %s thất bại: %w", domain, err)
	}

	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(60 * time.Second)
	defer deadline.Stop()

	for {
		if ok, issuer, exp := findValidPublicCertForDomain(dataDir, domain); ok {
			return "issued", issuer, exp, nil
		}
		if acmeErr := s.readRecentCaddyACMEError(domain, startAt); acmeErr != "" {
			return "", "", time.Time{}, fmt.Errorf("cấp chứng chỉ SSL cho %s thất bại: %s", domain, acmeErr)
		}
		select {
		case <-ctx.Done():
			return "", "", time.Time{}, ctx.Err()
		case <-deadline.C:
			return "", "", time.Time{}, fmt.Errorf("hết thời gian chờ (60s) cấp chứng chỉ SSL cho %s qua Cloudflare DNS-01; kiểm tra lại API Token, quyền DNS:Edit hoặc giới hạn rate limit Let's Encrypt", domain)
		case <-ticker.C:
		}
	}
}

// checkMgmtCertRenewalFallback checks whether an active Let's Encrypt cert on MgmtDomain
// has expired or failed renewal; if so, automatically falls back to MgmtCertInternal=true
// so administrators are never locked out of the management dashboard.
func (s *AppState) checkMgmtCertRenewalFallback(now time.Time) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	domain := strings.ToLower(strings.TrimSpace(s.config.MgmtDomain))
	certInternal := s.config.MgmtCertInternal
	hasCFToken := strings.TrimSpace(s.config.Cloudflare.APIToken) != ""
	s.mu.RUnlock()

	if domain == "" || net.ParseIP(domain) != nil || certInternal || !hasCFToken {
		return false
	}

	dataDir := s.effectiveCaddyDataDir()
	// Check if there is any non-expired public cert (>0s remaining)
	if ok, _, exp := findValidPublicCertForDomain(dataDir, domain); ok && exp.After(now.Add(24*time.Hour)) {
		return false
	}

	// Check whether any public cert exists at all for domain; if expired or missing while ACME failed, fallback
	certsRoot := filepath.Join(dataDir, "caddy", "certificates")
	hasUnexpiredPublic := false
	hasExpiredPublic := false
	_ = filepath.WalkDir(certsRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		lowerName := strings.ToLower(d.Name())
		if !strings.HasSuffix(lowerName, ".crt") && !strings.HasSuffix(lowerName, ".pem") {
			return nil
		}
		slashed := filepath.ToSlash(path)
		if strings.Contains(slashed, "/certificates/local/") || strings.Contains(slashed, "/certificates/internal/") {
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for len(raw) > 0 {
			var block *pem.Block
			block, raw = pem.Decode(raw)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, perr := x509.ParseCertificate(block.Bytes)
			if perr != nil || cert.IsCA || strings.Contains(cert.Issuer.CommonName, "Caddy Local Authority") {
				continue
			}
			if cert.VerifyHostname(domain) != nil {
				continue
			}
			if cert.NotAfter.After(now) {
				hasUnexpiredPublic = true
			} else {
				hasExpiredPublic = true
			}
		}
		return nil
	})

	if hasUnexpiredPublic {
		return false
	}

	acmeErr := s.readRecentCaddyACMEError(domain, now.Add(-15*time.Minute))
	if !hasExpiredPublic && acmeErr == "" {
		return false
	}

	reason := "Chứng chỉ Let's Encrypt đã hết hạn và chưa gia hạn được"
	if acmeErr != "" {
		reason = acmeErr
	}

	s.mu.Lock()
	if s.config.MgmtCertInternal || !strings.EqualFold(strings.TrimSpace(s.config.MgmtDomain), domain) {
		s.mu.Unlock()
		return false
	}
	s.config.MgmtCertInternal = true
	s.mu.Unlock()

	s.saveConfig()
	if s.reloadManager != nil {
		s.reloadManager.Trigger()
	}
	log.Printf("[Mgmt SSL] Auto-fallback sang chứng chỉ tự ký cho %s: %s", domain, reason)
	if s.adminAudit != nil {
		s.adminAudit.Record("system", "127.0.0.1", "mgmt_cert_auto_fallback", domain, "warning", reason)
	}
	if s.alertEngine != nil {
		s.alertEngine.NotifyCaddyEvent("Mgmt SSL Auto-Fallback to Self-Signed ("+domain+")", reason, AlertSeverityWarning)
	}
	return true
}

func effectiveMgmtCertMode(cfg Config) string {
	m := strings.ToLower(strings.TrimSpace(cfg.MgmtCertMode))
	if m == "custom" && strings.TrimSpace(cfg.MgmtCustomCertPath) != "" && strings.TrimSpace(cfg.MgmtCustomKeyPath) != "" {
		return "custom"
	}
	if m == "internal" || cfg.MgmtCertInternal {
		return "internal"
	}
	if m == "letsencrypt" {
		return "letsencrypt"
	}
	return "letsencrypt"
}

type MgmtPanelSSLInfo struct {
	Mode              string `json:"mode"`
	Challenge         string `json:"challenge"` // "dns01" | "http01"
	MgmtDomain        string `json:"mgmt_domain"`
	CFTokenConfigured bool   `json:"cf_token_configured"`
	Status            string `json:"status"` // "active", "self_signed", "expired", "none"
	Domain            string `json:"domain"`
	Issuer            string `json:"issuer"`
	NotBefore         string `json:"not_before,omitempty"`
	NotAfter          string `json:"not_after,omitempty"`
	TotalDays         int    `json:"total_days"`
	DaysRemaining     int    `json:"days_remaining"`
	CertPEM           string `json:"cert_pem,omitempty"`
	KeyPEM            string `json:"key_pem,omitempty"`
}

func inspectActiveMgmtCert(cfg Config, caddyDataDir string) MgmtPanelSSLInfo {
	mode := effectiveMgmtCertMode(cfg)
	challenge := strings.ToLower(strings.TrimSpace(cfg.MgmtCertChallenge))
	if challenge != "http01" {
		challenge = "dns01"
	}
	dom := strings.TrimSpace(cfg.MgmtDomain)
	info := MgmtPanelSSLInfo{
		Mode:              mode,
		Challenge:         challenge,
		MgmtDomain:        dom,
		CFTokenConfigured: strings.TrimSpace(cfg.Cloudflare.APIToken) != "",
		Status:            "none",
		Domain:            dom,
	}

	var bestCert *x509.Certificate
	var bestCertPEM, bestKeyPEM string

	loadPair := func(crtPath, keyPath string) (*x509.Certificate, string, string) {
		rawCrt, err := os.ReadFile(crtPath)
		if err != nil {
			return nil, "", ""
		}
		tmp := rawCrt
		for len(tmp) > 0 {
			var blk *pem.Block
			blk, tmp = pem.Decode(tmp)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				continue
			}
			c, perr := x509.ParseCertificate(blk.Bytes)
			if perr != nil || c.IsCA {
				continue
			}
			keyBytes, _ := os.ReadFile(keyPath)
			return c, string(rawCrt), string(keyBytes)
		}
		return nil, "", ""
	}

	if mode == "custom" && cfg.MgmtCustomCertPath != "" && cfg.MgmtCustomKeyPath != "" {
		c, cpem, kpem := loadPair(cfg.MgmtCustomCertPath, cfg.MgmtCustomKeyPath)
		bestCert, bestCertPEM, bestKeyPEM = c, cpem, kpem
	} else if caddyDataDir != "" {
		certsRoot := filepath.Join(caddyDataDir, "caddy", "certificates")
		targetDom := strings.ToLower(dom)
		wantPublic := mode == "letsencrypt" && targetDom != "" && net.ParseIP(targetDom) == nil

		_ = filepath.WalkDir(certsRoot, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			lowerName := strings.ToLower(d.Name())
			if !strings.HasSuffix(lowerName, ".crt") && !strings.HasSuffix(lowerName, ".pem") {
				return nil
			}
			slashed := filepath.ToSlash(path)
			isLocal := strings.Contains(slashed, "/certificates/local/") || strings.Contains(slashed, "/certificates/internal/")
			if wantPublic && isLocal {
				return nil
			}
			if !wantPublic && !isLocal {
				return nil
			}
			ext := filepath.Ext(path)
			keyPath := strings.TrimSuffix(path, ext) + ".key"
			c, cpem, kpem := loadPair(path, keyPath)
			if c == nil {
				return nil
			}
			if targetDom != "" {
				if c.VerifyHostname(targetDom) != nil {
					return nil
				}
			} else if c.VerifyHostname("127.0.0.1") != nil {
				return nil
			}
			if bestCert == nil || c.NotAfter.After(bestCert.NotAfter) {
				bestCert, bestCertPEM, bestKeyPEM = c, cpem, kpem
			}
			return nil
		})

		// If letsencrypt requested but no public cert cached yet, show local internal fallback cert if present
		if bestCert == nil && wantPublic {
			_ = filepath.WalkDir(certsRoot, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() || (!strings.HasSuffix(strings.ToLower(d.Name()), ".crt") && !strings.HasSuffix(strings.ToLower(d.Name()), ".pem")) {
					return nil
				}
				ext := filepath.Ext(path)
				c, cpem, kpem := loadPair(path, strings.TrimSuffix(path, ext)+".key")
				if c != nil && c.VerifyHostname(targetDom) == nil {
					if bestCert == nil || c.NotAfter.After(bestCert.NotAfter) {
						bestCert, bestCertPEM, bestKeyPEM = c, cpem, kpem
					}
				}
				return nil
			})
		}
	}

	if bestCert == nil {
		return info
	}

	now := time.Now()
	if len(bestCert.DNSNames) > 0 {
		info.Domain = strings.Join(bestCert.DNSNames, ", ")
	} else if bestCert.Subject.CommonName != "" {
		info.Domain = bestCert.Subject.CommonName
	}
	if bestCert.Issuer.CommonName != "" {
		info.Issuer = bestCert.Issuer.CommonName
	} else if len(bestCert.Issuer.Organization) > 0 {
		info.Issuer = bestCert.Issuer.Organization[0]
	}
	info.NotBefore = bestCert.NotBefore.UTC().Format(time.RFC3339)
	info.NotAfter = bestCert.NotAfter.UTC().Format(time.RFC3339)
	totalDays := int(bestCert.NotAfter.Sub(bestCert.NotBefore).Hours() / 24)
	if totalDays < 1 {
		totalDays = 1
	}
	remDays := int(bestCert.NotAfter.Sub(now).Hours() / 24)
	if remDays < 0 {
		remDays = 0
	}
	info.TotalDays = totalDays
	info.DaysRemaining = remDays
	info.CertPEM = bestCertPEM
	info.KeyPEM = bestKeyPEM

	isSelfOrLocal := strings.Contains(info.Issuer, "Caddy Local Authority") || bestCert.Issuer.String() == bestCert.Subject.String()
	if now.After(bestCert.NotAfter) {
		info.Status = "expired"
	} else if isSelfOrLocal {
		info.Status = "self_signed"
	} else {
		info.Status = "active"
	}
	return info
}
