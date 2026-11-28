package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

//go:embed web/*
var webFiles embed.FS

type AppState struct {
	mu              sync.RWMutex
	config          Config
	configPath      string
	caddyPath       string
	rulesPath       string
	logsPath        string
	certsDir        string
	wafAuditPath    string
	accessLogPath   string
	recentLogs      []AttackLog
	bannedMap       map[string]*BannedIPEntry
	sessions        map[string]Session
	sessionsMu      sync.RWMutex
	sshBannedCount  int64
	portScanCount   int64
	logManager      *PersistentLogManager
	reloadManager   *ReloadManager
	caddySupervisor *CaddySupervisor
	loginLimiter       *loginRateLimiter
	autoProxyCtrl      *AutoProxyController
	offenseCount       map[string]int
	eventsSocketPath   string
	shieldSockMu       sync.Mutex
	shieldSockListener net.Listener
	shieldLogSampleMu  sync.Mutex
	shieldLogSampleAt  map[string]time.Time
	firewallSyncHook   func()
	firewallMu         sync.Mutex
	bansStateMu        sync.Mutex
	bansStatePath      string
	offenseRecords     map[string]OffenseRecord
	telemetry          *TelemetryStore
	telemetryPath      string
	alertEngine        *AlertEngine
	adminAudit         *AdminAuditLogger
	adminAuditPath     string
	sseBroker           *SSEBroker
	caddyDataDir        string
	mgmtCertProvisioner func(ctx context.Context, cfgSnapshot Config) (certStatus string, issuer string, notAfter time.Time, err error)
}

func (s *AppState) effectiveAdminAuditPath() string {
	if s != nil && strings.TrimSpace(s.adminAuditPath) != "" {
		return strings.TrimSpace(s.adminAuditPath)
	}
	if s != nil && s.logsPath != "" && s.logsPath != "/var/log/vsafegate/attacks.jsonl" && s.logsPath != "./attacks.jsonl" {
		return filepath.Join(filepath.Dir(s.logsPath), "audit.jsonl")
	}
	if s != nil && s.configPath != "" && s.configPath != "/etc/vsafegate/config.json" && s.configPath != "./config.json" {
		return filepath.Join(filepath.Dir(s.configPath), "audit.jsonl")
	}
	if os.Getenv("ENV") == "dev" {
		return "./audit.jsonl"
	}
	return "/var/log/vsafegate/audit.jsonl"
}

func (s *AppState) ensurePhase4Subsystems() {
	if s == nil {
		return
	}
	if s.offenseCount == nil {
		s.offenseCount = make(map[string]int)
	}
	if s.offenseRecords == nil {
		s.offenseRecords = make(map[string]OffenseRecord)
	}
	if s.adminAudit == nil {
		s.adminAudit = NewAdminAuditLogger(s.effectiveAdminAuditPath())
	}
	if s.sseBroker == nil {
		s.sseBroker = NewSSEBroker()
	}
	if s.telemetry == nil {
		s.telemetry = NewTelemetryStore(s, s.effectiveTelemetryPath())
	}
	if s.alertEngine == nil {
		s.alertEngine = NewAlertEngine(s)
	}
}

func (s *AppState) requestActor(r *http.Request) string {
	if s != nil && r != nil {
		if cookie, err := r.Cookie("vsafegate_session"); err == nil {
			if user, ok := s.validateSession(cookie.Value); ok && strings.TrimSpace(user) != "" {
				return user
			}
		}
	}
	return "admin"
}

func (s *AppState) recordAuditFromRequest(r *http.Request, action, target, status, detail string) {
	if s == nil || s.adminAudit == nil {
		return
	}
	actor := s.requestActor(r)
	srcIP := ""
	if r != nil {
		srcIP = extractClientIP(r)
	}
	s.adminAudit.Record(actor, srcIP, action, target, status, detail)
}

func (s *AppState) triggerFirewallSync() {
	if s.firewallSyncHook != nil {
		s.firewallSyncHook()
		return
	}
	go s.applyIptablesRules()
}

var state *AppState

func isProcessRunning(name string) bool {
	out, err := exec.Command("pidof", name).CombinedOutput()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return true
	}
	out, err = exec.Command("pgrep", "-x", name).CombinedOutput()
	return err == nil && len(strings.TrimSpace(string(out))) > 0
}

func isServiceActive(service string) bool {
	if _, err := exec.LookPath("systemctl"); err == nil {
		out, err := exec.Command("systemctl", "is-active", service).CombinedOutput()
		return err == nil && strings.TrimSpace(string(out)) == "active"
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		out, err := exec.Command("rc-service", service, "status").CombinedOutput()
		return err == nil && strings.Contains(strings.ToLower(string(out)), "started")
	}
	return isProcessRunning(service)
}

func countSuricataRules() int {
	rulePaths := []string{
		"/etc/suricata/rules/suricata.rules",
		"/var/lib/suricata/rules/suricata.rules",
		"/etc/suricata/rules/default.rules",
	}
	for _, p := range rulePaths {
		f, err := os.Open(p)
		if err == nil {
			scanner := bufio.NewScanner(f)
			count := 0
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "alert") || strings.HasPrefix(line, "drop") || strings.HasPrefix(line, "reject") {
					count++
				}
			}
			f.Close()
			if count > 0 {
				return count
			}
		}
	}
	return 0
}

func initDefaults(cfgPath, caddyPath, rulesPath, logsPath string) *AppState {
	s := &AppState{
		configPath:     cfgPath,
		caddyPath:      caddyPath,
		rulesPath:      rulesPath,
		logsPath:       logsPath,
		recentLogs:     make([]AttackLog, 0),
		bannedMap:      make(map[string]*BannedIPEntry),
		sessions:       make(map[string]Session),
		loginLimiter:   newLoginRateLimiter(),
		offenseCount:   make(map[string]int),
		offenseRecords: make(map[string]OffenseRecord),
	}
	s.autoProxyCtrl = newAutoProxyController(s)
	s.adminAudit = NewAdminAuditLogger(s.effectiveAdminAuditPath())
	s.sseBroker = NewSSEBroker()
	s.telemetry = NewTelemetryStore(s, s.effectiveTelemetryPath())
	s.alertEngine = NewAlertEngine(s)

	// Initialize Persistent Log Manager
	s.logManager = NewPersistentLogManager(logsPath, 20*1024*1024)
	if recent, err := s.logManager.ReadRecent(100); err == nil && len(recent) > 0 {
		s.recentLogs = recent
	}

	// Initialize Reload Manager (2 seconds debounce)
	s.reloadManager = NewReloadManager(s, 2*time.Second)

	// Load configuration
	loaded := false
	if data, err := os.ReadFile(cfgPath); err == nil {
		if err := json.Unmarshal(data, &s.config); err == nil {
			loaded = true
		}
	}

	if !loaded {
		s.config = Config{
			Sites:            []Site{},
			BlacklistIP:      []string{},
			BannedIPs:        []BannedIPEntry{},
			WhitelistIPs:     []WhitelistIPEntry{},
			DefaultBanTTL:    24, // Default 24 hours auto-ban
			DefensePolicy: DefensePolicy{
				DefaultBanTTLHours:  24,
				SSHGuardEnabled:     true,
				SSHMaxAttempts:      3,
				CanaryEnabled:       true,
				WAFAutoBanEnabled:   true,
				WAFAutoBanThreshold: 10,
				SuricataAutoBan:     true,
			},
			GeoIPMode:        "disabled",
			AllowedCountries: []string{},
			BlockedCountries: []string{"CN", "RU"},
			MgmtDomain:       "",
			MgmtHTTPSPort:    4438,
			MgmtHTTPPort:     808,
			L4Services:       []L4Service{},
			Rules: []CustomRule{
				{
					ID:          "rule-1001",
					RuleID:      1001,
					Name:        "Chặn truy cập trang Admin ngoài mạng nội bộ",
					Target:      "URI",
					Operator:    "rx",
					Pattern:     "^/(admin|wp-admin|wp-login\\.php|phpmyadmin)",
					Action:      "deny",
					Description: "Chỉ cho phép IP mạng nội bộ truy cập /admin",
					Enabled:     true,
				},
				{
					ID:          "rule-1002",
					RuleID:      1002,
					Name:        "Chặn Scanner & Bad Bots (sqlmap, nikto, gobuster)",
					Target:      "HEADER:User-Agent",
					Operator:    "rx",
					Pattern:     "(?i)(sqlmap|nikto|acunetix|gobuster|dirbuster|nmap|masscan|wpscan)",
					Action:      "deny",
					Description: "Tự động phát hiện và chặn các công cụ quét tự động của hacker",
					Enabled:     true,
				},
				{
					ID:          "rule-1003",
					RuleID:      1003,
					Name:        "Chặn SQL Injection (Mẫu phổ biến)",
					Target:      "ARGS",
					Operator:    "rx",
					Pattern:     "(?i)(\\bunion\\b.*\\bselect\\b|\\bor\\b\\s+1=1|\\bdrop\\b\\s+\\btable\\b|;\\s*--)",
					Action:      "deny",
					Description: "Chặn các ký tự tấn công cơ sở dữ liệu qua query hoặc form",
					Enabled:     true,
				},
				{
					ID:          "rule-1004",
					RuleID:      1004,
					Name:        "Chặn Cross-Site Scripting (XSS)",
					Target:      "ARGS",
					Operator:    "rx",
					Pattern:     "(?i)(<script[^>]*>|javascript:|onerror=|onload=)",
					Action:      "deny",
					Description: "Ngăn chặn chèn mã độc JavaScript vào ứng dụng",
					Enabled:     true,
				},
			},
		}
	}

	// Auto-migrations & defaults
	if s.config.GeoIPMode == "" {
		s.config.GeoIPMode = "disabled"
	}
	if len(s.config.BlockedCountries) == 0 {
		s.config.BlockedCountries = []string{"CN", "RU"}
	}
	if s.config.DefaultBanTTL < 0 {
		s.config.DefaultBanTTL = 24
	}
	if len(s.config.WhitelistIPs) == 0 {
		now := time.Now()
		s.config.WhitelistIPs = []WhitelistIPEntry{
			{IP: "10.0.0.0/8", Note: "Dải mạng nội bộ LAN (Class A)", CreatedAt: now},
			{IP: "172.16.0.0/12", Note: "Dải mạng riêng (Class B)", CreatedAt: now},
			{IP: "192.168.0.0/16", Note: "Dải mạng nội bộ LAN Gateway / Router (Class C)", CreatedAt: now},
			{IP: "127.0.0.1", Note: "Localhost loopback", CreatedAt: now},
		}
	}
	if s.config.DefensePolicy.DefaultBanTTLHours < 0 {
		s.config.DefensePolicy.DefaultBanTTLHours = s.config.DefaultBanTTL
	}
	if s.config.DefensePolicy.DefaultBanTTLHours != s.config.DefaultBanTTL {
		if s.config.DefensePolicy.DefaultBanTTLHours >= 0 {
			s.config.DefaultBanTTL = s.config.DefensePolicy.DefaultBanTTLHours
		} else {
			s.config.DefensePolicy.DefaultBanTTLHours = s.config.DefaultBanTTL
		}
	}
	if s.config.DefensePolicy.SSHMaxAttempts <= 0 {
		s.config.DefensePolicy.SSHMaxAttempts = 3
	}
	if s.config.DefensePolicy.WAFAutoBanThreshold <= 0 {
		s.config.DefensePolicy.WAFAutoBanThreshold = 10
	}
	if !s.config.DefensePolicy.SSHGuardEnabled && !s.config.DefensePolicy.CanaryEnabled && !s.config.DefensePolicy.WAFAutoBanEnabled && !s.config.DefensePolicy.SuricataAutoBan {
		s.config.DefensePolicy.SSHGuardEnabled = true
		s.config.DefensePolicy.CanaryEnabled = true
		s.config.DefensePolicy.WAFAutoBanEnabled = true
		s.config.DefensePolicy.SuricataAutoBan = true
	}
	if s.config.MgmtHTTPSPort <= 0 {
		s.config.MgmtHTTPSPort = 4438
	}
	if s.config.MgmtHTTPPort <= 0 {
		s.config.MgmtHTTPPort = 808
	}

	// Migrate legacy BlacklistIP to BannedIPs
	if len(s.config.BannedIPs) == 0 && len(s.config.BlacklistIP) > 0 {
		for _, ip := range s.config.BlacklistIP {
			if ip != "" {
				s.config.BannedIPs = append(s.config.BannedIPs, BannedIPEntry{
					IP:            ip,
					Reason:        "[Migration] Khóa từ danh sách cũ",
					BannedAt:      time.Now(),
					ExpiresAt:     time.Time{}, // Permanent
					DurationHours: 0,
				})
			}
		}
	}

	// Populate in-memory map
	for i := range s.config.BannedIPs {
		b := &s.config.BannedIPs[i]
		s.bannedMap[b.IP] = b
	}

	// Auto-hash AdminPassword if plain-text
	if s.config.AdminPassword != "" && !strings.HasPrefix(s.config.AdminPassword, "$pbkdf_") {
		s.config.AdminPassword = hashPassword(s.config.AdminPassword)
	}

	// Ensure L7 Shield HMAC challenge secret exists
	if strings.TrimSpace(s.config.ShieldChallengeSecret) == "" {
		secretBytes := make([]byte, 32)
		if _, err := rand.Read(secretBytes); err == nil {
			s.config.ShieldChallengeSecret = hex.EncodeToString(secretBytes)
		}
	}

	if s.config.LogRetentionDays <= 0 {
		s.config.LogRetentionDays = 30
	}
	if s.config.LogMaxDiskMB <= 0 {
		s.config.LogMaxDiskMB = 512
	}
	if s.logManager != nil {
		s.logManager.ConfigureRetention(s.config.LogRetentionDays, s.config.LogMaxDiskMB)
	}
	s.loadBansState()

	if loaded {
		_ = os.Chmod(cfgPath, 0600)
	}

	s.saveConfig()
	l4Manager.SetBanChecker(func(ip string) bool {
		s.mu.RLock()
		_, banned := s.bannedMap[ip]
		whitelisted := s.isWhitelistedLocked(ip)
		s.mu.RUnlock()
		return banned && !whitelisted
	})
	l4Manager.Sync(s.config.L4Services)
	s.startSuricataWatcher()
	s.initFirewall()
	go s.syncGeoIP()
	s.startBanTTLExpirer()
	s.startSessionCleaner()

	return s
}

var configWriteMu sync.Mutex

// saveConfigLocked assumes s.mu is already held by the caller (read or write).
func (s *AppState) saveConfigLocked() {
	configWriteMu.Lock()
	defer configWriteMu.Unlock()

	data, err := json.MarshalIndent(s.config, "", "  ")
	if err != nil {
		return
	}

	dir := filepath.Dir(s.configPath)
	_ = os.MkdirAll(dir, 0750)

	// Atomic write with strict 0600 owner-only permissions
	tmpFile := s.configPath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err == nil {
		if err := os.Rename(tmpFile, s.configPath); err == nil {
			_ = os.Chmod(s.configPath, 0600)
		}
	}
}

// saveConfig acquires s.mu.RLock() safely when s.mu is NOT held by the caller.
func (s *AppState) saveConfig() {
	configWriteMu.Lock()
	defer configWriteMu.Unlock()

	s.mu.RLock()
	data, err := json.MarshalIndent(s.config, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return
	}

	dir := filepath.Dir(s.configPath)
	_ = os.MkdirAll(dir, 0750)

	// Atomic write with strict 0600 owner-only permissions
	tmpFile := s.configPath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err == nil {
		if err := os.Rename(tmpFile, s.configPath); err == nil {
			_ = os.Chmod(s.configPath, 0600)
		}
	}
}

func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
			if secSite := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")); strings.EqualFold(secSite, "cross-site") {
				http.Error(w, `{"error":"CSRF rejected (cross-site)"}`, http.StatusForbidden)
				return
			}
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if strings.EqualFold(origin, "null") {
				http.Error(w, `{"error":"CSRF rejected (null origin)"}`, http.StatusForbidden)
				return
			}
			if origin != "" {
				u, err := url.Parse(origin)
				if err != nil || !strings.EqualFold(u.Host, r.Host) {
					http.Error(w, `{"error":"CSRF rejected (origin mismatch)"}`, http.StatusForbidden)
					return
				}
			} else if ref := strings.TrimSpace(r.Header.Get("Referer")); ref != "" {
				u, err := url.Parse(ref)
				if err != nil || !strings.EqualFold(u.Host, r.Host) {
					http.Error(w, `{"error":"CSRF rejected (referer mismatch)"}`, http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("vsafegate_session")
		if err != nil {
			http.Error(w, `{"error":"Chưa đăng nhập"}`, http.StatusUnauthorized)
			return
		}
		_, ok := state.validateSession(cookie.Value)
		if !ok {
			http.Error(w, `{"error":"Phiên làm việc hết hạn hoặc không hợp lệ"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

var reValidSiteDomain = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*(:\d{1,5})?$`)

func validateSiteInput(site *Site) error {
	site.Domain = strings.ToLower(strings.TrimSpace(site.Domain))
	if site.Domain == "" || len(site.Domain) > 253 {
		return errors.New("tên miền không được để trống hoặc quá dài")
	}
	if strings.ContainsAny(site.Domain, " \t\r\n/\\{}'\";#@") || strings.Contains(site.Domain, "..") || !reValidSiteDomain.MatchString(site.Domain) {
		return errors.New("tên miền chứa ký tự không hợp lệ")
	}

	validateUpstream := func(raw string) (string, error) {
		u := strings.TrimRight(strings.TrimSpace(raw), "/")
		if u == "" {
			return "", errors.New("địa chỉ máy chủ đích (upstream) không được để trống")
		}
		if strings.ContainsAny(u, " \t\r\n{}'\";#`") {
			return "", errors.New("upstream chứa ký tự không hợp lệ")
		}
		if !strings.Contains(u, "://") {
			u = "http://" + u
		}
		parsed, err := url.Parse(u)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return "", fmt.Errorf("upstream không hợp lệ (%q): chỉ hỗ trợ http:// hoặc https://", raw)
		}
		return u, nil
	}

	cleanMain, err := validateUpstream(site.Upstream)
	if err != nil {
		return err
	}
	site.Upstream = cleanMain

	if len(site.Upstreams) > 0 {
		cleaned := make([]string, 0, len(site.Upstreams))
		for _, up := range site.Upstreams {
			if strings.TrimSpace(up) == "" {
				continue
			}
			cu, uerr := validateUpstream(up)
			if uerr != nil {
				return uerr
			}
			cleaned = append(cleaned, cu)
		}
		site.Upstreams = cleaned
	}

	wm := strings.ToLower(strings.TrimSpace(site.WAFMode))
	switch wm {
	case "":
		if site.WAF {
			site.WAFMode = "on"
		} else {
			site.WAFMode = "off"
		}
	case "on", "detection":
		site.WAFMode = wm
		site.WAF = true
	case "off":
		site.WAFMode = "off"
		site.WAF = false
	default:
		return errors.New("waf_mode phải là 'on', 'detection' hoặc 'off'")
	}

	if site.ParanoiaLevel < 0 || site.ParanoiaLevel > 4 {
		return errors.New("paranoia_level phải trong khoảng 1..4")
	}
	if site.ParanoiaLevel == 0 {
		site.ParanoiaLevel = 1
	}
	if site.InboundAnomalyThreshold < 0 || site.OutboundAnomalyThreshold < 0 {
		return errors.New("ngưỡng anomaly phải >= 0")
	}
	if site.RequestBodyMaxMB < 0 || site.RequestBodyMaxMB > 500 {
		return errors.New("request_body_max_mb phải từ 0..500 MB")
	}
	if site.AutoProxyWindowSec < 0 || site.AutoProxyHoldMinutes < 0 || site.AutoProxyThresholdRPS < 0 || site.AutoProxyThresholdDropPS < 0 {
		return errors.New("thông số Auto-Proxy không được âm")
	}

	ap := strings.ToLower(strings.TrimSpace(site.AppPreset))
	switch ap {
	case "", "generic", "wordpress", "api", "nextcloud", "nas":
		if ap == "" {
			ap = "generic"
		}
		site.AppPreset = ap
	default:
		return fmt.Errorf("app_preset không hợp lệ: %q", site.AppPreset)
	}

	cm := strings.ToLower(strings.TrimSpace(site.CertMode))
	switch cm {
	case "", "auto_http", "cloudflare_dns01", "uploaded", "internal", "none":
		if cm != "" {
			site.CertMode = cm
		} else if site.SSL {
			site.CertMode = "auto_http"
		} else {
			site.CertMode = "none"
		}
	default:
		return errors.New("cert_mode không hợp lệ")
	}

	for _, cidr := range site.TrustedProxies {
		s := strings.TrimSpace(cidr)
		if s == "" {
			continue
		}
		if _, err := netip.ParsePrefix(s); err != nil {
			if _, aerr := netip.ParseAddr(s); aerr != nil {
				return fmt.Errorf("trusted_proxy không hợp lệ: %q", cidr)
			}
		}
	}

	// Phase 2: L7 Shield & Anti-Bot validation
	sm := strings.ToLower(strings.TrimSpace(site.ShieldMode))
	switch sm {
	case "":
		if site.UnderAttackMode {
			site.ShieldMode = "under_attack"
		} else {
			site.ShieldMode = "normal"
		}
	case "normal":
		site.ShieldMode = "normal"
		site.UnderAttackMode = false
	case "under_attack":
		site.ShieldMode = "under_attack"
		site.UnderAttackMode = true
	case "off":
		site.ShieldMode = "off"
		site.UnderAttackMode = false
	default:
		return fmt.Errorf("shield_mode không hợp lệ: %q (chỉ hỗ trợ normal, under_attack, off)", site.ShieldMode)
	}
	if site.RateLimitRPS < 0 || site.RateLimitBurst < 0 || site.SubnetRateLimitRPS < 0 || site.HostRateLimitRPS < 0 || site.MaxConcurrentPerIP < 0 {
		return errors.New("thông số giới hạn tốc độ Shield không được âm")
	}
	if site.ChallengeDifficulty != 0 && (site.ChallengeDifficulty < 8 || site.ChallengeDifficulty > 22) {
		return errors.New("challenge_difficulty phải trong khoảng 8..22 (hoặc 0 để dùng mặc định)")
	}
	cleanPaths := func(paths []string, label string) ([]string, error) {
		if len(paths) == 0 {
			return nil, nil
		}
		out := make([]string, 0, len(paths))
		for _, p := range paths {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\r\n\t\x00 ") {
				return nil, fmt.Errorf("%s không hợp lệ: %q", label, p)
			}
			out = append(out, p)
		}
		return out, nil
	}
	var perr error
	if site.ExemptPaths, perr = cleanPaths(site.ExemptPaths, "exempt_paths"); perr != nil {
		return perr
	}
	if site.APIPaths, perr = cleanPaths(site.APIPaths, "api_paths"); perr != nil {
		return perr
	}
	if len(site.SensitiveRoutes) > 0 {
		cleanSens := make([]ShieldSensitiveRoute, 0, len(site.SensitiveRoutes))
		for _, sr := range site.SensitiveRoutes {
			sr.PathPrefix = strings.TrimSpace(sr.PathPrefix)
			if sr.PathPrefix == "" {
				continue
			}
			if !strings.HasPrefix(sr.PathPrefix, "/") || strings.ContainsAny(sr.PathPrefix, "\r\n\t\x00 ") {
				return fmt.Errorf("sensitive_route path không hợp lệ: %q", sr.PathPrefix)
			}
			if sr.RPS < 0 || sr.Burst < 0 {
				return errors.New("sensitive_route rps/burst không được âm")
			}
			cleanSens = append(cleanSens, sr)
		}
		site.SensitiveRoutes = cleanSens
	}

	// Phase 3: L7 Load Balancing, Health Check & Origin TLS validation
	lb := strings.ToLower(strings.TrimSpace(site.LBPolicy))
	switch lb {
	case "", "round_robin", "least_conn", "ip_hash", "client_ip_hash", "first", "random":
		site.LBPolicy = lb
	default:
		return fmt.Errorf("lb_policy không hợp lệ: %q", site.LBPolicy)
	}
	site.HealthCheckPath = strings.TrimSpace(site.HealthCheckPath)
	if site.HealthCheckPath != "" {
		if !strings.HasPrefix(site.HealthCheckPath, "/") || strings.ContainsAny(site.HealthCheckPath, "\r\n\t\x00 ") {
			return errors.New("health_check_path phải bắt đầu bằng '/' và không chứa khoảng trắng")
		}
	}
	site.HealthCheckInterval = strings.TrimSpace(site.HealthCheckInterval)
	if site.HealthCheckInterval != "" {
		d, derr := time.ParseDuration(site.HealthCheckInterval)
		if derr != nil || d <= 0 {
			return fmt.Errorf("health_check_interval không hợp lệ: %q (vd: 10s)", site.HealthCheckInterval)
		}
	}
	site.HealthCheckTimeout = strings.TrimSpace(site.HealthCheckTimeout)
	if site.HealthCheckTimeout != "" {
		d, derr := time.ParseDuration(site.HealthCheckTimeout)
		if derr != nil || d <= 0 {
			return fmt.Errorf("health_check_timeout không hợp lệ: %q (vd: 3s)", site.HealthCheckTimeout)
		}
	}
	otls := strings.ToLower(strings.TrimSpace(site.OriginTLSMode))
	switch otls {
	case "", "insecure", "system", "custom_ca":
		site.OriginTLSMode = otls
	default:
		return fmt.Errorf("origin_tls_mode không hợp lệ: %q (chỉ hỗ trợ insecure, system, custom_ca)", site.OriginTLSMode)
	}
	site.OriginTLSSNI = strings.ToLower(strings.TrimSpace(site.OriginTLSSNI))
	if site.OriginTLSSNI != "" && strings.ContainsAny(site.OriginTLSSNI, "* \t\r\n/\\{}'\";#@") {
		return errors.New("origin_tls_sni chứa ký tự không hợp lệ")
	}
	return nil
}

func validateAndNormalizeL4Service(svc *L4Service) error {
	svc.Name = strings.TrimSpace(svc.Name)
	svc.Protocol = strings.ToLower(strings.TrimSpace(svc.Protocol))
	if svc.Protocol == "" {
		svc.Protocol = "tcp"
	}
	if svc.Protocol != "tcp" && svc.Protocol != "udp" {
		return errors.New("protocol L4 chỉ hỗ trợ 'tcp' hoặc 'udp'")
	}
	if strings.TrimSpace(svc.Mode) == "" {
		svc.Mode = "proxy"
	}
	if svc.ListenPort <= 0 || svc.ListenPort > 65535 {
		return errors.New("Cổng lắng nghe không hợp lệ (1-65535)")
	}

	seen := make(map[string]bool)
	var cleanBackends []string
	addBackend := func(raw string) error {
		addr := strings.TrimSpace(raw)
		if addr == "" {
			return nil
		}
		if strings.ContainsAny(addr, " \t\r\n\x00{}'\";#`") {
			return fmt.Errorf("địa chỉ backend chứa ký tự không hợp lệ: %q", addr)
		}
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil || strings.TrimSpace(host) == "" {
			return fmt.Errorf("địa chỉ backend phải có dạng host:port: %q", addr)
		}
		p, perr := strconv.Atoi(portStr)
		if perr != nil || p <= 0 || p > 65535 {
			return fmt.Errorf("cổng backend không hợp lệ trong %q", addr)
		}
		if !seen[addr] {
			seen[addr] = true
			cleanBackends = append(cleanBackends, addr)
		}
		return nil
	}

	for _, b := range svc.Backends {
		if err := addBackend(b); err != nil {
			return err
		}
	}
	if len(cleanBackends) == 0 && strings.TrimSpace(svc.BackendAddr) != "" {
		if err := addBackend(svc.BackendAddr); err != nil {
			return err
		}
	}
	if len(cleanBackends) == 0 {
		return errors.New("Địa chỉ máy chủ đích (Backend) không được để trống")
	}
	svc.Backends = cleanBackends
	svc.BackendAddr = cleanBackends[0]

	lb := strings.ToLower(strings.TrimSpace(svc.LBPolicy))
	switch lb {
	case "", "round_robin", "least_conn", "ip_hash":
		svc.LBPolicy = lb
	default:
		return fmt.Errorf("lb_policy L4 không hợp lệ: %q", svc.LBPolicy)
	}

	pp := strings.ToLower(strings.TrimSpace(svc.ProxyProtocol))
	switch pp {
	case "", "off", "v1", "v2":
		svc.ProxyProtocol = pp
	default:
		return fmt.Errorf("proxy_protocol không hợp lệ: %q (chỉ hỗ trợ off, v1, v2)", svc.ProxyProtocol)
	}
	if svc.Protocol == "udp" && (pp == "v1" || pp == "v2") {
		return errors.New("PROXY Protocol chỉ hỗ trợ dịch vụ TCP")
	}

	if svc.MaxConns < 0 || svc.MaxConnsPerIP < 0 || svc.RateLimit < 0 || svc.DialTimeoutSec < 0 || svc.IdleTimeoutSec < 0 || svc.HealthCheckIntervalSec < 0 {
		return errors.New("các thông số giới hạn và timeout L4 phải >= 0")
	}
	return nil
}

func validateCustomRuleInput(rule *CustomRule) error {
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Pattern = strings.TrimSpace(rule.Pattern)
	rule.Target = strings.TrimSpace(rule.Target)
	rule.Operator = strings.TrimSpace(rule.Operator)
	rule.Action = strings.ToLower(strings.TrimSpace(rule.Action))

	if rule.Name == "" {
		return errors.New("tên rule không được để trống")
	}
	if rule.Pattern == "" {
		return errors.New("mẫu nhận dạng (pattern) không được để trống")
	}
	if strings.ContainsAny(rule.Name, "\r\n\x00") ||
		strings.ContainsAny(rule.Pattern, "\r\n\x00") ||
		strings.ContainsAny(rule.Target, "\r\n\x00") ||
		strings.ContainsAny(rule.Description, "\r\n\x00") {
		return errors.New("dữ liệu rule chứa ký tự điều khiển không hợp lệ")
	}

	if rule.Target == "" {
		rule.Target = "URI"
	}
	upperTarget := strings.ToUpper(rule.Target)
	if strings.HasPrefix(upperTarget, "HEADER:") {
		hdr := strings.TrimSpace(rule.Target[7:])
		if !reValidHeader.MatchString(hdr) {
			return fmt.Errorf("tên header trong target không hợp lệ: %q", hdr)
		}
		rule.Target = "HEADER:" + hdr
	} else {
		switch upperTarget {
		case "URI", "ARGS", "METHOD", "IP", "USER_AGENT", "ARGS|URI", "URI|ARGS":
			rule.Target = upperTarget
		default:
			return fmt.Errorf("target không được hỗ trợ: %q", rule.Target)
		}
	}

	if rule.Operator == "" {
		rule.Operator = "rx"
	}
	switch rule.Operator {
	case "rx", "ipMatch", "contains", "beginsWith":
	default:
		return fmt.Errorf("operator không hợp lệ: %q", rule.Operator)
	}
	if rule.Operator == "rx" {
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return fmt.Errorf("biểu thức regex không hợp lệ: %w", err)
		}
	} else if rule.Operator == "ipMatch" {
		tokens := strings.FieldsFunc(rule.Pattern, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		})
		if len(tokens) == 0 {
			return errors.New("ipMatch cần ít nhất 1 địa chỉ IP hoặc CIDR hợp lệ")
		}
		for _, tok := range tokens {
			if _, perr := netip.ParsePrefix(tok); perr != nil {
				if _, aerr := netip.ParseAddr(tok); aerr != nil {
					return fmt.Errorf("ipMatch chứa IP/CIDR không hợp lệ: %q", tok)
				}
			}
		}
	}

	if rule.Action == "" {
		rule.Action = "deny"
	}
	switch rule.Action {
	case "deny", "drop", "allow":
	default:
		return fmt.Errorf("action không hợp lệ (chỉ hỗ trợ deny, drop, allow): %q", rule.Action)
	}
	return nil
}

func handleCLISubcommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	cmd := strings.ToLower(strings.TrimSpace(args[0]))
	switch cmd {
	case "status":
		if _, err := exec.LookPath("systemctl"); err == nil {
			out, err := exec.Command("systemctl", "status", "vsafegate", "--no-pager").CombinedOutput()
			fmt.Print(string(out))
			if err != nil {
				os.Exit(1)
			}
			return true
		}
		if _, err := exec.LookPath("rc-service"); err == nil {
			out, err := exec.Command("rc-service", "vsafegate", "status").CombinedOutput()
			fmt.Print(string(out))
			if err != nil {
				os.Exit(1)
			}
			return true
		}
		fmt.Println("vSafeGate service manager not found (systemd/openrc)")
		return true
	case "restart":
		var c *exec.Cmd
		if _, err := exec.LookPath("systemctl"); err == nil {
			c = exec.Command("systemctl", "restart", "vsafegate")
		} else if _, err := exec.LookPath("rc-service"); err == nil {
			c = exec.Command("rc-service", "vsafegate", "restart")
		}
		if c == nil {
			fmt.Fprintln(os.Stderr, "Unsupported init system")
			os.Exit(1)
		}
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		if err := c.Run(); err != nil {
			os.Exit(1)
		}
		fmt.Println("vSafeGate restarted.")
		return true
	case "logs":
		var c *exec.Cmd
		if _, err := exec.LookPath("journalctl"); err == nil {
			c = exec.Command("journalctl", "-u", "vsafegate", "-f", "-n", "100")
		} else {
			c = exec.Command("tail", "-f", "-n", "100", "/var/log/vsafegate.log")
		}
		c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
		_ = c.Run()
		return true
	case "update":
		c := exec.Command("/usr/local/bin/vsafegate-update")
		c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
		if err := c.Run(); err != nil {
			os.Exit(1)
		}
		return true
	case "uninstall":
		uArgs := append([]string{"--uninstall"}, args[1:]...)
		c := exec.Command("/usr/local/bin/vsafegate-uninstall", uArgs...)
		c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
		if err := c.Run(); err != nil {
			os.Exit(1)
		}
		return true
	case "version", "--version", "-v":
		fmt.Println("vSafeGate v" + AppVersion)
		return true
	case "help", "--help", "-h":
		fmt.Println("Usage: vsafegate [command]")
		fmt.Println("Commands:")
		fmt.Println("  status      Show service status")
		fmt.Println("  restart     Restart vSafeGate service")
		fmt.Println("  logs        Tail live service logs")
		fmt.Println("  update      Update to latest release")
		fmt.Println("  uninstall   Uninstall vSafeGate cleanly")
		fmt.Println("  version     Print version")
		return true
	}
	return false
}

func main() {
	if handleCLISubcommand(os.Args[1:]) {
		return
	}
	caddyPath := "/etc/caddy/caddy.json"
	rulesPath := "/etc/caddy/rules/custom-rules.conf"
	configPath := "/etc/vsafegate/config.json"
	logsPath := "/var/log/vsafegate/attacks.jsonl"

	initAuthHelper()

	if os.Getenv("ENV") == "dev" {
		caddyPath = "./caddy.json"
		rulesPath = "./rules/custom-rules.conf"
		configPath = "./config.json"
		logsPath = "./attacks.jsonl"
	}

	state = initDefaults(configPath, caddyPath, rulesPath, logsPath)
	state.generateCaddyAndRules()
	if err := state.startShieldEventReceiver(); err != nil {
		log.Printf("[Shield Receiver] Warning: failed to start event socket: %v", err)
	}
	if runtime.GOOS == "linux" && os.Getenv("ENV") != "dev" {
		state.caddySupervisor = NewCaddySupervisor(caddyPath)
		state.caddySupervisor.SetOnUnexpectedExit(func(uptime time.Duration, err error) {
			if state.alertEngine != nil {
				msg := fmt.Sprintf("Caddy exited unexpectedly after %s (%v); supervisor is restarting it.", uptime.Round(time.Millisecond), err)
				state.alertEngine.NotifyCaddyEvent("Caddy Unexpected Restart", msg, AlertSeverityCritical)
			}
		})
		state.caddySupervisor.Start()
	}
	state.startLogWatcher()
	startCPUMonitor()
	state.startSSHWatcher()
	state.startCanaryHoneypot()
	if state.autoProxyCtrl != nil {
		state.autoProxyCtrl.Start()
	}
	if state.telemetry != nil {
		state.telemetry.Start()
	}
	if state.alertEngine != nil {
		state.alertEngine.Start()
	}
	state.startSharedThreatSyncLoop(nil)

	handler := setupRouter(state)
	port := "127.0.0.1:9444"
	effectiveMgmtIPs := resolveMgmtListenIPs(state.config.MgmtListenIPs, detectPrivateMgmtIPv4s())
	fmt.Printf("=====================================================\n")
	fmt.Printf("vSafeGate v%s Virtual Security Management Dashboard Started on %s\n", AppVersion, port)
	if state.config.MgmtDomain != "" {
		fmt.Printf("Web Panel (HTTPS): https://%s:%d\n", state.config.MgmtDomain, state.config.MgmtHTTPSPort)
		fmt.Printf("Web Panel (HTTP):  http://%s:%d\n", state.config.MgmtDomain, state.config.MgmtHTTPPort)
	} else {
		fmt.Printf("Web Panel: Port %d\n", state.config.MgmtHTTPSPort)
	}
	fmt.Printf("Web Panel Bind IPs: %s\n", strings.Join(effectiveMgmtIPs, ", "))
	fmt.Printf("Auth Method: Linux System Accounts (PAM / shadow) & Admin Config\n")
	fmt.Printf("Active Defenses: Caddy L7 JSON + Pre-TLS + Shield, SSH Guard, Canary, GeoIP, Auto-Ban TTL (%dh)\n", state.config.DefaultBanTTL)
	fmt.Printf("Persistent Log: %s\n", logsPath)
	fmt.Printf("=====================================================\n")

	srv := &http.Server{
		Addr:              port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("[Shutdown] Received signal %v, stopping managed services cleanly...", sig)
		if state.alertEngine != nil {
			state.alertEngine.Stop()
		}
		if state.telemetry != nil {
			state.telemetry.Stop()
		}
		if state.caddySupervisor != nil {
			state.caddySupervisor.Stop()
		}
		state.stopShieldEventReceiver()
		l4Manager.Sync(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		if state.caddySupervisor != nil {
			state.caddySupervisor.Stop()
		}
		log.Fatalf("Server failed: %v", err)
	}
}

func setupRouter(s *AppState) http.Handler {
	state = s
	s.ensurePhase4Subsystems()
	if s.loginLimiter == nil {
		s.loginLimiter = newLoginRateLimiter()
	}
	if s.autoProxyCtrl == nil {
		s.autoProxyCtrl = newAutoProxyController(s)
	}

	mux := http.NewServeMux()

	// Favicon Handlers
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		data, err := webFiles.ReadFile("web/favicon.ico")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(data)
	})

	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		data, err := webFiles.ReadFile("web/favicon.svg")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(data)
	})

	// Static UI assets
	sub, err := fs.Sub(webFiles, "web")
	if err != nil {
		log.Fatalf("Failed to load embedded web assets: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// Authentication Endpoints
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		clientIP := extractClientIP(r)
		w.Header().Set("Content-Type", "application/json")
		if blocked, retryAfter := state.loginLimiter.IsBlocked(clientIP); blocked {
			mins := int(retryAfter.Minutes()) + 1
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("Quá nhiều lần đăng nhập thất bại. Vui lòng thử lại sau %d phút.", mins),
			})
			return
		}

		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "Invalid Request", http.StatusBadRequest)
			return
		}

		if !verifyLinuxAuth(creds.Username, creds.Password) {
			if state.adminAudit != nil {
				state.adminAudit.Record(creds.Username, clientIP, "login_failed", creds.Username, "denied", "Invalid credentials")
			}
			locked, lockDur := state.loginLimiter.RecordFailure(clientIP)
			if locked {
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("Tạm khóa đăng nhập %d phút do sai mật khẩu quá 5 lần.", int(lockDur.Minutes())),
				})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Tên đăng nhập hoặc mật khẩu không chính xác!"})
			return
		}
		state.loginLimiter.Reset(clientIP)

		token := state.createSession(creds.Username)
		if state.adminAudit != nil {
			state.adminAudit.Record(creds.Username, clientIP, "login", creds.Username, "success", "Web UI login")
		}
		isHTTPS := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
		http.SetCookie(w, &http.Cookie{
			Name:     "vsafegate_session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   isHTTPS,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   86400, // 24 hours
		})

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"username": creds.Username,
		})
	})

	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if cookie, err := r.Cookie("vsafegate_session"); err == nil {
			if uname, ok := state.validateSession(cookie.Value); ok && state.adminAudit != nil {
				state.adminAudit.Record(uname, extractClientIP(r), "logout", uname, "success", "Web UI logout")
			}
			state.revokeSession(cookie.Value)
		}
		isHTTPS := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
		http.SetCookie(w, &http.Cookie{
			Name:     "vsafegate_session",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   isHTTPS,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
	})

	mux.HandleFunc("/api/auth/password", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		cookie, _ := r.Cookie("vsafegate_session")
		username, _ := state.validateSession(cookie.Value)
		var req struct {
			CurrentPassword string `json:"current_password"`
			NewPassword     string `json:"new_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid Request", http.StatusBadRequest)
			return
		}
		if err := changeLocalAdminPassword(state, username, req.CurrentPassword, req.NewPassword); err != nil {
			state.recordAuditFromRequest(r, "password_change", username, "error", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		state.recordAuditFromRequest(r, "password_change", username, "success", "Local admin password updated")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))

	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cookie, err := r.Cookie("vsafegate_session")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{"authenticated": false})
			return
		}
		username, ok := state.validateSession(cookie.Value)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{"authenticated": false})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": true,
			"username":      username,
		})
	})

	// System Live Metrics Endpoint
	mux.HandleFunc("/api/system/metrics", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		metrics := state.getSystemMetrics()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metrics)
	}))

	// GeoIP Country Endpoints
	mux.HandleFunc("/api/geoip", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		defer state.mu.RUnlock()

		mode := state.config.GeoIPMode
		if mode == "" {
			mode = "disabled"
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"geoip_mode":          mode,
			"allowed_countries":   state.config.AllowedCountries,
			"blocked_countries":   state.config.BlockedCountries,
			"ipset_allowed_count": getIpsetCount("vsafegate-allowed"),
			"ipset_blocked_count": getIpsetCount("vsafegate-countries"),
			"presets":             getGeoIPPresetList(),
		})
	}))

	mux.HandleFunc("/api/geoip/mode", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		newMode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
		if newMode != "disabled" && newMode != "whitelist" && newMode != "blacklist" {
			http.Error(w, "Chế độ không hợp lệ (phải là 'disabled', 'whitelist' hoặc 'blacklist')", 400)
			return
		}

		state.mu.Lock()
		state.config.GeoIPMode = newMode
		state.mu.Unlock()
		state.saveConfig()
		go state.syncGeoIP()
		state.recordAuditFromRequest(r, "geoip_mode", newMode, "success", "Changed GeoIP mode")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "ok",
			"geoip_mode": newMode,
		})
	}))

	mux.HandleFunc("/api/geoip/toggle", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		code := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("code")))
		if len(code) != 2 {
			http.Error(w, "Mã quốc gia không hợp lệ (phải là 2 ký tự ISO)", 400)
			return
		}

		state.mu.Lock()
		mode := state.config.GeoIPMode
		if mode == "" {
			mode = "disabled"
		}

		found := false
		if mode == "whitelist" {
			newList := make([]string, 0)
			for _, c := range state.config.AllowedCountries {
				if strings.ToUpper(c) == code {
					found = true
				} else {
					newList = append(newList, c)
				}
			}
			if !found {
				newList = append(newList, code)
			}
			state.config.AllowedCountries = newList
		} else {
			newList := make([]string, 0)
			for _, c := range state.config.BlockedCountries {
				if strings.ToUpper(c) == code {
					found = true
				} else {
					newList = append(newList, c)
				}
			}
			if !found {
				newList = append(newList, code)
			}
			state.config.BlockedCountries = newList
		}
		state.mu.Unlock()
		state.saveConfig()
		go state.syncGeoIP()
		state.recordAuditFromRequest(r, "geoip_toggle", code, "success", fmt.Sprintf("mode=%s action=%s", mode, map[bool]string{true: "removed", false: "added"}[found]))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "ok",
			"code":       code,
			"action":     map[bool]string{true: "removed", false: "added"}[found],
			"geoip_mode": mode,
		})
	}))

	mux.HandleFunc("/api/geoip/custom", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			Code string `json:"code"`
			Mode string `json:"mode,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid body", 400)
			return
		}
		code := strings.ToUpper(strings.TrimSpace(payload.Code))
		if len(code) != 2 {
			http.Error(w, "Mã quốc gia không hợp lệ (phải là 2 ký tự ISO, ví dụ: VN, FR, DE, SG)", 400)
			return
		}
		reqMode := strings.ToLower(strings.TrimSpace(payload.Mode))
		if reqMode != "" && reqMode != "whitelist" && reqMode != "blacklist" {
			http.Error(w, "Chế độ GeoIP không hợp lệ (phải là 'whitelist' hoặc 'blacklist')", 400)
			return
		}

		state.mu.Lock()
		if reqMode != "" && state.config.GeoIPMode != reqMode {
			state.config.GeoIPMode = reqMode
		}
		mode := state.config.GeoIPMode
		if mode == "" {
			mode = "disabled"
		}

		changed := reqMode != ""
		if mode == "whitelist" {
			exists := false
			for _, c := range state.config.AllowedCountries {
				if strings.ToUpper(c) == code {
					exists = true
					break
				}
			}
			if !exists {
				state.config.AllowedCountries = append(state.config.AllowedCountries, code)
				changed = true
			}
		} else {
			exists := false
			for _, c := range state.config.BlockedCountries {
				if strings.ToUpper(c) == code {
					exists = true
					break
				}
			}
			if !exists {
				state.config.BlockedCountries = append(state.config.BlockedCountries, code)
				changed = true
			}
		}
		state.mu.Unlock()

		if changed {
			state.saveConfig()
			go state.syncGeoIP()
			state.recordAuditFromRequest(r, "geoip_custom", code, "success", fmt.Sprintf("mode=%s", mode))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "ok",
			"code":       code,
			"geoip_mode": mode,
		})
	}))

	// L4 Services API
	mux.HandleFunc("/api/l4/services", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodGet {
			state.mu.RLock()
			services := make([]L4Service, len(state.config.L4Services))
			copy(services, state.config.L4Services)
			state.mu.RUnlock()

			l4Manager.mu.Lock()
			for i := range services {
				svc := &services[i]
				if managed, ok := l4Manager.services[svc.ID]; ok {
					svc.ActiveConns = atomic.LoadInt64(&managed.ActiveConns)
					svc.TotalConns = atomic.LoadInt64(&managed.TotalConns)
					svc.BytesIn = atomic.LoadInt64(&managed.BytesIn)
					svc.BytesOut = atomic.LoadInt64(&managed.BytesOut)
				}
			}
			l4Manager.mu.Unlock()

			json.NewEncoder(w).Encode(services)
			return
		}

		if r.Method == http.MethodPost {
			var newSvc L4Service
			if err := json.NewDecoder(r.Body).Decode(&newSvc); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if newSvc.ID == "" {
				newSvc.ID = fmt.Sprintf("l4-%d", time.Now().UnixNano())
			}
			if err := validateAndNormalizeL4Service(&newSvc); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}

			state.mu.Lock()
			for _, s := range state.config.L4Services {
				existingProto := strings.ToLower(strings.TrimSpace(s.Protocol))
				if existingProto == "" {
					existingProto = "tcp"
				}
				if s.ListenPort == newSvc.ListenPort && existingProto == newSvc.Protocol {
					state.mu.Unlock()
					http.Error(w, fmt.Sprintf("Cổng %s/%d đã được cấu hình cho dịch vụ '%s'", strings.ToUpper(newSvc.Protocol), newSvc.ListenPort, s.Name), 400)
					return
				}
			}

			state.config.L4Services = append(state.config.L4Services, newSvc)
			servicesCopy := make([]L4Service, len(state.config.L4Services))
			copy(servicesCopy, state.config.L4Services)
			state.mu.Unlock()

			state.saveConfig()
			l4Manager.Sync(servicesCopy)
			state.triggerFirewallSync()
			state.recordAuditFromRequest(r, "l4_create", newSvc.Name, "success", fmt.Sprintf("%s:%d", newSvc.Protocol, newSvc.ListenPort))
			json.NewEncoder(w).Encode(newSvc)
			return
		}

		if r.Method == http.MethodPut {
			var updated L4Service
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if err := validateAndNormalizeL4Service(&updated); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			found := false
			state.mu.Lock()
			for _, s := range state.config.L4Services {
				existingProto := strings.ToLower(strings.TrimSpace(s.Protocol))
				if existingProto == "" {
					existingProto = "tcp"
				}
				if s.ID != updated.ID && s.ListenPort == updated.ListenPort && existingProto == updated.Protocol {
					state.mu.Unlock()
					http.Error(w, fmt.Sprintf("Cổng %s/%d đã được cấu hình cho dịch vụ '%s'", strings.ToUpper(updated.Protocol), updated.ListenPort, s.Name), 400)
					return
				}
			}
			for i, s := range state.config.L4Services {
				if s.ID == updated.ID {
					state.config.L4Services[i].Name = updated.Name
					state.config.L4Services[i].ListenPort = updated.ListenPort
					state.config.L4Services[i].BackendAddr = updated.BackendAddr
					state.config.L4Services[i].Backends = updated.Backends
					state.config.L4Services[i].Protocol = updated.Protocol
					state.config.L4Services[i].LBPolicy = updated.LBPolicy
					state.config.L4Services[i].ProxyProtocol = updated.ProxyProtocol
					state.config.L4Services[i].Mode = updated.Mode
					state.config.L4Services[i].MaxConns = updated.MaxConns
					state.config.L4Services[i].MaxConnsPerIP = updated.MaxConnsPerIP
					state.config.L4Services[i].RateLimit = updated.RateLimit
					state.config.L4Services[i].DialTimeoutSec = updated.DialTimeoutSec
					state.config.L4Services[i].IdleTimeoutSec = updated.IdleTimeoutSec
					state.config.L4Services[i].HealthCheckIntervalSec = updated.HealthCheckIntervalSec
					state.config.L4Services[i].Description = updated.Description
					state.config.L4Services[i].Enabled = updated.Enabled
					found = true
					break
				}
			}
			servicesCopy := make([]L4Service, len(state.config.L4Services))
			copy(servicesCopy, state.config.L4Services)
			state.mu.Unlock()

			if !found {
				http.Error(w, "Service not found", 404)
				return
			}
			state.saveConfig()
			l4Manager.Sync(servicesCopy)
			state.triggerFirewallSync()
			state.recordAuditFromRequest(r, "l4_update", updated.Name, "success", fmt.Sprintf("%s:%d", updated.Protocol, updated.ListenPort))
			json.NewEncoder(w).Encode(updated)
			return
		}

		if r.Method == http.MethodDelete {
			id := r.URL.Query().Get("id")
			state.mu.Lock()
			filtered := make([]L4Service, 0)
			for _, s := range state.config.L4Services {
				if s.ID != id {
					filtered = append(filtered, s)
				}
			}
			state.config.L4Services = filtered
			servicesCopy := make([]L4Service, len(state.config.L4Services))
			copy(servicesCopy, state.config.L4Services)
			state.mu.Unlock()

			state.saveConfig()
			l4Manager.Sync(servicesCopy)
			state.triggerFirewallSync()
			state.recordAuditFromRequest(r, "l4_delete", id, "success", "Removed L4 service")
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}
	}))

	mux.HandleFunc("/api/l4/services/toggle", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "application/json")
		var toggled L4Service
		found := false

		state.mu.Lock()
		for i, s := range state.config.L4Services {
			if s.ID == id {
				state.config.L4Services[i].Enabled = !state.config.L4Services[i].Enabled
				toggled = state.config.L4Services[i]
				found = true
				break
			}
		}
		servicesCopy := make([]L4Service, len(state.config.L4Services))
		copy(servicesCopy, state.config.L4Services)
		state.mu.Unlock()

		if !found {
			http.Error(w, "Service not found", 404)
			return
		}

		state.saveConfig()
		l4Manager.Sync(servicesCopy)
		state.triggerFirewallSync()
		state.recordAuditFromRequest(r, "l4_toggle", toggled.Name, "success", fmt.Sprintf("enabled=%v", toggled.Enabled))
		json.NewEncoder(w).Encode(toggled)
	}))

	// Suricata IDS Stats API
	mux.HandleFunc("/api/ids/stats", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		idsRecentMu.RLock()
		recent := make([]AttackLog, len(idsRecentAlerts))
		copy(recent, idsRecentAlerts)
		idsRecentMu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(IDSStats{
			Running:       isProcessRunning("suricata") || isServiceActive("suricata"),
			TotalAlerts:   atomic.LoadInt64(&idsAlertTotal),
			Severity1High: atomic.LoadInt64(&idsSeverity1),
			Severity2Med:  atomic.LoadInt64(&idsSeverity2),
			Severity3Low:  atomic.LoadInt64(&idsSeverity3),
			RulesLoaded:   countSuricataRules(),
			RecentAlerts:  recent,
		})
	}))

	// System Services Status API (Real Check)
	mux.HandleFunc("/api/system/services", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		caddyStatus := "inactive"
		caddyManaged := false
		if state.caddySupervisor != nil {
			caddyManaged = state.caddySupervisor.IsManaged()
			if state.caddySupervisor.IsRunning() {
				caddyStatus = "running"
			}
		} else if isProcessRunning("caddy") || isServiceActive("caddy") {
			caddyStatus = "running"
		}

		suricataStatus := "inactive"
		if isProcessRunning("suricata") || isServiceActive("suricata") {
			suricataStatus = "active"
		}

		fwStatus := "inactive"
		if runtime.GOOS == "linux" {
			ipsetOK := exec.Command("ipset", "list", "vsafegate-blacklist", "-terse").Run() == nil
			iptablesOK := exec.Command("iptables", "-L", "INPUT", "-n").Run() == nil
			if ipsetOK && iptablesOK {
				fwStatus = "active"
			}
		}

		l4Status := "inactive"
		l4Manager.mu.Lock()
		if len(l4Manager.listeners) > 0 {
			l4Status = "active"
		}
		l4Manager.mu.Unlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"caddy_waf":     caddyStatus,
			"caddy_managed": caddyManaged,
			"iptables_fw":   fwStatus,
			"suricata_ids":  suricataStatus,
			"l4_gateway":    l4Status,
		})
	}))

	// General Status API
	mux.HandleFunc("/api/status", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		defer state.mu.RUnlock()

		initSystem := "Native Linux"
		if _, err := exec.LookPath("systemctl"); err == nil {
			initSystem = "Native Systemd"
		} else if _, err := exec.LookPath("rc-service"); err == nil {
			initSystem = "Native OpenRC"
		}

		bannedCount := len(state.config.BannedIPs)
		if bannedCount == 0 {
			bannedCount = len(state.config.BlacklistIP)
		}

		totalAttacks := len(state.recentLogs)
		if state.logManager != nil {
			if cnt := state.logManager.TotalCount(); cnt > 0 {
				totalAttacks = cnt
			}
		}

		var caddyManaged bool
		var caddyRestarts int64
		if state.caddySupervisor != nil {
			caddyManaged = state.caddySupervisor.IsManaged()
			caddyRestarts = state.caddySupervisor.RestartCount()
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version":         AppVersion,
			"status":          fmt.Sprintf("ACTIVE (%s)", initSystem),
			"engine":          "OWASP Coraza v4 + Caddy Core",
			"caddy_managed":   caddyManaged,
			"caddy_restarts":  caddyRestarts,
			"sites_count":     len(state.config.Sites),
			"rules_count":     len(state.config.Rules),
			"blacklist_count": bannedCount,
			"attacks_blocked": totalAttacks,
			"uptime":          "Running smoothly",
			"ssh_bans":        atomic.LoadInt64(&state.sshBannedCount),
			"port_scan_bans":  atomic.LoadInt64(&state.portScanCount),
			"geoip_mode":      state.config.GeoIPMode,
			"default_ban_ttl": state.config.DefaultBanTTL,
			"mgmt_https_port": state.config.MgmtHTTPSPort,
			"mgmt_http_port":  state.config.MgmtHTTPPort,
		})
	}))

	// Sites API
	mux.HandleFunc("/api/sites", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			state.mu.RLock()
			sites := make([]Site, len(state.config.Sites))
			copy(sites, state.config.Sites)
			state.mu.RUnlock()
			json.NewEncoder(w).Encode(sites)
			return
		}

		if r.Method == http.MethodPost {
			var newSite Site
			if err := json.NewDecoder(r.Body).Decode(&newSite); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if err := validateSiteInput(&newSite); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if newSite.ID == "" {
				newSite.ID = fmt.Sprintf("site-%d", time.Now().UnixNano())
			} else {
				newSite.ID = strings.TrimSpace(newSite.ID)
				if !reSafeCertID.MatchString(newSite.ID) {
					http.Error(w, "ID site không hợp lệ (chỉ cho phép chữ, số, _, -)", 400)
					return
				}
			}
			if strings.TrimSpace(newSite.OriginTLSCAPEM) != "" {
				caPath, caErr := state.saveUploadedOriginCA(newSite.ID, newSite.OriginTLSCAPEM)
				if caErr != nil {
					http.Error(w, caErr.Error(), 400)
					return
				}
				newSite.OriginTLSCAPath = caPath
				newSite.OriginTLSCAPEM = ""
			}
			if newSite.OriginTLSMode == "custom_ca" && strings.TrimSpace(newSite.OriginTLSCAPath) == "" {
				http.Error(w, "Chế độ Origin TLS custom_ca yêu cầu nội dung CA PEM", 400)
				return
			}
			newSite.CreatedAt = time.Now()

			state.mu.Lock()
			for _, ex := range state.config.Sites {
				if ex.ID == newSite.ID {
					state.mu.Unlock()
					if newSite.OriginTLSCAPath != "" {
						_ = os.Remove(newSite.OriginTLSCAPath)
					}
					http.Error(w, "ID site đã tồn tại", 400)
					return
				}
				if strings.EqualFold(ex.Domain, newSite.Domain) {
					state.mu.Unlock()
					if newSite.OriginTLSCAPath != "" {
						_ = os.Remove(newSite.OriginTLSCAPath)
					}
					http.Error(w, "Tên miền đã tồn tại", 400)
					return
				}
			}
			state.config.Sites = append(state.config.Sites, newSite)
			state.mu.Unlock()

			state.saveConfig()
			state.triggerFirewallSync()
			if state.reloadManager != nil {
				state.reloadManager.Trigger()
			}
			state.recordAuditFromRequest(r, "site_create", newSite.Domain, "success", fmt.Sprintf("id=%s upstream=%s", newSite.ID, newSite.Upstream))
			json.NewEncoder(w).Encode(newSite)
			return
		}

		if r.Method == http.MethodPut {
			var updated Site
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if err := validateSiteInput(&updated); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if !reSafeCertID.MatchString(updated.ID) {
				http.Error(w, "ID site không hợp lệ", 400)
				return
			}

			var newOriginCAPath string
			if strings.TrimSpace(updated.OriginTLSCAPEM) != "" {
				caPath, caErr := state.saveUploadedOriginCA(updated.ID, updated.OriginTLSCAPEM)
				if caErr != nil {
					http.Error(w, caErr.Error(), 400)
					return
				}
				newOriginCAPath = caPath
				updated.OriginTLSCAPath = caPath
				updated.OriginTLSCAPEM = ""
			}

			found := false
			var oldOriginCAToRemove string
			state.mu.Lock()
			for _, ex := range state.config.Sites {
				if ex.ID != updated.ID && strings.EqualFold(ex.Domain, updated.Domain) {
					state.mu.Unlock()
					http.Error(w, "Tên miền đã tồn tại", 400)
					return
				}
			}
			for i, s := range state.config.Sites {
				if s.ID == updated.ID {
					// Preserve server-managed cert paths/expiry & active failover state when not replaced
					if updated.CustomCertPath == "" {
						updated.CustomCertPath = s.CustomCertPath
						updated.CustomKeyPath = s.CustomKeyPath
						updated.CustomCertExpiry = s.CustomCertExpiry
						updated.CustomCertIssuer = s.CustomCertIssuer
					}
					if newOriginCAPath == "" && updated.OriginTLSCAPath == "" {
						if updated.OriginTLSMode == "custom_ca" {
							updated.OriginTLSCAPath = s.OriginTLSCAPath
						} else if s.OriginTLSCAPath != "" {
							oldOriginCAToRemove = s.OriginTLSCAPath
						}
					}
					if updated.OriginTLSMode == "custom_ca" && strings.TrimSpace(updated.OriginTLSCAPath) == "" {
						state.mu.Unlock()
						http.Error(w, "Chế độ Origin TLS custom_ca yêu cầu nội dung CA PEM", 400)
						return
					}
					if len(updated.Exclusions) == 0 && s.Exclusions != nil {
						updated.Exclusions = s.Exclusions
					}
					updated.AutoProxyActive = s.AutoProxyActive
					updated.AutoProxyActivatedAt = s.AutoProxyActivatedAt
					updated.CreatedAt = s.CreatedAt
					state.config.Sites[i] = updated
					found = true
					break
				}
			}
			state.mu.Unlock()

			if !found {
				if newOriginCAPath != "" {
					_ = os.Remove(newOriginCAPath)
				}
				http.Error(w, "Site not found", 404)
				return
			}
			if oldOriginCAToRemove != "" {
				_ = os.Remove(oldOriginCAToRemove)
			}
			state.saveConfig()
			state.triggerFirewallSync()
			if state.reloadManager != nil {
				state.reloadManager.Trigger()
			}
			state.recordAuditFromRequest(r, "site_update", updated.Domain, "success", fmt.Sprintf("id=%s shield=%s waf=%s", updated.ID, updated.ShieldMode, updated.WAFMode))
			json.NewEncoder(w).Encode(updated)
			return
		}

		if r.Method == http.MethodDelete {
			id := r.URL.Query().Get("id")
			var certToRemove, keyToRemove, originCAToRemove string
			state.mu.Lock()
			filtered := make([]Site, 0)
			for _, s := range state.config.Sites {
				if s.ID != id {
					filtered = append(filtered, s)
				} else {
					certToRemove = s.CustomCertPath
					keyToRemove = s.CustomKeyPath
					originCAToRemove = s.OriginTLSCAPath
				}
			}
			state.config.Sites = filtered
			state.mu.Unlock()

			if certToRemove != "" {
				_ = os.Remove(certToRemove)
			}
			if keyToRemove != "" {
				_ = os.Remove(keyToRemove)
			}
			if originCAToRemove != "" {
				_ = os.Remove(originCAToRemove)
			}

			state.saveConfig()
			state.triggerFirewallSync()
			if state.reloadManager != nil {
				state.reloadManager.Trigger()
			}
			state.recordAuditFromRequest(r, "site_delete", id, "success", "Removed protected site")
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}
	}))

	// Custom Certificate Upload & Removal API
	mux.HandleFunc("/api/sites/cert", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			var siteID, certPEM, keyPEM string
			ct := r.Header.Get("Content-Type")
			if strings.HasPrefix(ct, "multipart/form-data") {
				if err := r.ParseMultipartForm(4 << 20); err != nil {
					http.Error(w, "Lỗi đọc form upload cert: "+err.Error(), 400)
					return
				}
				siteID = r.FormValue("site_id")
				readFormOrFile := func(field string) string {
					if f, _, ferr := r.FormFile(field); ferr == nil {
						defer f.Close()
						b, _ := io.ReadAll(io.LimitReader(f, 1<<20))
						return string(b)
					}
					return r.FormValue(field)
				}
				certPEM = readFormOrFile("cert")
				if certPEM == "" {
					certPEM = r.FormValue("cert_pem")
				}
				keyPEM = readFormOrFile("key")
				if keyPEM == "" {
					keyPEM = r.FormValue("key_pem")
				}
			} else {
				var req struct {
					SiteID  string `json:"site_id"`
					CertPEM string `json:"cert_pem"`
					KeyPEM  string `json:"key_pem"`
				}
				if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&req); err != nil {
					http.Error(w, "Payload JSON không hợp lệ", 400)
					return
				}
				siteID, certPEM, keyPEM = req.SiteID, req.CertPEM, req.KeyPEM
			}

			meta, err := state.saveUploadedSiteCert(siteID, certPEM, keyPEM)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			state.recordAuditFromRequest(r, "site_cert_upload", siteID, "success", "Uploaded custom TLS cert")
			json.NewEncoder(w).Encode(map[string]any{
				"status": "ok",
				"cert":   meta,
			})
			return
		}

		if r.Method == http.MethodDelete {
			siteID := strings.TrimSpace(r.URL.Query().Get("site_id"))
			if siteID == "" {
				http.Error(w, "site_id required", 400)
				return
			}
			var oldCert, oldKey string
			found := false
			state.mu.Lock()
			for i := range state.config.Sites {
				if state.config.Sites[i].ID == siteID {
					oldCert = state.config.Sites[i].CustomCertPath
					oldKey = state.config.Sites[i].CustomKeyPath
					state.config.Sites[i].CustomCertPath = ""
					state.config.Sites[i].CustomKeyPath = ""
					state.config.Sites[i].CustomCertExpiry = ""
					state.config.Sites[i].CustomCertIssuer = ""
					if state.config.Sites[i].CertMode == "uploaded" {
						state.config.Sites[i].CertMode = "auto_http"
					}
					found = true
					break
				}
			}
			state.mu.Unlock()
			if !found {
				http.Error(w, "Site not found", 404)
				return
			}
			if oldCert != "" {
				_ = os.Remove(oldCert)
			}
			if oldKey != "" {
				_ = os.Remove(oldKey)
			}
			state.saveConfig()
			if state.reloadManager != nil {
				state.reloadManager.Trigger()
			}
			state.recordAuditFromRequest(r, "site_cert_delete", siteID, "success", "Removed custom TLS cert")
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}))

	// Rules API (Unique ID guaranteed + Enabled flag & strict validation)
	mux.HandleFunc("/api/rules", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			state.mu.RLock()
			rules := make([]CustomRule, len(state.config.Rules))
			copy(rules, state.config.Rules)
			state.mu.RUnlock()
			json.NewEncoder(w).Encode(rules)
			return
		}

		if r.Method == http.MethodPost {
			var payload struct {
				ID          string `json:"id"`
				RuleID      int    `json:"rule_id"`
				Name        string `json:"name"`
				Target      string `json:"target"`
				Operator    string `json:"operator"`
				Pattern     string `json:"pattern"`
				Action      string `json:"action"`
				Description string `json:"description"`
				Enabled     *bool  `json:"enabled"`
				SiteID      string `json:"site_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			enabled := true
			if payload.Enabled != nil {
				enabled = *payload.Enabled
			}
			newRule := CustomRule{
				ID:          payload.ID,
				RuleID:      payload.RuleID,
				Name:        payload.Name,
				Target:      payload.Target,
				Operator:    payload.Operator,
				Pattern:     payload.Pattern,
				Action:      payload.Action,
				Description: payload.Description,
				Enabled:     enabled,
				SiteID:      strings.TrimSpace(payload.SiteID),
			}
			if err := validateCustomRuleInput(&newRule); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if newRule.ID == "" {
				newRule.ID = fmt.Sprintf("rule-%d", time.Now().UnixNano())
			}

			// Guaranteed Unique RuleID
			state.mu.Lock()
			usedIDs := make(map[int]bool)
			maxID := 2000
			for _, existing := range state.config.Rules {
				usedIDs[existing.RuleID] = true
				if existing.RuleID > maxID {
					maxID = existing.RuleID
				}
			}
			if newRule.RuleID <= 0 || usedIDs[newRule.RuleID] {
				newRule.RuleID = maxID + 1
			}

			state.config.Rules = append(state.config.Rules, newRule)
			state.mu.Unlock()

			state.saveConfig()
			if state.reloadManager != nil {
				state.reloadManager.Trigger()
			}
			state.recordAuditFromRequest(r, "waf_rule_create", newRule.Name, "success", fmt.Sprintf("rule_id=%d action=%s", newRule.RuleID, newRule.Action))
			json.NewEncoder(w).Encode(newRule)
			return
		}

		if r.Method == http.MethodPut {
			var updated CustomRule
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if err := validateCustomRuleInput(&updated); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			found := false
			state.mu.Lock()
			for i, rl := range state.config.Rules {
				if rl.ID == updated.ID {
					state.config.Rules[i].Name = updated.Name
					state.config.Rules[i].Target = updated.Target
					state.config.Rules[i].Operator = updated.Operator
					state.config.Rules[i].Pattern = updated.Pattern
					state.config.Rules[i].Description = updated.Description
					state.config.Rules[i].Action = updated.Action
					state.config.Rules[i].Enabled = updated.Enabled
					state.config.Rules[i].SiteID = updated.SiteID
					updated.RuleID = state.config.Rules[i].RuleID
					found = true
					break
				}
			}
			state.mu.Unlock()

			if !found {
				http.Error(w, "Rule not found", 404)
				return
			}
			state.saveConfig()
			state.triggerFirewallSync()
			if state.reloadManager != nil {
				state.reloadManager.Trigger()
			}
			state.recordAuditFromRequest(r, "waf_rule_update", updated.Name, "success", fmt.Sprintf("rule_id=%d action=%s", updated.RuleID, updated.Action))
			json.NewEncoder(w).Encode(updated)
			return
		}

		if r.Method == http.MethodDelete {
			id := r.URL.Query().Get("id")
			state.mu.Lock()
			filtered := make([]CustomRule, 0)
			for _, rl := range state.config.Rules {
				if rl.ID != id {
					filtered = append(filtered, rl)
				}
			}
			state.config.Rules = filtered
			state.mu.Unlock()

			state.saveConfig()
			if state.reloadManager != nil {
				state.reloadManager.Trigger()
			}
			state.recordAuditFromRequest(r, "waf_rule_delete", id, "success", "Removed WAF rule")
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}
	}))

	// 1-Click WAF Exclusion API (tune false positives by Rule ID + URI / Args)
	mux.HandleFunc("/api/waf/exclusions", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			var req struct {
				SiteID     string   `json:"site_id"`
				Host       string   `json:"host"`
				RuleID     int      `json:"rule_id"`
				MatchURI   string   `json:"match_uri"`
				RemoveArgs []string `json:"remove_args"`
				Comment    string   `json:"comment"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Payload không hợp lệ", 400)
				return
			}
			if req.RuleID <= 0 {
				http.Error(w, "rule_id phải > 0", 400)
				return
			}
			cleanMatchURI := strings.TrimSpace(req.MatchURI)
			if strings.ContainsAny(cleanMatchURI, "\r\n\x00\"") {
				http.Error(w, "match_uri chứa ký tự không hợp lệ", 400)
				return
			}
			if cleanMatchURI != "" && !strings.HasPrefix(cleanMatchURI, "/") {
				http.Error(w, "match_uri phải bắt đầu bằng '/'", 400)
				return
			}
			cleanArgs := make([]string, 0, len(req.RemoveArgs))
			for _, arg := range req.RemoveArgs {
				a := strings.TrimSpace(arg)
				if a == "" {
					continue
				}
				if strings.ContainsAny(a, ",;\"'\\ \t\r\n\x00") {
					http.Error(w, "remove_args chứa ký tự không hợp lệ", 400)
					return
				}
				cleanArgs = append(cleanArgs, a)
			}
			cleanComment := strings.NewReplacer("\r", "", "\n", " ", "\x00", "").Replace(strings.TrimSpace(req.Comment))

			excl := WAFExclusion{
				ID:         fmt.Sprintf("excl-%d", time.Now().UnixNano()),
				RuleID:     req.RuleID,
				MatchURI:   cleanMatchURI,
				RemoveArgs: cleanArgs,
				Comment:    cleanComment,
				Enabled:    true,
			}

			stripPortLower := func(h string) string {
				h = strings.ToLower(strings.TrimSpace(h))
				if hostOnly, _, err := net.SplitHostPort(h); err == nil {
					return hostOnly
				}
				return h
			}
			reqHost := stripPortLower(req.Host)

			updatedSites := 0
			state.mu.Lock()
			for i := range state.config.Sites {
				site := &state.config.Sites[i]
				siteHost := stripPortLower(site.Domain)
				hostMatch := reqHost != "" && (siteHost == reqHost || (strings.HasPrefix(siteHost, "*.") && len(reqHost) > len(siteHost)-1 && strings.HasSuffix(reqHost, siteHost[1:])))
				match := (req.SiteID != "" && site.ID == req.SiteID) ||
					hostMatch ||
					(req.SiteID == "" && reqHost == "")
				if !match {
					continue
				}
				dup := false
				for _, existing := range site.Exclusions {
					if existing.RuleID == excl.RuleID && existing.MatchURI == excl.MatchURI && len(existing.RemoveArgs) == len(excl.RemoveArgs) {
						sameArgs := true
						for idx := range existing.RemoveArgs {
							if existing.RemoveArgs[idx] != excl.RemoveArgs[idx] {
								sameArgs = false
								break
							}
						}
						if sameArgs {
							dup = true
							break
						}
					}
				}
				if !dup {
					site.Exclusions = append(site.Exclusions, excl)
				}
				updatedSites++
			}
			state.mu.Unlock()

			if updatedSites == 0 {
				http.Error(w, "Không tìm thấy site phù hợp để thêm exclusion", 404)
				return
			}
			state.saveConfig()
			if state.reloadManager != nil {
				state.reloadManager.Trigger()
			}
			state.recordAuditFromRequest(r, "waf_exclusion_add", fmt.Sprintf("rule:%d", excl.RuleID), "success", fmt.Sprintf("uri=%s sites=%d", excl.MatchURI, updatedSites))
			json.NewEncoder(w).Encode(map[string]any{"status": "ok", "exclusion": excl, "sites_updated": updatedSites})
			return
		}

		if r.Method == http.MethodDelete {
			siteID := strings.TrimSpace(r.URL.Query().Get("site_id"))
			exclID := strings.TrimSpace(r.URL.Query().Get("id"))
			if siteID == "" || exclID == "" {
				http.Error(w, "site_id and id required", 400)
				return
			}
			state.mu.Lock()
			for i := range state.config.Sites {
				if state.config.Sites[i].ID == siteID {
					filtered := make([]WAFExclusion, 0, len(state.config.Sites[i].Exclusions))
					for _, ex := range state.config.Sites[i].Exclusions {
						if ex.ID != exclID {
							filtered = append(filtered, ex)
						}
					}
					state.config.Sites[i].Exclusions = filtered
				}
			}
			state.mu.Unlock()
			state.saveConfig()
			if state.reloadManager != nil {
				state.reloadManager.Trigger()
			}
			state.recordAuditFromRequest(r, "waf_exclusion_delete", exclID, "success", "site="+siteID)
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}))

	// Cloudflare Integration APIs (Token, Zones, DNS CRUD, IP Range Sync)
	mux.HandleFunc("/api/cloudflare/config", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			state.mu.RLock()
			cf := state.config.Cloudflare
			v4, v6 := effectiveCloudflareCIDRs(cf)
			state.mu.RUnlock()
			json.NewEncoder(w).Encode(map[string]any{
				"has_token":       strings.TrimSpace(cf.APIToken) != "",
				"token_masked":    maskAPIToken(cf.APIToken),
				"ipv4_count":      len(v4),
				"ipv6_count":      len(v6),
				"last_ip_sync_at": cf.LastIPSyncAt,
				"ip_sync_source":  cf.IPSyncSource,
			})
			return
		}
		if r.Method == http.MethodPost {
			var payload struct {
				APIToken string `json:"api_token"`
				Clear    bool   `json:"clear"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, "Payload không hợp lệ", 400)
				return
			}
			tok := strings.TrimSpace(payload.APIToken)
			state.mu.Lock()
			if payload.Clear {
				state.config.Cloudflare.APIToken = ""
			} else if tok != "" && !strings.Contains(tok, "...") && tok != "********" {
				state.config.Cloudflare.APIToken = tok
			}
			hasTok := state.config.Cloudflare.APIToken != ""
			masked := maskAPIToken(state.config.Cloudflare.APIToken)
			state.mu.Unlock()
			state.saveConfig()
			if state.reloadManager != nil {
				state.reloadManager.Trigger()
			}
			state.recordAuditFromRequest(r, "cloudflare_config", "api_token", "success", fmt.Sprintf("clear=%v has_token=%v", payload.Clear, hasTok))
			json.NewEncoder(w).Encode(map[string]any{"status": "ok", "has_token": hasTok, "token_masked": masked})
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}))

	mux.HandleFunc("/api/cloudflare/verify", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var payload struct {
			APIToken string `json:"api_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		tok := strings.TrimSpace(payload.APIToken)
		if tok == "" || strings.Contains(tok, "...") || tok == "********" {
			state.mu.RLock()
			tok = state.config.Cloudflare.APIToken
			state.mu.RUnlock()
		}
		status, err := newCloudflareClient(tok).VerifyToken(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"valid": false, "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"valid": true, "status": status})
	}))

	mux.HandleFunc("/api/cloudflare/zones", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		state.mu.RLock()
		tok := state.config.Cloudflare.APIToken
		state.mu.RUnlock()
		zones, err := newCloudflareClient(tok).ListZones(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(zones)
	}))

	mux.HandleFunc("/api/cloudflare/records", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		state.mu.RLock()
		tok := state.config.Cloudflare.APIToken
		state.mu.RUnlock()
		cf := newCloudflareClient(tok)

		switch r.Method {
		case http.MethodGet:
			zoneID := strings.TrimSpace(r.URL.Query().Get("zone_id"))
			recs, err := cf.ListDNSRecords(r.Context(), zoneID)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(recs)
		case http.MethodPost:
			var req struct {
				ZoneID string `json:"zone_id"`
				CFDNSRecord
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			rec, err := cf.CreateDNSRecord(r.Context(), req.ZoneID, req.CFDNSRecord)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			state.recordAuditFromRequest(r, "cf_dns_create", req.Name, "success", fmt.Sprintf("type=%s zone=%s", req.Type, req.ZoneID))
			json.NewEncoder(w).Encode(rec)
		case http.MethodPut:
			var req struct {
				ZoneID    string `json:"zone_id"`
				RecordID  string `json:"record_id"`
				ProxyOnly bool   `json:"proxy_only"`
				CFDNSRecord
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			var rec *CFDNSRecord
			var err error
			if req.ProxyOnly {
				rec, err = cf.PatchDNSRecordProxied(r.Context(), req.ZoneID, req.RecordID, req.Proxied)
			} else {
				rec, err = cf.UpdateDNSRecord(r.Context(), req.ZoneID, req.RecordID, req.CFDNSRecord)
			}
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			state.recordAuditFromRequest(r, "cf_dns_update", req.RecordID, "success", fmt.Sprintf("proxied=%v zone=%s", req.Proxied, req.ZoneID))
			json.NewEncoder(w).Encode(rec)
		case http.MethodDelete:
			zoneID := strings.TrimSpace(r.URL.Query().Get("zone_id"))
			recID := strings.TrimSpace(r.URL.Query().Get("record_id"))
			if err := cf.DeleteDNSRecord(r.Context(), zoneID, recID); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			state.recordAuditFromRequest(r, "cf_dns_delete", recID, "success", "zone="+zoneID)
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))

	mux.HandleFunc("/api/cloudflare/ips/sync", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := state.syncCloudflareIPsWithBase(r.Context(), ""); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		state.triggerFirewallSync()
		state.mu.RLock()
		cf := state.config.Cloudflare
		state.mu.RUnlock()
		state.recordAuditFromRequest(r, "cf_ip_sync", "cloudflare", "success", fmt.Sprintf("ipv4=%d ipv6=%d", len(cf.CachedIPv4), len(cf.CachedIPv6)))
		json.NewEncoder(w).Encode(map[string]any{
			"status":          "ok",
			"ipv4_count":      len(cf.CachedIPv4),
			"ipv6_count":      len(cf.CachedIPv6),
			"last_ip_sync_at": cf.LastIPSyncAt,
		})
	}))

	mux.HandleFunc("/api/rules/toggle", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "application/json")
		var toggled CustomRule
		found := false

		state.mu.Lock()
		for i, rl := range state.config.Rules {
			if rl.ID == id {
				state.config.Rules[i].Enabled = !state.config.Rules[i].Enabled
				toggled = state.config.Rules[i]
				found = true
				break
			}
		}
		state.mu.Unlock()

		if !found {
			http.Error(w, "Rule not found", 404)
			return
		}

		state.saveConfig()
		if state.reloadManager != nil {
			state.reloadManager.Trigger()
		}
		state.recordAuditFromRequest(r, "waf_rule_toggle", toggled.Name, "success", fmt.Sprintf("enabled=%v", toggled.Enabled))
		json.NewEncoder(w).Encode(toggled)
	}))

	mux.HandleFunc("/api/rules/presets", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(getRulePresets())
	}))

	registerNetworkDetectorRoutes(mux)

	// Persistent Logs API
	mux.HandleFunc("/api/logs", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		limit := 50
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if lVal, err := strconv.Atoi(lStr); err == nil && lVal > 0 {
				limit = lVal
			}
		}

		offset := 0
		if oStr := r.URL.Query().Get("offset"); oStr != "" {
			if oVal, err := strconv.Atoi(oStr); err == nil && oVal >= 0 {
				offset = oVal
			}
		}

		// Support page query param: ?page=1, 2...
		if pStr := r.URL.Query().Get("page"); pStr != "" {
			if pVal, err := strconv.Atoi(pStr); err == nil && pVal > 0 {
				offset = (pVal - 1) * limit
			}
		}

		search := r.URL.Query().Get("search")
		isPaged := r.URL.Query().Get("paged") == "true" || r.URL.Query().Get("format") == "paged" || r.URL.Query().Get("page") != ""

		if state.logManager != nil {
			logs, total, err := state.logManager.Query(search, limit, offset)
			if err == nil {
				w.Header().Set("X-Total-Count", strconv.Itoa(total))
				w.Header().Set("X-Offset", strconv.Itoa(offset))
				w.Header().Set("X-Limit", strconv.Itoa(limit))

				if isPaged {
					page := 1
					if limit > 0 {
						page = (offset / limit) + 1
					}
					totalPages := 1
					if limit > 0 && total > 0 {
						totalPages = (total + limit - 1) / limit
					}
					json.NewEncoder(w).Encode(map[string]interface{}{
						"logs":        logs,
						"total":       total,
						"limit":       limit,
						"offset":      offset,
						"page":        page,
						"total_pages": totalPages,
					})
					return
				}

				json.NewEncoder(w).Encode(logs)
				return
			}
		}

		state.mu.RLock()
		defer state.mu.RUnlock()
		if isPaged {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"logs":        state.recentLogs,
				"total":       len(state.recentLogs),
				"limit":       limit,
				"offset":      0,
				"page":        1,
				"total_pages": 1,
			})
			return
		}
		json.NewEncoder(w).Encode(state.recentLogs)
	}))

	mux.HandleFunc("/api/logs/clear", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", 405)
			return
		}
		state.mu.Lock()
		state.recentLogs = make([]AttackLog, 0)
		state.mu.Unlock()

		if state.logManager != nil {
			state.logManager.Clear()
		}
		state.recordAuditFromRequest(r, "logs_clear", "attack_logs", "success", "Cleared all attack log partitions")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
	}))

	mux.HandleFunc("/api/logs/export", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", "attachment; filename=\"vsafegate-attacks.jsonl\"")
		if state.logManager != nil {
			state.logManager.Export(w)
		}
	}))

	// Blacklist API with TTL Support
	mux.HandleFunc("/api/blacklist", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodGet {
			list := state.getBannedIPList()
			json.NewEncoder(w).Encode(list)
			return
		}

		if r.Method == http.MethodPost {
			var payload struct {
				IP            string `json:"ip"`
				Reason        string `json:"reason"`
				DurationHours *int   `json:"duration_hours"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || strings.TrimSpace(payload.IP) == "" {
				http.Error(w, "Vui lòng nhập địa chỉ IP", 400)
				return
			}
			targetIP, err := normalizeBanTarget(payload.IP)
			if err != nil {
				http.Error(w, "Định dạng địa chỉ IP/CIDR không hợp lệ", 400)
				return
			}
			if isPrivateOrReservedIP(targetIP) {
				http.Error(w, "Không thể chặn địa chỉ IP nội bộ hoặc loopback", 400)
				return
			}
			state.mu.RLock()
			isTrustedEdge := isTrustedProxyOrCloudflareIP(targetIP, state.config)
			state.mu.RUnlock()
			if isTrustedEdge {
				http.Error(w, "Không thể chặn địa chỉ IP thuộc Cloudflare Edge hoặc Trusted Proxy", 400)
				return
			}
			reason := payload.Reason
			if reason == "" {
				reason = "[Admin] Thủ công thêm vào Blacklist"
			}
			duration := -1
			if payload.DurationHours != nil {
				duration = *payload.DurationHours
			}
			state.banIP(targetIP, reason, duration)
			state.recordAuditFromRequest(r, "ban_ip", targetIP, "success", fmt.Sprintf("ttl_h=%d reason=%s", duration, reason))
			list := state.getBannedIPList()
			json.NewEncoder(w).Encode(list)
			return
		}

		if r.Method == http.MethodDelete {
			clearAll := r.URL.Query().Get("all")
			if clearAll == "true" || clearAll == "1" {
				state.clearAllBannedIPs("[Admin] Xóa toàn bộ danh sách Blacklist")
				state.recordAuditFromRequest(r, "unban_all", "*", "success", "Cleared entire blacklist")
			} else {
				ip := r.URL.Query().Get("ip")
				if ip != "" {
					state.unbanIP(ip, "[Admin] Gỡ chặn thủ công")
					state.recordAuditFromRequest(r, "unban_ip", ip, "success", "Manual unban")
				}
			}
			list := state.getBannedIPList()
			json.NewEncoder(w).Encode(list)
			return
		}
	}))

	// Blacklist Default TTL Configuration
	mux.HandleFunc("/api/blacklist/ttl", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodGet {
			state.mu.RLock()
			ttl := state.config.DefaultBanTTL
			state.mu.RUnlock()
			json.NewEncoder(w).Encode(map[string]int{"default_ban_ttl_hours": ttl})
			return
		}

		if r.Method == http.MethodPost {
			var payload struct {
				DefaultBanTTLHours int `json:"default_ban_ttl_hours"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err == nil && payload.DefaultBanTTLHours >= 0 {
				state.mu.Lock()
				state.config.DefaultBanTTL = payload.DefaultBanTTLHours
				state.config.DefensePolicy.DefaultBanTTLHours = payload.DefaultBanTTLHours
				state.mu.Unlock()
				state.saveConfig()
				state.recordAuditFromRequest(r, "ban_ttl_update", strconv.Itoa(payload.DefaultBanTTLHours)+"h", "success", "Updated default ban TTL")
				json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "default_ban_ttl_hours": payload.DefaultBanTTLHours})
				return
			}
			http.Error(w, "Invalid TTL value", 400)
			return
		}
	}))

	// Whitelist (Trusted IPs) API
	mux.HandleFunc("/api/whitelist", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodGet {
			state.mu.RLock()
			wl := make([]WhitelistIPEntry, len(state.config.WhitelistIPs))
			copy(wl, state.config.WhitelistIPs)
			state.mu.RUnlock()
			json.NewEncoder(w).Encode(wl)
			return
		}

		if r.Method == http.MethodPost {
			var payload struct {
				IP   string `json:"ip"`
				Note string `json:"note"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.IP == "" {
				http.Error(w, "Vui lòng nhập địa chỉ IP hoặc dải mạng CIDR", 400)
				return
			}
			if err := state.addWhitelistIP(payload.IP, payload.Note); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			state.recordAuditFromRequest(r, "whitelist_add", payload.IP, "success", payload.Note)
			state.mu.RLock()
			wl := make([]WhitelistIPEntry, len(state.config.WhitelistIPs))
			copy(wl, state.config.WhitelistIPs)
			state.mu.RUnlock()
			json.NewEncoder(w).Encode(wl)
			return
		}

		if r.Method == http.MethodDelete {
			ip := r.URL.Query().Get("ip")
			if ip == "" {
				http.Error(w, "Thiếu tham số ip", 400)
				return
			}
			if err := state.removeWhitelistIP(ip); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			state.recordAuditFromRequest(r, "whitelist_delete", ip, "success", "Removed from whitelist")
			state.mu.RLock()
			wl := make([]WhitelistIPEntry, len(state.config.WhitelistIPs))
			copy(wl, state.config.WhitelistIPs)
			state.mu.RUnlock()
			json.NewEncoder(w).Encode(wl)
			return
		}
	}))

	// Defense Policy & Default Behavior API
	mux.HandleFunc("/api/defense/policy", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodGet {
			state.mu.RLock()
			policy := state.config.DefensePolicy
			state.mu.RUnlock()
			json.NewEncoder(w).Encode(policy)
			return
		}

		if r.Method == http.MethodPost {
			var p DefensePolicy
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				http.Error(w, "Invalid policy payload", 400)
				return
			}
			if p.DefaultBanTTLHours < 0 {
				p.DefaultBanTTLHours = 24
			}
			if p.SSHMaxAttempts <= 0 {
				p.SSHMaxAttempts = 3
			}
			if p.WAFAutoBanThreshold <= 0 {
				p.WAFAutoBanThreshold = 10
			}

			state.mu.Lock()
			state.config.DefensePolicy = p
			state.config.DefaultBanTTL = p.DefaultBanTTLHours
			state.mu.Unlock()
			state.saveConfig()
			go state.applyIptablesRules()
			state.recordAuditFromRequest(r, "defense_policy_update", "defense_policy", "success", fmt.Sprintf("ssh_guard=%v waf_autoban=%v egress=%v", p.SSHGuardEnabled, p.WAFAutoBanEnabled, p.EgressFilterEnabled))

			json.NewEncoder(w).Encode(p)
			return
		}
	}))

	// L7 Shield Banlist API (Cloudflare / Trusted Proxy offenders - never kernel-banned)
	mux.HandleFunc("/api/shield/bans", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(state.getShieldBannedIPList())
			return
		}
		if r.Method == http.MethodDelete {
			if r.URL.Query().Get("clear") == "all" {
				state.clearAllShieldBans()
				state.recordAuditFromRequest(r, "shield_unban_all", "*", "success", "Cleared all Shield L7 bans")
				json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
				return
			}
			ip := strings.TrimSpace(r.URL.Query().Get("ip"))
			if ip == "" {
				http.Error(w, "ip parameter required", 400)
				return
			}
			state.unbanShieldIP(ip)
			state.recordAuditFromRequest(r, "shield_unban_ip", ip, "success", "Unbanned L7 Shield IP")
			json.NewEncoder(w).Encode(map[string]string{"status": "unbanned", "ip": ip})
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}))

	// 1-Click Under Attack Mode Toggle API (Per-Site or Global)
	mux.HandleFunc("/api/sites/under-attack", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			SiteID  string `json:"site_id"`
			Enabled bool   `json:"enabled"`
			All     bool   `json:"all"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid payload", 400)
			return
		}

		mode := "normal"
		if req.Enabled {
			mode = "under_attack"
		}

		updatedCount := 0
		state.mu.Lock()
		for i := range state.config.Sites {
			if req.All || state.config.Sites[i].ID == req.SiteID {
				state.config.Sites[i].UnderAttackMode = req.Enabled
				state.config.Sites[i].ShieldMode = mode
				updatedCount++
			}
		}
		state.mu.Unlock()

		if !req.All && updatedCount == 0 {
			http.Error(w, "Site not found", 404)
			return
		}
		state.saveConfig()
		if state.reloadManager != nil {
			state.reloadManager.Trigger()
		}
		targetName := req.SiteID
		if req.All {
			targetName = "*"
		}
		state.recordAuditFromRequest(r, "under_attack_toggle", targetName, "success", fmt.Sprintf("enabled=%v mode=%s count=%d", req.Enabled, mode, updatedCount))
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":            "ok",
			"under_attack_mode": req.Enabled,
			"shield_mode":       mode,
			"updated_sites":     updatedCount,
		})
	}))

	// Management Settings API (Domain, Ports, Isolation CIDRs & Trusted Proxies)
	mux.HandleFunc("/api/mgmt/settings", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodGet {
			state.mu.RLock()
			defer state.mu.RUnlock()
			effectiveIPs := resolveMgmtListenIPs(state.config.MgmtListenIPs, detectPrivateMgmtIPv4s())
			if len(state.config.MgmtListenIPs) == 0 && isMgmtPublicInternetAllowed(state.config) {
				effectiveIPs = []string{"0.0.0.0 (All Interfaces)"}
			}
			retDays := state.config.LogRetentionDays
			if retDays <= 0 {
				retDays = 30
			}
			maxMB := state.config.LogMaxDiskMB
			if maxMB <= 0 {
				maxMB = 512
			}
			certStatus := "none"
			certIssuer := ""
			certExpiry := ""
			if dom := strings.TrimSpace(state.config.MgmtDomain); dom != "" {
				if ok, iss, exp := findValidPublicCertForDomain(state.effectiveCaddyDataDir(), dom); ok && !state.config.MgmtCertInternal {
					certStatus = "public"
					certIssuer = iss
					certExpiry = exp.UTC().Format(time.RFC3339)
				} else {
					certStatus = "internal"
					certIssuer = "Caddy Local Authority (Self-Signed)"
				}
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"mgmt_domain":                 state.config.MgmtDomain,
				"mgmt_cert_internal":          state.config.MgmtCertInternal,
				"mgmt_cert_status":            certStatus,
				"mgmt_cert_issuer":            certIssuer,
				"mgmt_cert_expiry":            certExpiry,
				"mgmt_https_port":             state.config.MgmtHTTPSPort,
				"mgmt_http_port":              state.config.MgmtHTTPPort,
				"mgmt_listen_ips":             state.config.MgmtListenIPs,
				"effective_mgmt_listen_ips":   effectiveIPs,
				"mgmt_allowed_cidrs":          state.config.MgmtAllowedCIDRs,
				"mgmt_allow_public_internet":  isMgmtPublicInternetAllowed(state.config),
				"trusted_proxies":             state.config.TrustedProxies,
				"trusted_interfaces":          effectiveTrustedInterfaces(state.config),
				"ssh_ports":                   effectiveSSHPorts(state.config),
				"log_retention_days":          retDays,
				"log_max_disk_mb":             maxMB,
			})
			return
		}

		if r.Method == http.MethodPost {
			var payload struct {
				MgmtDomain              string   `json:"mgmt_domain"`
				MgmtUseLetsEncrypt      *bool    `json:"mgmt_use_letsencrypt"`
				MgmtCertInternal        *bool    `json:"mgmt_cert_internal"`
				MgmtHTTPSPort           int      `json:"mgmt_https_port"`
				MgmtHTTPPort            int      `json:"mgmt_http_port"`
				MgmtListenIPs           []string `json:"mgmt_listen_ips"`
				MgmtAllowedCIDRs        []string `json:"mgmt_allowed_cidrs"`
				MgmtAllowPublicInternet *bool    `json:"mgmt_allow_public_internet"`
				TrustedProxies          []string `json:"trusted_proxies"`
				TrustedInterfaces       []string `json:"trusted_interfaces"`
				SSHPorts                []int    `json:"ssh_ports"`
				LogRetentionDays        int      `json:"log_retention_days"`
				LogMaxDiskMB            int      `json:"log_max_disk_mb"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err == nil {
				for _, ipStr := range payload.MgmtListenIPs {
					s := strings.TrimSpace(ipStr)
					if s == "" {
						continue
					}
					if _, err := netip.ParseAddr(s); err != nil {
						http.Error(w, "mgmt_listen_ips chứa IP không hợp lệ: "+s, 400)
						return
					}
				}
				validateCIDRList := func(list []string, label string) error {
					for _, raw := range list {
						s := strings.TrimSpace(raw)
						if s == "" {
							continue
						}
						if strings.Contains(s, "/") {
							pfx, err := netip.ParsePrefix(s)
							if err != nil {
								return fmt.Errorf("%s chứa CIDR không hợp lệ: %s", label, s)
							}
							if pfx.Bits() == 0 {
								return fmt.Errorf("%s không cho phép dải mạng 0.0.0.0/0 hoặc ::/0: %s", label, s)
							}
						} else if _, aerr := netip.ParseAddr(s); aerr != nil {
							return fmt.Errorf("%s chứa IP/CIDR không hợp lệ: %s", label, s)
						}
					}
					return nil
				}
				if err := validateCIDRList(payload.MgmtAllowedCIDRs, "mgmt_allowed_cidrs"); err != nil {
					http.Error(w, err.Error(), 400)
					return
				}
				if err := validateCIDRList(payload.TrustedProxies, "trusted_proxies"); err != nil {
					http.Error(w, err.Error(), 400)
					return
				}

				cleanMgmtDomain := strings.ToLower(strings.TrimSpace(payload.MgmtDomain))
				if cleanMgmtDomain != "" {
					if len(cleanMgmtDomain) > 253 || strings.ContainsAny(cleanMgmtDomain, "*: \t\r\n/\\{}'\";#@") || strings.Contains(cleanMgmtDomain, "..") || !reValidSiteDomain.MatchString(cleanMgmtDomain) {
						http.Error(w, "mgmt_domain không hợp lệ", 400)
						return
					}
				}
				if payload.MgmtHTTPSPort < 0 || payload.MgmtHTTPSPort > 65535 {
					http.Error(w, "mgmt_https_port phải trong khoảng 1..65535", 400)
					return
				}
				if payload.MgmtHTTPPort < 0 || payload.MgmtHTTPPort > 65535 {
					http.Error(w, "mgmt_http_port phải trong khoảng 1..65535", 400)
					return
				}

				state.mu.RLock()
				prevConfig := state.config
				prevConfig.MgmtListenIPs = append([]string(nil), state.config.MgmtListenIPs...)
				prevConfig.MgmtAllowedCIDRs = append([]string(nil), state.config.MgmtAllowedCIDRs...)
				prevConfig.TrustedProxies = append([]string(nil), state.config.TrustedProxies...)
				nextHTTPS := state.config.MgmtHTTPSPort
				if nextHTTPS <= 0 {
					nextHTTPS = 4438
				}
				if payload.MgmtHTTPSPort > 0 {
					nextHTTPS = payload.MgmtHTTPSPort
				}
				nextHTTP := state.config.MgmtHTTPPort
				if nextHTTP <= 0 {
					nextHTTP = 808
				}
				if payload.MgmtHTTPPort > 0 {
					nextHTTP = payload.MgmtHTTPPort
				}
				state.mu.RUnlock()

				if nextHTTPS == 80 || nextHTTPS == 443 || nextHTTP == 80 || nextHTTP == 443 {
					http.Error(w, "cổng Management không được trùng cổng dịch vụ 80 hoặc 443", 400)
					return
				}
				if nextHTTPS == nextHTTP {
					http.Error(w, "mgmt_https_port và mgmt_http_port phải khác nhau", 400)
					return
				}

				curMode := effectiveMgmtCertMode(prevConfig)
				useLetsEncrypt := curMode == "letsencrypt"
				if payload.MgmtUseLetsEncrypt != nil {
					useLetsEncrypt = *payload.MgmtUseLetsEncrypt
				} else if payload.MgmtCertInternal != nil {
					useLetsEncrypt = !*payload.MgmtCertInternal
				}

				// Build candidate config snapshot and verify/provision SSL cert BEFORE committing
				candidate := prevConfig
				candidate.MgmtDomain = cleanMgmtDomain
				if curMode == "custom" && payload.MgmtUseLetsEncrypt == nil && payload.MgmtCertInternal == nil {
					candidate.MgmtCertMode = "custom"
					candidate.MgmtCertInternal = false
				} else if useLetsEncrypt {
					candidate.MgmtCertMode = "letsencrypt"
					candidate.MgmtCertInternal = false
				} else {
					candidate.MgmtCertMode = "internal"
					candidate.MgmtCertInternal = true
				}
				candidate.MgmtHTTPSPort = nextHTTPS
				candidate.MgmtHTTPPort = nextHTTP
				if payload.MgmtListenIPs != nil {
					candidate.MgmtListenIPs = append([]string(nil), payload.MgmtListenIPs...)
				}
				if payload.MgmtAllowedCIDRs != nil {
					candidate.MgmtAllowedCIDRs = append([]string(nil), payload.MgmtAllowedCIDRs...)
				}
				if payload.MgmtAllowPublicInternet != nil {
					v := *payload.MgmtAllowPublicInternet
					candidate.MgmtAllowPublicInternet = &v
				}
				if payload.TrustedProxies != nil {
					candidate.TrustedProxies = append([]string(nil), payload.TrustedProxies...)
				}
				if payload.TrustedInterfaces != nil {
					cleanIfaces := make([]string, 0, len(payload.TrustedInterfaces))
					for _, raw := range payload.TrustedInterfaces {
						iface := strings.TrimSpace(raw)
						if iface == "" || iface == "lo" {
							continue
						}
						if len(iface) > 20 || strings.ContainsAny(iface, " \t\n\r;|&$`\"'\\/") {
							http.Error(w, "trusted_interfaces chứa tên card mạng không hợp lệ: "+iface, 400)
							return
						}
						cleanIfaces = append(cleanIfaces, iface)
					}
					candidate.TrustedInterfaces = cleanIfaces
				}
				if payload.SSHPorts != nil {
					cleanSSH := make([]int, 0, len(payload.SSHPorts))
					for _, p := range payload.SSHPorts {
						if p < 1 || p > 65535 {
							http.Error(w, fmt.Sprintf("ssh_ports chứa cổng không hợp lệ: %d", p), 400)
							return
						}
						cleanSSH = append(cleanSSH, p)
					}
					candidate.SSHPorts = cleanSSH
				}
				if payload.LogRetentionDays > 0 {
					candidate.LogRetentionDays = payload.LogRetentionDays
				}
				if payload.LogMaxDiskMB > 0 {
					candidate.LogMaxDiskMB = payload.LogMaxDiskMB
				}

				certStatus := "none"
				certIssuer := ""
				certWarning := ""
				var certExpiry time.Time
				if cleanMgmtDomain != "" && net.ParseIP(cleanMgmtDomain) == nil {
					if candidate.MgmtCertMode == "custom" {
						certStatus = "custom"
						certIssuer = "Custom Uploaded Certificate"
					} else if candidate.MgmtCertInternal {
						certStatus = "internal"
						certIssuer = "Caddy Local Authority (Self-Signed)"
					} else {
						hasCached, cachedIssuer, cachedExp := findValidPublicCertForDomain(state.effectiveCaddyDataDir(), cleanMgmtDomain)
						domainChanged := !strings.EqualFold(strings.TrimSpace(prevConfig.MgmtDomain), cleanMgmtDomain)
						needsProvision := domainChanged || !hasCached || prevConfig.MgmtCertInternal

						if hasCached && !domainChanged && !prevConfig.MgmtCertInternal {
							certStatus = "reused"
							certIssuer = cachedIssuer
							certExpiry = cachedExp
						} else if strings.TrimSpace(candidate.Cloudflare.APIToken) != "" && needsProvision {
							var perr error
							certStatus, certIssuer, certExpiry, perr = state.ensureMgmtDomainCert(r.Context(), candidate)
							if perr != nil {
								// Fallback cleanly to self-signed internal cert so management access never breaks
								candidate.MgmtCertMode = "internal"
								candidate.MgmtCertInternal = true
								certStatus = "internal_fallback"
								certIssuer = "Caddy Local Authority (Self-Signed Fallback)"
								certWarning = perr.Error()
								state.recordAuditFromRequest(r, "mgmt_cert_fallback", cleanMgmtDomain, "warning", perr.Error())
							}
						} else {
							certStatus = "internal"
							certIssuer = "Caddy Local Authority (Self-Signed)"
						}
					}
				}

				state.mu.Lock()
				state.config.MgmtDomain = candidate.MgmtDomain
				state.config.MgmtCertMode = candidate.MgmtCertMode
				state.config.MgmtCertInternal = candidate.MgmtCertInternal
				state.config.MgmtHTTPSPort = candidate.MgmtHTTPSPort
				state.config.MgmtHTTPPort = candidate.MgmtHTTPPort
				state.config.MgmtListenIPs = candidate.MgmtListenIPs
				state.config.MgmtAllowedCIDRs = candidate.MgmtAllowedCIDRs
				state.config.MgmtAllowPublicInternet = candidate.MgmtAllowPublicInternet
				state.config.TrustedProxies = candidate.TrustedProxies
				state.config.TrustedInterfaces = candidate.TrustedInterfaces
				state.config.SSHPorts = candidate.SSHPorts
				state.config.LogRetentionDays = candidate.LogRetentionDays
				state.config.LogMaxDiskMB = candidate.LogMaxDiskMB
				retDays := state.config.LogRetentionDays
				maxMB := state.config.LogMaxDiskMB
				state.mu.Unlock()

				if state.logManager != nil && (payload.LogRetentionDays > 0 || payload.LogMaxDiskMB > 0) {
					state.logManager.ConfigureRetention(retDays, maxMB)
				}
				state.saveConfig()
				state.triggerFirewallSync()
				state.recordAuditFromRequest(r, "mgmt_settings_update", cleanMgmtDomain, "success", fmt.Sprintf("https=%d http=%d cert=%s", nextHTTPS, nextHTTP, certStatus))

				if state.reloadManager != nil {
					state.reloadManager.Trigger()
				}
				resp := map[string]interface{}{
					"status":                     "ok",
					"mgmt_domain":                cleanMgmtDomain,
					"mgmt_cert_internal":         candidate.MgmtCertInternal,
					"mgmt_allow_public_internet": isMgmtPublicInternetAllowed(candidate),
					"cert_status":                certStatus,
					"cert_issuer":                certIssuer,
				}
				if certWarning != "" {
					resp["cert_warning"] = certWarning
				}
				if !certExpiry.IsZero() {
					resp["cert_expiry"] = certExpiry.UTC().Format(time.RFC3339)
				}
				json.NewEncoder(w).Encode(resp)
				return
			}
			http.Error(w, "Invalid body", 400)
			return
		}
	}))

	// Panel SSL Management API (Inspect active cert/keys, switch Let's Encrypt / Self-Signed / Custom PEM)
	mux.HandleFunc("/api/mgmt/ssl", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			state.mu.RLock()
			cfgSnap := state.config
			state.mu.RUnlock()
			info := inspectActiveMgmtCert(cfgSnap, state.effectiveCaddyDataDir())
			json.NewEncoder(w).Encode(info)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			Mode      string `json:"mode"`
			Domain    string `json:"domain"`
			Challenge string `json:"challenge"`
			CertPEM   string `json:"cert_pem"`
			KeyPEM    string `json:"key_pem"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		mode := strings.ToLower(strings.TrimSpace(payload.Mode))
		switch mode {
		case "letsencrypt", "internal", "custom":
		default:
			http.Error(w, "Chế độ SSL không hợp lệ (chỉ hỗ trợ letsencrypt, internal, custom)", http.StatusBadRequest)
			return
		}
		challenge := strings.ToLower(strings.TrimSpace(payload.Challenge))
		if challenge != "http01" && challenge != "dns01" {
			challenge = ""
		}

		state.mu.RLock()
		prevConfig := state.config
		state.mu.RUnlock()

		candidate := prevConfig
		if reqDom := strings.TrimSpace(payload.Domain); reqDom != "" {
			cleanDom := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(reqDom, "https://"), "http://"))
			cleanDom = strings.Split(cleanDom, "/")[0]
			if idx := strings.Index(cleanDom, ":"); idx != -1 {
				cleanDom = cleanDom[:idx]
			}
			if cleanDom == "" || strings.ContainsAny(cleanDom, " \t\n\r") {
				http.Error(w, "Domain Quản Trị không hợp lệ", http.StatusBadRequest)
				return
			}
			candidate.MgmtDomain = cleanDom
		}
		if challenge != "" {
			candidate.MgmtCertChallenge = challenge
		}
		certStatus := mode
		certIssuer := ""
		certWarning := ""
		var certExpiry time.Time

		switch mode {
		case "custom":
			meta, err := saveValidatedCertFiles(state.certsBaseDir(), "mgmt-panel", payload.CertPEM, payload.KeyPEM)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			candidate.MgmtCertMode = "custom"
			candidate.MgmtCertInternal = false
			candidate.MgmtCustomCertPath = meta.CertPath
			candidate.MgmtCustomKeyPath = meta.KeyPath
			certIssuer = meta.Issuer

		case "internal":
			candidate.MgmtCertMode = "internal"
			candidate.MgmtCertInternal = true
			certIssuer = "Caddy Local Authority (Self-Signed)"

		case "letsencrypt":
			dom := strings.TrimSpace(candidate.MgmtDomain)
			if dom == "" || net.ParseIP(dom) != nil {
				http.Error(w, "Cần cấu hình Domain Quản Trị (không phải IP) trước khi bật Let's Encrypt", http.StatusBadRequest)
				return
			}
			effChallenge := strings.ToLower(strings.TrimSpace(candidate.MgmtCertChallenge))
			if effChallenge != "http01" {
				effChallenge = "dns01"
			}
			candidate.MgmtCertChallenge = effChallenge
			if effChallenge == "dns01" && strings.TrimSpace(candidate.Cloudflare.APIToken) == "" {
				http.Error(w, "Cần cấu hình Cloudflare API Token trước khi cấp SSL Let's Encrypt qua DNS-01 (hoặc chọn HTTP-01 nếu domain trỏ thẳng IP server)", http.StatusBadRequest)
				return
			}
			candidate.MgmtCertMode = "letsencrypt"
			candidate.MgmtCertInternal = false
			domainChanged := !strings.EqualFold(strings.TrimSpace(prevConfig.MgmtDomain), dom)
			hasCached, cachedIssuer, cachedExp := findValidPublicCertForDomain(state.effectiveCaddyDataDir(), dom)
			if hasCached && !domainChanged {
				certStatus = "reused"
				certIssuer = cachedIssuer
				certExpiry = cachedExp
			} else {
				var perr error
				certStatus, certIssuer, certExpiry, perr = state.ensureMgmtDomainCert(r.Context(), candidate)
				if perr != nil {
					candidate.MgmtCertMode = "internal"
					candidate.MgmtCertInternal = true
					certStatus = "internal_fallback"
					certIssuer = "Caddy Local Authority (Self-Signed Fallback)"
					certWarning = perr.Error()
					state.recordAuditFromRequest(r, "mgmt_cert_fallback", dom, "warning", perr.Error())
				}
			}
		}

		state.mu.Lock()
		state.config.MgmtDomain = candidate.MgmtDomain
		state.config.MgmtCertMode = candidate.MgmtCertMode
		state.config.MgmtCertChallenge = candidate.MgmtCertChallenge
		state.config.MgmtCertInternal = candidate.MgmtCertInternal
		state.config.MgmtCustomCertPath = candidate.MgmtCustomCertPath
		state.config.MgmtCustomKeyPath = candidate.MgmtCustomKeyPath
		state.mu.Unlock()

		state.saveConfig()
		state.recordAuditFromRequest(r, "mgmt_ssl_update", candidate.MgmtDomain, "success", fmt.Sprintf("mode=%s status=%s", candidate.MgmtCertMode, certStatus))
		if state.reloadManager != nil {
			state.reloadManager.Trigger()
		}

		state.mu.RLock()
		cfgSnap := state.config
		state.mu.RUnlock()
		info := inspectActiveMgmtCert(cfgSnap, state.effectiveCaddyDataDir())

		resp := map[string]interface{}{
			"status":      "ok",
			"cert_status": certStatus,
			"cert_issuer": certIssuer,
			"ssl_info":    info,
		}
		if certWarning != "" {
			resp["cert_warning"] = certWarning
		}
		if !certExpiry.IsZero() {
			resp["cert_expiry"] = certExpiry.UTC().Format(time.RFC3339)
		}
		json.NewEncoder(w).Encode(resp)
	}))

	// Log Retention Settings API
	mux.HandleFunc("/api/logs/retention", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			state.mu.RLock()
			retDays := state.config.LogRetentionDays
			maxMB := state.config.LogMaxDiskMB
			state.mu.RUnlock()
			if retDays <= 0 {
				retDays = 30
			}
			if maxMB <= 0 {
				maxMB = 512
			}
			totalCount := 0
			if state.logManager != nil {
				totalCount = state.logManager.TotalCount()
			}
			json.NewEncoder(w).Encode(map[string]any{
				"log_retention_days": retDays,
				"log_max_disk_mb":    maxMB,
				"total_entries":      totalCount,
			})
			return
		}
		if r.Method == http.MethodPost {
			var req struct {
				LogRetentionDays int `json:"log_retention_days"`
				LogMaxDiskMB     int `json:"log_max_disk_mb"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid payload", 400)
				return
			}
			if req.LogRetentionDays <= 0 || req.LogRetentionDays > 3650 {
				http.Error(w, "log_retention_days phải trong khoảng 1..3650", 400)
				return
			}
			if req.LogMaxDiskMB <= 0 || req.LogMaxDiskMB > 102400 {
				http.Error(w, "log_max_disk_mb phải trong khoảng 1..102400", 400)
				return
			}
			state.mu.Lock()
			state.config.LogRetentionDays = req.LogRetentionDays
			state.config.LogMaxDiskMB = req.LogMaxDiskMB
			state.mu.Unlock()
			if state.logManager != nil {
				state.logManager.ConfigureRetention(req.LogRetentionDays, req.LogMaxDiskMB)
			}
			state.saveConfig()
			state.recordAuditFromRequest(r, "log_retention_update", "attack_logs", "success", fmt.Sprintf("days=%d max_mb=%d", req.LogRetentionDays, req.LogMaxDiskMB))
			json.NewEncoder(w).Encode(map[string]any{
				"status":             "ok",
				"log_retention_days": req.LogRetentionDays,
				"log_max_disk_mb":    req.LogMaxDiskMB,
			})
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}))

	// SOC Telemetry APIs (/api/soc/telemetry, /api/soc/summary, /api/soc/stream)
	mux.HandleFunc("/api/soc/telemetry", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		rangeStr := r.URL.Query().Get("range")
		if state.telemetry == nil {
			json.NewEncoder(w).Encode(TelemetryQueryResult{Range: "24h", Categories: initCategoriesMap()})
			return
		}
		json.NewEncoder(w).Encode(state.telemetry.Query(rangeStr))
	}))

	mux.HandleFunc("/api/soc/summary", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var sum TelemetrySummary
		if state.telemetry != nil {
			sum = state.telemetry.Summary()
		} else {
			sum = TelemetrySummary{Categories: initCategoriesMap()}
		}
		type socSiteSummary struct {
			ID                       string `json:"id"`
			Domain                   string `json:"domain"`
			ShieldMode               string `json:"shield_mode"`
			WAFMode                  string `json:"waf_mode"`
			UnderAttackMode          bool   `json:"under_attack_mode"`
			AutoProxyEnabled         bool   `json:"auto_proxy_enabled"`
			AutoProxyActive          bool   `json:"auto_proxy_active"`
			AutoProxyThresholdRPS    int    `json:"auto_proxy_threshold_rps"`
			AutoProxyThresholdDropPS int    `json:"auto_proxy_threshold_drop_ps"`
			AutoProxyZoneID          string `json:"auto_proxy_zone_id,omitempty"`
		}
		state.mu.RLock()
		sites := make([]socSiteSummary, 0, len(state.config.Sites))
		for _, site := range state.config.Sites {
			sites = append(sites, socSiteSummary{
				ID:                       site.ID,
				Domain:                   site.Domain,
				ShieldMode:               effectiveSiteShieldMode(site),
				WAFMode:                  effectiveSiteWAFMode(site),
				UnderAttackMode:          site.UnderAttackMode,
				AutoProxyEnabled:         site.AutoProxyEnabled,
				AutoProxyActive:          site.AutoProxyActive,
				AutoProxyThresholdRPS:    site.AutoProxyThresholdRPS,
				AutoProxyThresholdDropPS: site.AutoProxyThresholdDropPS,
				AutoProxyZoneID:          site.AutoProxyZoneID,
			})
		}
		state.mu.RUnlock()

		var restarts int64
		var running bool
		if state.caddySupervisor != nil {
			restarts = state.caddySupervisor.RestartCount()
			running = state.caddySupervisor.IsRunning()
		}
		alertStatus := map[string]any{}
		if state.alertEngine != nil {
			alertStatus = state.alertEngine.StatusSnapshot()
		}

		json.NewEncoder(w).Encode(struct {
			TelemetrySummary
			AlertStatus   map[string]any   `json:"alert_status"`
			CaddyRunning  bool             `json:"caddy_running"`
			CaddyRestarts int64            `json:"caddy_restarts"`
			Sites         []socSiteSummary `json:"sites"`
		}{
			TelemetrySummary: sum,
			AlertStatus:      alertStatus,
			CaddyRunning:     running,
			CaddyRestarts:    restarts,
			Sites:            sites,
		})
	}))

	mux.HandleFunc("/api/soc/stream", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		if state.sseBroker == nil {
			state.sseBroker = NewSSEBroker()
		}
		ch := state.sseBroker.Subscribe()
		defer state.sseBroker.Unsubscribe(ch)

		_, _ = fmt.Fprintf(w, "event: ready\ndata: {\"status\":\"connected\",\"ts\":%d}\n\n", time.Now().Unix())
		flusher.Flush()

		keepalive := time.NewTicker(15 * time.Second)
		defer keepalive.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case msg, open := <-ch:
				if !open {
					return
				}
				_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", msg.Event, msg.Data)
				flusher.Flush()
			case <-keepalive.C:
				_, _ = fmt.Fprintf(w, ": ping %d\n\n", time.Now().Unix())
				flusher.Flush()
			}
		}
	}))

	// Email SMTP Alert Settings & Test API
	mux.HandleFunc("/api/alerts/smtp", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			state.mu.RLock()
			cfg := state.config.SMTP
			state.mu.RUnlock()
			hasPwd := cfg.Password != ""
			if hasPwd {
				cfg.Password = "********"
			}
			json.NewEncoder(w).Encode(struct {
				SMTPConfig
				HasPassword bool `json:"has_password"`
			}{
				SMTPConfig:  cfg,
				HasPassword: hasPwd,
			})
			return
		}
		if r.Method == http.MethodPost {
			var req struct {
				SMTPConfig
				ClearPassword bool `json:"clear_password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Payload SMTP không hợp lệ", 400)
				return
			}
			state.mu.RLock()
			existingPwd := state.config.SMTP.Password
			state.mu.RUnlock()

			next := req.SMTPConfig
			if req.ClearPassword {
				next.Password = ""
			} else if next.Password == "" || next.Password == "********" {
				next.Password = existingPwd
			}
			if err := validateSMTPConfig(&next); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			state.mu.Lock()
			state.config.SMTP = next
			state.mu.Unlock()
			state.saveConfig()
			state.recordAuditFromRequest(r, "smtp_update", next.SMTPHost, "success", fmt.Sprintf("enabled=%v port=%d tls=%s", next.Enabled, next.SMTPPort, next.TLSMode))

			hasPwd := next.Password != ""
			if hasPwd {
				next.Password = "********"
			}
			json.NewEncoder(w).Encode(map[string]any{
				"status":       "ok",
				"smtp":         next,
				"has_password": hasPwd,
			})
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}))

	mux.HandleFunc("/api/alerts/smtp/test", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var override *SMTPConfig
		if r.Body != nil {
			bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 256*1024))
			trimmed := strings.TrimSpace(string(bodyBytes))
			if trimmed != "" && trimmed != "{}" {
				var req SMTPConfig
				if err := json.Unmarshal(bodyBytes, &req); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{"error": "Payload SMTP không hợp lệ"})
					return
				}
				override = &req
			}
		}
		if err := state.alertEngine.SendTestEmail(r.Context(), override); err != nil {
			state.recordAuditFromRequest(r, "smtp_test", "smtp", "error", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		state.recordAuditFromRequest(r, "smtp_test", "smtp", "success", "Sent SMTP test email")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Email kiểm tra đã được gửi thành công"})
	}))

	// Telegram / Discord / Generic Webhook Alert Channels API
	mux.HandleFunc("/api/alerts/channels", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			state.mu.RLock()
			cfg := state.config.Alerts
			state.mu.RUnlock()
			hasTgToken := cfg.TelegramBotToken != ""
			hasWhSecret := cfg.WebhookSecret != ""
			if hasTgToken {
				cfg.TelegramBotToken = "********"
			}
			if hasWhSecret {
				cfg.WebhookSecret = "********"
			}
			json.NewEncoder(w).Encode(struct {
				AlertChannelsConfig
				HasTelegramToken bool `json:"has_telegram_token"`
				HasWebhookSecret bool `json:"has_webhook_secret"`
			}{
				AlertChannelsConfig: cfg,
				HasTelegramToken:    hasTgToken,
				HasWebhookSecret:    hasWhSecret,
			})
			return
		}
		if r.Method == http.MethodPost {
			var req struct {
				AlertChannelsConfig
				ClearTelegramToken bool `json:"clear_telegram_token"`
				ClearWebhookSecret bool `json:"clear_webhook_secret"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Payload cấu hình kênh cảnh báo không hợp lệ", 400)
				return
			}
			state.mu.RLock()
			existingTgToken := state.config.Alerts.TelegramBotToken
			existingWhSecret := state.config.Alerts.WebhookSecret
			state.mu.RUnlock()

			next := req.AlertChannelsConfig
			if req.ClearTelegramToken {
				next.TelegramBotToken = ""
			} else if next.TelegramBotToken == "" || next.TelegramBotToken == "********" {
				next.TelegramBotToken = existingTgToken
			}
			if req.ClearWebhookSecret {
				next.WebhookSecret = ""
			} else if next.WebhookSecret == "" || next.WebhookSecret == "********" {
				next.WebhookSecret = existingWhSecret
			}
			if err := validateAlertChannelsConfig(&next); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			state.mu.Lock()
			state.config.Alerts = next
			state.mu.Unlock()
			state.saveConfig()
			state.recordAuditFromRequest(r, "alert_channels_update", "alerts", "success", fmt.Sprintf("tg=%v discord=%v webhook=%v", next.TelegramEnabled, next.DiscordEnabled, next.WebhookEnabled))

			hasTgToken := next.TelegramBotToken != ""
			hasWhSecret := next.WebhookSecret != ""
			if hasTgToken {
				next.TelegramBotToken = "********"
			}
			if hasWhSecret {
				next.WebhookSecret = "********"
			}
			json.NewEncoder(w).Encode(map[string]any{
				"status":             "ok",
				"alerts":             next,
				"has_telegram_token": hasTgToken,
				"has_webhook_secret": hasWhSecret,
			})
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}))

	mux.HandleFunc("/api/alerts/channels/test", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			Channel string `json:"channel"`
			AlertChannelsConfig
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 256*1024)).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Payload kiểm tra kênh cảnh báo không hợp lệ"})
			return
		}
		if err := state.alertEngine.SendTestChannel(r.Context(), req.Channel, &req.AlertChannelsConfig); err != nil {
			state.recordAuditFromRequest(r, "alert_channel_test", req.Channel, "error", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		state.recordAuditFromRequest(r, "alert_channel_test", req.Channel, "success", "Sent test alert via "+req.Channel)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": fmt.Sprintf("Đã gửi cảnh báo thử nghiệm qua %s thành công!", strings.ToUpper(req.Channel)),
		})
	}))

	// Shared Threat Intelligence Hub API (Central Blocklist Sync & Reporting)
	mux.HandleFunc("/api/shared-threat", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			state.mu.RLock()
			cfg := state.config.SharedThreat
			state.mu.RUnlock()
			hasKey := cfg.APIKey != ""
			if hasKey {
				cfg.APIKey = "********"
			}
			if strings.TrimSpace(cfg.HubURL) == "" {
				cfg.HubURL = defaultSharedThreatHubURL
			}
			if cfg.SyncIntervalMin <= 0 {
				cfg.SyncIntervalMin = 15
			}
			json.NewEncoder(w).Encode(struct {
				SharedThreatConfig
				HasAPIKey bool `json:"has_api_key"`
			}{
				SharedThreatConfig: cfg,
				HasAPIKey:          hasKey,
			})
			return
		}
		if r.Method == http.MethodPost {
			var req struct {
				SharedThreatConfig
				ClearAPIKey bool `json:"clear_api_key"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Payload Shared Threat không hợp lệ", 400)
				return
			}
			state.mu.RLock()
			prev := state.config.SharedThreat
			state.mu.RUnlock()

			next := req.SharedThreatConfig
			if req.ClearAPIKey {
				next.APIKey = ""
			} else if next.APIKey == "" || next.APIKey == "********" {
				next.APIKey = prev.APIKey
			}
			next.LastSyncAt = prev.LastSyncAt
			next.LastSyncCount = prev.LastSyncCount
			next.LastSyncError = prev.LastSyncError
			if err := validateSharedThreatConfig(&next); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			state.mu.Lock()
			state.config.SharedThreat = next
			state.mu.Unlock()
			state.saveConfig()
			state.triggerFirewallSync()
			state.recordAuditFromRequest(r, "shared_threat_update", next.HubURL, "success", fmt.Sprintf("enabled=%v push=%v sync=%v", next.Enabled, next.PushOnBan, next.SyncEnabled))

			hasKey := next.APIKey != ""
			if hasKey {
				next.APIKey = "********"
			}
			json.NewEncoder(w).Encode(map[string]any{
				"status":        "ok",
				"shared_threat": next,
				"has_api_key":   hasKey,
			})
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}))

	mux.HandleFunc("/api/shared-threat/sync", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		pushed, perr := state.PushExistingBannedIPs(r.Context())
		if perr != nil {
			state.recordAuditFromRequest(r, "shared_threat_push", "hub", "warning", perr.Error())
		}
		cnt, err := state.SyncSharedThreatList(r.Context())
		if err != nil {
			state.recordAuditFromRequest(r, "shared_threat_sync", "hub", "error", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		state.recordAuditFromRequest(r, "shared_threat_sync", "hub", "success", fmt.Sprintf("pushed=%d synced=%d", pushed, cnt))
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"pushed":  pushed,
			"count":   cnt,
			"message": fmt.Sprintf("Đã đẩy %d IP đã chặn lên Hub và đồng bộ %d IP/CIDR về Firewall!", pushed, cnt),
		})
	}))

	// Config Backup / Restore Bundle API
	mux.HandleFunc("/api/config/backup", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		bundle := state.exportConfigBackupBundle()
		state.recordAuditFromRequest(r, "config_backup", "bundle", "success", fmt.Sprintf("sites=%d rules=%d l4=%d", len(bundle.Config.Sites), len(bundle.Config.Rules), len(bundle.Config.L4Services)))

		filename := fmt.Sprintf("vsafegate-backup-%s.json", time.Now().UTC().Format("20060102-150405"))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(bundle)
	}))

	mux.HandleFunc("/api/config/restore", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var bundle ConfigBackupBundle
		if err := json.NewDecoder(io.LimitReader(r.Body, 10<<20)).Decode(&bundle); err != nil {
			state.recordAuditFromRequest(r, "config_restore", "bundle", "error", "Invalid JSON payload")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "File backup JSON không hợp lệ: " + err.Error()})
			return
		}
		if err := state.restoreConfigBackupBundle(&bundle); err != nil {
			state.recordAuditFromRequest(r, "config_restore", "bundle", "error", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		state.recordAuditFromRequest(r, "config_restore", "bundle", "success", fmt.Sprintf("sites=%d rules=%d l4=%d", len(bundle.Config.Sites), len(bundle.Config.Rules), len(bundle.Config.L4Services)))
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"message": "Khôi phục cấu hình thành công",
			"sites":   len(bundle.Config.Sites),
			"rules":   len(bundle.Config.Rules),
			"l4":      len(bundle.Config.L4Services),
		})
	}))

	// Admin Audit Log API (/var/log/vsafegate/audit.jsonl)
	mux.HandleFunc("/api/audit", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		limit := 50
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if lVal, err := strconv.Atoi(lStr); err == nil && lVal > 0 {
				limit = lVal
			}
		}
		offset := 0
		if oStr := r.URL.Query().Get("offset"); oStr != "" {
			if oVal, err := strconv.Atoi(oStr); err == nil && oVal >= 0 {
				offset = oVal
			}
		}
		if pStr := r.URL.Query().Get("page"); pStr != "" {
			if pVal, err := strconv.Atoi(pStr); err == nil && pVal > 0 {
				offset = (pVal - 1) * limit
			}
		}
		search := r.URL.Query().Get("search")
		var entries []AdminAuditEntry
		var total int
		if state.adminAudit != nil {
			entries, total = state.adminAudit.Query(search, limit, offset)
		}
		if entries == nil {
			entries = []AdminAuditEntry{}
		}
		json.NewEncoder(w).Encode(map[string]any{
			"entries": entries,
			"total":   total,
			"limit":   limit,
			"offset":  offset,
		})
	}))

	// Hot Reload API (Force Immediate)
	mux.HandleFunc("/api/reload", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if state.reloadManager != nil {
			state.reloadManager.ForceReload()
		} else {
			state.generateCaddyAndRules()
		}
		state.recordAuditFromRequest(r, "caddy_reload", "caddy", "success", "Forced manual reload")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "reloaded successfully"})
	}))

	return csrfMiddleware(mux)
}

func (s *AppState) exportConfigBackupBundle() ConfigBackupBundle {
	s.mu.RLock()
	cfgCopy := s.config
	cfgCopy.Sites = make([]Site, len(s.config.Sites))
	copy(cfgCopy.Sites, s.config.Sites)
	for i := range cfgCopy.Sites {
		cfgCopy.Sites[i].SensitiveRoutes = append([]ShieldSensitiveRoute(nil), s.config.Sites[i].SensitiveRoutes...)
		cfgCopy.Sites[i].ExemptPaths = append([]string(nil), s.config.Sites[i].ExemptPaths...)
		cfgCopy.Sites[i].APIPaths = append([]string(nil), s.config.Sites[i].APIPaths...)
		cfgCopy.Sites[i].Exclusions = append([]WAFExclusion(nil), s.config.Sites[i].Exclusions...)
		cfgCopy.Sites[i].TrustedProxies = append([]string(nil), s.config.Sites[i].TrustedProxies...)
	}
	cfgCopy.Rules = append([]CustomRule(nil), s.config.Rules...)
	cfgCopy.L4Services = append([]L4Service(nil), s.config.L4Services...)
	for i := range cfgCopy.L4Services {
		cfgCopy.L4Services[i].Backends = append([]string(nil), s.config.L4Services[i].Backends...)
	}
	cfgCopy.BannedIPs = append([]BannedIPEntry(nil), s.config.BannedIPs...)
	cfgCopy.ShieldBannedIPs = append([]ShieldBanEntry(nil), s.config.ShieldBannedIPs...)
	cfgCopy.WhitelistIPs = append([]WhitelistIPEntry(nil), s.config.WhitelistIPs...)
	cfgCopy.AllowedCountries = append([]string(nil), s.config.AllowedCountries...)
	cfgCopy.BlockedCountries = append([]string(nil), s.config.BlockedCountries...)
	cfgCopy.MgmtListenIPs = append([]string(nil), s.config.MgmtListenIPs...)
	cfgCopy.MgmtAllowedCIDRs = append([]string(nil), s.config.MgmtAllowedCIDRs...)
	cfgCopy.TrustedProxies = append([]string(nil), s.config.TrustedProxies...)
	cfgCopy.Cloudflare.CachedIPv4 = append([]string(nil), s.config.Cloudflare.CachedIPv4...)
	cfgCopy.Cloudflare.CachedIPv6 = append([]string(nil), s.config.Cloudflare.CachedIPv6...)
	cfgCopy.SMTP.ToAddresses = append([]string(nil), s.config.SMTP.ToAddresses...)
	// Scrub host auth & HMAC credentials from backup exports
	cfgCopy.AdminPassword = ""
	cfgCopy.ShieldChallengeSecret = ""
	cfgCopy.BlacklistIP = nil

	offenses := make(map[string]int, len(s.offenseCount))
	for k, v := range s.offenseCount {
		if v > 0 {
			offenses[k] = v
		}
	}
	s.mu.RUnlock()

	return ConfigBackupBundle{
		Version:    "1",
		ExportedAt: time.Now().UTC(),
		Config:     cfgCopy,
		Offenses:   offenses,
	}
}

func (s *AppState) restoreConfigBackupBundle(bundle *ConfigBackupBundle) error {
	if bundle == nil || strings.TrimSpace(bundle.Version) == "" {
		return errors.New("thiếu trường version trong Config Backup Bundle")
	}
	next := bundle.Config

	// Validate Sites
	seenSiteIDs := make(map[string]struct{}, len(next.Sites))
	seenDomains := make(map[string]struct{}, len(next.Sites))
	for i := range next.Sites {
		if strings.TrimSpace(next.Sites[i].ID) == "" {
			return fmt.Errorf("site[%d].id không được để trống", i)
		}
		if !reSafeCertID.MatchString(next.Sites[i].ID) {
			return fmt.Errorf("site[%d].id không hợp lệ: %q", i, next.Sites[i].ID)
		}
		if _, dup := seenSiteIDs[next.Sites[i].ID]; dup {
			return fmt.Errorf("trùng site id trong backup: %s", next.Sites[i].ID)
		}
		seenSiteIDs[next.Sites[i].ID] = struct{}{}
		if err := validateSiteInput(&next.Sites[i]); err != nil {
			return fmt.Errorf("site %s: %w", next.Sites[i].Domain, err)
		}
		domLower := strings.ToLower(next.Sites[i].Domain)
		if _, dup := seenDomains[domLower]; dup {
			return fmt.Errorf("trùng domain trong backup: %s", next.Sites[i].Domain)
		}
		seenDomains[domLower] = struct{}{}
		// Clear file paths whose files don't exist on this node to prevent broken Caddy config on DR restore
		if next.Sites[i].CustomCertPath != "" {
			if _, err := os.Stat(next.Sites[i].CustomCertPath); err != nil {
				next.Sites[i].CustomCertPath = ""
				next.Sites[i].CustomKeyPath = ""
			}
		}
		if next.Sites[i].OriginTLSCAPath != "" {
			if _, err := os.Stat(next.Sites[i].OriginTLSCAPath); err != nil {
				next.Sites[i].OriginTLSCAPath = ""
			}
		}
	}

	// Validate Rules
	seenRuleIDs := make(map[string]struct{}, len(next.Rules))
	for i := range next.Rules {
		if strings.TrimSpace(next.Rules[i].ID) == "" {
			return fmt.Errorf("rule[%d].id không được để trống", i)
		}
		if _, dup := seenRuleIDs[next.Rules[i].ID]; dup {
			return fmt.Errorf("trùng rule id trong backup: %s", next.Rules[i].ID)
		}
		seenRuleIDs[next.Rules[i].ID] = struct{}{}
		if err := validateCustomRuleInput(&next.Rules[i]); err != nil {
			return fmt.Errorf("rule %s: %w", next.Rules[i].Name, err)
		}
	}

	// Validate L4 Services
	seenL4Ports := make(map[string]struct{}, len(next.L4Services))
	for i := range next.L4Services {
		if err := validateAndNormalizeL4Service(&next.L4Services[i]); err != nil {
			return fmt.Errorf("l4_service %s: %w", next.L4Services[i].Name, err)
		}
		pk := fmt.Sprintf("%s:%d", next.L4Services[i].Protocol, next.L4Services[i].ListenPort)
		if _, dup := seenL4Ports[pk]; dup {
			return fmt.Errorf("trùng cổng L4 trong backup: %s", pk)
		}
		seenL4Ports[pk] = struct{}{}
	}

	// Validate Whitelist
	for i := range next.WhitelistIPs {
		norm, err := normalizeBanTarget(next.WhitelistIPs[i].IP)
		if err != nil {
			return fmt.Errorf("whitelist[%d]: %w", i, err)
		}
		next.WhitelistIPs[i].IP = norm
	}

	// Validate Mgmt & Trusted Proxies
	cleanMgmtDomain := strings.ToLower(strings.TrimSpace(next.MgmtDomain))
	if cleanMgmtDomain != "" {
		if len(cleanMgmtDomain) > 253 || strings.ContainsAny(cleanMgmtDomain, "*: \t\r\n/\\{}'\";#@") || strings.Contains(cleanMgmtDomain, "..") || !reValidSiteDomain.MatchString(cleanMgmtDomain) {
			return errors.New("mgmt_domain trong backup không hợp lệ")
		}
	}
	next.MgmtDomain = cleanMgmtDomain
	if next.MgmtHTTPSPort == 0 {
		next.MgmtHTTPSPort = 4438
	}
	if next.MgmtHTTPPort == 0 {
		next.MgmtHTTPPort = 808
	}
	if next.MgmtHTTPSPort < 1 || next.MgmtHTTPSPort > 65535 || next.MgmtHTTPPort < 1 || next.MgmtHTTPPort > 65535 {
		return errors.New("cổng Management trong backup phải nằm trong 1..65535")
	}
	if next.MgmtHTTPSPort == 80 || next.MgmtHTTPSPort == 443 || next.MgmtHTTPPort == 80 || next.MgmtHTTPPort == 443 || next.MgmtHTTPSPort == next.MgmtHTTPPort {
		return errors.New("cổng Management trong backup xung đột với cổng 80/443 hoặc trùng nhau")
	}
	for _, rawIP := range next.MgmtListenIPs {
		if s := strings.TrimSpace(rawIP); s != "" {
			if _, err := netip.ParseAddr(s); err != nil {
				return fmt.Errorf("mgmt_listen_ips chứa IP không hợp lệ: %s", s)
			}
		}
	}
	validateCIDR := func(list []string, label string) error {
		for _, raw := range list {
			s := strings.TrimSpace(raw)
			if s == "" {
				continue
			}
			if _, err := normalizeBanTarget(s); err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
		}
		return nil
	}
	if err := validateCIDR(next.MgmtAllowedCIDRs, "mgmt_allowed_cidrs"); err != nil {
		return err
	}
	if err := validateCIDR(next.TrustedProxies, "trusted_proxies"); err != nil {
		return err
	}

	// Validate GeoIP
	next.GeoIPMode = strings.ToLower(strings.TrimSpace(next.GeoIPMode))
	switch next.GeoIPMode {
	case "", "disabled", "whitelist", "blacklist":
	default:
		return fmt.Errorf("geoip_mode không hợp lệ: %q", next.GeoIPMode)
	}
	if next.GeoIPMode == "" {
		next.GeoIPMode = "disabled"
	}
	for _, c := range append(append([]string(nil), next.AllowedCountries...), next.BlockedCountries...) {
		if len(strings.TrimSpace(c)) != 2 {
			return fmt.Errorf("mã quốc gia GeoIP không hợp lệ: %q", c)
		}
	}

	// Validate BannedIPs & ShieldBannedIPs (with Trusted Proxy & Private checks using restored config)
	cleanBans := make([]BannedIPEntry, 0, len(next.BannedIPs))
	newBannedMap := make(map[string]*BannedIPEntry, len(next.BannedIPs))
	for i := range next.BannedIPs {
		norm, err := normalizeBanTarget(next.BannedIPs[i].IP)
		if err != nil {
			return fmt.Errorf("banned_ips[%d]: %w", i, err)
		}
		if isPrivateOrReservedIP(norm) || isTrustedProxyOrCloudflareIP(norm, next) {
			return fmt.Errorf("banned_ips[%d] chứa IP nội bộ hoặc Cloudflare/TrustedProxy: %s", i, norm)
		}
		entry := next.BannedIPs[i]
		entry.IP = norm
		cleanBans = append(cleanBans, entry)
	}
	next.BannedIPs = cleanBans
	for i := range next.BannedIPs {
		newBannedMap[next.BannedIPs[i].IP] = &next.BannedIPs[i]
	}

	for i := range next.ShieldBannedIPs {
		norm, err := normalizeBanTarget(next.ShieldBannedIPs[i].IP)
		if err != nil {
			return fmt.Errorf("shield_banned_ips[%d]: %w", i, err)
		}
		next.ShieldBannedIPs[i].IP = norm
	}

	// Validate Offenses
	cleanOffenses := make(map[string]int, len(bundle.Offenses))
	cleanOffenseRecs := make(map[string]OffenseRecord, len(bundle.Offenses))
	now := time.Now().UTC()
	for rawIP, cnt := range bundle.Offenses {
		if cnt <= 0 {
			continue
		}
		norm, err := normalizeBanTarget(rawIP)
		if err != nil {
			return fmt.Errorf("offenses[%s]: %w", rawIP, err)
		}
		if isPrivateOrReservedIP(norm) || isTrustedProxyOrCloudflareIP(norm, next) {
			continue
		}
		cleanOffenses[norm] = cnt
		cleanOffenseRecs[norm] = OffenseRecord{Count: cnt, LastSeenAt: now, LastReason: "[Restore] Backup bundle"}
	}

	// Validate SMTP & Alert channels (preserve existing secrets if redacted in bundle)
	s.mu.RLock()
	existingSMTPPwd := s.config.SMTP.Password
	existingTgToken := s.config.Alerts.TelegramBotToken
	existingWhSecret := s.config.Alerts.WebhookSecret
	existingAdminUser := s.config.AdminUser
	existingAdminPwd := s.config.AdminPassword
	existingShieldSecret := s.config.ShieldChallengeSecret
	s.mu.RUnlock()

	if next.SMTP.Password == "" || next.SMTP.Password == "********" {
		next.SMTP.Password = existingSMTPPwd
	}
	if err := validateSMTPConfig(&next.SMTP); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	if next.Alerts.TelegramBotToken == "" || next.Alerts.TelegramBotToken == "********" {
		next.Alerts.TelegramBotToken = existingTgToken
	}
	if next.Alerts.WebhookSecret == "" || next.Alerts.WebhookSecret == "********" {
		next.Alerts.WebhookSecret = existingWhSecret
	}
	if err := validateAlertChannelsConfig(&next.Alerts); err != nil {
		return fmt.Errorf("alerts: %w", err)
	}

	if next.DefaultBanTTL <= 0 && next.DefensePolicy.DefaultBanTTLHours > 0 {
		next.DefaultBanTTL = next.DefensePolicy.DefaultBanTTLHours
	}
	if next.DefensePolicy.SSHMaxAttempts <= 0 {
		next.DefensePolicy.SSHMaxAttempts = 3
	}
	if next.DefensePolicy.WAFAutoBanThreshold <= 0 {
		next.DefensePolicy.WAFAutoBanThreshold = 10
	}
	if next.LogRetentionDays <= 0 {
		next.LogRetentionDays = 30
	}
	if next.LogMaxDiskMB <= 0 {
		next.LogMaxDiskMB = 512
	}
	next.AdminUser = existingAdminUser
	next.AdminPassword = existingAdminPwd
	next.ShieldChallengeSecret = existingShieldSecret
	if strings.TrimSpace(next.ShieldChallengeSecret) == "" {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		next.ShieldChallengeSecret = hex.EncodeToString(b)
	}
	next.BlacklistIP = nil

	// Commit atomically under lock
	s.mu.Lock()
	s.config = next
	s.bannedMap = newBannedMap
	s.offenseCount = cleanOffenses
	s.offenseRecords = cleanOffenseRecs
	servicesCopy := append([]L4Service(nil), s.config.L4Services...)
	s.mu.Unlock()

	s.saveConfig()
	s.saveBansState()
	if s.logManager != nil {
		s.logManager.ConfigureRetention(next.LogRetentionDays, next.LogMaxDiskMB)
	}
	l4Manager.Sync(servicesCopy)
	s.triggerFirewallSync()
	go s.syncGeoIP()
	if s.reloadManager != nil {
		s.reloadManager.Trigger()
	}
	return nil
}
