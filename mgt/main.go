package main

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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
	recentLogs      []AttackLog
	bannedMap       map[string]*BannedIPEntry
	sessions        map[string]Session
	sessionsMu      sync.RWMutex
	sshBannedCount  int64
	portScanCount   int64
	logManager      *PersistentLogManager
	reloadManager   *ReloadManager
	caddySupervisor *CaddySupervisor
	offenseCount    map[string]int
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
	return 53593 // Default fallback estimated rules count
}

func initDefaults(cfgPath, caddyPath, rulesPath, logsPath string) *AppState {
	s := &AppState{
		configPath: cfgPath,
		caddyPath:  caddyPath,
		rulesPath:  rulesPath,
		logsPath:   logsPath,
		recentLogs: make([]AttackLog, 0),
		bannedMap:    make(map[string]*BannedIPEntry),
		sessions:     make(map[string]Session),
		offenseCount: make(map[string]int),
	}

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

	s.saveConfig()
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
	os.MkdirAll(dir, 0755)

	// Atomic write
	tmpFile := s.configPath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err == nil {
		os.Rename(tmpFile, s.configPath)
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
	os.MkdirAll(dir, 0755)

	// Atomic write
	tmpFile := s.configPath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err == nil {
		os.Rename(tmpFile, s.configPath)
	}
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

func main() {
	caddyPath := "/etc/caddy/Caddyfile"
	rulesPath := "/etc/caddy/rules/custom-rules.conf"
	configPath := "/etc/vsafegate/config.json"
	logsPath := "/var/log/vsafegate/attacks.jsonl"

	initAuthHelper()

	if os.Getenv("ENV") == "dev" {
		caddyPath = "./Caddyfile"
		rulesPath = "./rules/custom-rules.conf"
		configPath = "./config.json"
		logsPath = "./attacks.jsonl"
	}

	state = initDefaults(configPath, caddyPath, rulesPath, logsPath)
	state.generateCaddyAndRules()
	if runtime.GOOS == "linux" && os.Getenv("ENV") != "dev" {
		state.caddySupervisor = NewCaddySupervisor(caddyPath)
		state.caddySupervisor.Start()
	}
	state.startLogWatcher()
	startCPUMonitor()
	state.startSSHWatcher()
	state.startCanaryHoneypot()

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
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "Invalid Request", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if !verifyLinuxAuth(creds.Username, creds.Password) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Tên đăng nhập hoặc mật khẩu không chính xác!"})
			return
		}

		token := state.createSession(creds.Username)
		isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" || (state != nil && state.config.MgmtHTTPSPort > 0)
		http.SetCookie(w, &http.Cookie{
			Name:     "vsafegate_session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   isHTTPS,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   86400, // 24 hours
		})

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"username": creds.Username,
		})
	})

	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("vsafegate_session"); err == nil {
			state.revokeSession(cookie.Value)
		}
		isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" || (state != nil && state.config.MgmtHTTPSPort > 0)
		http.SetCookie(w, &http.Cookie{
			Name:     "vsafegate_session",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   isHTTPS,
			MaxAge:   -1,
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
	})

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
			mode = "whitelist"
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
		newMode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
		if newMode != "whitelist" && newMode != "blacklist" {
			http.Error(w, "Chế độ không hợp lệ (phải là 'whitelist' hoặc 'blacklist')", 400)
			return
		}

		state.mu.Lock()
		state.config.GeoIPMode = newMode
		state.mu.Unlock()
		state.saveConfig()

		go state.syncGeoIP()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "ok",
			"geoip_mode": newMode,
		})
	}))

	mux.HandleFunc("/api/geoip/toggle", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		code := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("code")))
		if len(code) != 2 {
			http.Error(w, "Mã quốc gia không hợp lệ (phải là 2 ký tự ISO)", 400)
			return
		}

		state.mu.Lock()
		mode := state.config.GeoIPMode
		if mode == "" {
			mode = "whitelist"
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

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "ok",
			"code":       code,
			"action":     map[bool]string{true: "removed", false: "added"}[found],
			"geoip_mode": mode,
		})
	}))

	mux.HandleFunc("/api/geoip/custom", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Code string `json:"code"`
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

		state.mu.Lock()
		mode := state.config.GeoIPMode
		if mode == "" {
			mode = "whitelist"
		}

		changed := false
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
			if newSvc.Protocol == "" {
				newSvc.Protocol = "tcp"
			}
			if newSvc.Mode == "" {
				newSvc.Mode = "proxy"
			}
			if newSvc.ListenPort <= 0 || newSvc.ListenPort > 65535 {
				http.Error(w, "Cổng lắng nghe không hợp lệ (1-65535)", 400)
				return
			}
			if newSvc.BackendAddr == "" {
				http.Error(w, "Địa chỉ máy chủ đích (Backend) không được để trống", 400)
				return
			}

			state.mu.Lock()
			for _, s := range state.config.L4Services {
				if s.ListenPort == newSvc.ListenPort {
					state.mu.Unlock()
					http.Error(w, fmt.Sprintf("Cổng %d đã được cấu hình cho dịch vụ '%s'", newSvc.ListenPort, s.Name), 400)
					return
				}
			}

			state.config.L4Services = append(state.config.L4Services, newSvc)
			servicesCopy := make([]L4Service, len(state.config.L4Services))
			copy(servicesCopy, state.config.L4Services)
			state.mu.Unlock()

			state.saveConfig()
			l4Manager.Sync(servicesCopy)
			json.NewEncoder(w).Encode(newSvc)
			return
		}

		if r.Method == http.MethodPut {
			var updated L4Service
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			found := false
			state.mu.Lock()
			for i, s := range state.config.L4Services {
				if s.ID == updated.ID {
					state.config.L4Services[i].Name = updated.Name
					state.config.L4Services[i].ListenPort = updated.ListenPort
					state.config.L4Services[i].BackendAddr = updated.BackendAddr
					state.config.L4Services[i].Protocol = updated.Protocol
					state.config.L4Services[i].Mode = updated.Mode
					state.config.L4Services[i].MaxConns = updated.MaxConns
					state.config.L4Services[i].RateLimit = updated.RateLimit
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
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}
	}))

	mux.HandleFunc("/api/l4/services/toggle", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
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

		fwStatus := "active"
		if err := exec.Command("ipset", "list", "vsafegate-blacklist", "-terse").Run(); err != nil {
			fwStatus = "inactive"
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
			"nftables_fw":   fwStatus,
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
			newSite.Domain = strings.TrimSpace(newSite.Domain)
			if newSite.Domain == "" {
				http.Error(w, "Domain is required", 400)
				return
			}
			newSite.Upstream = strings.TrimRight(strings.TrimSpace(newSite.Upstream), "/")
			newSite.ID = fmt.Sprintf("site-%d", time.Now().UnixNano())
			newSite.CreatedAt = time.Now()

			state.mu.Lock()
			state.config.Sites = append(state.config.Sites, newSite)
			state.mu.Unlock()

			state.saveConfig()
			if state.reloadManager != nil {
				state.reloadManager.Trigger()
			}
			json.NewEncoder(w).Encode(newSite)
			return
		}

		if r.Method == http.MethodPut {
			var updated Site
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			found := false
			state.mu.Lock()
			for i, s := range state.config.Sites {
				if s.ID == updated.ID {
					state.config.Sites[i].Domain = updated.Domain
					state.config.Sites[i].Upstream = strings.TrimRight(strings.TrimSpace(updated.Upstream), "/")
					state.config.Sites[i].SSL = updated.SSL
					state.config.Sites[i].WAF = updated.WAF
					found = true
					break
				}
			}
			state.mu.Unlock()

			if !found {
				http.Error(w, "Site not found", 404)
				return
			}
			state.saveConfig()
			if state.reloadManager != nil {
				state.reloadManager.Trigger()
			}
			json.NewEncoder(w).Encode(updated)
			return
		}

		if r.Method == http.MethodDelete {
			id := r.URL.Query().Get("id")
			state.mu.Lock()
			filtered := make([]Site, 0)
			for _, s := range state.config.Sites {
				if s.ID != id {
					filtered = append(filtered, s)
				}
			}
			state.config.Sites = filtered
			state.mu.Unlock()

			state.saveConfig()
			if state.reloadManager != nil {
				state.reloadManager.Trigger()
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}
	}))

	// Rules API (Unique ID guaranteed)
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
			var newRule CustomRule
			if err := json.NewDecoder(r.Body).Decode(&newRule); err != nil {
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

			newRule.Enabled = true
			state.config.Rules = append(state.config.Rules, newRule)
			state.mu.Unlock()

			state.saveConfig()
			if state.reloadManager != nil {
				state.reloadManager.Trigger()
			}
			json.NewEncoder(w).Encode(newRule)
			return
		}

		if r.Method == http.MethodPut {
			var updated CustomRule
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
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
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}
	}))

	mux.HandleFunc("/api/rules/toggle", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
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
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.IP == "" {
				http.Error(w, "Vui lòng nhập địa chỉ IP", 400)
				return
			}
			targetIP := strings.TrimSpace(payload.IP)
			if net.ParseIP(targetIP) == nil {
				http.Error(w, "Định dạng địa chỉ IP không hợp lệ", 400)
				return
			}
			if isPrivateOrReservedIP(targetIP) {
				http.Error(w, "Không thể chặn địa chỉ IP nội bộ hoặc loopback", 400)
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
			list := state.getBannedIPList()
			json.NewEncoder(w).Encode(list)
			return
		}

		if r.Method == http.MethodDelete {
			clearAll := r.URL.Query().Get("all")
			if clearAll == "true" || clearAll == "1" {
				state.clearAllBannedIPs("[Admin] Xóa toàn bộ danh sách Blacklist")
			} else {
				ip := r.URL.Query().Get("ip")
				if ip != "" {
					state.unbanIP(ip, "[Admin] Gỡ chặn thủ công")
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

			json.NewEncoder(w).Encode(p)
			return
		}
	}))

	// Management Settings API (Domain, Ports)
	mux.HandleFunc("/api/mgmt/settings", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodGet {
			state.mu.RLock()
			defer state.mu.RUnlock()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"mgmt_domain":     state.config.MgmtDomain,
				"mgmt_https_port": state.config.MgmtHTTPSPort,
				"mgmt_http_port":  state.config.MgmtHTTPPort,
			})
			return
		}

		if r.Method == http.MethodPost {
			var payload struct {
				MgmtDomain    string `json:"mgmt_domain"`
				MgmtHTTPSPort int    `json:"mgmt_https_port"`
				MgmtHTTPPort  int    `json:"mgmt_http_port"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err == nil {
				state.mu.Lock()
				state.config.MgmtDomain = strings.TrimSpace(payload.MgmtDomain)
				if payload.MgmtHTTPSPort > 0 {
					state.config.MgmtHTTPSPort = payload.MgmtHTTPSPort
				}
				if payload.MgmtHTTPPort > 0 {
					state.config.MgmtHTTPPort = payload.MgmtHTTPPort
				}
				state.mu.Unlock()
				state.saveConfig()

				if state.reloadManager != nil {
					state.reloadManager.Trigger()
				}
				json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
				return
			}
			http.Error(w, "Invalid body", 400)
			return
		}
	}))

	// Hot Reload API (Force Immediate)
	mux.HandleFunc("/api/reload", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if state.reloadManager != nil {
			state.reloadManager.ForceReload()
		} else {
			state.generateCaddyAndRules()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "reloaded successfully"})
	}))

	port := "127.0.0.1:9444"
	fmt.Printf("=====================================================\n")
	fmt.Printf("vSafeGate v%s Virtual Security Management Dashboard Started on %s\n", AppVersion, port)
	if state.config.MgmtDomain != "" {
		fmt.Printf("Web Panel (HTTPS): https://%s:%d\n", state.config.MgmtDomain, state.config.MgmtHTTPSPort)
		fmt.Printf("Web Panel (HTTP):  http://%s:%d\n", state.config.MgmtDomain, state.config.MgmtHTTPPort)
	} else {
		fmt.Printf("Web Panel: Port %d\n", state.config.MgmtHTTPSPort)
	}
	fmt.Printf("Auth Method: Linux System Accounts (PAM / shadow) & Admin Config\n")
	fmt.Printf("Active Defenses: Caddy L7 Supervisor, SSH Guard, Canary, GeoIP, Auto-Ban TTL (%dh)\n", state.config.DefaultBanTTL)
	fmt.Printf("Persistent Log: %s\n", logsPath)
	fmt.Printf("=====================================================\n")

	srv := &http.Server{
		Addr:    port,
		Handler: mux,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("[Shutdown] Received signal %v, stopping managed services cleanly...", sig)
		if state.caddySupervisor != nil {
			state.caddySupervisor.Stop()
		}
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
