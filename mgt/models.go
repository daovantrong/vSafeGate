package main

import (
	"strings"
	"time"
)

// AppVersion holds the semantic version of vSafeGate (overrideable at link time via -ldflags).
var AppVersion = "1.0.1"

type L4Service struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	Protocol               string   `json:"protocol"` // "tcp" or "udp"
	ListenPort             int      `json:"listen_port"`
	BackendAddr            string   `json:"backend_addr"`
	Backends               []string `json:"backends,omitempty"`
	LBPolicy               string   `json:"lb_policy,omitempty"`      // "round_robin", "least_conn", "ip_hash"
	ProxyProtocol          string   `json:"proxy_protocol,omitempty"` // "", "off", "v1", "v2"
	Mode                   string   `json:"mode"`                     // "proxy"
	Enabled                bool     `json:"enabled"`
	MaxConns               int      `json:"max_conns"`
	MaxConnsPerIP          int      `json:"max_conns_per_ip,omitempty"`
	RateLimit              int      `json:"rate_limit"`
	DialTimeoutSec         int      `json:"dial_timeout_sec,omitempty"`
	IdleTimeoutSec         int      `json:"idle_timeout_sec,omitempty"`
	HealthCheckIntervalSec int      `json:"health_check_interval_sec,omitempty"`
	Description            string   `json:"description"`
	ActiveConns            int64    `json:"active_conns"`
	TotalConns             int64    `json:"total_conns"`
	BytesIn                int64    `json:"bytes_in"`
	BytesOut               int64    `json:"bytes_out"`
}

type ShieldSensitiveRoute struct {
	PathPrefix string  `json:"path_prefix"`
	RPS        float64 `json:"rps"`
	Burst      int     `json:"burst,omitempty"`
}

type ShieldBanEntry struct {
	IP        string    `json:"ip"`
	Host      string    `json:"host,omitempty"`
	SiteID    string    `json:"site_id,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type WAFExclusion struct {
	ID         string   `json:"id"`
	RuleID     int      `json:"rule_id"`
	MatchURI   string   `json:"match_uri,omitempty"`
	RemoveArgs []string `json:"remove_args,omitempty"`
	Comment    string   `json:"comment,omitempty"`
	Enabled    bool     `json:"enabled"`
}

type Site struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Upstream  string    `json:"upstream"`
	Upstreams []string  `json:"upstreams,omitempty"`
	SSL       bool      `json:"ssl"`
	WAF       bool      `json:"waf"`
	CreatedAt time.Time `json:"created_at"`

	// Phase 1 WAF CRS v4, TLS, Identity Hiding & Cloudflare Failover fields
	WAFMode                  string         `json:"waf_mode,omitempty"`                   // "on", "detection", "off"
	ParanoiaLevel            int            `json:"paranoia_level,omitempty"`             // 1..4 (default 1)
	InboundAnomalyThreshold  int            `json:"inbound_anomaly_threshold,omitempty"`  // default 5
	OutboundAnomalyThreshold int            `json:"outbound_anomaly_threshold,omitempty"` // default 4
	AppPreset                string         `json:"app_preset,omitempty"`                 // "generic", "wordpress", "api", "nextcloud", "nas"
	Exclusions               []WAFExclusion `json:"exclusions,omitempty"`
	RequestBodyMaxMB         int            `json:"request_body_max_mb,omitempty"` // default 100
	TrustedProxies           []string       `json:"trusted_proxies,omitempty"`
	StrictCloudflareOrigin   bool           `json:"strict_cloudflare_origin,omitempty"`
	CertMode                 string         `json:"cert_mode,omitempty"` // "auto_http", "cloudflare_dns01", "uploaded", "internal", "none"
	CustomCertPath           string         `json:"custom_cert_path,omitempty"`
	CustomKeyPath            string         `json:"custom_key_path,omitempty"`
	CustomCertExpiry         string         `json:"custom_cert_expiry,omitempty"`
	CustomCertIssuer         string         `json:"custom_cert_issuer,omitempty"`
	HideAltSvc               bool           `json:"hide_alt_svc,omitempty"`

	AutoProxyEnabled         bool      `json:"auto_proxy_enabled,omitempty"`
	AutoProxyZoneID          string    `json:"auto_proxy_zone_id,omitempty"`
	AutoProxyRecordIDs       []string  `json:"auto_proxy_record_ids,omitempty"`
	AutoProxyThresholdRPS    int       `json:"auto_proxy_threshold_rps,omitempty"`
	AutoProxyThresholdDropPS int       `json:"auto_proxy_threshold_drop_ps,omitempty"`
	AutoProxyWindowSec       int       `json:"auto_proxy_window_sec,omitempty"`
	AutoProxyHoldMinutes     int       `json:"auto_proxy_hold_minutes,omitempty"`
	AutoProxyAutoRevert      bool      `json:"auto_proxy_auto_revert,omitempty"`
	AutoProxyUnderAttack     bool      `json:"auto_proxy_under_attack,omitempty"`
	AutoProxyActive          bool      `json:"auto_proxy_active,omitempty"`
	AutoProxyActivatedAt     time.Time `json:"auto_proxy_activated_at,omitempty"`

	// Phase 2 L7 Shield & Anti-Bot fields
	ShieldMode          string                 `json:"shield_mode,omitempty"` // "normal", "under_attack", "off"
	UnderAttackMode     bool                   `json:"under_attack_mode,omitempty"`
	RateLimitRPS        float64                `json:"rate_limit_rps,omitempty"`
	RateLimitBurst      int                    `json:"rate_limit_burst,omitempty"`
	SubnetRateLimitRPS  float64                `json:"subnet_rate_limit_rps,omitempty"`
	HostRateLimitRPS    float64                `json:"host_rate_limit_rps,omitempty"`
	MaxConcurrentPerIP  int                    `json:"max_concurrent_per_ip,omitempty"`
	ChallengeDifficulty int                    `json:"challenge_difficulty,omitempty"`
	SensitiveRoutes     []ShieldSensitiveRoute `json:"sensitive_routes,omitempty"`
	ExemptPaths         []string               `json:"exempt_paths,omitempty"`
	APIPaths            []string               `json:"api_paths,omitempty"`
	VerifySearchBots    *bool                  `json:"verify_search_bots,omitempty"`

	// Phase 3 L7 Multi-Upstream LB, Health Checks & Origin TLS fields
	LBPolicy            string `json:"lb_policy,omitempty"`             // "round_robin", "least_conn", "ip_hash", "first", "random"
	HealthCheckPath     string `json:"health_check_path,omitempty"`     // e.g. "/healthz"
	HealthCheckInterval string `json:"health_check_interval,omitempty"` // e.g. "10s"
	HealthCheckTimeout  string `json:"health_check_timeout,omitempty"`  // e.g. "3s"
	OriginTLSMode       string `json:"origin_tls_mode,omitempty"`       // "insecure", "system", "custom_ca"
	OriginTLSSNI        string `json:"origin_tls_sni,omitempty"`
	OriginTLSCAPath     string `json:"origin_tls_ca_path,omitempty"`
	OriginTLSCAPEM      string `json:"origin_tls_ca_pem,omitempty"`
	SecurityHeaders     *bool  `json:"security_headers,omitempty"`
}

type CustomRule struct {
	ID          string `json:"id"`
	RuleID      int    `json:"rule_id"`
	Name        string `json:"name"`
	Target      string `json:"target"`   // URI, HEADER, ARGS, IP, METHOD, ARGS|URI
	Operator    string `json:"operator"` // rx, ipMatch, contains, beginsWith
	Pattern     string `json:"pattern"`
	Action      string `json:"action"` // deny, drop, allow
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	SiteID      string `json:"site_id,omitempty"`
}

type RulePreset struct {
	Category    string `json:"category"`
	Name        string `json:"name"`
	Target      string `json:"target"`
	Operator    string `json:"operator"`
	Pattern     string `json:"pattern"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

type AttackLog struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	ClientIP   string    `json:"client_ip"`
	Host       string    `json:"host"`
	URI        string    `json:"uri"`
	Method     string    `json:"method"`
	RuleID     int       `json:"rule_id"`
	RuleName   string    `json:"rule_name"`
	Action     string    `json:"action"`
	UserAgent  string    `json:"user_agent"`
	MatchedVar string    `json:"matched_var,omitempty"`
	Phase      int       `json:"phase,omitempty"`
	Severity   string    `json:"severity,omitempty"`
	UniqueID   string    `json:"unique_id,omitempty"`
}

type BannedIPEntry struct {
	IP            string    `json:"ip"`
	Reason        string    `json:"reason"`
	BannedAt      time.Time `json:"banned_at"`
	ExpiresAt     time.Time `json:"expires_at"`     // Zero time = permanent
	DurationHours int       `json:"duration_hours"` // 0 = permanent, 1, 6, 24, 72, 168...
}

type BannedIPResponse struct {
	IP               string    `json:"ip"`
	Reason           string    `json:"reason"`
	BannedAt         time.Time `json:"banned_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	DurationHours    int       `json:"duration_hours"`
	IsPermanent      bool      `json:"is_permanent"`
	RemainingSeconds int64     `json:"remaining_seconds"`
	RemainingText    string    `json:"remaining_text"`
}

type WhitelistIPEntry struct {
	IP        string    `json:"ip"`   // IP or CIDR (e.g. "1.2.3.4" or "192.168.1.0/24")
	Note      string    `json:"note"` // Description e.g. "Văn phòng Admin"
	CreatedAt time.Time `json:"created_at"`
}

type DefensePolicy struct {
	DefaultBanTTLHours  int  `json:"default_ban_ttl_hours"`  // e.g. 24
	SSHGuardEnabled     bool `json:"ssh_guard_enabled"`      // true
	SSHMaxAttempts      int  `json:"ssh_max_attempts"`       // 3
	CanaryEnabled       bool `json:"canary_enabled"`         // true
	WAFAutoBanEnabled   bool `json:"waf_auto_ban_enabled"`   // true
	WAFAutoBanThreshold int  `json:"waf_auto_ban_threshold"` // e.g. 10
	SuricataAutoBan     bool `json:"suricata_auto_ban"`      // true
	EgressFilterEnabled bool `json:"egress_filter_enabled,omitempty"`
}

type CloudflareConfig struct {
	APIToken     string    `json:"api_token,omitempty"`
	CachedIPv4   []string  `json:"cached_ipv4,omitempty"`
	CachedIPv6   []string  `json:"cached_ipv6,omitempty"`
	LastIPSyncAt time.Time `json:"last_ip_sync_at,omitempty"`
	IPSyncSource string    `json:"ip_sync_source,omitempty"`
}

type SMTPConfig struct {
	Enabled              bool     `json:"enabled"`
	SMTPHost             string   `json:"smtp_host"`
	SMTPPort             int      `json:"smtp_port"` // 587 STARTTLS, 465 implicit TLS, 25 plain
	TLSMode              string   `json:"tls_mode"`  // "starttls", "tls", "none"
	Username             string   `json:"username"`
	Password             string   `json:"password,omitempty"`
	FromAddress          string   `json:"from_address"`
	ToAddresses          []string `json:"to_addresses"`
	InsecureSkipVerify   bool     `json:"insecure_skip_verify,omitempty"`
	CooldownMinutes      int      `json:"cooldown_minutes,omitempty"`
	DropSpikeThresholdPS float64  `json:"drop_spike_threshold_ps,omitempty"`
	CertExpiryWarnDays   int      `json:"cert_expiry_warn_days,omitempty"`
}

type AlertChannelsConfig struct {
	TelegramEnabled   bool   `json:"telegram_enabled"`
	TelegramBotToken  string `json:"telegram_bot_token,omitempty"`
	TelegramChatID    string `json:"telegram_chat_id,omitempty"`
	DiscordEnabled    bool   `json:"discord_enabled"`
	DiscordWebhookURL string `json:"discord_webhook_url,omitempty"`
	WebhookEnabled    bool   `json:"webhook_enabled"`
	WebhookURL        string `json:"webhook_url,omitempty"`
	WebhookSecret     string `json:"webhook_secret,omitempty"`
}

type SharedThreatConfig struct {
	Enabled         bool      `json:"enabled"`
	HubURL          string    `json:"hub_url,omitempty"`
	APIKey          string    `json:"api_key,omitempty"`
	NodeName        string    `json:"node_name,omitempty"`
	PushOnBan       bool      `json:"push_on_ban"`
	SyncEnabled     bool      `json:"sync_enabled"`
	SyncIntervalMin int       `json:"sync_interval_min,omitempty"`
	LastSyncAt      time.Time `json:"last_sync_at,omitempty"`
	LastSyncCount   int       `json:"last_sync_count,omitempty"`
	LastSyncError   string    `json:"last_sync_error,omitempty"`
}

type AdminAuditEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	SourceIP  string    `json:"source_ip"`
	Action    string    `json:"action"`
	Target    string    `json:"target,omitempty"`
	Status    string    `json:"status"`
	Detail    string    `json:"detail,omitempty"`
}

type ConfigBackupBundle struct {
	Version    string         `json:"version"`
	ExportedAt time.Time      `json:"exported_at"`
	Config     Config         `json:"config"`
	Offenses   map[string]int `json:"offenses,omitempty"`
}

type Config struct {
	Sites                 []Site             `json:"sites"`
	Rules                 []CustomRule       `json:"rules"`
	L4Services            []L4Service        `json:"l4_services"`
	BlacklistIP           []string           `json:"blacklist_ip,omitempty"` // Legacy compat
	BannedIPs             []BannedIPEntry    `json:"banned_ips"`
	ShieldBannedIPs       []ShieldBanEntry   `json:"shield_banned_ips,omitempty"`
	WhitelistIPs          []WhitelistIPEntry `json:"whitelist_ips"`
	DefaultBanTTL         int                `json:"default_ban_ttl_hours"` // Default TTL hours (e.g. 24)
	DefensePolicy         DefensePolicy      `json:"defense_policy"`
	GeoIPMode             string             `json:"geoip_mode"` // "disabled", "whitelist", or "blacklist"
	AllowedCountries      []string           `json:"allowed_countries"`
	BlockedCountries      []string           `json:"blocked_countries"`
	MgmtDomain            string             `json:"mgmt_domain"`
	MgmtCertMode          string             `json:"mgmt_cert_mode,omitempty"` // "letsencrypt", "internal", "custom"
	MgmtCertChallenge     string             `json:"mgmt_cert_challenge,omitempty"` // "dns01" (default) | "http01"
	MgmtCertInternal      bool               `json:"mgmt_cert_internal,omitempty"`
	MgmtCustomCertPath    string             `json:"mgmt_custom_cert_path,omitempty"`
	MgmtCustomKeyPath     string             `json:"mgmt_custom_key_path,omitempty"`
	MgmtHTTPSPort         int                `json:"mgmt_https_port"`
	MgmtHTTPPort          int                `json:"mgmt_http_port"`
	MgmtListenIPs           []string           `json:"mgmt_listen_ips,omitempty"`
	MgmtAllowedCIDRs        []string           `json:"mgmt_allowed_cidrs,omitempty"`
	MgmtAllowPublicInternet *bool              `json:"mgmt_allow_public_internet,omitempty"`
	TrustedProxies          []string           `json:"trusted_proxies,omitempty"`
	TrustedInterfaces       []string           `json:"trusted_interfaces,omitempty"`
	SSHPorts                []int              `json:"ssh_ports,omitempty"`
	Cloudflare            CloudflareConfig   `json:"cloudflare,omitempty"`
	SMTP                  SMTPConfig          `json:"smtp,omitempty"`
	Alerts                AlertChannelsConfig `json:"alerts,omitempty"`
	SharedThreat          SharedThreatConfig  `json:"shared_threat,omitempty"`
	LogRetentionDays      int                `json:"log_retention_days,omitempty"`
	LogMaxDiskMB          int                `json:"log_max_disk_mb,omitempty"`
	ShieldChallengeSecret string             `json:"shield_challenge_secret,omitempty"`
	AdminUser             string             `json:"admin_user,omitempty"`
	AdminPassword         string             `json:"admin_password,omitempty"`
}

func isMgmtPublicInternetAllowed(cfg Config) bool {
	if cfg.MgmtAllowPublicInternet == nil {
		return true
	}
	return *cfg.MgmtAllowPublicInternet
}

func effectiveTrustedInterfaces(cfg Config) []string {
	if len(cfg.TrustedInterfaces) == 0 {
		return []string{"tailscale+", "zt+"}
	}
	out := make([]string, 0, len(cfg.TrustedInterfaces))
	seen := make(map[string]struct{}, len(cfg.TrustedInterfaces))
	for _, raw := range cfg.TrustedInterfaces {
		s := strings.TrimSpace(raw)
		if s == "" || s == "lo" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func effectiveSSHPorts(cfg Config) []int {
	if len(cfg.SSHPorts) == 0 {
		return []int{2251, 22222, 22}
	}
	out := make([]int, 0, len(cfg.SSHPorts))
	seen := make(map[int]struct{}, len(cfg.SSHPorts))
	for _, p := range cfg.SSHPorts {
		if p < 1 || p > 65535 {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return []int{2251, 22222, 22}
	}
	return out
}

type Session struct {
	Username  string
	ExpiresAt time.Time
}

type SystemMetrics struct {
	CPUPercent     float64 `json:"cpu_percent"`
	MemUsedMB      int64   `json:"mem_used_mb"`
	MemTotalMB     int64   `json:"mem_total_mb"`
	MemPercent     float64 `json:"mem_percent"`
	DiskUsedGB     float64 `json:"disk_used_gb"`
	DiskTotalGB    float64 `json:"disk_total_gb"`
	DiskPercent    float64 `json:"disk_percent"`
	Load1          float64 `json:"load_1"`
	Load5          float64 `json:"load_5"`
	Load15         float64 `json:"load_15"`
	UptimeSeconds  int64   `json:"uptime_seconds"`
	UptimeStr      string  `json:"uptime_str"`
	TCPConns       int     `json:"tcp_conns"`
	IDSAlerts      int64   `json:"ids_alerts"`
	L4ActiveConns  int64   `json:"l4_active_conns"`
	L4ServiceCount int     `json:"l4_service_count"`
	SSHBans        int64   `json:"ssh_bans"`
	PortScanBans   int64   `json:"port_scan_bans"`
	BlockedIPs     int     `json:"blocked_ips"`
	GeoIPCount     int     `json:"geoip_count"`
	GeoIPMode      string  `json:"geoip_mode"`
}

type GeoIPCountryPreset struct {
	Code string `json:"code"`
	Name string `json:"name"`
	Flag string `json:"flag"`
}

type EveAlert struct {
	Timestamp string `json:"timestamp"`
	FlowID    int64  `json:"flow_id"`
	InIface   string `json:"in_iface"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Alert     struct {
		Action      string `json:"action"`
		SignatureID int    `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
}

type IDSStats struct {
	Running       bool        `json:"running"`
	TotalAlerts   int64       `json:"total_alerts"`
	Severity1High int64       `json:"severity_1_high"`
	Severity2Med  int64       `json:"severity_2_med"`
	Severity3Low  int64       `json:"severity_3_low"`
	RulesLoaded   int         `json:"rules_loaded"`
	RecentAlerts  []AttackLog `json:"recent_alerts"`
}

func getRulePresets() []RulePreset {
	return []RulePreset{
		{
			Category:    "Synology NAS & Lưu Trữ",
			Name:        "[NAS] Chống Brute-force & Dò mật khẩu DSM",
			Target:      "URI",
			Operator:    "rx",
			Pattern:     "^/webapi/auth\\.cgi",
			Action:      "deny",
			Description: "Ngăn chặn các cuộc tấn công dò quét mật khẩu tự động vào API đăng nhập Synology",
		},
		{
			Category:    "Synology NAS & Lưu Trữ",
			Name:        "[NAS] Chặn tải lên mã độc thực thi (File Upload Guard)",
			Target:      "URI",
			Operator:    "rx",
			Pattern:     "(?i)\\.(php|phtml|sh|bash|exe|dll|jsp|asp|aspx)(\\?|$)",
			Action:      "deny",
			Description: "Chặn tải lên web shell hoặc file thực thi độc hại qua WebDAV / File Station",
		},
		{
			Category:    "Synology NAS & Lưu Trữ",
			Name:        "[NAS] Chặn khai thác can thiệp CGI nội bộ DSM",
			Target:      "ARGS",
			Operator:    "rx",
			Pattern:     "(?i)(syno_token|dsm_vuln|cgi-bin/.*\\.cgi)",
			Action:      "deny",
			Description: "Ngăn chặn kẻ tấn công can thiệp vào các tham số nhạy cảm trong CGI của hệ điều hành DSM",
		},
		{
			Category:    "Synology NAS & Lưu Trữ",
			Name:        "[NAS] Bảo vệ WebDAV: Chặn HTTP Method nguy hiểm",
			Target:      "HEADER:X-HTTP-Method-Override",
			Operator:    "rx",
			Pattern:     "(?i)^(CONNECT|TRACE|TRACK)$",
			Action:      "deny",
			Description: "Chống giả mạo phương thức HTTP nguy hiểm khi truyền dữ liệu qua WebDAV",
		},
		{
			Category:    "Cơ Sở Dữ Liệu & API",
			Name:        "[Database] Chặn SQL Injection sâu (Union, Time-based, Stacked)",
			Target:      "ARGS",
			Operator:    "rx",
			Pattern:     "(?i)(\\bunion\\b.*\\bselect\\b|\\bor\\b\\s+1=1|\\bdrop\\b\\s+\\btable\\b|;\\s*--|\\bwaitfor\\b\\s+\\bdelay\\b|\\bsleep\\(\\d+\\))",
			Action:      "deny",
			Description: "Bảo vệ CSDL khỏi các mẫu tấn công SQLi phức tạp (Blind, Time-based, Stacked Queries)",
		},
		{
			Category:    "Cơ Sở Dữ Liệu & API",
			Name:        "[Database] Chặn NoSQL & MongoDB Query Injection",
			Target:      "ARGS",
			Operator:    "rx",
			Pattern:     "(?i)(\\$where|\\$ne|\\$regex|\\$gt|\\$lt|\\$in|\\$nin)",
			Action:      "deny",
			Description: "Ngăn chặn can thiệp cấu trúc truy vấn vào các CSDL NoSQL / MongoDB",
		},
		{
			Category:    "Cơ Sở Dữ Liệu & API",
			Name:        "[API] Chặn Cross-Site Scripting (XSS) & Cookie Theft",
			Target:      "ARGS",
			Operator:    "rx",
			Pattern:     "(?i)(<script[^>]*>|javascript:|onerror=|onload=|document\\.cookie)",
			Action:      "deny",
			Description: "Ngăn chặn mã độc JavaScript đánh cắp phiên làm việc và dữ liệu người dùng",
		},
		{
			Category:    "Bảo Vệ Tệp Tin & Hệ Thống",
			Name:        "[Hệ Thống] Chặn lộ lọt file nhạy cảm (.env, .git, .sql, .bak)",
			Target:      "URI",
			Operator:    "rx",
			Pattern:     "(?i)(\\.env|\\.git|\\.vscode|\\.bak|\\.sql|\\.config|composer\\.json|package\\.json)",
			Action:      "deny",
			Description: "Chặn hacker quét tìm file cấu hình chứa thông tin tài khoản và mã nguồn",
		},
		{
			Category:    "Bảo Vệ Tệp Tin & Hệ Thống",
			Name:        "[Hệ Thống] Chống Path Traversal (Đọc trộm file hệ thống)",
			Target:      "ARGS",
			Operator:    "rx",
			Pattern:     "(?i)(\\.\\./\\.\\./|\\.\\.\\\\.\\.\\\\|/etc/passwd|/windows/win\\.ini)",
			Action:      "deny",
			Description: "Ngăn chặn kỹ thuật vượt thư mục để đọc tệp tin nhạy cảm của Linux / Windows",
		},
		{
			Category:    "Bảo Vệ Tệp Tin & Hệ Thống",
			Name:        "[Bảo Mật] Chặn Scanner & Hacker Tools (sqlmap, nikto, nuclei)",
			Target:      "HEADER:User-Agent",
			Operator:    "rx",
			Pattern:     "(?i)(sqlmap|nikto|acunetix|gobuster|dirbuster|nmap|masscan|wpscan|nuclei|zgrab)",
			Action:      "deny",
			Description: "Tự động phát hiện và chặn đứng các công cụ quét lỗ hổng tự động của hacker",
		},
		{
			Category:    "Bảo Vệ Tệp Tin & Hệ Thống",
			Name:        "[Bảo Mật] Giới hạn trang Quản Trị chỉ cho mạng nội bộ",
			Target:      "URI",
			Operator:    "rx",
			Pattern:     "^/(admin|wp-admin|wp-login\\.php|phpmyadmin)",
			Action:      "deny",
			Description: "Chỉ cho phép IP mạng nội bộ truy cập các đường dẫn quản trị nhạy cảm",
		},
	}
}

func getGeoIPPresetList() []GeoIPCountryPreset {
	return []GeoIPCountryPreset{
		{Code: "VN", Name: "Việt Nam", Flag: "🇻🇳"},
		{Code: "CN", Name: "Trung Quốc", Flag: "🇨🇳"},
		{Code: "RU", Name: "Nga", Flag: "🇷🇺"},
		{Code: "US", Name: "Hoa Kỳ", Flag: "🇺🇸"},
		{Code: "JP", Name: "Nhật Bản", Flag: "🇯🇵"},
		{Code: "KR", Name: "Hàn Quốc", Flag: "🇰🇷"},
		{Code: "SG", Name: "Singapore", Flag: "🇸🇬"},
		{Code: "KP", Name: "Triều Tiên", Flag: "🇰🇵"},
		{Code: "IR", Name: "Iran", Flag: "🇮🇷"},
		{Code: "IN", Name: "Ấn Độ", Flag: "🇮🇳"},
		{Code: "BR", Name: "Brazil", Flag: "🇧🇷"},
		{Code: "ID", Name: "Indonesia", Flag: "🇮🇩"},
	}
}
