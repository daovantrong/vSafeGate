package main

import (
	"time"
)

type L4Service struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"` // "tcp"
	ListenPort  int    `json:"listen_port"`
	BackendAddr string `json:"backend_addr"`
	Mode        string `json:"mode"` // "proxy"
	Enabled     bool   `json:"enabled"`
	MaxConns    int    `json:"max_conns"`
	RateLimit   int    `json:"rate_limit"`
	Description string `json:"description"`
	ActiveConns int64  `json:"active_conns"`
	TotalConns  int64  `json:"total_conns"`
	BytesIn     int64  `json:"bytes_in"`
	BytesOut    int64  `json:"bytes_out"`
}

type Site struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Upstream  string    `json:"upstream"`
	SSL       bool      `json:"ssl"`
	WAF       bool      `json:"waf"`
	CreatedAt time.Time `json:"created_at"`
}

type CustomRule struct {
	ID          string `json:"id"`
	RuleID      int    `json:"rule_id"`
	Name        string `json:"name"`
	Target      string `json:"target"`   // URI, HEADER, ARGS, IP
	Operator    string `json:"operator"` // rx, ipMatch, contains, beginsWith
	Pattern     string `json:"pattern"`
	Action      string `json:"action"`   // deny, allow
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
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
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	ClientIP  string    `json:"client_ip"`
	Host      string    `json:"host"`
	URI       string    `json:"uri"`
	Method    string    `json:"method"`
	RuleID    int       `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	Action    string    `json:"action"`
	UserAgent string    `json:"user_agent"`
}

type BannedIPEntry struct {
	IP            string    `json:"ip"`
	Reason        string    `json:"reason"`
	BannedAt      time.Time `json:"banned_at"`
	ExpiresAt     time.Time `json:"expires_at"`    // Zero time = permanent
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
	IP        string    `json:"ip"`        // IP or CIDR (e.g. "1.2.3.4" or "192.168.1.0/24")
	Note      string    `json:"note"`      // Description e.g. "Văn phòng Admin"
	CreatedAt time.Time `json:"created_at"`
}

type DefensePolicy struct {
	DefaultBanTTLHours  int  `json:"default_ban_ttl_hours"`  // e.g. 24
	SSHGuardEnabled     bool `json:"ssh_guard_enabled"`      // true
	SSHMaxAttempts      int  `json:"ssh_max_attempts"`       // 3
	CanaryEnabled       bool `json:"canary_enabled"`          // true
	WAFAutoBanEnabled   bool `json:"waf_auto_ban_enabled"`    // true
	WAFAutoBanThreshold int  `json:"waf_auto_ban_threshold"`  // e.g. 10
	SuricataAutoBan     bool `json:"suricata_auto_ban"`      // true
}

type Config struct {
	Sites            []Site             `json:"sites"`
	Rules            []CustomRule       `json:"rules"`
	L4Services       []L4Service        `json:"l4_services"`
	BlacklistIP      []string           `json:"blacklist_ip,omitempty"` // Legacy compat
	BannedIPs        []BannedIPEntry    `json:"banned_ips"`
	WhitelistIPs     []WhitelistIPEntry `json:"whitelist_ips"`
	DefaultBanTTL    int                `json:"default_ban_ttl_hours"` // Default TTL hours (e.g. 24)
	DefensePolicy    DefensePolicy      `json:"defense_policy"`
	GeoIPMode        string             `json:"geoip_mode"`            // "whitelist" or "blacklist"
	AllowedCountries []string           `json:"allowed_countries"`
	BlockedCountries []string           `json:"blocked_countries"`
	MgmtDomain       string             `json:"mgmt_domain"`
	MgmtHTTPSPort    int                `json:"mgmt_https_port"`
	MgmtHTTPPort     int                `json:"mgmt_http_port"`
	AdminUser        string             `json:"admin_user,omitempty"`
	AdminPassword    string             `json:"admin_password,omitempty"`
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
