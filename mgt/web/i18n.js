// vSafeGate Internationalization (i18n) Engine
// Supported Languages: 'vi' (Tiếng Việt), 'en' (English)

const i18nData = {
  vi: {
    brand: {
      name: "vSafeGate",
      subtitle: "Virtual Security Gateway & WAF",
      tagline: "Hệ thống tường lửa chuyên nghiệp 2 tầng"
    },
    nav: {
      dashboard: "Tổng Quan",
      sites: "Website & Proxy",
      l4: "Dịch Vụ L4",
      rules: "Quy Tắc Phòng Thủ",
      ipmgmt: "Giám Sát Địa Chỉ IP",
      logs: "Nhật Ký Tấn Công",
      settings: "Cài Đặt & Cloudflare",
      logout: "Đăng Xuất",
      core_status: "Trạng Thái Lõi",
      protecting: "Đang Bảo Vệ",
      native_mode: "Native Linux (0 Docker)",
      reload_rules: "Nạp Lại Quy Tắc"
    },
    theme: {
      dark: "Chế độ tối",
      light: "Chế độ sáng",
      toggle: "Đổi giao diện Sáng / Tối"
    },
    lang: {
      vi: "Tiếng Việt",
      en: "English",
      toggle: "Chuyển đổi ngôn ngữ (VI / EN)"
    },
    dashboard: {
      title: "Bảng Điều Khiển Tổng Quan (Dashboard)",
      subtitle: "Giám sát tải phần cứng máy chủ, lưu lượng mạng và các cơ chế phòng thủ tự động",
      badge_live: "Hoạt động thời gian thực",
      active_defenses: "Phòng thủ chủ động:",
      ids_alerts: "cảnh báo",
      l4_sessions: "phiên",
      geoip_title: "GeoIP:",
      ssh_guard: "SSH Guard:",
      pass_probes: "dò pass",
      port_canary: "Port Canary:",
      bot_drops: "bot drop",
      cpu: "CPU Usage",
      ram: "Bộ Nhớ RAM",
      disk: "Ổ Đĩa Hệ Thống",
      uptime: "Thời Gian Chạy",
      tcp_conns: "Kết Nối TCP",
      stat_total_attacks: "Tổng Lượt Chặn",
      stat_waf_blocks: "Chặn WAF (L7)",
      stat_blacklist: "Kernel Drop (L3/L4)",
      traffic_trend: "Xu Hướng Lưu Lượng & Tấn Công",
      threat_types: "Phân Loại Mối Đe Dọa",
      recent_attacks: "Lịch Sử Tấn Công Gần Nhất (Live Stream)",
      view_all: "Xem Tất Cả →",
      empty_attacks: "Chưa ghi nhận cuộc tấn công nào. Hệ thống đang an toàn!",
      col_time: "Thời Gian",
      col_ip: "IP Nguồn",
      col_host: "Tên Miền",
      col_uri: "URI / Payload",
      col_rule: "Quy Tắc Vi Phạm",
      col_action: "Hành Động",
      col_handle: "Xử Lý"
    },
    sites: {
      title: "Quản Lý Website & Proxy Chuyển Tiếp",
      subtitle: "Thêm, sửa, cấu hình đích chuyển tiếp (Upstream) và SSL tự động Let's Encrypt",
      btn_add: "+ Thêm Website Mới",
      col_domain: "Tên Miền (Host)",
      col_upstream: "Chuyển Tiếp Về (Upstream)",
      col_ssl: "Tự Động SSL",
      col_waf: "Chế Độ WAF",
      col_actions: "Thao Tác",
      empty: "Chưa có website nào được khai báo bảo vệ."
    },
    l4: {
      title: "Cổng Dịch Vụ Mạng L4 & Stream Gateway",
      subtitle: "Định tuyến bảo vệ SMB, SSH, RDP, Database... cho mạng nội bộ. Lưu lượng được kiểm soát qua Kernel Firewall, ThreatIntel và IDS.",
      btn_add: "+ Khai Báo Cổng Mới",
      col_name: "Tên Dịch Vụ",
      col_proto: "Giao Thức",
      col_port: "Cổng Nghe",
      col_target: "Máy Chủ Đích",
      col_mode: "Chế Độ",
      col_sessions: "Phiên",
      col_status: "Trạng Thái",
      col_actions: "Thao Tác",
      empty: "Đang tải danh sách dịch vụ L4..."
    },
    rules: {
      title: "Trung Tâm Quy Tắc Phòng Thủ (Unified Rules Engine)",
      subtitle: "Quản lý danh sách các quy tắc Quốc Gia (GeoIP), Dải mạng tin cậy (CIDR) và WAF Ứng Dụng",
      btn_detect_interfaces: "Rule Mẫu Card Mạng",
      btn_presets: "Rule Mẫu (Presets)",
      btn_add: "+ Thêm Quy Tắc Mới",
      zero_trust_title: "🔒 NGUYÊN TẮC ZERO-TRUST & PHÒNG THỦ ĐA TẦNG",
      zero_trust_desc: "vSafeGate vận hành theo cơ chế Default Deny ở tầng Linux Kernel (ipset hash:net O(1)). Toàn bộ kết nối không nằm trong danh sách cho phép (Whitelist) hoặc thuộc danh sách quốc gia bị chặn đều bị DROP ngay lập tức.",
      col_id: "ID Quy Tắc",
      col_name: "Tên Quy Tắc",
      col_target: "Đối Tượng Lọc",
      col_operator: "Toán Tử",
      col_pattern: "Mẫu So Khớp (Pattern)",
      col_action: "Hành Động",
      col_actions: "Thao Tác"
    },
    ipmgmt: {
      title: "Giám Sát Địa Chỉ IP",
      subtitle: "Quản lý danh sách IP Chặn (Blacklist có TTL đếm ngược), IP Tin Cậy (Whitelist) và Thiết lập chính sách bảo vệ",
      tab_blacklist: "🔴 IP Bị Chặn (Blacklist & TTL)",
      tab_whitelist: "🟢 IP Tin Cậy (Whitelist)",
      tab_policies: "⚙️ Chính Sách Mặc Định",
      bl_desc: "Tự động cô lập tức thì ở tầng Linux Kernel (ipset hash:ip O(1)) với cơ chế tự động mở khóa đếm ngược (TTL Auto-Unban)",
      btn_clear_all: "Xóa Tất Cả (Gỡ Hết)",
      btn_manual_ban: "+ Khóa IP Thủ Công",
      stat_total_blocked: "Tổng IP Bị Chặn",
      stat_ttl_blocked: "Chặn Có Thời Hạn (TTL)",
      stat_perm_blocked: "Khóa Vĩnh Viễn",
      ph_search_blacklist: "Tìm kiếm theo IP, lý do...",
      wl_title: "Đặc quyền Danh Sách Cho Phép (Whitelist IP/CIDR)",
      wl_desc: "Toàn bộ IP hoặc dải mạng trong danh sách này được MIỄN NHIỄM 100% khỏi IP Blacklist, SSH Guard, Port Canary và GeoIP Block. Kernel Linux tự động nạp vào vsafegate-allowed (ipset hash:net O(1)) để luôn được ưu tiên đi qua mà không bị chặn nhầm.",
      btn_detect_card: "⚡ Quét & Nạp Card Mạng (Auto-Detect)",
      btn_default_cidrs: "Nạp Dải Mạng Mặc Định",
      btn_add_ip: "+ Thêm IP / Dải Mạng",
      ph_search_whitelist: "Tìm kiếm theo IP, ghi chú...",
      pol_title: "Thiết Lập Chính Sách Phòng Thủ Tự Động",
      pol_desc: "Tùy biến hành vi tự động khóa IP của hệ thống khi phát hiện hành vi tấn công dò quét",
      btn_save_policies: "Lưu Toàn Bộ Thiết Lập Quy Tắc & Hành Vi"
    },
    logs: {
      title: "Nhật Ký Tấn Công Bền Vững (Persistent JSONL)",
      subtitle: "Lưu trữ không giới hạn vào file attacks.jsonl (tự động xoay vòng an toàn khi đạt 20MB)",
      events_badge: "sự kiện",
      btn_export: "Xuất File .jsonl",
      btn_clear: "Dọn Dẹp Log",
      ph_search: "Tìm kiếm theo IP, URI, tên miền, quy tắc vi phạm...",
      mode_pagination: "Phân Trang",
      mode_infinite: "Cuộn Không Giới Hạn",
      per_page: "Mỗi trang:",
      col_time: "Thời Gian",
      col_ip: "IP Tấn Công",
      col_domain: "Tên Miền",
      col_method_uri: "Phương Thức & URI / Payload",
      col_rule: "Quy Tắc Vi Phạm",
      col_action: "Hành Động",
      col_actions: "Thao Tác"
    },
    common: {
      loading: "Đang tải dữ liệu...",
      save: "Lưu Cấu Hình",
      cancel: "Hủy Bỏ",
      close: "Đóng",
      delete: "Xóa",
      edit: "Chỉnh Sửa",
      confirm: "Xác Nhận",
      success: "Thành công",
      error: "Đã xảy ra lỗi",
      enabled: "Bật",
      disabled: "Tắt",
      actions: "Thao Tác"
    }
  },

  en: {
    brand: {
      name: "vSafeGate",
      subtitle: "Virtual Security Gateway & WAF",
      tagline: "Professional 2-Tier Security Firewall"
    },
    nav: {
      dashboard: "Dashboard",
      sites: "Sites & Proxy",
      l4: "L4 Services",
      rules: "Defense Rules",
      ipmgmt: "IP Management",
      logs: "Attack Logs",
      settings: "Settings & Cloudflare",
      logout: "Logout",
      core_status: "Core Status",
      protecting: "Active Shield",
      native_mode: "Native Linux (0 Docker)",
      reload_rules: "Reload Rules"
    },
    theme: {
      dark: "Dark Mode",
      light: "Light Mode",
      toggle: "Toggle Light / Dark Theme"
    },
    lang: {
      vi: "Tiếng Việt",
      en: "English",
      toggle: "Switch Language (VI / EN)"
    },
    dashboard: {
      title: "Dashboard Overview",
      subtitle: "Monitor server system resources, network throughput, and real-time automated defense engines",
      badge_live: "Live Telemetry",
      active_defenses: "Active Defense:",
      ids_alerts: "alerts",
      l4_sessions: "sessions",
      geoip_title: "GeoIP:",
      ssh_guard: "SSH Guard:",
      pass_probes: "failed probes",
      port_canary: "Port Canary:",
      bot_drops: "bots dropped",
      cpu: "CPU Usage",
      ram: "Memory (RAM)",
      disk: "Disk Storage",
      uptime: "System Uptime",
      tcp_conns: "TCP Connections",
      stat_total_attacks: "Total Blocked",
      stat_waf_blocks: "WAF Blocks (L7)",
      stat_blacklist: "Kernel Drops (L3/L4)",
      traffic_trend: "Traffic & Threat Trends",
      threat_types: "Threat Classification",
      recent_attacks: "Recent Attack Events (Live Feed)",
      view_all: "View All Logs →",
      empty_attacks: "No security threats detected. System is running securely!",
      col_time: "Timestamp",
      col_ip: "Source IP",
      col_host: "Domain / Host",
      col_uri: "URI / Payload",
      col_rule: "Violated Rule",
      col_action: "Action",
      col_handle: "Actions"
    },
    sites: {
      title: "Website & Reverse Proxy Management",
      subtitle: "Add, modify, configure upstream destinations, and automate Let's Encrypt SSL/TLS certificates",
      btn_add: "+ Add New Website",
      col_domain: "Domain (Host)",
      col_upstream: "Forward Upstream",
      col_ssl: "Auto SSL",
      col_waf: "WAF Mode",
      col_actions: "Actions",
      empty: "No websites declared for protection yet."
    },
    l4: {
      title: "L4 Network Services & Stream Gateway",
      subtitle: "High-performance zero-copy proxy routing for SMB, SSH, RDP, Database and LAN servers. Filtered via Kernel Firewall, ThreatIntel and IDS.",
      btn_add: "+ Declare New L4 Port",
      col_name: "Service Name",
      col_proto: "Protocol",
      col_port: "Listen Port",
      col_target: "Target Host",
      col_mode: "Mode",
      col_sessions: "Sessions",
      col_status: "Status",
      col_actions: "Actions",
      empty: "Loading L4 service list..."
    },
    rules: {
      title: "Unified Defense Rules Engine",
      subtitle: "Centralized policy management for Country GeoIP filters, Trusted Subnets (CIDR), and Application WAF rules",
      btn_detect_interfaces: "Interface Presets",
      btn_presets: "Rule Templates",
      btn_add: "+ Add New Rule",
      zero_trust_title: "🔒 ZERO-TRUST PRINCIPLE & MULTI-TIER DEFENSE",
      zero_trust_desc: "vSafeGate operates under a Default Deny mechanism at the Linux Kernel tier (ipset hash:net O(1)). Any inbound traffic not explicitly in the Whitelist or originating from blocked regions is DROPPED immediately.",
      col_id: "Rule ID",
      col_name: "Rule Name",
      col_target: "Inspection Target",
      col_operator: "Operator",
      col_pattern: "Matching Pattern",
      col_action: "Action",
      col_actions: "Actions"
    },
    ipmgmt: {
      title: "IP Address Management & Threat Control",
      subtitle: "Manage Blacklisted IPs (with TTL countdown auto-unban), Whitelisted Subnets, and automated defense thresholds",
      tab_blacklist: "🔴 Blocked IPs (Blacklist & TTL)",
      tab_whitelist: "🟢 Trusted IPs (Whitelist)",
      tab_policies: "⚙️ Defense Policies",
      bl_desc: "Instant kernel-level isolation (ipset hash:ip O(1)) with automated progressive expiration countdown (TTL Auto-Unban)",
      btn_clear_all: "Clear All (Flush)",
      btn_manual_ban: "+ Manual IP Ban",
      stat_total_blocked: "Total Blocked IPs",
      stat_ttl_blocked: "Temporary Bans (TTL)",
      stat_perm_blocked: "Permanent Bans",
      ph_search_blacklist: "Search by IP, violation reason...",
      wl_title: "Privileged Trusted Allowlist (Whitelist IP/CIDR)",
      wl_desc: "All IP addresses or subnets in this list are 100% IMMUNE from Blacklist drops, SSH Guard, Port Canary, and GeoIP filters. Synchronized directly into kernel vsafegate-allowed (ipset hash:net O(1)).",
      btn_detect_card: "⚡ Auto-Detect Network Cards",
      btn_default_cidrs: "Load Default Subnets",
      btn_add_ip: "+ Add IP / CIDR",
      ph_search_whitelist: "Search by IP, notes...",
      pol_title: "Automated Defense Policy Configuration",
      pol_desc: "Fine-tune progressive ban durations, SSH brute-force thresholds, honeypot traps, and IDS integration",
      btn_save_policies: "Save All Policy Configurations"
    },
    logs: {
      title: "Persistent Security & Attack Logs (JSONL)",
      subtitle: "Uncapped high-performance logging into attacks.jsonl (safe auto-rotation upon reaching 20MB)",
      events_badge: "events",
      btn_export: "Export .jsonl File",
      btn_clear: "Flush Logs",
      ph_search: "Search by IP, URI, hostname, violated rule...",
      mode_pagination: "Pagination Mode",
      mode_infinite: "Infinite Scroll",
      per_page: "Per page:",
      col_time: "Timestamp",
      col_ip: "Source IP",
      col_domain: "Domain / Host",
      col_method_uri: "Method & URI / Payload",
      col_rule: "Rule Violated",
      col_action: "Action",
      col_actions: "Actions"
    },
    common: {
      loading: "Loading data...",
      save: "Save Configuration",
      cancel: "Cancel",
      close: "Close",
      delete: "Delete",
      edit: "Edit",
      confirm: "Confirm",
      success: "Success",
      error: "An error occurred",
      enabled: "Enabled",
      disabled: "Disabled",
      actions: "Actions"
    }
  }
};

// Global i18n Controller
class I18nManager {
  constructor() {
    this.currentLang = localStorage.getItem('vsafegate_lang') || (navigator.language && navigator.language.startsWith('vi') ? 'vi' : 'en');
  }

  getLang() {
    return this.currentLang;
  }

  setLang(lang) {
    if (!i18nData[lang]) return;
    this.currentLang = lang;
    localStorage.setItem('vsafegate_lang', lang);
    this.apply();
    // Dispatch event for components that need re-rendering
    window.dispatchEvent(new CustomEvent('vsafegate:languageChange', { detail: { lang } }));
  }

  t(path, fallback = '') {
    const keys = path.split('.');
    let cur = i18nData[this.currentLang];
    for (const k of keys) {
      if (cur && cur[k] !== undefined) {
        cur = cur[k];
      } else {
        // Fallback to English if missing in target
        let enCur = i18nData['en'];
        for (const ek of keys) {
          if (enCur && enCur[ek] !== undefined) enCur = enCur[ek];
          else return fallback || path;
        }
        return enCur || fallback || path;
      }
    }
    return cur || fallback || path;
  }

  apply() {
    // 1. Text elements with data-i18n
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const val = this.t(key);
      if (val) el.textContent = val;
    });

    // 2. HTML elements with data-i18n-html
    document.querySelectorAll('[data-i18n-html]').forEach(el => {
      const key = el.getAttribute('data-i18n-html');
      const val = this.t(key);
      if (val) el.innerHTML = val;
    });

    // 3. Placeholders with data-i18n-ph
    document.querySelectorAll('[data-i18n-ph]').forEach(el => {
      const key = el.getAttribute('data-i18n-ph');
      const val = this.t(key);
      if (val) el.setAttribute('placeholder', val);
    });

    // 4. Titles with data-i18n-title
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
      const key = el.getAttribute('data-i18n-title');
      const val = this.t(key);
      if (val) el.setAttribute('title', val);
    });

    // 5. Update Language Switcher UI if present
    const langLabel = document.getElementById('current-lang-label');
    if (langLabel) {
      langLabel.textContent = this.currentLang === 'vi' ? '🇻🇳 VI' : '🇬🇧 EN';
    }
  }
}

const i18n = new I18nManager();
window.i18n = i18n;
window.t = (key, fallback) => i18n.t(key, fallback);

// Auto-init on DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
  i18n.apply();
});
