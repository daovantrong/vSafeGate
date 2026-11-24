# 🧠 MEMORY.md — BỘ NHỚ TOÀN DIỆN DỰ ÁN vSafeGate

> **DÀNH CHO AGENT / DEVELOPER TRONG CÁC PHIÊN LÀM VIỆC TIẾP THEO:**  
> Tài liệu này lưu trữ đầy đủ toàn bộ bối cảnh, lịch sử tối ưu, cấu trúc mã nguồn, thông tin máy chủ production, quy tắc an ninh và quy trình build/deploy của dự án **vSafeGate** (tiền thân là OpenWAF / SafeLineWAF). Đọc kỹ tài liệu này trước khi thực hiện bất kỳ thao tác kỹ thuật nào.

---

## 1. TỔNG QUAN DỰ ÁN & ĐỊNH DANH

* **Tên chính thức:** **`vSafeGate`** *(Virtual Security Gateway & Web Application Firewall)*
* **Tác giả & Bản quyền:** `© TRONG.PRO`
* **Mục tiêu cốt lõi:** Cổng bảo mật tích hợp đa tầng (All-in-One Security Gateway) bảo vệ toàn diện hệ thống máy chủ web và thiết bị lưu trữ dữ liệu (Synology NAS):
  1. **Tầng L7 Web Application Firewall:** Caddy Core v2 tích hợp Coraza WAF (OWASP CRS v4 + bộ Custom SecLang Rules).
  2. **Tầng L4 Streaming Gateway:** Bộ Proxy TCP nội suy Linux `splice()` Zero-Copy (bảo vệ SMB :445, DSM :5000/:5001, WebDAV :5005/:5006).
  3. **Tầng Kernel Tường lửa Chủ động:** Linux `iptables` kết hợp `ipset` hash:net O(1) chống quét cổng Canary Honeypot, chống brute-force SSH Guard, GeoIP Filtering (Chỉ cho phép Việt Nam) và Threat Intelligence Feed (4.659 dải IP botnet quốc tế).
  4. **Giao diện Quản trị Web (Management Daemon):** Viết bằng Golang thuần (không dùng Docker, không phụ thuộc runtime bên ngoài), nhúng toàn bộ HTML/CSS/JS tĩnh vào 1 file thực thi duy nhất (`//go:embed web/*`).

---

## 2. THÔNG TIN HẠ TẦNG & MÁY CHỦ PRODUCTION

Tài liệu chi tiết xem tại [`SERVERS.md`](file:///d:/SafeLineWAF/SERVERS.md). Dưới đây là tóm tắt nhanh:

### A. Server 1: PVE Local (Local Jump Host / Proxmox VE)
* **IP LAN:** `10.20.30.254` | **IP Tailscale:** `100.101.102.5`
* **SSH:** Cổng `22` | User: `trong` | Pass: `Trong@152310`
* **Hệ điều hành:** Debian / Proxmox VE (Quản lý dịch vụ bằng **`systemd`**)
* **Dịch vụ quản trị:** `vsafegate.service` (`/usr/local/bin/vsafegate`)
* **Thư mục cấu hình:** `/etc/vsafegate/config.json` | **Log:** `/var/log/vsafegate/attacks.jsonl`
* **Web GUI Dashboard:** `https://10.20.30.254:4438/` hoặc `https://100.101.102.5:4438/`

### B. Server 2: Remote Gateway VM (Máy ảo Alpine Linux chạy trên Synology NAS)
* **IP Tailscale:** `100.101.102.1` | **IP LAN:** `192.168.1.251`
* **Domain công khai:** `data.kientrucht.com`
* **SSH Chính thức:** **Cổng `2251`** *(Cổng 22 đã ĐÓNG để diệt bot scan; Cổng `22222` làm dự phòng)*
* **Tài khoản SSH:** User: `trong` | Pass: `ThomYen@152310`
* **Hệ điều hành:** Alpine Linux 6.18 x86_64 (Quản lý dịch vụ bằng **`OpenRC`**)
* **Dịch vụ quản trị:** `rc-service vsafegate` (`/usr/local/bin/vsafegate`)
* **Thư mục cấu hình:** `/etc/vsafegate/config.json` | **Log:** `/var/log/vsafegate/attacks.jsonl`
* **Threat Intel Updater:** `/usr/local/bin/vsafegate-sync-threatintel.sh` (Cron: `/etc/periodic/daily/vsafegate-threatintel`)
* **Web GUI Dashboard:** `https://100.101.102.1:4438/`

### C. Server 3: Remote NAS Host (Máy chủ vật lý Synology DSM - Host Mẹ của Server 2)
* **IP LAN:** `192.168.1.254`
* **SSH:** Cổng `22` | User: `Trong` | Pass: `Trong@152310`
* **Vai trò:** Chứa dữ liệu thực tế và chạy máy ảo Server 2. **Toàn bộ traffic WAN đều trỏ vào Server 2 (`192.168.1.251`), tuyệt đối không trỏ trực tiếp vào NAS!**

---

## 3. CẤU TRÚC THƯ MỤC & MÃ NGUỒN

```
d:/SafeLineWAF/ (hoặc d:/vSafeGate/)
├── Caddyfile                        # File cấu hình Caddy Core & Coraza WAF
├── docker-compose.yml               # Mẫu chạy Docker (nếu muốn đóng gói container)
├── README.md                        # Giới thiệu kiến trúc & tính năng tổng quan
├── SERVERS.md                       # Ma trận kết nối máy chủ & chính sách an ninh
├── Memory.md                        # (File này) Bộ nhớ dự án vĩnh viễn
├── smb-guide.html                   # Trang tài liệu hướng dẫn truy cập SMB an toàn
├── rules/
│   └── custom-rules.conf            # Bộ SecLang Rules proactive (SQLi, XSS, Scanner, Admin lock)
└── mgt/                             # Mã nguồn Go của vSafeGate Management Daemon
    ├── go.mod                       # Module vsafegate-mgt (Go 1.22)
    ├── main.go                      # REST API, Web router, Session cookie, Lifecycle
    ├── auth.go                      # Xác thực PAM qua /usr/local/bin/vsafegate-auth (SUID root)
    ├── blacklist.go                 # Xử lý Blacklist O(1), Ban TTL, Whitelist, Tự động gỡ khóa
    ├── firewall.go                  # Khởi tạo ipset kernel, đồng bộ GeoIP, cập nhật iptables
    ├── l4proxy.go                   # Linux splice() Zero-Copy proxy engine cho TCP ports
    ├── caddy.go                     # Trình quản lý cấu hình động cho Caddyfile & WAF rules
    ├── watchers.go                  # Giám sát Suricata EVE logs, Port Scan Canary, SSH Guard
    ├── log_manager.go               # Ghi log tấn công bền vững (JSONL rotate 20MB)
    ├── metrics_linux.go             # Thu thập số liệu CPU, RAM, lưu lượng mạng, kernel ipset
    ├── blacklist_test.go            # Unit test logic blacklist & whitelist
    ├── log_manager_test.go          # Unit test rotation & log buffer
    ├── fixes_test.go                # Unit test các bản vá an ninh & proxy
    └── web/                         # Giao diện quản trị Web GUI (Single Page Application)
        ├── index.html               # Frontend chính (Ghim Sidebar, 100% tiếng Việt)
        ├── tailwind.min.css         # Tailwind CSS đã biên dịch tĩnh (38 KB, 0 CDN)
        ├── chart.min.js             # Thư viện biểu đồ Chart.js nhúng nội bộ (210 KB)
        ├── lucide.min.js            # Thư viện icon Lucide nhúng nội bộ (500 KB)
        ├── favicon.ico / .svg       # Biểu tượng trang web
        └── smb-guide.html           # Embedded guide hướng dẫn kết nối SMB
```

---

## 4. CÁC TỐI ƯU & SỬA LỖI ĐÃ HOÀN TẤT (LỊCH SỬ DỰ ÁN)

1. **Khắc phục Crash & Tràn Bộ Nhớ (Log Manager):**
   * *Vấn đề cũ:* Ghi dồn toàn bộ sự kiện tấn công vào RAM (`AppState.recentLogs`), gây OOM crash khi bị DDoS.
   * *Đã sửa:* Xây dựng `PersistentLogManager` lưu nhật ký tuần tự ra file `/var/log/vsafegate/attacks.jsonl` với Log Rotation 20MB (tối đa 5 backup). RAM chỉ giữ Ring Buffer 500 sự kiện mới nhất.

2. **Tối ưu Hiệu Năng Truyền File (L4 Splice Zero-Copy):**
   * *Vấn đề cũ:* Dùng `io.Copy()` Go userspace thông qua 2 buffer trung gian, tiêu tốn CPU khi copy file SMB qua mạng 1Gbps.
   * *Đã sửa:* Triển khai `spliceConnection()` dùng trực tiếp Linux Syscall `SYS_SPLICE` thông qua `os.Pipe()`, chuyển buffer ngay trong Linux Kernel pipe mà không sao chép lên Userspace. CPU giảm xuống < 1%.

3. **Chính Sách Khóa IP Luỹ Tiến Có Thời Hạn (TTL Escalation Ban):**
   * Tự động theo dõi số lần tái phạm của IP:
     * **Lần 1:** Khóa **24 giờ**.
     * **Lần 2:** Khóa **72 giờ (3 ngày)**.
     * **Lần 3 trở lên:** Khóa **VĨNH VIỄN** (`duration_hours = 0`).
   * Tự động giải phóng IP khỏi Kernel `vsafegate-blacklist` khi hết hạn.

4. **Danh Sách Cho Phép Bất Khả Xâm Phạm (`vsafegate-allowed`):**
   * Bảo vệ các dải IP nội bộ và quản trị (`100.64.0.0/10` Tailscale, `10.20.30.0/24`, `192.168.1.0/24`, `127.0.0.1`) miễn nhiễm 100% khỏi WAF, Honeypot Canary, SSH Guard và GeoIP.

5. **Phòng Chống Lỗ Hổng An Ninh (Sanitization):**
   * Ngăn chặn Command Injection khi reload Caddy (dùng `exec.Command("caddy", "reload", "--config", ...)` trực tiếp thay vì `sh -c`).
   * Ngăn chặn Regex Injection (ReDoS) bằng `regexp.QuoteMeta` và kiểm tra an toàn cú pháp.
   * Bảo vệ xác thực bằng `subtle.ConstantTimeCompare` chống Timing Attacks.

6. **Đổi Tên Toàn Diện sang `vSafeGate` (Không còn tàn dư OpenWAF):**
   * Dịch vụ: `vsafegate.service` (Systemd) & `/etc/init.d/vsafegate` (OpenRC).
   * Binary: `/usr/local/bin/vsafegate`.
   * Thư mục: `/etc/vsafegate/`, `/var/log/vsafegate/`.
   * Kernel ipset: `vsafegate-blacklist`, `vsafegate-threatintel`, `vsafegate-countries`, `vsafegate-allowed`.
   * Web session cookie: `vsafegate_session`.

7. **Sửa Lỗi Hiển Thị Sidebar & Bản Quyền:**
   * Khung hình Dashboard chuẩn viewport `h-screen overflow-hidden`.
   * Khối **Trạng Thái Lõi + Nút Nạp Lại + `2026 © TRONG.PRO`** được ghim cứng ngay đáy thanh bên (không bị trôi theo khung phải, không cần cuộn trang).
   * Thay ký tự `(c)` bằng ký tự chuẩn **`©`**.
   * Badge core runtime tự nhận diện hệ điều hành (`Systemd Native` trên PVE, `OpenRC Native` trên Alpine).

8. **Độc Lập Ngoại Vi 100% (Loại Bỏ Hoàn Toàn CDN):**
   * Dùng Tailwind CLI biên dịch tĩnh thành `tailwind.min.css` (38 KB).
   * Nhúng trực tiếp `chart.min.js` và `lucide.min.js`.
   * Triệt tiêu hoàn toàn cảnh báo `cdn.tailwindcss.com should not be used in production` và `Tracking Prevention blocked access to storage`.
   * Trang web chạy 100% offline không cần Internet.

9. **Rule Mẫu Tự Động Quét Card Mạng (Live Auto-Detect Network Interfaces):**
   * Module `mgt/network_detector.go` (`GET /api/network/interfaces`, `POST /api/network/interfaces/apply`): Quét trực tiếp qua Linux Kernel `net.Interfaces()` mỗi khi người dùng bấm nút, không dùng cache cũ.
   * Tự động nhận diện danh tính và dải mạng khuyến nghị: Tailscale VPN (`100.64.0.0/10`), ZeroTier VPN (`172.29.0.0/16`), Proxmox Bridge (`vmbr*`), Docker (`docker0`), LAN Ethernet (`eth*`, `en*`).
   * Cung cấp nút bấm trực quan trên thanh công cụ Quy Tắc Phòng Thủ, tab Whitelist và trong cửa sổ Rule Mẫu (Presets) để nạp nhanh 1-click vào `vsafegate-allowed`.

---

## 5. QUY TRÌNH BUILD & TRIỂN KHAI (CHEATSHEET)

### A. Chạy Kiểm Thử Đơn Vị (Unit Test)
```powershell
cd d:\SafeLineWAF\mgt   # (hoặc d:\vSafeGate\mgt)
go test ./... -v
```

### B. Biên Dịch Lại Tailwind CSS (Khi có chỉnh sửa HTML)
```powershell
npx tailwindcss@3 -c scratch\tailwind.config.js -i scratch\input.css -o mgt\web\tailwind.min.css --minify
```

### C. Biên Dịch Binary Linux amd64
```powershell
cd d:\SafeLineWAF\mgt   # (hoặc d:\vSafeGate\mgt)
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -v -o ../vsafegate-linux-amd64 .
```

### D. Triển Khai Lên Server (Khuyến nghị dùng Python Paramiko)
Do Windows OpenSSH CLI có thể bị kẹt `known_hosts` hoặc prompt mật khẩu, luôn ưu tiên dùng script Python Paramiko:
* Script mẫu: [`scratch/deploy_ui_update.py`](file:///C:/Users/Trong/.gemini/antigravity/brain/ed8b1757-0310-4654-874f-f7f728b0e196/scratch/deploy_ui_update.py)
* Các bước thực hiện:
  1. SFTP đẩy binary lên `/tmp/vsafegate_new`.
  2. Sudo move đè lên `/usr/local/bin/vsafegate` và `chmod 755`.
  3. Restart dịch vụ:
     * Server 1 (PVE): `sudo systemctl restart vsafegate`
     * Server 2 (Alpine): `sudo rc-service vsafegate restart`

---

## 6. QUY TẮC AN TOÀN BẤT KHẢ XÂM PHẠM

1. **Tuyệt đối không bao giờ xóa hoặc làm rỗng ipset `vsafegate-allowed`:** Dải IP VPN Tailscale `100.64.0.0/10` và LAN `192.168.1.0/24` bắt buộc phải luôn nằm trong ipset này để tránh bị tường lửa Drop kết nối SSH quản trị.
2. **Cổng SSH Server 2 luôn là `2251`:** Không được dùng cổng 22 khi kết nối vào Server 2 (`100.101.102.1`).
3. **Mọi lưu lượng Web & SMB ra ngoài Internet:** Luôn đi qua máy ảo `192.168.1.251` (Server 2), không cấu hình port forwarding trên router trỏ trực tiếp đến NAS `192.168.1.254`.
4. **Mật khẩu & Tài khoản:** Tuân thủ bảng thông tin tại Mục 2 hoặc file `SERVERS.md`.
