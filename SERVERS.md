# HƯỚNG DẪN MẪU KHAI BÁO THÔNG TIN MÁY CHỦ vSafeGate (TEMPLATE)

> [!TIP]
> Đây là tệp tài liệu mẫu (Template). Để lưu trữ thông tin thực tế của các máy chủ trong hạ tầng của bạn mà không bị lộ lên Git, hãy sao chép tệp này sang `SERVERS.local.md` (tệp `*.local.md` đã được cấu hình trong `.gitignore` để không bao giờ bị push lên GitHub).

---

## 1. MẪU MÁY CHỦ QUẢN TRỊ NỘI BỘ (LOCAL LAN / JUMP HOST)

| Tiêu chí | Giá trị mẫu | Ghi chú cấu hình |
| :--- | :--- | :--- |
| **Vai trò / Vị trí** | Máy chủ quản trị nội bộ / Jump Host | Đặt trong mạng LAN an toàn |
| **Hostname / Domain** | `pve.example.local` | Tên định danh máy chủ |
| **Địa chỉ IP LAN** | `192.168.1.10` / `10.0.0.10` | IP tĩnh của máy chủ |
| **Địa chỉ VPN (nếu có)**| `10.8.0.2` / `100.64.0.2` | WireGuard / Tailscale / OpenVPN |
| **Cổng SSH** | `22` (hoặc cổng tùy chỉnh) | Port SSH quản trị |
| **Tài khoản SSH** | `admin` / `your-username` | Tài khoản Linux có quyền sudo |
| **Mật khẩu SSH / Sudo** | `[LƯU TẠI SERVERS.local.md]` | Không commit mật khẩu vào Git |
| **Cổng Web Panel HTTPS** | `https://192.168.1.10:4438/` | Giao diện quản trị vSafeGate |
| **Hệ điều hành** | **Debian / Ubuntu (Systemd)** | Service: `systemctl restart vsafegate` |
| **Đường dẫn Binary** | `/usr/local/bin/vsafegate` | Nhị phân duy nhất |
| **Đường dẫn Cấu hình** | `/etc/vsafegate/config.json` | Cấu hình JSON |
| **Đường dẫn Log** | `/var/log/vsafegate/attacks.jsonl`| Nhật ký tấn công bền vững |

---

## 2. MẪU MÁY CHỦ BIÊN GATEWAY & WAF (PRODUCTION GATEWAY)

| Tiêu chí | Giá trị mẫu | Ghi chú cấu hình |
| :--- | :--- | :--- |
| **Vai trò** | Cổng bảo vệ Gateway chính cho Web & L4 Proxy | Đặt tại biên mạng (DMZ / WAN) |
| **Tên miền công khai** | `gateway.yourdomain.com` | Tự động đồng bộ DNS/DDNS |
| **Địa chỉ IP Public/WAN**| `<PUBLIC_IP>` | IP tiếp nhận lưu lượng Internet |
| **Địa chỉ IP Private** | `192.168.1.250` | Giao tiếp nội bộ với Backend/NAS |
| **Cổng SSH Quản Trị** | `2251` (Khuyến nghị đổi cổng khác 22) | Đóng cổng 22 để diệt bot scan |
| **Tài khoản SSH** | `gateway-admin` | Không dùng tài khoản root trực tiếp |
| **Mật khẩu / SSH Key** | `[LƯU TẠI SERVERS.local.md]` | Khuyến nghị dùng SSH Key ed25519 |
| **Cổng Web Panel HTTPS** | `https://<GATEWAY_IP>:4438/` | Xác thực PAM Linux |
| **Hệ điều hành** | **Alpine Linux (OpenRC) / Debian** | Quản lý: `rc-service` hoặc `systemctl` |

---

## 3. MẪU BẢNG ÁNH XẠ DỊCH VỤ & CỔNG BẢO VỆ (PORT MAPPING)

Tất cả lưu lượng từ Router WAN được trỏ về **vSafeGate Gateway**, sau đó được lọc 2 tầng (Kernel O(1) + WAF L7) trước khi chuyển tiếp về Backend:

### A. Tầng L7 (Website & Coraza WAF)
| Dịch vụ | Tên miền (Host) | Cổng WAF | Upstream Backend | Bảo vệ WAF |
| :--- | :--- | :--- | :--- | :--- |
| **Website Chính** | `example.com` | `:80`, `:443` | `http://192.168.1.100:80` | OWASP CRS v4 + Proactive Rules |
| **Cổng Quản Trị** | `gateway.yourdomain.com`| `:4438` | `http://127.0.0.1:9444` | Xác thực PAM + IP Whitelist |

### B. Tầng L4 Gateway (Zero-Copy Linux Splice)
| Dịch vụ | Cổng nghe Gateway | Backend Host:Port | Kỹ thuật | Chính sách bảo vệ |
| :--- | :--- | :--- | :--- | :--- |
| **File Server / SMB** | `:445` | `192.168.1.200:445` | Linux `splice()` | GeoIP + ThreatIntel + IPSet |
| **SSH Gateway Proxy** | `:2222` | `192.168.1.200:22` | Linux `splice()` | GeoIP + SSH Guard + IPSet |
| **Database Proxy** | `:3306` | `192.168.1.150:3306`| Linux `splice()` | Whitelist CIDR Only |
