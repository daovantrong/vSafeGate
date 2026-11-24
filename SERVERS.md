# DANH MỤC THÔNG TIN MÁY CHỦ vSafeGate & QUY TẮC KẾT NỐI

> [!IMPORTANT]
> **TÀI LIỆU QUAN TRỌNG:** Phân định rõ ràng giữa các máy chủ để tránh bị nhầm lẫn tài khoản, cổng kết nối và không bao giờ bị hệ thống phòng thủ tự động (**SSH Guard / Port Canary Honeypot / IP Auto-Ban / Threat Intelligence**) khóa IP quản trị.

---

## 1. MÁY CHỦ 1: PVE NỘI BỘ (LOCAL LAN SERVER / JUMP HOST)

| Tiêu chí | Thông tin chi tiết |
| :--- | :--- |
| **Vai trò / Vị trí** | Máy chủ ảo hóa Proxmox VE (PVE) cục bộ trong cùng mạng văn phòng / gia đình (Jump Host) |
| **Hostname / Domain** | `pve.trong.pro` |
| **Địa chỉ IP LAN** | **`10.20.30.254`** |
| **Địa chỉ Tailscale IP** | `100.101.102.5` (Interface `tailscale0`) |
| **Cổng SSH** | **`22`** |
| **Tài khoản SSH** | **`trong`** |
| **Mật khẩu SSH / Sudo** | **`Trong@152310`** |
| **Cổng Web Panel HTTPS** | **`https://10.20.30.254:4438/`** |
| **Hệ điều hành** | **Debian / Proxmox VE (Systemd)** |
| **Lệnh quản lý Service** | `sudo systemctl restart vsafegate` <br> `sudo systemctl restart caddy` |
| **Đường dẫn Binary** | `/usr/local/bin/vsafegate` |
| **Đường dẫn Cấu hình** | `/etc/vsafegate/config.json` |
| **Đường dẫn Log tấn công** | `/var/log/vsafegate/attacks.jsonl` |

---

## 2. MÁY CHỦ TỪ XA (CHUNG 1 THIẾT BỊ VẬT LÝ SYNOLOGY NAS)

> [!NOTE]
> Hai host dưới đây **CHUNG 1 MÁY CHỦ VẬT LÝ** tại địa điểm từ xa:
> - **Host Mẹ (Physical Host):** Synology NAS DSM (chạy Virtual Machine Manager).
> - **Host Con (Guest VM):** Máy ảo Alpine Linux chạy vSafeGate Gateway bên trong.

### A. Remote vSafeGate Gateway (Máy ảo Alpine Linux - Đích đến quản trị WAF & Gateway)
| Tiêu chí | Thông tin chi tiết |
| :--- | :--- |
| **Vai trò** | Cổng bảo vệ vSafeGate Gateway chính cho toàn bộ dịch vụ web và NAS từ xa |
| **Tên miền công khai** | **`data.kientrucht.com`** (Dynamic IP WAN: tự động đồng bộ DDNS) |
| **Địa chỉ Tailscale IP** | **`100.101.102.1`** (Tailscale VPN) |
| **Địa chỉ IP LAN** | **`192.168.1.251`** (Bridge nội bộ với Router/NAS) |
| **Hostname** | `vsafegate` *(hoặc `openwaf`)* |
| **Cổng SSH Chính thức** | **`2251`** *(Cổng 22 đã ĐÓNG hoàn toàn để chặn botnet scan; Cổng 22222 làm dự phòng)* |
| **Tài khoản SSH** | **`trong`** (hoặc root khi sudo) |
| **Mật khẩu SSH / Sudo** | **`ThomYen@152310`** |
| **Cổng Web Panel HTTPS** | **`https://100.101.102.1:4438/`** hoặc **`https://192.168.1.251:4438/`** |
| **Hệ điều hành** | **Alpine Linux 6.18 x86_64 (OpenRC)** |
| **Lệnh quản lý Service** | `sudo rc-service vsafegate restart` <br> `sudo rc-service caddy restart` |
| **Đường dẫn Binary** | `/usr/local/bin/vsafegate` |
| **Đường dẫn Cấu hình** | `/etc/vsafegate/config.json` |
| **Đường dẫn Caddyfile** | `/etc/caddy/Caddyfile` |
| **Đường dẫn Rules WAF** | `/etc/caddy/rules/custom-rules.conf` |
| **Đường dẫn Threat Intel** | `/usr/local/bin/vsafegate-sync-threatintel.sh` (Cron: `/etc/periodic/daily/vsafegate-threatintel`) |
| **Đường dẫn Log tấn công** | `/var/log/vsafegate/attacks.jsonl` |

### B. Remote NAS Host (Máy chủ vật lý Synology DSM - Host Mẹ)
| Tiêu chí | Thông tin chi tiết |
| :--- | :--- |
| **Vai trò** | Thiết bị phần cứng vật lý Synology NAS lưu trữ dữ liệu và chạy máy ảo vSafeGate |
| **Hostname** | `KienTrucHT` |
| **Địa chỉ ZeroTier IP** | **`172.29.9.22`** |
| **Địa chỉ IP LAN** | **`192.168.1.254`** |
| **Cổng SSH NAS** | **`22`** (Chỉ truy cập nội bộ qua LAN hoặc ZeroTier) |
| **Tài khoản SSH** | **`Trong`** (hoặc `root`) |
| **Mật khẩu SSH / Sudo** | **`Trong@152310`** |
| **Giao diện Web DSM** | `http://192.168.1.254:5000/` hoặc `https://192.168.1.254:5001/` |
| **Hệ điều hành** | **Synology DSM 7.x** |

---

## 3. BẢNG TRA CỨU NHANH (QUICK REFERENCE MATRIX)

| Máy chủ / Thực thể | Địa chỉ IP | Cổng SSH | Tài khoản | Mật khẩu xác thực | Service Manager | Mục đích / Web Panel |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. PVE Local (LAN/Jump)** | `10.20.30.254` / `100.101.102.5` | **22** | `trong` | `Trong@152310` | **systemctl** | `https://10.20.30.254:4438/` |
| **2. Remote vSafeGate (VM)** | `100.101.102.1` / `192.168.1.251` | **2251** (dự phòng `22222`) | `trong` | `ThomYen@152310` | **rc-service** | `https://100.101.102.1:4438/` |
| **3. Remote NAS Host (DSM)**| `172.29.9.22` / `192.168.1.254` | **22** | `Trong` | `Trong@152310` | DSM sys | `http://192.168.1.254:5000/` |

---

## 4. BẢNG ÁNH XẠ DỊCH VỤ & CỔNG BẢO VỆ (PORT MAPPING)

Tất cả lưu lượng từ Router WAN được trỏ về **vSafeGate VM (`192.168.1.251`)**, tuyệt đối không trỏ trực tiếp đến NAS (`192.168.1.254`).

### A. Tầng L7 (Website & Coraza WAF - Caddy Core)
| Dịch vụ | Tên miền | Cổng nghe WAF | Upstream Backend | Bảo vệ WAF |
| :--- | :--- | :--- | :--- | :--- |
| **Web Station (HTTP)** | `data.kientrucht.com` | `80` (TCP) | `http://192.168.1.254:80` | OWASP CRS v4 + 10 Proactive Rules |
| **Web Station (HTTPS)**| `data.kientrucht.com` | `443` (TCP) | `https://192.168.1.254:443` | OWASP CRS v4 + 10 Proactive Rules |
| **vSafeGate Admin Panel**| `data.kientrucht.com` / IP | `4438` (TCP) | `http://127.0.0.1:9444` | Xác thực PAM + IP Whitelist |

### B. Tầng L4 Gateway (Zero-Copy Linux Splice Proxy)
| Dịch vụ | Cổng nghe vSafeGate | Backend Host:Port | Kỹ thuật Stream | Chính sách bảo vệ |
| :--- | :--- | :--- | :--- | :--- |
| **Synology SMB File Share** | `:445` | `192.168.1.254:445` | Linux `splice()` Zero-Copy | GeoIP (VN Only) + ThreatIntel + IPSet |
| **Synology DSM HTTP** | `:5000` | `192.168.1.254:5000` | Linux `splice()` Zero-Copy | GeoIP (VN Only) + ThreatIntel + IPSet |
| **Synology DSM HTTPS** | `:5001` | `192.168.1.254:5001` | Linux `splice()` Zero-Copy | GeoIP (VN Only) + ThreatIntel + IPSet |
| **Synology WebDAV HTTP** | `:5005` | `192.168.1.254:5005` | Linux `splice()` Zero-Copy | GeoIP (VN Only) + ThreatIntel + IPSet |
| **Synology WebDAV HTTPS**| `:5006` | `192.168.1.254:5006` | Linux `splice()` Zero-Copy | GeoIP (VN Only) + ThreatIntel + IPSet |

---

## 5. CƠ CHẾ PHÒNG THỦ & QUY TẮC AN TOÀN (SECURITY POLICIES)

### 1. Kiến trúc Tường lửa Kernel 2 Tầng (2-Tier Defense)
- **Tầng 1 (Kernel iptables + ipset O(1)):**
  - **Vị trí 5:** `vsafegate-blacklist` (`hash:net` CIDR) - DROP lập tức các IP/dải IP vi phạm.
  - **Vị trí 6:** `vsafegate-threatintel` (`hash:net` CIDR) - DROP **4.659 dải IP botnet quốc tế** (FireHOL Level 1 + Censys + Shodan + Shadowserver + BinaryEdge).
  - **Vị trí 7:** Port 80 ACCEPT (cho Let's Encrypt HTTP-01 challenge).
  - **Vị trí 8:** GeoIP Filter - DROP mọi IP ngoài Việt Nam (`! vsafegate-allowed`).
  - **Vị trí 9:** SSH Ports (`2251`, `22222`) ACCEPT.
- **Tầng 2 (L7 Coraza WAF):**
  - 10 Proactive Security Rules chặn đứng SQLi, XSS, Path Traversal, Bot scanners (`sqlmap`, `nuclei`, `nikto`), rò rỉ `.env`, `.git`, mã độc web shells (`shell.php`, `alfa.php`).

### 2. Chính sách Khóa IP Luỹ Tiến (Escalation Ban Policy)
Hệ thống tự động theo dõi lịch sử vi phạm (`ban_history`) và tăng mức phạt theo số lần tái phạm:
- **Vi phạm lần 1:** Khóa **24 giờ**.
- **Vi phạm lần 2:** Khóa **72 giờ (3 ngày)**.
- **Vi phạm lần 3 trở lên:** Khóa **VĨNH VIỄN** (`duration_hours = 0`).

### 3. Danh sách Mạng Whitelist Bất Khả Xâm Phạm (`vsafegate-allowed`)
Bắt buộc duy trì trong `/etc/vsafegate/config.json` và kernel ipset:
- `100.64.0.0/10`: Toàn bộ dải Tailscale VPN (`100.101.102.1`, `100.101.102.5`, máy admin).
- `10.20.30.0/24`: Dải mạng LAN văn phòng / PVE (`10.20.30.254`).
- `192.168.1.0/24`: Dải mạng LAN nội bộ Gateway / Router / NAS.
- `127.0.0.1`: Loopback nội bộ.

### 4. Lệnh Gỡ Khóa Khẩn Cấp (Emergency Unban)
Nếu chẳng may một IP quản trị bị khóa, đăng nhập từ console hoặc qua ZeroTier/LAN chạy:
```bash
sudo ipset del vsafegate-blacklist <IP_BỊ_KHÓA>
sudo ipset add vsafegate-allowed <IP_BỊ_KHÓA>
```
Đồng thời xóa IP khỏi `/etc/vsafegate/config.json` và reload:
```bash
sudo rc-service vsafegate restart
```
