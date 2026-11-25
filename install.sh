#!/usr/bin/env bash
# ==============================================================================
#  🛡️ vSafeGate Universal One-Line Installer
#  GitHub Repository: https://github.com/daovantrong/vSafeGate
#  Supports: Debian, Ubuntu, Proxmox VE, Alpine Linux, RHEL/Rocky/Alma, Arch
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo "  __      __ _____        __         _____       _        "
echo "  \ \    / // ____|      / _|       / ____|     | |       "
echo "   \ \  / /| (___   __ _| |_ ___   | |  __  __ _| |_ ___  "
echo "    \ \/ /  \___ \ / _\` |  _/ _ \  | | |_ |/ _\` | __/ _ \ "
echo "     \  /   ____) | (_| | ||  __/  | |__| | (_| | ||  __/ "
echo "      \/   |_____/ \__,_|_| \___|   \_____|\__,_|\__\___| "
echo -e "${NC}"
echo -e "${GREEN}==> vSafeGate Next-Gen Security Gateway & WAF Installer${NC}\n"

# 1. Check Root Privileges
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This installer must be run as root.${NC}"
    echo -e "Please re-run with: ${YELLOW}sudo bash install.sh${NC} or as root user."
    exit 1
fi

# 2. Detect Architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        TARGET_ARCH="amd64"
        ;;
    aarch64|arm64)
        TARGET_ARCH="arm64"
        ;;
    *)
        echo -e "${RED}[ERROR] Unsupported CPU architecture: $ARCH${NC}"
        echo -e "vSafeGate currently supports x86_64 (amd64) and aarch64 (arm64)."
        exit 1
        ;;
esac
echo -e "${BLUE}[INFO] Architecture detected:${NC} ${BOLD}$TARGET_ARCH${NC}"

# 3. Detect Operating System & Init System
INIT_SYSTEM="systemd"
if [ -f /etc/alpine-release ]; then
    OS="alpine"
    INIT_SYSTEM="openrc"
elif [ -f /etc/debian_version ]; then
    OS="debian"
elif [ -f /etc/redhat-release ]; then
    OS="rhel"
elif [ -f /etc/arch-release ]; then
    OS="arch"
else
    OS="linux"
fi

if [ "$OS" != "alpine" ] && ! command -v systemctl >/dev/null 2>&1; then
    if [ -x /sbin/rc-service ]; then
        INIT_SYSTEM="openrc"
    fi
fi

echo -e "${BLUE}[INFO] Operating System:${NC} ${BOLD}$OS${NC} (${INIT_SYSTEM})"

# 4. Install Prerequisites
echo -e "\n${BLUE}[INFO] Checking and installing prerequisites...${NC}"
case "$OS" in
    debian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y curl ipset iptables ca-certificates tar python3 >/dev/null 2>&1
        ;;
    alpine)
        apk update >/dev/null 2>&1 || true
        apk add --no-cache curl ipset iptables ca-certificates tar bash python3 >/dev/null 2>&1
        ;;
    rhel)
        yum install -y curl ipset iptables ca-certificates tar python3 >/dev/null 2>&1 || dnf install -y curl ipset iptables ca-certificates tar python3 >/dev/null 2>&1
        ;;
    arch)
        pacman -Sy --noconfirm curl ipset iptables ca-certificates tar python3 >/dev/null 2>&1
        ;;
esac
echo -e "${GREEN}[OK] Prerequisites ready.${NC}"

# 5. Fail-Safe Anti-Lockout Detection
ADMIN_IP=""
if [ -n "$SSH_CLIENT" ]; then
    ADMIN_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
elif [ -n "$SSH_CONNECTION" ]; then
    ADMIN_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
fi

if [ -n "$ADMIN_IP" ]; then
    echo -e "${YELLOW}[SAFETY] Detected current SSH Administrator IP:${NC} ${BOLD}$ADMIN_IP${NC}"
    echo -e "${YELLOW}[SAFETY] This IP will be permanently whitelisted to prevent any self-lockout.${NC}"
fi

# 6. Fetch and Install Binary
REPO="daovantrong/vSafeGate"
INSTALL_BIN="/usr/local/bin/vsafegate"
CONFIG_DIR="/etc/vsafegate"
LOG_DIR="/var/log/vsafegate"

mkdir -p "$CONFIG_DIR" "$LOG_DIR" /usr/local/bin

echo -e "\n${BLUE}[INFO] Fetching latest release binary from GitHub...${NC}"
LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)

DOWNLOAD_SUCCESS=false
if [ -n "$LATEST_TAG" ]; then
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_TAG/vsafegate-linux-$TARGET_ARCH"
    echo -e "${BLUE}[INFO] Downloading:${NC} $DOWNLOAD_URL"
    if curl -fsSL -o /tmp/vsafegate_dl "$DOWNLOAD_URL"; then
        mv /tmp/vsafegate_dl "$INSTALL_BIN"
        chmod 755 "$INSTALL_BIN"
        DOWNLOAD_SUCCESS=true
        echo -e "${GREEN}[OK] Successfully installed vSafeGate binary ($LATEST_TAG).${NC}"
    fi
fi

if [ "$DOWNLOAD_SUCCESS" = false ]; then
    if [ -f "./vsafegate-linux-$TARGET_ARCH" ]; then
        echo -e "${YELLOW}[INFO] Using local binary ./vsafegate-linux-$TARGET_ARCH...${NC}"
        cp "./vsafegate-linux-$TARGET_ARCH" "$INSTALL_BIN"
        chmod 755 "$INSTALL_BIN"
    elif [ -f "./vsafegate" ]; then
        cp "./vsafegate" "$INSTALL_BIN"
        chmod 755 "$INSTALL_BIN"
    else
        echo -e "${YELLOW}[WARN] Could not download binary from GitHub Releases yet (Repo may be newly created).${NC}"
        echo -e "${YELLOW}[INFO] Attempting to build from local Go environment if available...${NC}"
        if command -v go >/dev/null 2>&1 && [ -d "./mgt" ]; then
            (cd ./mgt && go build -o "$INSTALL_BIN" .)
            chmod 755 "$INSTALL_BIN"
            echo -e "${GREEN}[OK] Successfully built and installed from source.${NC}"
        else
            echo -e "${RED}[ERROR] Binary not found. Please download or compile vsafegate into $INSTALL_BIN.${NC}"
            exit 1
        fi
    fi
fi

# 7. Create Initial Safe Configuration if missing
CONFIG_FILE="$CONFIG_DIR/config.json"
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${BLUE}[INFO] Initializing new zero-trust safe configuration...${NC}"
    NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Auto-detect local interface IPs
    LOCAL_IPS_JSON=""
    if [ -n "$ADMIN_IP" ]; then
        LOCAL_IPS_JSON="{\"ip\": \"$ADMIN_IP\", \"note\": \"Admin Current SSH Session IP\", \"created_at\": \"$NOW\"},"
    fi

    cat <<EOF > "$CONFIG_FILE"
{
  "sites": [],
  "l4_services": [],
  "rules": [
    {
      "id": "rule-1001",
      "rule_id": 1001,
      "name": "Chặn truy cập file cấu hình nhạy cảm (.env, .git)",
      "target": "URI",
      "operator": "rx",
      "pattern": "(^|/)(\\.env|\\.git|\\.aws|config\\.json)",
      "action": "deny",
      "description": "Ngăn chặn rò rỉ mã nguồn và biến môi trường",
      "enabled": true
    }
  ],
  "banned_ips": [],
  "whitelist_ips": [
    $LOCAL_IPS_JSON
    {"ip": "127.0.0.1", "note": "Localhost loopback", "created_at": "$NOW"},
    {"ip": "10.0.0.0/8", "note": "Dải mạng nội bộ LAN (Class A)", "created_at": "$NOW"},
    {"ip": "172.16.0.0/12", "note": "Dải mạng riêng (Class B)", "created_at": "$NOW"},
    {"ip": "192.168.0.0/16", "note": "Dải mạng nội bộ LAN Gateway / Router (Class C)", "created_at": "$NOW"}
  ],
  "default_ban_ttl_hours": 24,
  "defense_policy": {
    "default_ban_ttl_hours": 24,
    "ssh_guard_enabled": true,
    "ssh_max_attempts": 3,
    "canary_enabled": true,
    "waf_auto_ban_enabled": true,
    "waf_auto_ban_threshold": 10,
    "suricata_auto_ban": true
  },
  "geoip_mode": "disabled",
  "allowed_countries": [],
  "blocked_countries": ["CN", "RU"],
  "mgmt_domain": "",
  "mgmt_https_port": 4438,
  "mgmt_http_port": 808
}
EOF
    echo -e "${GREEN}[OK] Configuration created at $CONFIG_FILE${NC}"
fi

# 8. Setup System Service
echo -e "${BLUE}[INFO] Configuring $INIT_SYSTEM service...${NC}"
if [ "$INIT_SYSTEM" = "systemd" ]; then
    cat <<EOF > /etc/systemd/system/vsafegate.service
[Unit]
Description=vSafeGate Virtual Security Gateway & WAF Daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vsafegate
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable vsafegate >/dev/null 2>&1
    systemctl restart vsafegate
    echo -e "${GREEN}[OK] Systemd service enabled and started.${NC}"
elif [ "$INIT_SYSTEM" = "openrc" ]; then
    cat <<'EOF' > /etc/init.d/vsafegate
#!/sbin/openrc-run
name="vsafegate"
description="vSafeGate Virtual Security Gateway & WAF"
command="/usr/local/bin/vsafegate"
command_background="true"
pidfile="/run/vsafegate.pid"

depend() {
    need net
    after firewall
}
EOF
    chmod +x /etc/init.d/vsafegate
    rc-update add vsafegate default >/dev/null 2>&1 || true
    rc-service vsafegate restart
    echo -e "${GREEN}[OK] OpenRC service enabled and started.${NC}"
fi

# 9. CLI Shortcut
if [ ! -L /usr/bin/vsafegate ] && [ -f /usr/local/bin/vsafegate ]; then
    ln -sf /usr/local/bin/vsafegate /usr/bin/vsafegate 2>/dev/null || true
fi

# 10. Summary Banner
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
echo -e "\n${GREEN}${BOLD}========================================================================${NC}"
echo -e "${GREEN}${BOLD}   🎉 vSafeGate Installed & Started Successfully!${NC}"
echo -e "${GREEN}${BOLD}========================================================================${NC}"
if command -v caddy >/dev/null 2>&1; then
    echo -e "  🌐 ${BOLD}Web Admin Dashboard:${NC}  ${CYAN}https://${HOST_IP}:4438/${NC}"
else
    echo -e "  🌐 ${BOLD}Daemon Listening:${NC}     ${CYAN}http://127.0.0.1:9444/${NC} (local bind)"
    echo -e "  🔌 ${BOLD}SSH Tunnel Access:${NC}    ${YELLOW}ssh -L 9444:127.0.0.1:9444 <user>@${HOST_IP}${NC}"
    echo -e "  ⚠️  ${YELLOW}[NOTE] 'caddy' not found: install Caddy with Coraza WAF for L7 WAF & HTTPS :4438.${NC}"
fi
echo -e "  🔐 ${BOLD}Authentication:${NC}       Use your Linux PAM server credentials (sudo user)"
echo -e "  📂 ${BOLD}Configuration File:${NC}   $CONFIG_FILE"
echo -e "  📜 ${BOLD}Attack Log Stream:${NC}    $LOG_DIR/attacks.jsonl"
echo -e "  ⚙️  ${BOLD}Service Command:${NC}      ${YELLOW}systemctl restart vsafegate${NC} or ${YELLOW}rc-service vsafegate restart${NC}"
echo -e "${GREEN}${BOLD}========================================================================${NC}\n"
