#!/usr/bin/env bash
# ==============================================================================
#  vSafeGate All-in-One Automated Installer & Updater (v1.0.1)
#  GitHub Repository: https://github.com/daovantrong/vSafeGate
#  Supports: Debian, Ubuntu, Proxmox VE, Alpine Linux, RHEL/Rocky/Alma, Arch
# ==============================================================================

set -e

REPO="daovantrong/vSafeGate"
REPO_URL="https://github.com/${REPO}.git"
RAW_URL="https://raw.githubusercontent.com/${REPO}/main"
DEFAULT_VERSION="1.0.1"
PINNED_GO_VER="go1.27.1"

INSTALL_BIN="/usr/local/bin/vsafegate"
CADDY_BIN="/usr/bin/caddy"
CONFIG_DIR="/etc/vsafegate"
CONFIG_FILE="${CONFIG_DIR}/config.json"
LOG_DIR="/var/log/vsafegate"
CADDY_DIR="/etc/caddy"
CADDY_RULES_DIR="${CADDY_DIR}/rules"
CADDY_LOG_DIR="/var/log/caddy"

TMP_SRC="/tmp/vsafegate-src"
TMP_GO="/tmp/vsafegate-go"
TMP_GOPATH="/tmp/vsafegate-gopath"
ALPINE_TMP_GO=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

cleanup() {
    rm -rf "$TMP_SRC" "$TMP_GO" "$TMP_GOPATH" /tmp/vsafegate_dl /tmp/caddy_dl 2>/dev/null || true
    if [ "$ALPINE_TMP_GO" -eq 1 ]; then
        apk del .vsafegate-go .vsafegate-build >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

VSAFE_VER="$DEFAULT_VERSION"
if [ -f "./VERSION" ]; then
    VSAFE_VER=$(tr -d '[:space:]' < ./VERSION)
fi

ACTION="install"
PURGE=false
SCRIPT_BASENAME="$(basename "${0:-install.sh}")"
case "$SCRIPT_BASENAME" in
    *vsafegate-uninstall*)
        ACTION="uninstall"
        ;;
esac

for arg in "$@"; do
    case "$arg" in
        --uninstall|uninstall)
            ACTION="uninstall"
            ;;
        --purge|-y|--yes)
            PURGE=true
            ;;
        --help|-h)
            echo "vSafeGate v${VSAFE_VER} Installer & Uninstaller"
            echo "Usage: bash install.sh [OPTIONS]"
            echo "  (default)     Install or upgrade vSafeGate + Caddy Coraza WAF"
            echo "  --uninstall   Stop services, remove rules/binaries, backup config to /var/backups/vsafegate"
            echo "  --purge       Combined with --uninstall: also delete config backups permanently"
            exit 0
            ;;
    esac
done

echo -e "${CYAN}${BOLD}"
echo "  __      __ _____        __         _____       _        "
echo "  \ \    / // ____|      / _|       / ____|     | |       "
echo "   \ \  / /| (___   __ _| |_ ___   | |  __  __ _| |_ ___  "
echo "    \ \/ /  \___ \ / _\` |  _/ _ \  | | |_ |/ _\` | __/ _ \ "
echo "     \  /   ____) | (_| | ||  __/  | |__| | (_| | ||  __/ "
echo "      \/   |_____/ \__,_|_| \___|   \_____|\__,_|\__\___| "
echo -e "${NC}"
echo -e "${GREEN}==> vSafeGate v${VSAFE_VER} Manager (Vendored & Reproducible)${NC}\n"

# 1. Check Root Privileges
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This script must be run as root.${NC}"
    echo -e "Please run with ${YELLOW}sudo${NC}."
    exit 1
fi

# 2. Detect CPU Architecture & Init System
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        TARGET_ARCH="amd64"
        ;;
    aarch64|arm64)
        TARGET_ARCH="arm64"
        ;;
    *)
        if [ "$ACTION" = "install" ]; then
            echo -e "${RED}[ERROR] Unsupported CPU architecture: $ARCH (supports amd64 / arm64).${NC}"
            exit 1
        fi
        TARGET_ARCH="$ARCH"
        ;;
esac

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
    if [ -x /sbin/rc-service ] || [ -x /usr/sbin/rc-service ]; then
        INIT_SYSTEM="openrc"
    fi
fi

do_uninstall() {
    echo -e "${YELLOW}[1/5] Stopping and disabling vSafeGate & Caddy services (${INIT_SYSTEM})...${NC}"
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl stop vsafegate caddy >/dev/null 2>&1 || true
        systemctl disable vsafegate caddy >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/vsafegate.service /etc/systemd/system/caddy.service
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl reset-failed >/dev/null 2>&1 || true
    elif [ "$INIT_SYSTEM" = "openrc" ]; then
        rc-service vsafegate stop >/dev/null 2>&1 || true
        rc-service caddy stop >/dev/null 2>&1 || true
        rc-update del vsafegate default >/dev/null 2>&1 || true
        rc-update del caddy default >/dev/null 2>&1 || true
        rm -f /etc/init.d/vsafegate /etc/init.d/caddy
    fi
    echo -e "${GREEN}[OK] Services stopped and removed.${NC}"

    BACKUP_MSG="Removed permanently (--purge)"
    if [ "$PURGE" = false ] && [ -f "$CONFIG_FILE" ]; then
        BACKUP_DIR="/var/backups/vsafegate"
        BACKUP_FILE="${BACKUP_DIR}/config.json.$(date +%Y%m%d-%H%M%S).bak"
        mkdir -p "$BACKUP_DIR"
        cp -f "$CONFIG_FILE" "$BACKUP_FILE"
        BACKUP_MSG="Saved backup to ${BACKUP_FILE}"
        echo -e "${BLUE}[INFO] Configuration backed up to ${BACKUP_FILE}${NC}"
    elif [ "$PURGE" = true ]; then
        rm -rf /var/backups/vsafegate
    fi

    echo -e "${YELLOW}[2/5] Removing binaries, helper scripts, and cron jobs...${NC}"
    rm -f "$INSTALL_BIN" /usr/local/bin/vsafegate-auth /usr/local/bin/vsafegate-sync-threatintel.sh \
          /usr/local/bin/vsafegate-update /usr/bin/vsafegate \
          /etc/cron.daily/vsafegate-threatintel /etc/periodic/daily/vsafegate-threatintel

    if [ -f "$CADDY_BIN" ] || [ -f /usr/local/bin/caddy ]; then
        if grep -q "vSafeGate" /etc/caddy/Caddyfile 2>/dev/null || [ -f /etc/caddy/caddy.json ] || \
           ("$CADDY_BIN" list-modules 2>/dev/null | grep -qE "(http\.handlers\.waf|coraza|vsafegate_pre_tls|dns\.providers\.cloudflare)") || \
           (/usr/local/bin/caddy list-modules 2>/dev/null | grep -qE "(http\.handlers\.waf|coraza|vsafegate_pre_tls|dns\.providers\.cloudflare)"); then
            rm -f "$CADDY_BIN" /usr/local/bin/caddy
        fi
    fi
    echo -e "${GREEN}[OK] Binaries and cron jobs removed.${NC}"

    echo -e "${YELLOW}[3/5] Removing configuration directories and logs...${NC}"
    rm -rf "$CONFIG_DIR" "$CADDY_DIR" "$LOG_DIR" "$CADDY_LOG_DIR" /var/lib/vsafegate
    echo -e "${GREEN}[OK] Configs and logs cleaned up.${NC}"

    echo -e "${YELLOW}[4/5] Removing vSafeGate iptables rules & kernel ipsets...${NC}"
    if command -v iptables >/dev/null 2>&1; then
        while iptables -D INPUT -j VSAFEGATE_INPUT 2>/dev/null; do :; done
        iptables -F VSAFEGATE_INPUT 2>/dev/null || true
        iptables -X VSAFEGATE_INPUT 2>/dev/null || true
        while iptables -D OUTPUT -j VSAFEGATE_OUTPUT 2>/dev/null; do :; done
        iptables -F VSAFEGATE_OUTPUT 2>/dev/null || true
        iptables -X VSAFEGATE_OUTPUT 2>/dev/null || true
        while iptables -D INPUT -i tailscale+ -j ACCEPT 2>/dev/null; do :; done
        while iptables -D INPUT -i zt+ -j ACCEPT 2>/dev/null; do :; done
        while iptables -D INPUT -p udp --dport 41641 -j ACCEPT 2>/dev/null; do :; done
        while iptables -D INPUT -p udp --dport 9993 -j ACCEPT 2>/dev/null; do :; done
        while iptables -D INPUT -m set --match-set vsafegate-blacklist src -j DROP 2>/dev/null; do :; done
        while iptables -D INPUT -m set --match-set vsafegate-threatintel src -j DROP 2>/dev/null; do :; done
        while iptables -D INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null; do :; done
        while iptables -D INPUT ! -i tailscale+ ! -i zt+ ! -i lo -m conntrack --ctstate NEW -m set ! --match-set vsafegate-allowed src -j DROP 2>/dev/null; do :; done
        while iptables -D INPUT ! -i tailscale+ ! -i zt+ ! -i lo -m set --match-set vsafegate-countries src -j DROP 2>/dev/null; do :; done
        while iptables -D INPUT -m set --match-set vsafegate-countries src -j DROP 2>/dev/null; do :; done
        while iptables -D INPUT -p tcp -m multiport --dports 2251,22222,22 -j ACCEPT 2>/dev/null; do :; done
        while iptables -D INPUT -p tcp -m multiport --dports 22,22222 -j ACCEPT 2>/dev/null; do :; done
    fi
    if command -v ip6tables >/dev/null 2>&1; then
        while ip6tables -D INPUT -j VSAFEGATE6_INPUT 2>/dev/null; do :; done
        ip6tables -F VSAFEGATE6_INPUT 2>/dev/null || true
        ip6tables -X VSAFEGATE6_INPUT 2>/dev/null || true
    fi

    if command -v ipset >/dev/null 2>&1; then
        for s in vsafegate-blacklist vsafegate-blacklist-tmp vsafegate-threatintel vsafegate-threatintel-tmp vsafegate-countries vsafegate-countries-tmp vsafegate-allowed vsafegate-allowed-tmp vsafegate-whitelist vsafegate-whitelist-tmp vsafegate-trusted vsafegate-trusted-tmp; do
            ipset destroy "$s" 2>/dev/null || true
        done
    fi
    echo -e "${GREEN}[OK] Firewall rules and ipsets cleaned.${NC}"

    echo -e "${YELLOW}[5/5] Finalizing uninstaller cleanup...${NC}"
    rm -f /usr/local/bin/vsafegate-uninstall

    echo -e "\n${GREEN}${BOLD}========================================================================${NC}"
    echo -e "${GREEN}${BOLD}   🧹 vSafeGate Uninstalled & Cleaned Successfully!${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo -e "  📦 ${BOLD}Config Status:${NC}  ${BACKUP_MSG}"
    echo -e "  🛡️  ${BOLD}Firewall State:${NC} All vsafegate iptables rules & ipsets removed"
    echo -e "${GREEN}${BOLD}========================================================================${NC}\n"
    exit 0
}

if [ "$ACTION" = "uninstall" ]; then
    do_uninstall
fi

echo -e "${BLUE}[1/8] Architecture:${NC} ${BOLD}${TARGET_ARCH}${NC}"
echo -e "${BLUE}[2/8] System Detected:${NC} ${BOLD}${OS}${NC} (${INIT_SYSTEM})"

# 4. Install OS Prerequisites Automatically (Debian/PVE VM, LXC, Alpine, RHEL, Arch)
echo -e "${BLUE}[3/8] Installing system dependencies (iptables, ipset, curl, git, python3)...${NC}"
case "$OS" in
    debian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y curl git ipset iptables iproute2 procps ca-certificates tar gzip python3 >/dev/null 2>&1 || \
        apt-get install -y curl git ipset iptables ca-certificates tar gzip python3 >/dev/null 2>&1
        ;;
    alpine)
        apk update >/dev/null 2>&1 || true
        apk add --no-cache curl git ipset iptables ip6tables iproute2 procps ca-certificates tar gzip bash python3 >/dev/null 2>&1 || \
        apk add --no-cache curl git ipset iptables ca-certificates tar gzip bash python3 >/dev/null 2>&1 || \
        { command -v iptables >/dev/null 2>&1 && command -v ipset >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; }
        ;;
    rhel)
        yum install -y curl git ipset iptables iproute procps-ng ca-certificates tar gzip python3 >/dev/null 2>&1 || \
        dnf install -y curl git ipset iptables iproute procps-ng ca-certificates tar gzip python3 >/dev/null 2>&1 || \
        yum install -y curl git ipset iptables ca-certificates tar gzip python3 >/dev/null 2>&1 || \
        dnf install -y curl git ipset iptables ca-certificates tar gzip python3 >/dev/null 2>&1
        ;;
    arch)
        pacman -Sy --noconfirm curl git ipset iptables iproute2 procps-ng ca-certificates tar gzip python3 >/dev/null 2>&1 || \
        pacman -Sy --noconfirm curl git ipset iptables ca-certificates tar gzip python3 >/dev/null 2>&1
        ;;
esac
echo -e "${GREEN}[OK] System dependencies installed.${NC}"

# 5. Anti-Lockout SSH Detection (works even when sudo strips SSH_CLIENT)
ADMIN_IP=""
if [ -n "$SSH_CLIENT" ]; then
    ADMIN_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
elif [ -n "$SSH_CONNECTION" ]; then
    ADMIN_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
elif command -v who >/dev/null 2>&1; then
    ADMIN_IP=$(who -m 2>/dev/null | sed -n 's/.*(\([0-9a-fA-F.:]*\)).*/\1/p' | head -n1 || true)
fi

if [ -n "$ADMIN_IP" ]; then
    echo -e "${YELLOW}[SAFETY] Detected active SSH admin IP (${BOLD}${ADMIN_IP}${NC}${YELLOW}) -> auto-adding to allowlist.${NC}"
fi

# Helper: Parse Go major/minor safely (handles rc/beta tags without tripping set -e)
parse_go_ver_ok() {
    GO_CUR=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//' || true)
    GO_MAJ=$(printf '%s' "$GO_CUR" | awk -F. '{gsub(/[^0-9].*/,"",$1); print ($1==""?"0":$1)}' || echo "0")
    GO_MIN=$(printf '%s' "$GO_CUR" | awk -F. '{gsub(/[^0-9].*/,"",$2); print ($2==""?"0":$2)}' || echo "0")
    GO_MAJ="${GO_MAJ:-0}"
    GO_MIN="${GO_MIN:-0}"
    [ "$GO_MAJ" -gt 1 ] || { [ "$GO_MAJ" -eq 1 ] && [ "$GO_MIN" -ge 27 ]; }
}

# Helper: Ensure Go >= 1.27.1 is available for reproducible vendored source builds
ensure_go() {
    if command -v go >/dev/null 2>&1 && parse_go_ver_ok; then
        return 0
    fi

    if [ "$OS" = "alpine" ]; then
        apk add --no-cache --virtual .vsafegate-go go >/dev/null 2>&1 || true
        if command -v go >/dev/null 2>&1 && parse_go_ver_ok; then
            ALPINE_TMP_GO=1
            return 0
        fi
        # Remove outdated repo Go before installing gcompat so virtual packages never collide
        apk del .vsafegate-go >/dev/null 2>&1 || true
        # Fallback if Alpine repo Go < 1.27: install gcompat so official pinned Go binary runs cleanly
        apk add --no-cache --virtual .vsafegate-build gcompat >/dev/null 2>&1
        ALPINE_TMP_GO=1
    fi

    echo -e "${YELLOW}[INFO] Fetching pinned Go toolchain (${PINNED_GO_VER}) for reproducible build...${NC}"
    rm -rf "$TMP_GO"
    mkdir -p "$TMP_GO"
    curl -fsSL "https://go.dev/dl/${PINNED_GO_VER}.linux-${TARGET_ARCH}.tar.gz" | tar -C "$TMP_GO" -xzf -
    export PATH="${TMP_GO}/go/bin:${PATH}"
    export GOPATH="$TMP_GOPATH"
    mkdir -p "$TMP_GOPATH"
}

# Helper: Ensure repository source tree exists locally
ensure_source() {
    if [ -d "./mgt" ] && [ -f "./mgt/go.mod" ]; then
        SRC_DIR="$(pwd)"
        return 0
    fi
    if [ ! -d "$TMP_SRC/mgt" ]; then
        echo -e "${YELLOW}[INFO] Cloning source tree from ${REPO_URL}...${NC}"
        rm -rf "$TMP_SRC"
        git clone --depth 1 "$REPO_URL" "$TMP_SRC" >/dev/null 2>&1
    fi
    SRC_DIR="$TMP_SRC"
    if [ -f "${SRC_DIR}/VERSION" ]; then
        VSAFE_VER=$(tr -d '[:space:]' < "${SRC_DIR}/VERSION")
    fi
}

# Stop existing services cleanly & retire any legacy standalone caddy service (vsafegate supervises Caddy now)
if [ "$INIT_SYSTEM" = "systemd" ]; then
    systemctl stop vsafegate caddy >/dev/null 2>&1 || true
    systemctl disable caddy >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/caddy.service
    systemctl daemon-reload >/dev/null 2>&1 || true
elif [ "$INIT_SYSTEM" = "openrc" ]; then
    rc-service vsafegate stop >/dev/null 2>&1 || true
    rc-service caddy stop >/dev/null 2>&1 || true
    rc-update del caddy default >/dev/null 2>&1 || true
    rm -f /etc/init.d/caddy
fi

mkdir -p "$CONFIG_DIR" "${CONFIG_DIR}/certs" /var/lib/vsafegate "$LOG_DIR" "$CADDY_DIR" "$CADDY_RULES_DIR" "$CADDY_LOG_DIR" /usr/local/bin /usr/bin
chmod 700 "${CONFIG_DIR}/certs"
chmod 750 "$CONFIG_DIR" /var/lib/vsafegate

# 6. Install vSafeGate Binary (GitHub Releases -> Local -> Vendored Source Build)
echo -e "${BLUE}[4/8] Installing vSafeGate core daemon...${NC}"
LATEST_TAG=$(curl -s --max-time 10 "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)
if [ ! -f "./VERSION" ]; then
    if [ -n "$LATEST_TAG" ]; then
        VSAFE_VER="${LATEST_TAG#v}"
    else
        REMOTE_VER=$(curl -fsSL --max-time 5 "${RAW_URL}/VERSION" 2>/dev/null | tr -d '[:space:]' || true)
        if [ -n "$REMOTE_VER" ]; then
            VSAFE_VER="${REMOTE_VER#v}"
        fi
    fi
fi

VSAFE_OK=false
if [ -n "$LATEST_TAG" ]; then
    DL_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/vsafegate-linux-${TARGET_ARCH}"
    echo -e "      Trying GitHub Release ${LATEST_TAG}..."
    if curl -fsSL -o /tmp/vsafegate_dl "$DL_URL"; then
        mv -f /tmp/vsafegate_dl "$INSTALL_BIN"
        chmod 755 "$INSTALL_BIN"
        VSAFE_OK=true
    fi
fi

if [ "$VSAFE_OK" = false ] && [ -f "./vsafegate-linux-${TARGET_ARCH}" ]; then
    echo -e "      Using local binary ./vsafegate-linux-${TARGET_ARCH}..."
    cp -f "./vsafegate-linux-${TARGET_ARCH}" "$INSTALL_BIN"
    chmod 755 "$INSTALL_BIN"
    VSAFE_OK=true
fi

if [ "$VSAFE_OK" = false ]; then
    echo -e "      Compiling from self-contained repo source (std-lib only)..."
    ensure_go
    ensure_source
    (cd "${SRC_DIR}/mgt" && CGO_ENABLED=0 go build -ldflags="-s -w -X main.AppVersion=${VSAFE_VER}" -o "$INSTALL_BIN" .)
    chmod 755 "$INSTALL_BIN"
fi
echo -e "${GREEN}[OK] vSafeGate binary installed at ${INSTALL_BIN} (v${VSAFE_VER}).${NC}"

# Helper: verify custom vSafeGate modules are compiled into the Caddy binary
caddy_has_required_modules() {
    local bin="$1"
    [ -x "$bin" ] || return 1
    local mods
    mods=$("$bin" list-modules 2>/dev/null || true)
    echo "$mods" | grep -qE "(^|[[:space:]])http\.handlers\.waf([[:space:]]|$)" && \
    echo "$mods" | grep -qE "(^|[[:space:]])http\.handlers\.vsafegate_shield([[:space:]]|$)" && \
    echo "$mods" | grep -qE "(^|[[:space:]])caddy\.listeners\.vsafegate_pre_tls([[:space:]]|$)" && \
    echo "$mods" | grep -qE "(^|[[:space:]])dns\.providers\.cloudflare([[:space:]]|$)"
}

# 7. Install Caddy + Coraza WAF (Exact Version & Module Verification -> Release -> Local -> Vendored Build)
echo -e "${BLUE}[5/8] Installing vendored Caddy + Coraza WAF (L7 Core & HTTPS Proxy)...${NC}"
TARGET_CADDY_VER="${VSAFE_VER#v}"
INSTALLED_CADDY_VER=""
if [ -f "${CONFIG_DIR}/.caddy-version" ]; then
    INSTALLED_CADDY_VER=$(tr -d '[:space:]' < "${CONFIG_DIR}/.caddy-version" | sed 's/^v//')
fi

# Remove stale /usr/local/bin/caddy if it shadows /usr/bin/caddy
if [ -x /usr/local/bin/caddy ] && [ "$CADDY_BIN" != "/usr/local/bin/caddy" ]; then
    rm -f /usr/local/bin/caddy
fi

CADDY_OK=false
if [ -x "$CADDY_BIN" ] && [ "$INSTALLED_CADDY_VER" = "$TARGET_CADDY_VER" ] && caddy_has_required_modules "$CADDY_BIN"; then
    echo -e "${GREEN}[OK] Existing Caddy v${INSTALLED_CADDY_VER} with all required vSafeGate modules detected.${NC}"
    CADDY_OK=true
elif [ -x "$CADDY_BIN" ]; then
    echo -e "${YELLOW}[INFO] Existing Caddy requires upgrade (installed: '${INSTALLED_CADDY_VER:-unknown}', target: '${TARGET_CADDY_VER}', or missing custom modules).${NC}"
fi

if [ "$CADDY_OK" = false ] && [ -n "$LATEST_TAG" ]; then
    CADDY_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/caddy-coraza-linux-${TARGET_ARCH}"
    echo -e "      Trying GitHub Release Caddy+Coraza (${LATEST_TAG})..."
    if curl -fsSL -o /tmp/caddy_dl "$CADDY_URL"; then
        chmod 755 /tmp/caddy_dl
        if caddy_has_required_modules /tmp/caddy_dl; then
            mv -f /tmp/caddy_dl "$CADDY_BIN"
            CADDY_OK=true
        else
            echo -e "${YELLOW}[WARN] Release Caddy binary lacks required custom modules; falling back to vendored source build.${NC}"
            rm -f /tmp/caddy_dl
        fi
    fi
fi

if [ "$CADDY_OK" = false ] && [ -f "./caddy-coraza-linux-${TARGET_ARCH}" ]; then
    cp -f "./caddy-coraza-linux-${TARGET_ARCH}" "$CADDY_BIN"
    chmod 755 "$CADDY_BIN"
    if caddy_has_required_modules "$CADDY_BIN"; then
        CADDY_OK=true
    fi
elif [ "$CADDY_OK" = false ] && [ "$TARGET_ARCH" = "amd64" ] && [ -f "./caddy-linux-amd64" ]; then
    cp -f "./caddy-linux-amd64" "$CADDY_BIN"
    chmod 755 "$CADDY_BIN"
    if caddy_has_required_modules "$CADDY_BIN"; then
        CADDY_OK=true
    fi
elif [ "$CADDY_OK" = false ] && [ "$TARGET_ARCH" = "amd64" ] && [ -f "./caddy.gz" ]; then
    gzip -dc "./caddy.gz" > "$CADDY_BIN"
    chmod 755 "$CADDY_BIN"
    if caddy_has_required_modules "$CADDY_BIN"; then
        CADDY_OK=true
    fi
fi

if [ "$CADDY_OK" = false ]; then
    echo -e "      Building pinned Caddy + Coraza WAF offline from vendored caddy-core/ (-mod=vendor)..."
    ensure_go
    ensure_source
    (cd "${SRC_DIR}/caddy-core" && CGO_ENABLED=0 go build -mod=vendor -ldflags="-s -w" -o "$CADDY_BIN" .)
    chmod 755 "$CADDY_BIN"
    if ! caddy_has_required_modules "$CADDY_BIN"; then
        echo -e "${RED}[ERROR] Built Caddy binary failed module verification!${NC}"
        exit 1
    fi
    CADDY_OK=true
fi
echo "${TARGET_CADDY_VER}" > "${CONFIG_DIR}/.caddy-version"
echo -e "${GREEN}[OK] Caddy + Coraza WAF v${TARGET_CADDY_VER} installed & verified at ${CADDY_BIN}.${NC}"

# 8. Initialize Safe Configuration & Threat Intelligence Sync Script
echo -e "${BLUE}[6/8] Initializing safe default configuration & Threat Intel sync...${NC}"
if [ ! -f "$CONFIG_FILE" ]; then
    NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    ADMIN_IP_ENV="$ADMIN_IP" NOW_ENV="$NOW" CONFIG_PATH_ENV="$CONFIG_FILE" python3 - <<'PYEOF'
import json, os

now = os.environ["NOW_ENV"]
admin_ip = os.environ.get("ADMIN_IP_ENV", "").strip()
whitelist = []
if admin_ip:
    whitelist.append({"ip": admin_ip, "note": "Admin Initial SSH IP (Auto-Protected)", "created_at": now})
whitelist.extend([
    {"ip": "127.0.0.1", "note": "Localhost loopback", "created_at": now},
    {"ip": "10.0.0.0/8", "note": "Private LAN (Class A)", "created_at": now},
    {"ip": "172.16.0.0/12", "note": "Private Network (Class B)", "created_at": now},
    {"ip": "192.168.0.0/16", "note": "Private LAN / Gateway (Class C)", "created_at": now},
])

cfg = {
    "sites": [],
    "l4_services": [],
    "rules": [
        {
            "id": "rule-1001",
            "rule_id": 1001,
            "name": "Block sensitive files (.env, .git, .aws)",
            "target": "URI",
            "operator": "rx",
            "pattern": r"(^|/)(\.env|\.git|\.aws|config\.json)",
            "action": "deny",
            "description": "Prevent exposure of source code and environment credentials",
            "enabled": True,
        }
    ],
    "banned_ips": [],
    "whitelist_ips": whitelist,
    "default_ban_ttl_hours": 24,
    "defense_policy": {
        "default_ban_ttl_hours": 24,
        "ssh_guard_enabled": True,
        "ssh_max_attempts": 3,
        "canary_enabled": True,
        "waf_auto_ban_enabled": True,
        "waf_auto_ban_threshold": 10,
        "suricata_auto_ban": True,
    },
    "geoip_mode": "disabled",
    "allowed_countries": [],
    "blocked_countries": ["CN", "RU"],
    "mgmt_domain": "",
    "mgmt_https_port": 4438,
    "mgmt_http_port": 808,
}
with open(os.environ["CONFIG_PATH_ENV"], "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
    f.write("\n")
PYEOF
    chmod 600 "$CONFIG_FILE"
    echo -e "${GREEN}[OK] Safe configuration initialized at ${CONFIG_FILE} (0600).${NC}"
else
    chmod 600 "$CONFIG_FILE"
    echo -e "${YELLOW}[INFO] Existing ${CONFIG_FILE} preserved (permissions hardened to 0600).${NC}"
fi

# Install automated Threat Intelligence feed sync script + daily cron
if [ -n "${SRC_DIR:-}" ] && [ -f "${SRC_DIR}/scripts/vsafegate-sync-threatintel.sh" ]; then
    cp -f "${SRC_DIR}/scripts/vsafegate-sync-threatintel.sh" /usr/local/bin/vsafegate-sync-threatintel.sh
elif [ -f "./scripts/vsafegate-sync-threatintel.sh" ]; then
    cp -f "./scripts/vsafegate-sync-threatintel.sh" /usr/local/bin/vsafegate-sync-threatintel.sh
else
    cat <<'EOF' > /usr/local/bin/vsafegate-sync-threatintel.sh
#!/usr/bin/env bash
set -e
TMP_LIST=$(mktemp /tmp/vsafegate_ti_raw.XXXXXX)
IPSET_SCRIPT=$(mktemp /tmp/vsafegate_ti_restore.XXXXXX)
trap 'rm -f "$TMP_LIST" "$IPSET_SCRIPT"' EXIT

curl -fsSL --max-time 15 "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" >> "$TMP_LIST" 2>/dev/null || true
curl -fsSL --max-time 15 "https://www.spamhaus.org/drop/drop.txt" >> "$TMP_LIST" 2>/dev/null || true

if [ ! -s "$TMP_LIST" ]; then
    exit 0
fi

ipset create vsafegate-threatintel hash:net maxelem 131072 -exist
ipset create vsafegate-threatintel-tmp hash:net maxelem 131072 -exist
ipset flush vsafegate-threatintel-tmp

echo "flush vsafegate-threatintel-tmp" > "$IPSET_SCRIPT"
grep -Eo '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "$TMP_LIST" | \
    grep -Ev '/0$' | \
    grep -Ev '^(0\.|10\.|127\.|169\.254\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|224\.|240\.)' | \
    sort -u | awk '{print "add vsafegate-threatintel-tmp " $1 " -exist"}' >> "$IPSET_SCRIPT"

ipset restore < "$IPSET_SCRIPT"
ipset swap vsafegate-threatintel-tmp vsafegate-threatintel
ipset destroy vsafegate-threatintel-tmp
EOF
fi
chmod 755 /usr/local/bin/vsafegate-sync-threatintel.sh

if [ "$OS" = "alpine" ] || [ -d /etc/periodic/daily ]; then
    mkdir -p /etc/periodic/daily
    ln -sf /usr/local/bin/vsafegate-sync-threatintel.sh /etc/periodic/daily/vsafegate-threatintel
    if [ "$INIT_SYSTEM" = "openrc" ] && command -v rc-service >/dev/null 2>&1; then
        rc-update add crond default >/dev/null 2>&1 || true
        rc-service crond start >/dev/null 2>&1 || true
    fi
elif [ -d /etc/cron.daily ]; then
    ln -sf /usr/local/bin/vsafegate-sync-threatintel.sh /etc/cron.daily/vsafegate-threatintel
fi

# One-command updater & uninstaller helpers
cat <<EOF > /usr/local/bin/vsafegate-update
#!/usr/bin/env bash
exec curl -fsSL "${RAW_URL}/install.sh" | bash
EOF
chmod 755 /usr/local/bin/vsafegate-update

if [ -n "${SRC_DIR:-}" ] && [ -f "${SRC_DIR}/install.sh" ]; then
    cp -f "${SRC_DIR}/install.sh" /usr/local/bin/vsafegate-uninstall
elif [ -f "./install.sh" ]; then
    cp -f "./install.sh" /usr/local/bin/vsafegate-uninstall
elif [ -f "$0" ] && [ -r "$0" ] && ! basename "$0" | grep -qE '^(bash|sh|dash)$'; then
    cp -f "$0" /usr/local/bin/vsafegate-uninstall
else
    curl -fsSL --max-time 15 "${RAW_URL}/install.sh" -o /usr/local/bin/vsafegate-uninstall || true
fi
if [ -f /usr/local/bin/vsafegate-uninstall ]; then
    chmod 755 /usr/local/bin/vsafegate-uninstall
fi

# 9. Configure & Start Unified Single Service (vsafegate supervises Caddy directly)
echo -e "${BLUE}[7/8] Configuring & starting unified ${INIT_SYSTEM} service (vsafegate + embedded Caddy supervisor)...${NC}"
if [ "$INIT_SYSTEM" = "systemd" ]; then
    cat <<EOF > /etc/systemd/system/vsafegate.service
[Unit]
Description=vSafeGate Unified Security Gateway, L4 Proxy & Managed Caddy WAF
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_BIN}
Restart=always
RestartSec=3
TimeoutStopSec=15
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable vsafegate >/dev/null 2>&1
    systemctl restart vsafegate
    echo -e "${GREEN}[OK] Unified systemd service (vsafegate + managed Caddy L7) active.${NC}"
elif [ "$INIT_SYSTEM" = "openrc" ]; then
    cat <<EOF > /etc/init.d/vsafegate
#!/sbin/openrc-run
name="vsafegate"
description="vSafeGate Unified Security Gateway & Managed Caddy WAF"
command="${INSTALL_BIN}"
command_background="true"
pidfile="/run/vsafegate.pid"
retry="TERM/10/KILL/5"

depend() {
    need net
    after firewall
}
EOF

    chmod +x /etc/init.d/vsafegate
    rc-update add vsafegate default >/dev/null 2>&1 || true
    rc-service vsafegate restart
    echo -e "${GREEN}[OK] Unified OpenRC service (vsafegate + managed Caddy L7) active.${NC}"
fi

echo -e "${BLUE}[8/8] Syncing initial Threat Intelligence feed (background-safe)...${NC}"
/usr/local/bin/vsafegate-sync-threatintel.sh >/dev/null 2>&1 || true

# 10. Summary Banner
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
[ -z "$HOST_IP" ] && HOST_IP=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)
[ -z "$HOST_IP" ] && HOST_IP="127.0.0.1"

echo -e "\n${GREEN}${BOLD}========================================================================${NC}"
echo -e "${GREEN}${BOLD}   🎉 vSafeGate v${VSAFE_VER} Installed & Started Successfully!${NC}"
echo -e "${GREEN}${BOLD}========================================================================${NC}"
echo -e "  🌐 ${BOLD}Web Admin Dashboard:${NC}  ${CYAN}https://127.0.0.1:4438/${NC} + auto-detected private LAN / Tailscale IPs (:4438)"
echo -e "  🚇 ${BOLD}SSH Tunnel Option:${NC}    ${YELLOW}ssh -N -L 4438:127.0.0.1:4438 root@${HOST_IP}${NC}"
echo -e "     ${BOLD}(or customize listen IPs/CIDRs via Settings -> Management Listen IPs)${NC}"
echo -e "  🔐 ${BOLD}Authentication:${NC}       Linux PAM server account (sudo user)"
echo -e "  📂 ${BOLD}Configuration File:${NC}   ${CONFIG_FILE} (0600)"
echo -e "  🛡️  ${BOLD}Caddy & WAF Config:${NC}   ${CADDY_DIR}/caddy.json & ${CADDY_RULES_DIR}/custom-rules.conf"
echo -e "  📜 ${BOLD}Attack Log Stream:${NC}    ${LOG_DIR}/attacks.jsonl"
echo -e "  🔄 ${BOLD}One-Line Updater:${NC}     ${YELLOW}sudo vsafegate-update${NC}"
echo -e "  🧹 ${BOLD}Clean Uninstaller:${NC}    ${YELLOW}sudo vsafegate-uninstall${NC} (or ${YELLOW}--purge${NC})"
echo -e "  ⚙️  ${BOLD}Unified CLI Control:${NC}  ${YELLOW}sudo vsafegate status|restart|logs|update|uninstall${NC}"
echo -e "${GREEN}${BOLD}========================================================================${NC}\n"
