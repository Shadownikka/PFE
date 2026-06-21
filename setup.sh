#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║           NetMind — One-Shot Setup Script                   ║
# ║  Supports: Ubuntu · Debian · Kali · Fedora · Arch · Mint   ║
# ║  Usage:    sudo bash setup.sh                               ║
# ╚══════════════════════════════════════════════════════════════╝

set -e

# ── Colours ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}  ✔ $*${RESET}"; }
info() { echo -e "${CYAN}  ▸ $*${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${RESET}"; }
err()  { echo -e "${RED}  ✘ $*${RESET}"; exit 1; }
hdr()  { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(eval echo ~$REAL_USER)"

# ── Root check ─────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "Please run with sudo:  sudo bash setup.sh"
fi

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║        NetMind — Automated Setup             ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${RESET}"
echo ""

# ════════════════════════════════════════════════════════════════
# 1. DETECT DISTRIBUTION
# ════════════════════════════════════════════════════════════════
hdr "Step 1/8 — Detecting Linux Distribution"

if [ -f /etc/os-release ]; then
  . /etc/os-release
  DISTRO="${ID,,}"   # lowercase
  DISTRO_LIKE="${ID_LIKE,,}"
else
  err "Cannot detect Linux distribution."
fi

info "Detected: $PRETTY_NAME"

case "$DISTRO" in
  ubuntu|debian|kali|linuxmint|pop)     PKG_MGR="apt" ;;
  fedora|rhel|centos|rocky|alma)        PKG_MGR="dnf" ;;
  arch|manjaro|endeavouros|garuda)      PKG_MGR="pacman" ;;
  opensuse*|sles)                       PKG_MGR="zypper" ;;
  *)
    if [[ "$DISTRO_LIKE" == *"debian"* ]] || [[ "$DISTRO_LIKE" == *"ubuntu"* ]]; then
      PKG_MGR="apt"
    elif [[ "$DISTRO_LIKE" == *"fedora"* ]] || [[ "$DISTRO_LIKE" == *"rhel"* ]]; then
      PKG_MGR="dnf"
    elif [[ "$DISTRO_LIKE" == *"arch"* ]]; then
      PKG_MGR="pacman"
    else
      warn "Unknown distro '$DISTRO'. Assuming apt-based. You may need to install deps manually."
      PKG_MGR="apt"
    fi
  ;;
esac

ok "Package manager: $PKG_MGR"

# ════════════════════════════════════════════════════════════════
# 2. SYSTEM PACKAGES
# ════════════════════════════════════════════════════════════════
hdr "Step 2/8 — Installing System Packages"

APT_PKGS=(
  python3 python3-pip python3-dev python3-venv
  python3-pyqt6 python3-pyqt6.qtsvg
  libgl1 libglib2.0-0 libxcb-xinerama0 libxcb-icccm4 libxcb-image0
  libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-xkb1
  libxkbcommon-x11-0 libxkbcommon0 libegl1 libdbus-1-3
  libpcap-dev libffi-dev libssl-dev
  net-tools iproute2 curl wget git ca-certificates gnupg
  portaudio19-dev   # for voice input
)

DNF_PKGS=(
  python3 python3-pip python3-devel python3-PyQt6
  mesa-libGL glib2 libpcap-devel libffi-devel openssl-devel
  net-tools iproute curl wget git ca-certificates
  portaudio-devel
)

PACMAN_PKGS=(
  python python-pip python-pyqt6
  mesa glib2 libpcap libffi openssl
  net-tools iproute2 curl wget git
  portaudio
)

case "$PKG_MGR" in
  apt)
    info "Updating package index..."
    apt-get update -qq
    info "Installing packages..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${APT_PKGS[@]}" 2>&1 | grep -E "^(Setting|Unpacking|Selecting|Get)" || true
    ;;
  dnf)
    info "Installing packages..."
    dnf install -y "${DNF_PKGS[@]}" 2>&1 | tail -5
    ;;
  pacman)
    info "Updating and installing packages..."
    pacman -Sy --noconfirm "${PACMAN_PKGS[@]}" 2>&1 | tail -10
    ;;
  zypper)
    info "Installing packages..."
    zypper install -y python3 python3-pip libGL1 curl wget git 2>&1 | tail -5
    ;;
esac

ok "System packages installed"

# ════════════════════════════════════════════════════════════════
# 3. PYTHON DEPENDENCIES
# ════════════════════════════════════════════════════════════════
hdr "Step 3/8 — Installing Python Dependencies"

info "Installing from requirements.txt..."

# Try pip3 install; handle both system-managed and normal envs
PIP_FLAGS="--quiet --no-warn-script-location"
PIP_CMD="pip3 install $PIP_FLAGS"

if pip3 install $PIP_FLAGS -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null; then
  ok "Python packages installed"
else
  info "System-managed Python detected. Using --break-system-packages flag..."
  pip3 install $PIP_FLAGS --break-system-packages -r "$SCRIPT_DIR/requirements.txt"
  ok "Python packages installed (break-system-packages)"
fi

# ════════════════════════════════════════════════════════════════
# 4. DOCKER
# ════════════════════════════════════════════════════════════════
hdr "Step 4/8 — Docker"

if command -v docker &>/dev/null; then
  DOCKER_VER=$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')
  ok "Docker already installed (v$DOCKER_VER)"
else
  info "Installing Docker..."
  case "$PKG_MGR" in
    apt)
      install -m 0755 -d /etc/apt/keyrings
      curl -fsSL https://download.docker.com/linux/${DISTRO}/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      chmod a+r /etc/apt/keyrings/docker.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/${DISTRO} $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        | tee /etc/apt/sources.list.d/docker.list > /dev/null
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y \
        docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      ;;
    dnf)
      dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
      dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
      ;;
    pacman)
      pacman -Sy --noconfirm docker docker-compose
      ;;
  esac
  ok "Docker installed"
fi

# Enable & start Docker
systemctl enable docker --now 2>/dev/null || true

# Add real user to docker group so they don't need sudo for docker
if id "$REAL_USER" &>/dev/null; then
  usermod -aG docker "$REAL_USER" 2>/dev/null || true
  ok "User '$REAL_USER' added to docker group"
fi

# Verify docker compose plugin
if docker compose version &>/dev/null; then
  ok "Docker Compose plugin available"
else
  warn "Docker Compose plugin not found. Trying standalone..."
  pip3 install docker-compose --quiet || true
fi

# ════════════════════════════════════════════════════════════════
# 5. OLLAMA
# ════════════════════════════════════════════════════════════════
hdr "Step 5/8 — Ollama (Local AI Runtime)"

if command -v ollama &>/dev/null; then
  ok "Ollama already installed"
else
  info "Downloading and installing Ollama..."
  curl -fsSL https://ollama.com/install.sh | sh
  ok "Ollama installed"
fi

# Start Ollama service if not running
if ! pgrep -x ollama &>/dev/null; then
  info "Starting Ollama service..."
  nohup ollama serve > /tmp/ollama.log 2>&1 &
  sleep 4
fi

# Wait until Ollama API is reachable
info "Waiting for Ollama API..."
for i in $(seq 1 20); do
  if curl -sf http://localhost:11434/api/tags &>/dev/null; then
    ok "Ollama API is ready"
    break
  fi
  sleep 2
  if [ $i -eq 20 ]; then
    warn "Ollama did not respond in time. You may need to run 'ollama serve' manually."
  fi
done

# ════════════════════════════════════════════════════════════════
# 6. AI MODEL
# ════════════════════════════════════════════════════════════════
hdr "Step 6/8 — Downloading Llama 3.1 AI Model (~4.9 GB)"

if ollama list 2>/dev/null | grep -q "llama3.1"; then
  ok "Llama 3.1 model already downloaded"
else
  info "Pulling llama3.1 — this may take a few minutes depending on your connection..."
  ollama pull llama3.1
  ok "Llama 3.1 downloaded"
fi

# ════════════════════════════════════════════════════════════════
# 7. PERMISSIONS & GIT CONFIG
# ════════════════════════════════════════════════════════════════
hdr "Step 7/8 — Permissions & Configuration"

# Fix ownership (sudo may have created root-owned files)
info "Fixing file ownership..."
chown -R "$REAL_USER":"$REAL_USER" "$SCRIPT_DIR"
ok "Ownership set to $REAL_USER"

# Git safe directory (git 2.35.2+ refuses repos owned by another user)
if command -v git &>/dev/null; then
  sudo -u "$REAL_USER" git config --global --add safe.directory "$SCRIPT_DIR" 2>/dev/null || true
  ok "Git safe.directory configured"
fi

# Make scripts executable
chmod +x "$SCRIPT_DIR/start.sh" "$SCRIPT_DIR/stop.sh" "$SCRIPT_DIR/setup.sh"

# Disable WiFi power-save (reduces latency overhead significantly)
WIFI_IFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | head -1)
if [ -n "$WIFI_IFACE" ]; then
  iw dev "$WIFI_IFACE" set power_save off 2>/dev/null || true
  ok "Wi-Fi power-save disabled on $WIFI_IFACE"
fi

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
# Make it persistent
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
ok "IP forwarding enabled"

# ════════════════════════════════════════════════════════════════
# 8. HEALTH CHECK
# ════════════════════════════════════════════════════════════════
hdr "Step 8/8 — Final Health Check"

PASS=0; FAIL=0

check() {
  local label="$1"; local cmd="$2"
  if eval "$cmd" &>/dev/null; then
    ok "$label"
    ((PASS++))
  else
    warn "FAILED: $label"
    ((FAIL++))
  fi
}

check "Python 3.10+"          "python3 -c 'import sys; assert sys.version_info >= (3,10)'"
check "PyQt6"                 "python3 -c 'from PyQt6.QtWidgets import QApplication'"
check "Scapy"                 "python3 -c 'import scapy'"
check "Requests"              "python3 -c 'import requests'"
check "Docker"                "docker --version"
check "Docker Compose"        "docker compose version"
check "Ollama reachable"      "curl -sf http://localhost:11434/api/tags"
check "Llama 3.1 model"       "ollama list | grep -q llama3.1"
check "NetMindDesktop.py"     "test -f '$SCRIPT_DIR/NetMindDesktop.py'"
check "core/tool.py"          "test -f '$SCRIPT_DIR/core/tool.py'"
check "observability/docker-compose.yml" "test -f '$SCRIPT_DIR/observability/docker-compose.yml'"

echo ""
echo -e "${BOLD}Results: ${GREEN}$PASS passed${RESET}  ${RED}$FAIL failed${RESET}"

# ════════════════════════════════════════════════════════════════
# DONE
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║         ✅  Setup Complete!                  ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}To launch NetMind:${RESET}"
echo -e "    ${CYAN}sudo bash start.sh${RESET}          # starts Grafana + app"
echo -e "    ${CYAN}sudo python3 NetMindDesktop.py${RESET}  # app only"
echo ""

if [ $FAIL -gt 0 ]; then
  echo -e "  ${YELLOW}⚠  $FAIL check(s) failed — review the warnings above before launching.${RESET}"
  echo ""
fi

# Offer to launch immediately
read -rp "  Launch NetMind now? [y/N] " LAUNCH
if [[ "$LAUNCH" =~ ^[Yy]$ ]]; then
  echo ""
  bash "$SCRIPT_DIR/start.sh"
fi
