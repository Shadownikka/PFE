#!/bin/bash
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║              NetMind — Bootstrap Installer                               ║
# ║                                                                          ║
# ║  This is the ONLY file you need. Run it once and NetMind installs        ║
# ║  itself completely — no extra steps, no terminal after this.             ║
# ║                                                                          ║
# ║  Usage:  sudo bash setup.sh                                              ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

set -e

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; MAGENTA='\033[0;35m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}  ✔ $*${RESET}"; }
info() { echo -e "${CYAN}  ▸ $*${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${RESET}"; }
err()  { echo -e "${RED}  ✘ $*${RESET}"; exit 1; }
step() { echo -e "\n${BOLD}${MAGENTA}[$1/9]${RESET} ${BOLD}$2${RESET}"; }

# ── Config ────────────────────────────────────────────────────────────────────
GITHUB_REPO="Shadownikka/PFE"
RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/netmind-app-latest.tar.gz"
INSTALL_DIR="/opt/netmind"
LAUNCHER_BIN="/usr/local/bin/netmind-launch"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(eval echo ~$REAL_USER)"

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "Please run with sudo:  sudo bash setup.sh"

# ── Banner ────────────────────────────────────────────────────────────────────
clear
echo ""
echo -e "${BOLD}${CYAN}"
echo "  ███╗   ██╗███████╗████████╗███╗   ███╗██╗███╗   ██╗██████╗ "
echo "  ████╗  ██║██╔════╝╚══██╔══╝████╗ ████║██║████╗  ██║██╔══██╗"
echo "  ██╔██╗ ██║█████╗     ██║   ██╔████╔██║██║██╔██╗ ██║██║  ██║"
echo "  ██║╚██╗██║██╔══╝     ██║   ██║╚██╔╝██║██║██║╚██╗██║██║  ██║"
echo "  ██║ ╚████║███████╗   ██║   ██║ ╚═╝ ██║██║██║ ╚████║██████╔╝"
echo "  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝ "
echo -e "${RESET}"
echo -e "${BOLD}  AI-Powered Network Manager — Complete Installer${RESET}"
echo ""
echo -e "${CYAN}  Run this once. NetMind will install itself and appear on your desktop.${RESET}"
echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 1 — DETECT DISTRIBUTION
# ════════════════════════════════════════════════════════════════════════════
step 1 "Detecting Linux Distribution"

[[ -f /etc/os-release ]] || err "Cannot detect Linux distribution."
. /etc/os-release
DISTRO="${ID,,}"
DISTRO_LIKE="${ID_LIKE,,}"
info "Detected: $PRETTY_NAME"

case "$DISTRO" in
  ubuntu|debian|kali|linuxmint|pop)     PKG_MGR="apt" ;;
  fedora|rhel|centos|rocky|alma)        PKG_MGR="dnf" ;;
  arch|manjaro|endeavouros|garuda)      PKG_MGR="pacman" ;;
  opensuse*|sles)                       PKG_MGR="zypper" ;;
  *)
    if   [[ "$DISTRO_LIKE" == *"debian"* || "$DISTRO_LIKE" == *"ubuntu"* ]]; then PKG_MGR="apt"
    elif [[ "$DISTRO_LIKE" == *"fedora"* || "$DISTRO_LIKE" == *"rhel"*   ]]; then PKG_MGR="dnf"
    elif [[ "$DISTRO_LIKE" == *"arch"*                                    ]]; then PKG_MGR="pacman"
    else warn "Unknown distro. Assuming apt."; PKG_MGR="apt"
    fi ;;
esac
ok "Package manager: $PKG_MGR"

# ════════════════════════════════════════════════════════════════════════════
# STEP 2 — SYSTEM PACKAGES
# ════════════════════════════════════════════════════════════════════════════
step 2 "Installing System Packages"

APT_PKGS=(
  python3 python3-pip python3-dev python3-venv
  python3-pyqt6 python3-pyqt6.qtsvg
  libgl1 libglib2.0-0 libxcb-xinerama0 libxcb-icccm4 libxcb-image0
  libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-xkb1
  libxkbcommon-x11-0 libxkbcommon0 libegl1 libdbus-1-3
  libpcap-dev libffi-dev libssl-dev
  net-tools iproute2 curl wget git ca-certificates gnupg
  portaudio19-dev policykit-1
)
DNF_PKGS=(python3 python3-pip python3-devel python3-PyQt6 mesa-libGL glib2
  libpcap-devel libffi-devel openssl-devel net-tools iproute curl wget git
  ca-certificates portaudio-devel polkit)
PACMAN_PKGS=(python python-pip python-pyqt6 mesa glib2 libpcap libffi openssl
  net-tools iproute2 curl wget git portaudio polkit)

case "$PKG_MGR" in
  apt)
    info "Updating package index..."
    apt-get update -qq
    info "Installing packages..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${APT_PKGS[@]}" 2>&1 \
      | grep -E "^(Setting|Unpacking|Get:)" || true ;;
  dnf)    dnf install -y "${DNF_PKGS[@]}"        2>&1 | tail -5 ;;
  pacman) pacman -Sy --noconfirm "${PACMAN_PKGS[@]}" 2>&1 | tail -10 ;;
  zypper) zypper install -y python3 python3-pip libGL1 curl wget git polkit 2>&1 | tail -5 ;;
esac
ok "System packages installed"

# ════════════════════════════════════════════════════════════════════════════
# STEP 3 — DOWNLOAD APP FILES FROM GITHUB RELEASES
# ════════════════════════════════════════════════════════════════════════════
step 3 "Downloading NetMind Application Files"

mkdir -p "$INSTALL_DIR"

# ── Check if app files are already present locally (developer mode) ──────────
if [[ -f "$SCRIPT_DIR/NetMindDesktop.py" ]]; then
  info "Local project files detected — using local copy (developer mode)"
  info "Copying project files to $INSTALL_DIR..."
  rsync -a --delete \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.gitkeep' \
    --exclude='dist/' \
    --exclude='build/' \
    --exclude='packaging/releases/' \
    "$SCRIPT_DIR/" "$INSTALL_DIR/" 2>/dev/null || {
      cp -r "$SCRIPT_DIR/." "$INSTALL_DIR/"
      find "$INSTALL_DIR" -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
      find "$INSTALL_DIR" -name '*.pyc' -delete 2>/dev/null || true
    }
  ok "App files copied from local source"

# ── Fresh install: download from GitHub Releases ─────────────────────────────
else
  info "Downloading from GitHub Releases..."
  info "URL: $RELEASE_URL"

  TMP_TARBALL="/tmp/netmind-app.tar.gz"

  # Download with progress
  if command -v wget &>/dev/null; then
    wget --show-progress -q "$RELEASE_URL" -O "$TMP_TARBALL" 2>&1 || \
      err "Download failed. Check your internet connection and try again."
  else
    curl -L --progress-bar "$RELEASE_URL" -o "$TMP_TARBALL" || \
      err "Download failed. Check your internet connection and try again."
  fi

  ok "Download complete ($(du -sh $TMP_TARBALL | cut -f1))"

  info "Extracting to $INSTALL_DIR..."
  tar -xzf "$TMP_TARBALL" -C "$INSTALL_DIR"
  rm -f "$TMP_TARBALL"
  ok "App files extracted to $INSTALL_DIR"
fi

# Verify critical file extracted correctly
[[ -f "$INSTALL_DIR/NetMindDesktop.py" ]] || \
  err "Extraction failed — NetMindDesktop.py not found in $INSTALL_DIR"

ok "NetMind app files ready at $INSTALL_DIR"

# ════════════════════════════════════════════════════════════════════════════
# STEP 4 — PYTHON DEPENDENCIES
# ════════════════════════════════════════════════════════════════════════════
step 4 "Installing Python Dependencies"

REQS="$INSTALL_DIR/requirements.txt"
PIP_FLAGS="--quiet --no-warn-script-location"

info "Installing from requirements.txt..."
if pip3 install $PIP_FLAGS -r "$REQS" 2>/dev/null; then
  ok "Python packages installed"
else
  info "System-managed Python — using --break-system-packages..."
  pip3 install $PIP_FLAGS --break-system-packages -r "$REQS"
  ok "Python packages installed"
fi

# Also install system-wide so root (sudo python3) can import them
pip3 install $PIP_FLAGS --break-system-packages -r "$REQS" 2>/dev/null || true
ok "Packages available for root Python"

# ════════════════════════════════════════════════════════════════════════════
# STEP 5 — DOCKER
# ════════════════════════════════════════════════════════════════════════════
step 5 "Installing Docker"

if command -v docker &>/dev/null; then
  ok "Docker already installed ($(docker --version | awk '{print $3}' | tr -d ','))"
else
  info "Installing Docker..."
  case "$PKG_MGR" in
    apt)
      install -m 0755 -d /etc/apt/keyrings
      curl -fsSL "https://download.docker.com/linux/${DISTRO}/gpg" \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      chmod a+r /etc/apt/keyrings/docker.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/${DISTRO} \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        | tee /etc/apt/sources.list.d/docker.list > /dev/null
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y \
        docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin ;;
    dnf)
      dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
      dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin ;;
    pacman) pacman -Sy --noconfirm docker docker-compose ;;
  esac
  ok "Docker installed"
fi

systemctl enable docker --now 2>/dev/null || true
usermod -aG docker "$REAL_USER" 2>/dev/null || true
docker compose version &>/dev/null && ok "Docker Compose ready" || warn "Docker Compose not found"

# ════════════════════════════════════════════════════════════════════════════
# STEP 6 — OLLAMA + AI MODEL
# ════════════════════════════════════════════════════════════════════════════
step 6 "Installing Ollama + Llama 3.1 AI Model (~4.9 GB)"

if ! command -v ollama &>/dev/null; then
  info "Installing Ollama..."
  curl -fsSL https://ollama.com/install.sh | sh
  ok "Ollama installed"
else
  ok "Ollama already installed"
fi

if ! pgrep -x ollama &>/dev/null; then
  info "Starting Ollama..."
  nohup ollama serve > /tmp/ollama-setup.log 2>&1 &
  sleep 5
fi

info "Waiting for Ollama API..."
for i in $(seq 1 30); do
  curl -sf http://localhost:11434/api/tags &>/dev/null && ok "Ollama ready" && break
  sleep 2
  [[ $i -eq 30 ]] && warn "Ollama slow to start — continuing anyway"
done

if ollama list 2>/dev/null | grep -q "llama3.1"; then
  ok "Llama 3.1 already downloaded"
else
  info "Pulling Llama 3.1 (may take 5–20 minutes)..."
  ollama pull llama3.1 && ok "Llama 3.1 downloaded"
fi

# ════════════════════════════════════════════════════════════════════════════
# STEP 7 — SYSTEM CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════
step 7 "System Configuration"

# Fix ownership
chown -R "$REAL_USER":"$REAL_USER" "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/start.sh" \
         "$INSTALL_DIR/stop.sh"  \
         "$INSTALL_DIR/netmind-launch.sh" 2>/dev/null || true

# IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null || \
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
ok "IP forwarding enabled"

# Disable WiFi power-save
WIFI_IFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | head -1)
[[ -n "$WIFI_IFACE" ]] && iw dev "$WIFI_IFACE" set power_save off 2>/dev/null && \
  ok "Wi-Fi power-save disabled on $WIFI_IFACE"

# Git safe directory
command -v git &>/dev/null && \
  sudo -u "$REAL_USER" git config --global --add safe.directory "$INSTALL_DIR" 2>/dev/null || true

# ════════════════════════════════════════════════════════════════════════════
# STEP 8 — INSTALL AS DESKTOP APPLICATION
# ════════════════════════════════════════════════════════════════════════════
step 8 "Installing Desktop Application (double-click to launch)"

# ── Icon ─────────────────────────────────────────────────────────────────────
info "Installing app icon..."
mkdir -p /usr/share/icons/hicolor/256x256/apps \
         /usr/share/icons/hicolor/512x512/apps
if [[ -f "$INSTALL_DIR/assets/netmind.png" ]]; then
  cp "$INSTALL_DIR/assets/netmind.png" /usr/share/icons/hicolor/256x256/apps/netmind.png
  cp "$INSTALL_DIR/assets/netmind.png" /usr/share/icons/hicolor/512x512/apps/netmind.png
  gtk-update-icon-cache -f -t /usr/share/icons/hicolor/ 2>/dev/null || true
  ok "Icon installed"
fi

# ── Launcher script ───────────────────────────────────────────────────────────
info "Installing launcher..."
cat > "$LAUNCHER_BIN" << LAUNCHER_EOF
#!/bin/bash
# NetMind launcher — runs as root via pkexec, no terminal needed
INSTALL_DIR="$INSTALL_DIR"
OBS_DIR="\$INSTALL_DIR/observability"
exec >> /tmp/netmind.log 2>&1
echo "=== NetMind launch \$(date) ==="

export DISPLAY="\${DISPLAY:-:0}"
export XAUTHORITY="\${XAUTHORITY:-$REAL_HOME/.Xauthority}"
export QT_X11_NO_MITSHM=1

# Make sure prometheus_client is importable
for sp in /home/*/.local/lib/python*/site-packages; do
  export PYTHONPATH="\$sp:\${PYTHONPATH}"
done

# Docker
docker info > /dev/null 2>&1 || {
  systemctl start docker 2>/dev/null || service docker start 2>/dev/null || true
  sleep 3
}

# Prometheus + Grafana
docker compose -f "\$OBS_DIR/docker-compose.yml" down --remove-orphans 2>/dev/null || true
docker compose -f "\$OBS_DIR/docker-compose.yml" up -d 2>/dev/null || true

# Wait for Grafana (non-blocking)
for i in \$(seq 1 15); do
  curl -sf http://localhost:3000 > /dev/null 2>&1 && break; sleep 1
done

# Ollama
curl -sf http://localhost:11434/api/tags > /dev/null 2>&1 || {
  su - $REAL_USER -c "nohup ollama serve > /tmp/ollama.log 2>&1 &" 2>/dev/null || true
  sleep 3
}

cd "\$INSTALL_DIR"
exec python3 -B "\$INSTALL_DIR/NetMindDesktop.py"
LAUNCHER_EOF
chmod +x "$LAUNCHER_BIN"
ok "Launcher installed at $LAUNCHER_BIN"

# ── Polkit policy ─────────────────────────────────────────────────────────────
info "Installing privilege policy..."
mkdir -p /usr/share/polkit-1/actions
cat > /usr/share/polkit-1/actions/com.netmind.app.policy << 'POLICY_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="com.netmind.app.launch">
    <description>Run NetMind AI Network Manager</description>
    <message>NetMind needs administrator access to monitor and manage network traffic.</message>
    <icon_name>netmind</icon_name>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/local/bin/netmind-launch</annotate>
    <annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate>
  </action>
</policyconfig>
POLICY_EOF
ok "Privilege policy installed"

# ── .desktop entry ────────────────────────────────────────────────────────────
info "Creating app menu entry..."
cat > /usr/share/applications/netmind.desktop << DESKTOP_EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=NetMind
GenericName=AI Network Manager
Comment=Intelligent bandwidth management and network monitoring powered by AI
Exec=pkexec /usr/local/bin/netmind-launch
Icon=netmind
Terminal=false
Categories=Network;System;Security;
Keywords=network;bandwidth;monitoring;ai;firewall;
StartupNotify=true
StartupWMClass=NetMindDesktop
DESKTOP_EOF
chmod 644 /usr/share/applications/netmind.desktop
update-desktop-database /usr/share/applications/ 2>/dev/null || true
ok "App entry created (visible in application menu)"

# ── Desktop shortcut ──────────────────────────────────────────────────────────
USER_DESKTOP="$REAL_HOME/Desktop"
if [[ -d "$USER_DESKTOP" ]]; then
  cp /usr/share/applications/netmind.desktop "$USER_DESKTOP/NetMind.desktop"
  chmod +x "$USER_DESKTOP/NetMind.desktop"
  chown "$REAL_USER":"$REAL_USER" "$USER_DESKTOP/NetMind.desktop"
  ok "Desktop shortcut created at ~/Desktop/NetMind.desktop"
fi

# ════════════════════════════════════════════════════════════════════════════
# STEP 9 — HEALTH CHECK
# ════════════════════════════════════════════════════════════════════════════
step 9 "Final Health Check"

PASS=0; FAIL=0
check() {
  if eval "$2" &>/dev/null; then ok "$1"; ((PASS++))
  else warn "FAILED: $1"; ((FAIL++))
  fi
}

check "Python 3.10+"         "python3 -c 'import sys; assert sys.version_info >= (3,10)'"
check "PyQt6"                "python3 -c 'from PyQt6.QtWidgets import QApplication'"
check "Scapy"                "python3 -c 'import scapy'"
check "prometheus-client"    "python3 -c 'import prometheus_client'"
check "Docker"               "docker --version"
check "Docker Compose"       "docker compose version"
check "Ollama reachable"     "curl -sf http://localhost:11434/api/tags"
check "Llama 3.1 model"      "ollama list | grep -q llama3.1"
check "NetMindDesktop.py"    "test -f '$INSTALL_DIR/NetMindDesktop.py'"
check "Launcher script"      "test -x '$LAUNCHER_BIN'"
check "Desktop shortcut"     "test -f '/usr/share/applications/netmind.desktop'"

echo ""
echo -e "  ${BOLD}Results: ${GREEN}$PASS passed${RESET}  ${RED}$FAIL failed${RESET}"

# ════════════════════════════════════════════════════════════════════════════
# DONE
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔═══════════════════════════════════════════════════════════╗"
echo "  ║                                                           ║"
echo "  ║   ✅  NetMind is installed and ready!                    ║"
echo "  ║                                                           ║"
echo "  ║   ▸ Double-click  NetMind  on your Desktop               ║"
echo "  ║   ▸ Or search  NetMind  in your application menu         ║"
echo "  ║                                                           ║"
echo "  ║   On first launch:                                        ║"
echo "  ║     1. Enter your password when prompted                  ║"
echo "  ║     2. Click  Initialize  to scan your network            ║"
echo "  ║     3. Click  ▶ Start  to begin monitoring                ║"
echo "  ║     4. Open http://localhost:3000 for Grafana charts      ║"
echo "  ║                                                           ║"
echo "  ╚═══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

[[ $FAIL -gt 0 ]] && echo -e "  ${YELLOW}⚠  $FAIL check(s) failed — see warnings above.${RESET}\n"

echo -e "  ${CYAN}Launch NetMind right now? [y/N]${RESET} \c"
read -r LAUNCH
if [[ "$LAUNCH" =~ ^[Yy]$ ]]; then
  info "Launching NetMind..."
  docker compose -f "$INSTALL_DIR/observability/docker-compose.yml" up -d 2>/dev/null || true
  sleep 2
  sudo -u "$REAL_USER" DISPLAY="${DISPLAY:-:0}" \
    XAUTHORITY="${XAUTHORITY:-$REAL_HOME/.Xauthority}" \
    python3 -B "$INSTALL_DIR/NetMindDesktop.py" &
  ok "NetMind launched!"
fi
