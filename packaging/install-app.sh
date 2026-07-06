#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# NetMind — One-Command Desktop App Installer
# Creates a double-clickable launcher with icon and app menu entry
# Usage:  sudo bash packaging/install-app.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}  ✔ $*${RESET}"; }
info() { echo -e "${CYAN}  ▸ $*${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${RESET}"; }
err()  { echo -e "${RED}  ✘ $*${RESET}"; exit 1; }

[[ $EUID -ne 0 ]] && err "Please run with sudo:  sudo bash packaging/install-app.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(eval echo ~$REAL_USER)"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║     NetMind — Installing Desktop Application    ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""

# ── 1. Install prometheus-client for root Python (fixes metrics) ──────────────
info "Installing Python dependencies for root..."
pip3 install --break-system-packages prometheus-client --quiet 2>/dev/null || \
pip3 install prometheus-client --quiet 2>/dev/null || true
ok "Python dependencies ready"

# ── 2. Install icon ───────────────────────────────────────────────────────────
info "Installing application icon..."
mkdir -p /usr/share/icons/hicolor/256x256/apps
cp "$PROJECT_DIR/assets/netmind.png" /usr/share/icons/hicolor/256x256/apps/netmind.png
gtk-update-icon-cache -f -t /usr/share/icons/hicolor/ 2>/dev/null || true
ok "Icon installed"

# ── 3. Create launcher at /usr/local/bin/netmind-launch ──────────────────────
info "Installing launcher script..."
cat > /usr/local/bin/netmind-launch << LAUNCHER
#!/bin/bash
# NetMind GUI Launcher (runs as root via pkexec)
PROJECT_DIR="$PROJECT_DIR"
OBS_DIR="\$PROJECT_DIR/observability"

# Forward display to root
export DISPLAY="\${DISPLAY:-:0}"
export XAUTHORITY="\${XAUTHORITY:-$REAL_HOME/.Xauthority}"
export QT_X11_NO_MITSHM=1

# Ensure prometheus-client is available
python3 -c "import prometheus_client" 2>/dev/null || \\
    pip3 install --break-system-packages prometheus-client --quiet 2>/dev/null || true

# Add user site-packages to path (fallback)
for sp in /home/*/.local/lib/python*/site-packages; do
    export PYTHONPATH="\$sp:\${PYTHONPATH}"
done

# Start Docker if not running
if ! docker info > /dev/null 2>&1; then
    systemctl start docker 2>/dev/null || service docker start 2>/dev/null || true
    sleep 3
fi

# Start Prometheus + Grafana
docker compose -f "\$OBS_DIR/docker-compose.yml" down --remove-orphans 2>/dev/null || true
docker compose -f "\$OBS_DIR/docker-compose.yml" up -d 2>/dev/null || true

# Wait for Grafana
for i in \$(seq 1 15); do
    curl -sf http://localhost:3000 > /dev/null 2>&1 && break
    sleep 1
done

# Start Ollama if not running
if ! curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
    su - $REAL_USER -c "ollama serve > /tmp/ollama.log 2>&1 &" 2>/dev/null || true
    sleep 3
fi

# Launch the app
cd "\$PROJECT_DIR"
exec python3 -B "\$PROJECT_DIR/NetMindDesktop.py"
LAUNCHER

chmod +x /usr/local/bin/netmind-launch
ok "Launcher installed at /usr/local/bin/netmind-launch"

# ── 4. Install polkit policy ──────────────────────────────────────────────────
info "Installing privilege policy..."
POLICY_DIR="/usr/share/polkit-1/actions"
mkdir -p "$POLICY_DIR"
cat > "$POLICY_DIR/com.netmind.app.policy" << 'POLICY'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="com.netmind.app.launch">
    <description>Run NetMind network manager</description>
    <message>NetMind requires administrator privileges to manage network traffic.</message>
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
POLICY
ok "Polkit policy installed"

# ── 5. Install .desktop entry ─────────────────────────────────────────────────
info "Installing desktop entry..."
cat > /usr/share/applications/netmind.desktop << DESKTOP
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
Keywords=network;bandwidth;monitoring;ai;firewall;arp;
StartupNotify=true
StartupWMClass=NetMindDesktop
DESKTOP

chmod 644 /usr/share/applications/netmind.desktop
update-desktop-database /usr/share/applications/ 2>/dev/null || true
ok "Desktop entry installed → visible in app menu"

# ── 6. Desktop shortcut ───────────────────────────────────────────────────────
USER_DESKTOP="$REAL_HOME/Desktop"
if [[ -d "$USER_DESKTOP" ]]; then
    info "Creating desktop shortcut..."
    cp /usr/share/applications/netmind.desktop "$USER_DESKTOP/NetMind.desktop"
    chmod +x "$USER_DESKTOP/NetMind.desktop"
    chown "$REAL_USER:$REAL_USER" "$USER_DESKTOP/NetMind.desktop"
    ok "Desktop shortcut created at ~/Desktop/NetMind.desktop"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  ✅ NetMind is now installed as a desktop application!${RESET}"
echo ""
echo "  To launch NetMind:"
echo "    • Double-click the  NetMind  icon on your desktop"
echo "    • Search  NetMind  in your application menu"
echo "    • Or run:  pkexec /usr/local/bin/netmind-launch"
echo ""
echo "  When launched, it will:"
echo "    1. Ask for your password (once per session)"
echo "    2. Start Prometheus + Grafana automatically"
echo "    3. Open the NetMind window"
echo ""
