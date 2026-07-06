#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# NetMind — GUI Launcher (called by the .desktop file via pkexec)
# This script runs AS ROOT (via pkexec). It:
#   1. Starts Docker + Prometheus + Grafana
#   2. Installs any missing Python dependencies
#   3. Launches the NetMind PyQt6 desktop app
# ─────────────────────────────────────────────────────────────────────────────

# Resolve project directory (this script lives at /usr/local/bin/netmind-launch,
# so the project path is stored in the config file written by install-app.sh)
PROJECT_DIR="/home/mahdi/NetMind Project/NetMind"
OBS_DIR="$PROJECT_DIR/observability"
LOG_FILE="/tmp/netmind-launch.log"

# Export display so Qt can find the screen even when running as root via pkexec
export DISPLAY="${DISPLAY:-:0}"
export XAUTHORITY="${XAUTHORITY:-/home/mahdi/.Xauthority}"
export QT_X11_NO_MITSHM=1

# Redirect all output to log file (pkexec has no terminal)
exec > >(tee -a "$LOG_FILE") 2>&1
echo "=== NetMind Launch $(date) ==="

# ── Ensure prometheus-client is available for root ───────────────────────────
python3 -c "import prometheus_client" 2>/dev/null || {
    echo "[*] Installing prometheus-client..."
    pip3 install --break-system-packages prometheus-client --quiet 2>/dev/null || \
    pip3 install prometheus-client --quiet 2>/dev/null || true
}

# ── Start Docker if not running ───────────────────────────────────────────────
if ! docker info > /dev/null 2>&1; then
    echo "[*] Starting Docker daemon..."
    systemctl start docker 2>/dev/null || service docker start 2>/dev/null || true
    sleep 3
fi

# ── Start Prometheus + Grafana ────────────────────────────────────────────────
echo "[*] Starting observability stack..."
docker compose -f "$OBS_DIR/docker-compose.yml" down --remove-orphans 2>/dev/null || true
docker compose -f "$OBS_DIR/docker-compose.yml" up -d 2>/dev/null || true

# Wait briefly for Grafana
for i in $(seq 1 15); do
    curl -sf http://localhost:3000 > /dev/null 2>&1 && break
    sleep 1
done
echo "[*] Grafana ready at http://localhost:3000"

# ── Check Ollama ──────────────────────────────────────────────────────────────
if ! curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "[*] Starting Ollama..."
    su - mahdi -c "ollama serve" &
    sleep 3
fi

# ── Launch the desktop app ────────────────────────────────────────────────────
echo "[*] Launching NetMind..."
cd "$PROJECT_DIR"
exec python3 -B "$PROJECT_DIR/NetMindDesktop.py"
