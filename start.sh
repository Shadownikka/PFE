#!/bin/bash
# NetMind — Start services and launch the app
# Works whether run from the clone directory or from /opt/netmind
# Usage: sudo bash start.sh   (or just double-click the desktop icon instead)

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OBS_DIR="$SCRIPT_DIR/observability"
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(eval echo ~$REAL_USER)"

echo "╔══════════════════════════════════════════╗"
echo "║       NetMind — Starting Services        ║"
echo "╚══════════════════════════════════════════╝"

# Ollama
echo "[1/3] Checking Ollama..."
if curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
  echo "  ✔ Ollama running"
else
  echo "  ▸ Starting Ollama..."
  sudo -u "$REAL_USER" nohup ollama serve > /tmp/ollama.log 2>&1 &
  sleep 4
  echo "  ✔ Ollama started"
fi

# Prometheus + Grafana
echo "[2/3] Starting Prometheus + Grafana..."
docker compose -f "$OBS_DIR/docker-compose.yml" down --remove-orphans 2>/dev/null || true
docker compose -f "$OBS_DIR/docker-compose.yml" up -d

echo "[3/3] Waiting for Grafana..."
for i in $(seq 1 20); do
  curl -sf http://localhost:3000 > /dev/null 2>&1 && break
  sleep 2
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✔ Grafana:    http://localhost:3000   (admin/admin)"
echo "  ✔ Prometheus: http://localhost:9091"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Launching NetMind..."
python3 -B "$SCRIPT_DIR/NetMindDesktop.py"
