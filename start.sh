#!/bin/bash
# NetMind — Start support services (Prometheus + Grafana)
# Ollama is assumed to be running natively on the host.
# Usage: sudo bash start.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "╔══════════════════════════════════════════╗"
echo "║      NetMind — Starting Services         ║"
echo "╚══════════════════════════════════════════╝"

# Check Ollama is reachable on host
echo "[1/3] Checking Ollama..."
if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo "  ✅ Ollama running on localhost:11434"
else
    echo "  ⚠️  Ollama not detected. Starting it..."
    ollama serve &
    sleep 3
    echo "  ✅ Ollama started"
fi

echo "[2/3] Starting Prometheus + Grafana..."
docker compose up -d

echo "[3/3] Waiting for Grafana..."
for i in $(seq 1 15); do
    curl -sf http://localhost:3000 >/dev/null 2>&1 && break
    sleep 2
done

echo ""
echo "✅ Services ready:"
echo "  🤖 Ollama (Llama 3.2): http://localhost:11434  (native)"
echo "  📊 Grafana:            http://localhost:3000   (admin/admin)"
echo "  📈 Prometheus:         http://localhost:9091"
echo ""
echo "Launching NetMind desktop app..."
sudo python3 -B "$SCRIPT_DIR/NetMindDesktop.py"

# Cleanup on exit
echo "[NetMind] Cleaning __pycache__..."
find "$SCRIPT_DIR" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find "$SCRIPT_DIR" -name "*.pyc" -delete 2>/dev/null || true
echo "Done."
