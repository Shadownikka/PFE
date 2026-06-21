#!/bin/bash
# NetMind — Stop all Docker services and clean __pycache__
# Usage: sudo bash stop.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OBS_DIR="$SCRIPT_DIR/observability"

echo "[1/2] Stopping Docker services..."
docker compose -f "$OBS_DIR/docker-compose.yml" down

echo "[2/2] Cleaning __pycache__ and .pyc files..."
find "$SCRIPT_DIR" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find "$SCRIPT_DIR" -name "*.pyc" -delete 2>/dev/null || true

echo "✅ Stopped and cleaned."
