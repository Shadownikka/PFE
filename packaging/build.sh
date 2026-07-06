#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# NetMind — Build Script
# Produces a standalone executable in dist/NetMind/NetMind
# Usage: bash packaging/build.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}  ✔ $*${RESET}"; }
info() { echo -e "${CYAN}  ▸ $*${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${RESET}"; }
err()  { echo -e "${RED}  ✘ $*${RESET}"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║        NetMind — Building Executable             ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""

cd "$PROJECT_DIR"

# ── 1. Check Python deps ──────────────────────────────────────────────────────
info "Checking build dependencies..."
python3 -c "import PyInstaller" 2>/dev/null || {
    warn "PyInstaller not found. Installing..."
    pip3 install --break-system-packages pyinstaller 2>/dev/null || \
    pip3 install pyinstaller
}
python3 -c "import PyQt6" 2>/dev/null || err "PyQt6 not installed. Run: pip3 install PyQt6"
python3 -c "import scapy"  2>/dev/null || err "scapy not installed. Run: pip3 install scapy"
ok "All build dependencies present"

# ── 2. Generate icon if missing ───────────────────────────────────────────────
if [[ ! -f "assets/netmind.png" ]]; then
    info "Generating application icon..."
    python3 - << 'PYEOF'
import sys
try:
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtGui import QPixmap, QPainter, QColor, QBrush, QPen, QFont, QLinearGradient, QRadialGradient
    from PyQt6.QtCore import Qt
    import os

    app = QApplication(sys.argv)
    size = 512
    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)
    p = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Background circle
    bg_grad = QRadialGradient(size//2, size//2, size//2)
    bg_grad.setColorAt(0, QColor("#0d1117"))
    bg_grad.setColorAt(1, QColor("#07090f"))
    p.setBrush(QBrush(bg_grad))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(10, 10, size-20, size-20)

    # "N" letter with gradient
    grad = QLinearGradient(0, 0, size, size)
    grad.setColorAt(0, QColor("#00d4ff"))
    grad.setColorAt(1, QColor("#7c3aed"))
    p.setBrush(QBrush(grad))
    p.setPen(Qt.PenStyle.NoPen)

    font = QFont("Arial", size//2, QFont.Weight.Black)
    p.setFont(font)
    p.setPen(QPen(QColor("#00d4ff")))
    p.drawText(px.rect(), Qt.AlignmentFlag.AlignCenter, "N")

    p.end()
    os.makedirs("assets", exist_ok=True)
    px.save("assets/netmind.png")
    print("Icon generated: assets/netmind.png")
except Exception as e:
    print(f"Icon gen skipped: {e}")
PYEOF
fi

# ── 3. Run PyInstaller ────────────────────────────────────────────────────────
info "Building with PyInstaller (this takes 1–3 minutes)..."
pyinstaller packaging/NetMind.spec --clean --noconfirm 2>&1 | \
  grep -E "^(INFO|WARNING|ERROR|Building|Appending|Checking|Copying|excluding)" || true
ok "Build complete"

# ── 4. Verify output ──────────────────────────────────────────────────────────
BINARY="dist/NetMind/NetMind"
if [[ -f "$BINARY" ]]; then
    SIZE=$(du -sh "dist/NetMind" | cut -f1)
    ok "Executable: $PROJECT_DIR/$BINARY ($SIZE total)"
else
    err "Build failed — executable not found at dist/NetMind/NetMind"
fi

# ── 5. Install as desktop app ─────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo "  Next: Install NetMind as a desktop app (double-click to launch)"
echo "  Run:  sudo bash packaging/install-app.sh"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

# ── 6. Quick run option ───────────────────────────────────────────────────────
echo "  Or test it right now:"
echo "  sudo dist/NetMind/NetMind"
echo ""
