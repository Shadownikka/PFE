#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# NetMind — Release Packager
# Creates netmind-app.tar.gz ready to upload to GitHub Releases.
#
# Usage:  bash packaging/release.sh [version]
# Output: packaging/releases/netmind-app-v1.0.0.tar.gz
#          packaging/releases/netmind-app-latest.tar.gz  (always overwritten)
#
# After running this, upload BOTH files to a GitHub Release:
#   https://github.com/Shadownikka/PFE/releases/new
# ─────────────────────────────────────────────────────────────────────────────
set -e

GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}  ✔ $*${RESET}"; }
info() { echo -e "${CYAN}  ▸ $*${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RELEASE_DIR="$SCRIPT_DIR/releases"
VERSION="${1:-1.0.0}"
TARBALL="netmind-app-v${VERSION}.tar.gz"
LATEST="netmind-app-latest.tar.gz"

mkdir -p "$RELEASE_DIR"

echo ""
echo -e "${BOLD}${CYAN}━━━ NetMind Release Packager ━━━${RESET}"
echo -e "  Version : ${BOLD}v${VERSION}${RESET}"
echo -e "  Output  : ${BOLD}packaging/releases/${TARBALL}${RESET}"
echo ""

# Files and directories to include in the release tarball
# (everything the app needs to run — NOT the bootstrap files)
INCLUDE=(
  "NetMindDesktop.py"
  "netmind-launch.sh"
  "requirements.txt"
  "start.sh"
  "stop.sh"
  "core/"
  "assets/"
  "observability/"
)

info "Creating release archive..."

# Build tar from project root, including only app files
cd "$PROJECT_DIR"
tar -czf "$RELEASE_DIR/$TARBALL" \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='.git' \
  --exclude='.gitkeep' \
  --exclude='dist/' \
  --exclude='build/' \
  "${INCLUDE[@]}" 2>/dev/null

# Also write as "latest" (setup.sh downloads this URL)
cp "$RELEASE_DIR/$TARBALL" "$RELEASE_DIR/$LATEST"

SIZE=$(du -sh "$RELEASE_DIR/$TARBALL" | cut -f1)
ok "Archive created: packaging/releases/$TARBALL  ($SIZE)"
ok "Latest alias:    packaging/releases/$LATEST"

echo ""
echo -e "${BOLD}  Contents of the archive:${RESET}"
tar -tzf "$RELEASE_DIR/$TARBALL" | head -30
echo ""

echo -e "${BOLD}${CYAN}━━━ Next Steps ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo "  1. Push the bootstrap files to GitHub main branch:"
echo "     (setup.sh, README.md, LICENSE — NOT the app source)"
echo ""
echo "  2. Create a new GitHub Release:"
echo "     https://github.com/Shadownikka/PFE/releases/new"
echo "     Tag: v${VERSION}"
echo ""
echo "  3. Upload these files to the release:"
echo "     packaging/releases/$TARBALL"
echo "     packaging/releases/$LATEST"
echo ""
echo "  4. Users install with:"
echo "     git clone https://github.com/Shadownikka/PFE.git"
echo "     cd PFE"
echo "     sudo bash setup.sh"
echo ""
