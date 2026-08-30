#!/bin/bash
# =============================================================================
#  ULTIMATE HARDENING — INSTALLER (free tier)
#
#  Installs the free tier to /opt/ultimate-hardening and puts an
#  `ultimate-harden` command on PATH.
#
#  This repository is the free tier only. Pro and Enterprise ship separately;
#  this installer does not reference them. It previously created symlinks to
#  src/pro/ and src/enterprise/, which produced two dead symlinks and a
#  closing message advertising commands that did not exist.
# =============================================================================

set -euo pipefail

INSTALL_DIR="/opt/ultimate-hardening"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/hardening"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

# Source lib/core.sh purely for UH_VERSION, so the banner cannot drift from
# the code again — this file once said "INSTALLER v2.0" while the site said
# v2.2.0 and the code said 2.1.0.
# shellcheck source=../lib/core.sh
source "$PROJECT_DIR/lib/core.sh" 2>/dev/null || true
UH_VERSION="${UH_VERSION:-unknown}"

# Banner box. The width is computed, not typed: the version line was written
# without a closing edge, so the box never closed, and any change to
# UH_VERSION would have shifted it anyway.
BANNER_W=63
banner_rule() { local r; printf -v r '%*s' "$BANNER_W" ''; printf '%s' "${r// /═}"; }
banner_line() {
    local t="$1" p
    p=$(( BANNER_W - ${#t} ))
    if (( p < 0 )); then p=0; fi
    printf '║%s%*s║\n' "$t" "$p" ''
}

echo -e "$CYAN"
printf '╔%s╗\n' "$(banner_rule)"
banner_line ""
banner_line "                    ULTIMATE HARDENING"
banner_line "                    Installer — v${UH_VERSION}"
banner_line ""
printf '╚%s╝\n' "$(banner_rule)"
echo -e "$NC"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}❌ This installer must be run as root.${NC}" >&2
    echo -e "${CYAN}Try: sudo $0${NC}" >&2
    exit 1
fi

# --- sanity: refuse to produce a broken install ------------------------------
# lib/ is not optional. The tier script resolves it relative to its own
# location and exits if it cannot be found, so an install missing lib/ leaves
# a command on PATH that fails on every invocation. This installer used to do
# exactly that — it copied src/ and never copied lib/.
for required in lib/core.sh lib/platform.sh lib/modules.sh lib/cis.sh \
                lib/menu.sh lib/update.sh src/free/ultimate_hardening.sh; do
    if [[ ! -f "$PROJECT_DIR/$required" ]]; then
        echo -e "${RED}❌ Missing $required — this is not a complete checkout.${NC}" >&2
        echo -e "${YELLOW}   Nothing was installed.${NC}" >&2
        exit 1
    fi
done

echo -e "${BLUE}📁 Creating directories...${NC}"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"

echo -e "${BLUE}📦 Copying source...${NC}"
cp -r "$PROJECT_DIR/lib"  "$INSTALL_DIR/"      # required — see the check above
cp -r "$PROJECT_DIR/src"  "$INSTALL_DIR/"
cp -r "$PROJECT_DIR/docs" "$INSTALL_DIR/" 2>/dev/null || true
cp -r "$PROJECT_DIR/examples" "$INSTALL_DIR/" 2>/dev/null || true
cp "$PROJECT_DIR/README.md" "$INSTALL_DIR/"
cp "$PROJECT_DIR/LICENSE"   "$INSTALL_DIR/"

echo -e "${BLUE}🔗 Creating symlink...${NC}"
ln -sf "$INSTALL_DIR/src/free/ultimate_hardening.sh" "$BIN_DIR/ultimate-harden"

chmod +x "$INSTALL_DIR/src/free/ultimate_hardening.sh"
chmod +x "$INSTALL_DIR/lib/"*.sh 2>/dev/null || true
chmod 755 "$INSTALL_DIR"

# --- verify the install actually works before claiming success ---------------
echo -e "${BLUE}🧪 Verifying...${NC}"
if ! "$BIN_DIR/ultimate-harden" --version >/dev/null 2>&1; then
    echo -e "${RED}❌ Installed, but 'ultimate-harden --version' failed.${NC}" >&2
    echo -e "${YELLOW}   The install is present at $INSTALL_DIR but not working.${NC}" >&2
    echo -e "${YELLOW}   Run it directly to see the error:${NC}" >&2
    echo -e "${YELLOW}     $INSTALL_DIR/src/free/ultimate_hardening.sh --version${NC}" >&2
    exit 1
fi
installed_version="$("$BIN_DIR/ultimate-harden" --version 2>/dev/null)"

echo ""
echo -e "${GREEN}✅ Installation complete — ${installed_version}${NC}"
echo ""
echo -e "  ${WHITE}Command:${NC}"
echo "    ultimate-harden                       # interactive menu"
echo "    sudo ultimate-harden --dry-run --auto-mode   # preview, changes nothing"
echo ""
echo -e "  ${WHITE}Documentation:${NC}"
echo "    $INSTALL_DIR/README.md"
echo ""
echo -e "  ${WHITE}Logs:${NC}"
echo "    /var/log/ultimate_hardening_*.log"
echo ""
echo -e "  ${CYAN}Pro and Enterprise are separate products — see PRICING.md online.${NC}"
echo ""

read -r -p "Run a dry-run now to see what it would change? (y/N): " choice
if [[ "$choice" =~ ^[Yy]$ ]]; then
    echo -e "\n${BLUE}🧪 Dry run — nothing will be modified...${NC}\n"
    ultimate-harden --dry-run --auto-mode || \
        echo -e "${YELLOW}⚠️  Dry run reported an error — check the log.${NC}"
fi
