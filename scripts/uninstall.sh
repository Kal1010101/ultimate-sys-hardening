#!/bin/bash
# =============================================================================
#  ULTIMATE HARDENING — UNINSTALLER (free tier)
#
#  Removes the installed files. It does NOT undo hardening — and that
#  distinction matters more than it sounds: deleting the script also deletes
#  the only thing that can revert its changes. This script therefore offers
#  to revert BEFORE it removes anything.
# =============================================================================

set -euo pipefail

INSTALL_DIR="/opt/ultimate-hardening"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/hardening"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo "🛡️  Ultimate Hardening — Uninstall"
echo "=================================="
echo ""

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}❌ Run as root.${NC}" >&2
    exit 1
fi

# --- the important warning ---------------------------------------------------
echo -e "${YELLOW}⚠️  Uninstalling does NOT undo any hardening that was applied.${NC}"
echo ""
echo "   SSH config, firewall rules, sysctl values, file permissions and"
echo "   everything else stay exactly as they are."
echo ""
echo -e "${YELLOW}   Removing the script also removes your ability to run --revert.${NC}"
echo "   If you want the system back the way it was, revert first."
echo ""

backup_count=$(find /root -maxdepth 1 -type d -name 'hardening_backup_*' 2>/dev/null | wc -l)
if [[ "$backup_count" -gt 0 ]]; then
    echo -e "${CYAN}   Found $backup_count backup(s) under /root — a revert is possible.${NC}"
    echo ""
    read -r -p "Revert all hardening changes now, before uninstalling? (y/N): " do_revert
    if [[ "$do_revert" =~ ^[Yy]$ ]]; then
        if [[ -x "$INSTALL_DIR/src/free/ultimate_hardening.sh" ]]; then
            "$INSTALL_DIR/src/free/ultimate_hardening.sh" --revert || {
                echo -e "${RED}❌ Revert failed. Nothing has been uninstalled.${NC}" >&2
                echo -e "${YELLOW}   Resolve the revert first — uninstalling now would strip${NC}" >&2
                echo -e "${YELLOW}   your ability to retry it.${NC}" >&2
                exit 1
            }
            echo -e "${GREEN}✅ Revert complete.${NC}"
            echo ""
        else
            echo -e "${RED}❌ Cannot find the installed script to revert with.${NC}" >&2
            echo -e "${YELLOW}   Run --revert from a checkout before uninstalling.${NC}" >&2
            exit 1
        fi
    fi
else
    echo -e "${CYAN}   No backups found under /root — either nothing was applied,${NC}"
    echo -e "${CYAN}   or it ran with --skip-backup (in which case revert was never${NC}"
    echo -e "${CYAN}   available).${NC}"
    echo ""
fi

read -r -p "Proceed with uninstall? (y/N): " choice
if [[ ! "$choice" =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled."
    exit 0
fi

echo "🔗 Removing command..."
rm -f "$BIN_DIR/ultimate-harden"

echo "📁 Removing installation directory..."
rm -rf "$INSTALL_DIR"

if [[ -d "$CONFIG_DIR" ]]; then
    read -r -p "Remove configuration directory ($CONFIG_DIR)? (y/N): " rm_config
    if [[ "$rm_config" =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        echo -e "${GREEN}✅ Configuration removed${NC}"
    else
        echo -e "${CYAN}ℹ️  Configuration kept at $CONFIG_DIR${NC}"
    fi
fi

echo "🕐 Removing scheduled runs..."
crontab -l 2>/dev/null | grep -v "ultimate-hardening" | crontab - 2>/dev/null || true

echo ""
echo -e "${GREEN}✅ Uninstall complete${NC}"
echo ""
echo "Deliberately left in place:"
echo "  /root/hardening_backup_*            your backups"
echo "  /root/.ultimate_hardening_genesis   original pre-hardening copies"
echo "  /var/log/ultimate_hardening_*.log   run logs"
echo ""
echo "Those are kept so a revert is still possible from a fresh checkout."
echo "Delete them yourself once you are sure you will not need them."
