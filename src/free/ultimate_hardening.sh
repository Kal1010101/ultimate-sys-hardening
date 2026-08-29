#!/bin/bash
# =============================================================================
#  ULTIMATE HARDENING — FREE
#
#  CIS-aligned Linux hardening with backup, dry-run, and full revert.
#
#  This is the open tier: MIT licensed, with no expiry and no feature clock —
#  nothing here is held back for a paywall. It's also an early-stage project:
#  the module set will keep growing, and the Pro/Enterprise tiers build
#  reporting and fleet tooling on top of this same engine. Issues and PRs
#  welcome.
#
#  Usage: sudo ./ultimate_hardening.sh [OPTIONS]
#
#  Every module is implemented once in lib/ and shared by all three tiers,
#  so a fix here reaches every tier at the same time.
# =============================================================================

set -euo pipefail

# ------------------------------------------------------------ locate the lib --
# Resolve symlinks before locating lib/. `ultimate-harden` on PATH is a
# symlink into the install directory, so an unresolved BASH_SOURCE makes every
# candidate below relative to /usr/local/bin and lib/ is never found — the
# installer produced a command that failed on every invocation.
SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [[ -L "$SCRIPT_SOURCE" ]]; do
    SCRIPT_LINK_DIR="$(cd -P -- "$(dirname -- "$SCRIPT_SOURCE")" && pwd)"
    SCRIPT_SOURCE="$(readlink -- "$SCRIPT_SOURCE")"
    [[ "$SCRIPT_SOURCE" != /* ]] && SCRIPT_SOURCE="$SCRIPT_LINK_DIR/$SCRIPT_SOURCE"
done
SCRIPT_DIR="$(cd -P -- "$(dirname -- "$SCRIPT_SOURCE")" && pwd)"
LIB_DIR=""
for candidate in \
    "$SCRIPT_DIR/../../lib" \
    "$SCRIPT_DIR/../lib" \
    "$SCRIPT_DIR/lib" \
    "/usr/local/share/ultimate-hardening/lib" \
    "/usr/share/ultimate-hardening/lib"
do
    if [[ -f "$candidate/core.sh" ]]; then
        LIB_DIR="$(cd -- "$candidate" && pwd)"
        break
    fi
done

if [[ -z "$LIB_DIR" ]]; then
    echo "ERROR: Could not locate lib/ (looked for lib/core.sh)." >&2
    echo "Run this script from inside a full checkout of the repository." >&2
    exit 1
fi

# shellcheck source=../../lib/core.sh
source "$LIB_DIR/core.sh"
# shellcheck source=../../lib/platform.sh
source "$LIB_DIR/platform.sh"
# shellcheck source=../../lib/modules.sh
source "$LIB_DIR/modules.sh"
# shellcheck source=../../lib/cis.sh
source "$LIB_DIR/cis.sh"
# shellcheck source=../../lib/menu.sh
source "$LIB_DIR/menu.sh"
# shellcheck source=../../lib/update.sh
source "$LIB_DIR/update.sh"

CIS_ONLY=false
REVERT_MODE=false
REVERT_SUID_ONLY=false
SAFE_ONLY=false

usage() {
    cat << EOF
Ultimate Hardening ${UH_VERSION} — Free tier

Usage: sudo $0 [OPTIONS]

  --auto-mode     Run without prompts (accepts every module)
  --safe-only     With --auto-mode, skip the High-risk modules (9, 16)
  --dry-run       Print every intended change, modify nothing
  --cis-only      Run read-only compliance checks, print score, exit
  --skip-backup   Skip backup creation (disables revert)
  --revert        Restore everything from the most recent backup
  --revert-suid   Restore only SUID/SGID permissions
  --check-update  Check GitHub for a newer release, then exit
  --version       Print version and exit
  --help          Show this help

Examples:
  sudo $0                          Interactive menu
  sudo $0 --auto-mode --dry-run    Preview a full run, change nothing
  sudo $0 --auto-mode              Apply all 22 modules
  sudo $0 --auto-mode --safe-only  Apply everything except the High-risk modules
  sudo $0 --cis-only               Score the system, change nothing
  sudo $0 --revert                 Undo the most recent run

Free is the complete hardening engine. Pro adds compliance reports, scheduled
runs, and email alerts; Enterprise adds a multi-host dashboard, remote deploy,
policy-as-code, drift detection, and OpenSCAP. See README.md.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --auto-mode)   AUTO_MODE=true ;;
        --safe-only)   SAFE_ONLY=true ;;
        --dry-run)     DRY_RUN=true ;;
        --skip-backup) SKIP_BACKUP=true ;;
        --cis-only)    CIS_ONLY=true; AUTO_MODE=true ;;
        --revert)      REVERT_MODE=true ;;
        --revert-suid) REVERT_SUID_ONLY=true ;;
        --check-update) check_for_updates; exit 0 ;;
        --version)     echo "Ultimate Hardening ${UH_VERSION} (Free)"; exit 0 ;;
        --help|-h)     usage; exit 0 ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}" >&2
            echo "Run '$0 --help' for usage." >&2
            exit 1
            ;;
    esac
    shift
done

show_menu() {
    # Re-derive every module's [enable ]/[disable] tag from the compliance
    # checks before drawing, so applying or reverting a module is reflected
    # the moment the menu comes back.
    refresh_module_states
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║       ${SHIELD} ULTIMATE HARDENING ${UH_VERSION} — FREE TIER ${SHIELD}                 ║${NC}"
    echo -e "${CYAN}║       Platform: ${WHITE}${DISTRO_TYPE}${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"

    if [[ "$DRY_RUN" == true ]]; then
        echo -e "\n  ${YELLOW}${WARNING} DRY RUN — nothing will be modified${NC}"
    fi
    echo ""
    echo -e "  ${WHITE}[enable ]${NC} already in place   ${WHITE}[disable]${NC} not applied yet   ${WHITE}[  N/A  ]${NC} not applicable here"
    echo ""
    render_module_list
    echo ""
    printf "  ${WHITE}%2s)${NC} %s\n"  23 "Apply all Safe/Medium modules (skip High risk)"
    printf "  ${WHITE}%2s)${NC} %s\n"  24 "Apply all 22 modules (includes High risk)"
    printf "  ${WHITE}%2s)${NC} %s\n"  C "Run compliance checks (read-only)"
    printf "  ${WHITE}%2s)${NC} %s\n"  U "Check for updates"
    printf "  ${WHITE}%2s)${NC} %s\n"  R "Revert everything from backup"
    printf "  ${WHITE}%2s)${NC} %s\n"  S "Revert SUID/SGID only"
    printf "  ${WHITE}%2s)${NC} %s\n"  Q "Quit"
    echo ""

    local choice
    read -r -p "$(echo -e "  ${WHITE}Choice:${NC} ")" choice

    case "$choice" in
        1)  apply_system_updates ;;
        2)  apply_ssh_hardening ;;
        3)  apply_firewall ;;
        4)  apply_fail2ban ;;
        5)  apply_permission_hardening ;;
        6)  apply_kernel_hardening ;;
        7)  apply_audit_config ;;
        8)  apply_password_policies ;;
        9)  apply_suid_hardening ;;
        10) apply_aide ;;
        11) apply_rkhunter ;;
        12) apply_disable_services ;;
        13) apply_apparmor ;;
        14) apply_etckeeper ;;
        15) apply_boot_secure ;;
        16) apply_grub_password ;;
        17) apply_docker_security ;;
        18) apply_modsecurity ;;
        19) apply_unused_protocols ;;
        20) apply_compiler_restriction ;;
        21) apply_remote_syslog ;;
        22) apply_umask_hardening ;;
        23) confirm "Apply all Safe/Medium modules (skip High risk)?" && apply_safe_modules ;;
        24) confirm "Apply all 22 modules, including the High-risk ones?" && apply_all_modules ;;
        C|c) run_cis_checks ;;
        U|u) check_for_updates ;;
        R|r) confirm_risky "Revert ALL hardening changes?" && full_system_revert ;;
        S|s) undo_suid_hardening ;;
        Q|q)
            log_info "Log file: $LOG_FILE"
            [[ -d "$BACKUP_DIR" ]] && echo -e "  ${CYAN}Backup: $BACKUP_DIR${NC}"
            exit 0
            ;;
        *)  log_error "Invalid choice: '$choice'" ;;
    esac

    echo ""
    read -r -p "  Press Enter to return to the menu..."
    show_menu
}

main() {
    check_root

    if [[ "$REVERT_MODE" == true ]];      then full_system_revert;  exit 0; fi
    if [[ "$REVERT_SUID_ONLY" == true ]]; then undo_suid_hardening; exit 0; fi

    show_distro_menu

    if [[ "$CIS_ONLY" == true ]]; then
        run_cis_checks
        exit 0
    fi

    if [[ "$AUTO_MODE" == true ]]; then
        if [[ "$SAFE_ONLY" == true ]]; then
            apply_safe_modules
        else
            apply_all_modules
        fi
        run_cis_checks
        exit 0
    fi

    # The update check is explicitly-invoked only (menu option U, or
    # --check-update) — never automatic. That's a documented trust claim
    # on the project site ("no telemetry, no network calls... the only
    # outbound request is the optional, explicitly-invoked update check"),
    # so it must never fire silently at startup.
    trap 'echo -e "\n${RED}Interrupted.${NC}"; exit 130' INT TERM
    show_menu
}

main "$@"
