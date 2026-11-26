#!/bin/bash
# =============================================================================
#  ULTIMATE HARDENING — FREE
#
#  CIS-aligned Linux hardening with backup, dry-run, and full revert.
#
#  This is the open tier: MIT licensed, with no expiry and no feature clock —
#  all 23 modules, the CIS checks, dry-run and full revert. It's also an
#  early-stage project: the module set will keep growing, and the
#  Pro/Enterprise tiers build reporting, fleet tooling and extra modules on
#  top of this same engine. Issues and PRs welcome.
#
#  Usage: sudo ./ultimate_hardening.sh [OPTIONS]
#
#  Every module is implemented once in lib/ and shared by all three tiers,
#  so a fix here reaches every tier at the same time.
# =============================================================================

set -euo pipefail

# ------------------------------------------------------------ bash 4 or newer --
# macOS ships bash 3.2 as /bin/bash and the shebang picks it, but lib/ needs
# bash 4+ (associative arrays): under 3.2 every run died at lib/menu.sh with
# "unbound variable". So under an older bash, restart under a newer one if the
# system has it (Homebrew's, or another on PATH; sudo's PATH usually lacks
# Homebrew, hence the fixed paths), else stop and say how to get one. Keep this
# block bash-3.2 compatible: ${1+"$@"} because "$@" trips set -u there when no
# options are given. UH_BASH_REEXEC stops a restart loop.
MIN_BASH_MAJOR=4
if (( BASH_VERSINFO[0] < MIN_BASH_MAJOR )); then
    if [[ -z "${UH_BASH_REEXEC:-}" ]]; then
        for newer_bash in /opt/homebrew/bin/bash /usr/local/bin/bash "$(command -v bash 2>/dev/null || true)"; do
            [[ -x "$newer_bash" ]] || continue
            "$newer_bash" -c "(( BASH_VERSINFO[0] >= $MIN_BASH_MAJOR ))" 2>/dev/null || continue
            # exec only returns if that bash could not start; then try the next one.
            # shellcheck disable=SC2093
            UH_BASH_REEXEC=1 exec "$newer_bash" "$0" ${1+"$@"}
        done
    fi
    echo "ERROR: Ultimate Hardening needs bash ${MIN_BASH_MAJOR} or newer; this is bash ${BASH_VERSION}." >&2
    echo "On macOS, install it with 'brew install bash', then run this command again." >&2
    exit 1
fi

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
AIDE_REFRESH=false
AIDE_FINGERPRINT=false
AIDE_VERIFY=""
VERIFY=false
SAFE_ONLY=false
REPORT_FORMAT=""
PROFILE_FLAG=""

usage() {
    cat << EOF
Ultimate Hardening ${UH_VERSION} — Free tier

Usage: sudo $0 [OPTIONS]

Everything needs root except --cis-only, --json, --sarif, --check-update,
--version and --help. Without root, the few checks that need it are reported
as "not checked" rather than failed.

  --profile <modern|cis>
                  Hardening profile. cis: CIS Benchmark defaults. modern: for
                  shared/multi-user servers (no forced password expiry, umask
                  007, compilers left out of "apply all"). Without it,
                  unattended runs use UH_PROFILE, else the profile last applied
                  on this host, else cis. Interactive runs ask first.
  --auto-mode     Run without prompts (accepts every module)
  --safe-only     With --auto-mode, skip the High-risk modules (9, 16)
  --dry-run       Print every intended change, modify nothing
  --cis-only      Run read-only compliance checks, print score, exit
  --json          Like --cis-only, but print the results as JSON on stdout
  --sarif         Like --cis-only, but print the results as SARIF 2.1.0 on stdout
                  (for code scanning). Other output goes to stderr.
  --skip-backup   Skip backup creation (disables revert)
  --revert        Restore everything from the most recent backup
  --revert-suid   Restore only SUID/SGID permissions
  --aide-refresh  Update the AIDE baseline, after showing the changes for approval
  --aide-fingerprint
                  Record the fingerprint of the current AIDE baseline
  --aide-verify <hash|file>
                  Check the AIDE baseline against a fingerprint kept elsewhere
  --verify        Check the host is still healthy: sshd running and listening,
                  no systemd unit failed since the last run, a firewall loaded
                  where one was before or module 3 ran. After --auto-mode it
                  runs once the modules finish. Changes nothing.
  --check-update  Check GitHub for a newer release and for security advisories
                  that affect this version, then exit
  --version       Print version and exit
  --help          Show this help

Examples:
  sudo $0                          Interactive menu
  sudo $0 --auto-mode --dry-run    Preview a full run, change nothing
  sudo $0 --auto-mode              Apply all 23 modules
  sudo $0 --auto-mode --safe-only  Apply everything except the High-risk modules
  sudo $0 --auto-mode --profile modern
                                   Apply all modules with the modern profile
  $0 --cis-only                    Score the system without root, change nothing
  sudo $0 --cis-only               The same, with the checks that need root
  sudo $0 --json > cis.json        The same checks, as JSON for scripts and CI
  sudo $0 --revert                 Undo the most recent run
  sudo $0 --auto-mode --verify     Apply, then check sshd, units and firewall

Exit status: 0 done; 10 done, but the kernel was upgraded and a reboot is
required (unattended runs never reboot); 20 the --verify health check found a
problem (it prints which).

This tier is the hardening engine. Pro adds compliance reports, scheduled
runs, and email alerts; Enterprise adds a multi-host dashboard, remote deploy,
policy-as-code, drift detection, and OpenSCAP. See README.md.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --auto-mode)   AUTO_MODE=true ;;
        --safe-only)   SAFE_ONLY=true ;;
        --profile)
            [[ -n "${2:-}" ]] || \
                { echo -e "${RED}--profile requires modern or cis${NC}" >&2; usage >&2; exit 1; }
            PROFILE_FLAG="$2"; shift ;;
        --profile=*)   PROFILE_FLAG="${1#--profile=}" ;;
        --dry-run)     DRY_RUN=true ;;
        --skip-backup) SKIP_BACKUP=true ;;
        --cis-only)    CIS_ONLY=true; AUTO_MODE=true ;;
        --json|--sarif)
            [[ -z "$REPORT_FORMAT" || "$REPORT_FORMAT" == "${1#--}" ]] || \
                { echo -e "${RED}--json and --sarif cannot be used together${NC}" >&2; exit 1; }
            REPORT_FORMAT="${1#--}"; CIS_ONLY=true; AUTO_MODE=true ;;
        --revert)      REVERT_MODE=true ;;
        --revert-suid) REVERT_SUID_ONLY=true ;;
        --aide-refresh) AIDE_REFRESH=true ;;
        --aide-fingerprint) AIDE_FINGERPRINT=true ;;
        --aide-verify)
            [[ -n "${2:-}" ]] || \
                { echo -e "${RED}--aide-verify requires a fingerprint or a fingerprint file${NC}" >&2; exit 1; }
            AIDE_VERIFY="$2"; shift ;;
        --verify)      VERIFY=true ;;
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

if ! resolve_profile "$PROFILE_FLAG"; then
    echo "Run '$0 --help' for usage." >&2
    exit 1
fi

# --verify without --auto-mode only checks. It still needs the platform
# detected without the interactive distro menu.
VERIFY_ONLY=false
if [[ "$VERIFY" == true && "$AUTO_MODE" != true ]]; then
    VERIFY_ONLY=true
    UH_AUTODETECT_PLATFORM=true
fi

# A report goes to stdout alone: everything else the run prints (platform
# detection, warnings) moves to stderr, and the report is written to fd 3.
if [[ -n "$REPORT_FORMAT" ]]; then
    exec 3>&1 1>&2
fi

show_menu() {
    # Re-derive every module's [enable ]/[disable] tag from the compliance
    # checks before drawing, so applying or reverting a module is reflected
    # the moment the menu comes back.
    refresh_module_states
    clear 2>/dev/null || true
    # The header box is drawn by box_line() in lib/menu.sh, which computes the
    # padding. It was hand-padded, and both inner lines were wrong: the
    # Platform line had no closing edge at all, and the title line assumed the
    # shield emoji was two columns wide when many fonts render it as one. The
    # shields are gone from the header for that reason: no amount of
    # re-counting makes an emoji-bearing fixed-width box align on every
    # terminal, so the border holds text only.
    box_top
    box_line "${CYAN}       ULTIMATE HARDENING ${UH_VERSION} — FREE TIER${NC}"
    box_line "${CYAN}       Platform: ${WHITE}${DISTRO_TYPE}${CYAN}   Profile: ${WHITE}$(active_profile)${NC}"
    box_bottom

    if [[ "$DRY_RUN" == true ]]; then
        echo -e "\n  ${YELLOW}${WARNING} DRY RUN — nothing will be modified${NC}"
    fi
    echo ""
    echo -e "  ${WHITE}[enable ]${NC} already in place   ${WHITE}[disable]${NC} not applied yet   ${WHITE}[  N/A  ]${NC} not applicable here"
    echo -e "  ${WHITE}[cis    ]${NC} ${WHITE}[modern ]${NC} in place, applied with that profile"
    echo ""
    render_module_list
    echo ""
    printf "  ${WHITE}%2s)${NC} %s\n"  24 "Apply all Safe/Medium modules (skip High risk)"
    printf "  ${WHITE}%2s)${NC} %s\n"  25 "Apply all 23 modules (includes High risk)"
    printf "  ${WHITE}%2s)${NC} %s\n"  C "Run compliance checks (read-only)"
    printf "  ${WHITE}%2s)${NC} %s\n"  U "Check for updates"
    printf "  ${WHITE}%2s)${NC} %s\n"  R "Revert everything from backup"
    printf "  ${WHITE}%2s)${NC} %s\n"  S "Revert SUID/SGID only"
    printf "  ${WHITE}%2s)${NC} %s\n"  P "Back to profile selection"
    echo ""

    local choice
    read -r -p "$(echo -e "  ${WHITE}Choice:${NC} ")" choice

    case "$choice" in
        1)  dispatch_module_choice updates   apply_system_updates ;;
        2)  dispatch_module_choice ssh       apply_ssh_hardening ;;
        3)  dispatch_module_choice firewall  apply_firewall ;;
        4)  dispatch_module_choice fail2ban  apply_fail2ban ;;
        5)  dispatch_module_choice perms     apply_permission_hardening ;;
        6)  dispatch_module_choice kernel    apply_kernel_hardening ;;
        7)  dispatch_module_choice audit     apply_audit_config ;;
        8)  dispatch_module_choice password  apply_password_policies ;;
        9)  dispatch_module_choice suid      apply_suid_hardening ;;
        10) dispatch_module_choice aide      apply_aide ;;
        11) dispatch_module_choice rkhunter  apply_rkhunter ;;
        12) dispatch_module_choice services  apply_disable_services ;;
        13) dispatch_module_choice apparmor  apply_apparmor ;;
        14) dispatch_module_choice etckeeper apply_etckeeper ;;
        15) dispatch_module_choice boot      apply_boot_secure ;;
        16) dispatch_module_choice grubpw    apply_grub_password ;;
        17) dispatch_module_choice docker    apply_docker_security ;;
        18) dispatch_module_choice modsec    apply_modsecurity ;;
        19) dispatch_module_choice protocols apply_unused_protocols ;;
        20) dispatch_module_choice compiler  apply_compiler_restriction ;;
        21) dispatch_module_choice syslog    apply_remote_syslog ;;
        22) dispatch_module_choice umask     apply_umask_hardening ;;
        23) dispatch_module_choice basesys   apply_base_system ;;
        24) confirm "Apply all Safe/Medium modules (skip High risk)?" && apply_safe_modules ;;
        25) confirm "Apply all 23 modules, including the High-risk ones?" && apply_all_modules ;;
        C|c) run_cis_checks ;;
        U|u) check_for_updates ;;
        # Both return 1 when there is nothing to revert (they log why); under
        # set -e that ended the program instead of returning to this menu.
        R|r) confirm_risky "Revert ALL hardening changes?" && { full_system_revert || true; } ;;
        S|s) undo_suid_hardening || true ;;
        # Back to the profile screen; only Q there quits.
        P|p) return 0 ;;
        *)  log_error "Invalid choice: '$choice'" ;;
    esac

    echo ""
    read -r -p "  Press Enter to return to the menu..."
    show_menu
}

# --cis-only, --json and --sarif only read, so they run without root: a check
# that needs root reports "not checked" rather than failing. Anything else,
# including those combined with --revert or an --aide-* action, needs root.
needs_root() {
    [[ "$CIS_ONLY" == true ]] || return 0
    [[ "$REVERT_MODE" == true || "$REVERT_SUID_ONLY" == true || "$AIDE_REFRESH" == true \
       || "$AIDE_FINGERPRINT" == true || -n "$AIDE_VERIFY" ]] && return 0
    return 1
}

main() {
    if needs_root; then
        check_root
    fi
    check_base_tools

    if [[ "$REVERT_MODE" == true ]];      then full_system_revert;  exit 0; fi
    if [[ "$REVERT_SUID_ONLY" == true ]]; then undo_suid_hardening; exit 0; fi
    if [[ "$AIDE_REFRESH" == true ]];     then aide_refresh;        exit $?; fi
    if [[ "$AIDE_FINGERPRINT" == true ]]; then aide_fingerprint_current; exit $?; fi
    if [[ -n "$AIDE_VERIFY" ]];           then aide_verify "$AIDE_VERIFY"; exit $?; fi

    # Interactive runs open on the profile screen and reach the OS menu from
    # there (run_interactive); everything else detects the platform here.
    #
    # The update check is explicitly-invoked only (menu option U, or
    # --check-update) — never automatic. That's a documented trust claim
    # on the project site ("no telemetry, no network calls... the only
    # outbound traffic is the optional, explicitly-invoked update check"),
    # so it must never fire silently at startup.
    if [[ "$AUTO_MODE" != true && "$VERIFY_ONLY" != true ]]; then
        trap 'echo -e "\n${RED}Interrupted.${NC}"; exit 130' INT TERM
        run_interactive
    fi

    show_distro_menu

    if [[ "$CIS_ONLY" == true ]]; then
        if [[ -n "$REPORT_FORMAT" ]]; then
            print_cis_report "$REPORT_FORMAT" >&3
            exit $?
        fi
        run_cis_checks
        exit 0
    fi

    # --verify on its own checks and exits; it applies nothing.
    if [[ "$VERIFY" == true && "$VERIFY_ONLY" == true ]]; then
        verify_health && exit 0
        exit "$UH_EXIT_VERIFY_FAILED"
    fi

    refuse_changes_on_macos

    if [[ "$AUTO_MODE" == true ]]; then
        if [[ "$SAFE_ONLY" == true ]]; then
            apply_safe_modules
        else
            apply_all_modules
        fi
        run_cis_checks
        if [[ "$VERIFY" == true ]] && ! verify_health; then
            exit "$UH_EXIT_VERIFY_FAILED"
        fi
        exit "$(uh_exit_status)"
    fi
}

# Profile screen -> OS menu (first pass only) -> hardening menu, round and
# round (run_profile_loop in lib/menu.sh): P in the hardening menu comes back
# to the profile screen, Q there quits.
interactive_first_pass() {
    show_distro_menu
    refuse_changes_on_macos
}

run_interactive() {
    run_profile_loop show_menu interactive_first_pass
    log_info "Log file: $UH_LOG_PATH"
    [[ -d "$BACKUP_DIR" ]] && echo -e "  ${CYAN}Backup: $BACKUP_DIR${NC}"
    exit 0
}

main "$@"
