#!/bin/bash
# =============================================================================
#  lib/menu.sh — shared module table for all three tiers
#
#  Renders the 22 shared hardening modules as one consistent table:
#
#      1) System updates              (Safe)    [enable ]
#      2) SSH hardening               (Medium)  [disable]
#     17) Docker security             (Medium)  [  N/A  ]
#
#  [enable ] the module's settings are already in place on this host.
#  [disable] they are not, so running the module would change something.
#  [  N/A  ] the module cannot apply here at all — no Docker for the Docker
#            module, no GRUB for the GRUB password, a non-Linux platform for
#            a Linux-only module. Without this third state those rows would
#            sit at a permanent [disable] and read as broken rather than
#            irrelevant.
#
#  The tag reflects the CURRENT state of the system, not a remembered
#  selection — nothing is persisted between runs, or even between redraws.
#  Apply a module and its tag flips on the next redraw; revert it and the
#  tag flips back.
#
#  Where that state comes from: refresh_module_states() runs the real CIS
#  compliance checks in quiet mode (UH_QUIET_CHECKS) and maps each result
#  back to the module that owns it via cis_check_module() in lib/cis.sh.
#  A module reads [enable ] only when EVERY compliance check mapped to it
#  passes. That means a module's tag and its compliance-check row can never
#  disagree — they are the same data.
#
#  Modules with no compliance check of their own fall back to
#  module_probe_state() below — a direct look at the system, written to
#  mirror that module's own condition rather than approximate it. Adding
#  real CIS checks for them would change the published CIS score, so that is
#  deliberately left as a separate decision.
# =============================================================================

# Parallel arrays: module key -> label / risk / apply function.
# Order matches the numbered 1-22 menu everywhere else in the project.
MOD_KEYS=(updates ssh firewall fail2ban perms kernel audit password suid aide rkhunter services apparmor etckeeper boot grubpw docker modsec protocols compiler syslog umask)

declare -A MOD_LABEL=(
    [updates]="System updates"
    [ssh]="SSH hardening"
    [firewall]="Firewall"
    [fail2ban]="Fail2Ban"
    [perms]="File permissions"
    [kernel]="Kernel & network"
    [audit]="Audit daemon"
    [password]="Password policy"
    [suid]="SUID/SGID hardening"
    [aide]="AIDE file integrity"
    [rkhunter]="Rootkit scanner"
    [services]="Disable unused services"
    [apparmor]="AppArmor / SELinux"
    [etckeeper]="/etc version control"
    [boot]="Boot security"
    [grubpw]="GRUB password"
    [docker]="Docker security"
    [modsec]="ModSecurity WAF"
    [protocols]="Disable unused kernel modules"
    [compiler]="Compiler access restriction"
    [syslog]="Remote syslog"
    [umask]="UMASK hardening"
)

declare -A MOD_RISK=(
    [updates]=safe [ssh]=medium [firewall]=medium [fail2ban]=safe
    [perms]=safe [kernel]=safe [audit]=safe [password]=safe
    [suid]=high [aide]=safe [rkhunter]=safe [services]=safe
    [apparmor]=medium [etckeeper]=safe [boot]=safe
    [grubpw]=high [docker]=medium [modsec]=medium [protocols]=safe
    [compiler]=medium [syslog]=safe [umask]=safe
)

# Which file(s) a module's own apply_* function calls backup_file() on —
# the same paths, read straight out of lib/modules.sh, not re-derived. Used
# by revert_module() below to revert one module on its own, from the menu,
# without a full system revert. A module missing here has no automated
# per-module revert (see revert_module()'s own comment for exactly why,
# per module) — selecting it while [enable ] just explains that instead of
# guessing at something destructive or silently doing nothing.
declare -A MOD_REVERT_FILES=(
    # apply_ssh_hardening() also writes a same-named drop-in
    # (00-ultimate-hardening.conf, sorted to win sshd's first-value-wins
    # parsing over things like cloud-init's own 50-cloud-init.conf) —
    # skipped here at first, then found the hard way: reverting sshd_config
    # alone left the drop-in's settings in effect, so the "revert" changed
    # nothing sshd actually enforced. The drop-in never existed before this
    # tool wrote it, so revert_backed_up_file() correctly deletes it rather
    # than trying to restore a backup that was never taken.
    [ssh]="/etc/ssh/sshd_config /etc/ssh/sshd_config.d/00-ultimate-hardening.conf"
    [fail2ban]="/etc/fail2ban/jail.local"
    [kernel]="/etc/sysctl.d/99-hardening.conf"
    [audit]="/etc/audit/rules.d/99-hardening.rules"
    [password]="/etc/login.defs"
    [grubpw]="/etc/grub.d/40_custom"
    [docker]="/etc/docker/daemon.json"
    [protocols]="/etc/modprobe.d/disable-unused-protocols.conf /etc/modprobe.d/disable-unused-filesystems.conf"
    [syslog]="/etc/rsyslog.conf"
    [umask]="/etc/login.defs /etc/profile.d/hardening-umask.sh /etc/bash.bashrc"
)
# apparmor is split: the AppArmor branch enables a service and calls
# aa-enforce, with no single settings file to revert; the SELinux branch
# writes exactly one file. Handled as a special case in revert_module()
# rather than forced into the generic table above.

# Live state, filled by refresh_module_states(). Values: on | off | na
declare -A MOD_STATE=()

# ------------------------------------------------------------ applicability --
# Does this module do anything at all on THIS host? A module that cannot
# apply here renders [  N/A  ] rather than a permanent [disable], which
# would otherwise read as "broken" instead of "not relevant".
#
# v2.2.0 had this third state and the lib/ refactor dropped it along with
# the modules that need it most — Docker security on a host with no Docker,
# a GRUB password on a machine with no GRUB.
#
# Each condition mirrors the module's own early-return guard, so a module
# shown as N/A is exactly one that would log "skipping" and do nothing.
module_applicable() {
    local key="$1"
    case "$key" in
        kernel|apparmor|boot|protocols)
            is_linux && return 0 || return 1 ;;
        grubpw)
            is_linux && command -v grub-mkpasswd-pbkdf2 >/dev/null 2>&1 ;;
        docker)
            command -v docker >/dev/null 2>&1 ;;
        modsec)
            is_linux && { command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; } ;;
        syslog)
            [[ -f /etc/rsyslog.conf ]] ;;
        compiler)
            command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1 \
                || command -v cc >/dev/null 2>&1 ;;
        ssh)
            [[ -f /etc/ssh/sshd_config ]] ;;
        *)
            return 0 ;;
    esac
}

# --------------------------------------------------- module-derived probes --
# Each of these re-runs a module's OWN condition read-only, rather than
# approximating it, so the tag and what the module would actually do cannot
# disagree. They read the same UH_* arrays the modules themselves use.

# Module 12: the module stops any of UH_UNNEEDED_SERVICES that is active, so
# "nothing active" means "nothing for it to do". ~0.3s for the full list.
disabled_services_state() {
    local svc
    for svc in "${UH_UNNEEDED_SERVICES[@]}"; do
        if is_service_active "$svc"; then
            echo off
            return 0
        fi
    done
    echo on
}

# Module 9: the module strips SUID from every -perm -4000 file not in
# UH_SUID_SAFELIST, so "no such file remains" means "nothing to do". This is
# a full-filesystem walk — only called when UH_SUID_SCAN=1.
suid_scan_state() {
    local bin s keep
    while IFS= read -r bin; do
        keep=false
        for s in "${UH_SUID_SAFELIST[@]}"; do
            [[ "$bin" == "$s" ]] && { keep=true; break; }
        done
        if [[ "$keep" == false ]]; then
            echo off
            return 0
        fi
    done < <(find / -xdev -perm -4000 -type f 2>/dev/null)
    echo on
}

# Module 1: anything pending against the CURRENT package index.
#
# Cached per process — the simulation costs ~1.4s on apt and the index cannot
# change mid-session unless module 1 itself runs, which clears the cache.
#
# The cache is FILLED by refresh_module_states(), never here: probes are
# invoked as `MOD_STATE[k]=$(module_probe_state k)`, and a command
# substitution runs in a subshell, so an assignment made in this function
# would be discarded the moment it returned. Read-only here by design.
UH_PENDING_CACHE=""
invalidate_pending_updates_cache() { UH_PENDING_CACHE=""; }

count_pending_updates_state() {
    # "unknown" (package manager with no cheap offline query) reads as
    # actionable rather than silently claiming the host is current.
    [[ "$UH_PENDING_CACHE" == "0" ]] && echo on || echo off
}

# ---------------------------------------------------------------- fallbacks --
# Direct probe for the modules no compliance check covers. Best effort only:
# an unreadable file or a missing command reads as off. Never fails.
module_probe_state() {
    local key="$1" val
    case "$key" in
        updates)
            # Counts upgrades pending against the package index AS IT STANDS.
            # Deliberately does NOT refresh the index first: that needs the
            # network and would stall every menu redraw. So this answers "is
            # there anything to install right now", not "is this host current
            # with upstream" — the module itself refreshes before upgrading.
            count_pending_updates_state ;;
        suid)
            # Exactly detectable — re-run the module's own selection logic
            # read-only and see whether any non-safe-list SUID binary is left.
            # But that is a full `find / -xdev`, measured at ~12s on a modest
            # root filesystem, and the module table redraws on every return to
            # the menu. Off by default for that reason alone; set UH_SUID_SCAN=1
            # to pay the cost and get a real answer.
            if [[ "${UH_SUID_SCAN:-0}" == "1" ]]; then
                suid_scan_state
            else
                echo off
            fi ;;
        aide)
            command -v aide >/dev/null 2>&1 \
                && { [[ -f /var/lib/aide/aide.db.gz ]] || [[ -f /var/lib/aide/aide.db ]]; } \
                && echo on || echo off ;;
        rkhunter)
            command -v rkhunter >/dev/null 2>&1 && [[ -f /etc/cron.daily/rkhunter ]] \
                && echo on || echo off ;;
        services)
            # Exactly the module's own condition, read-only: it stops any of
            # its 20 listed services that are currently active, so if none are
            # active there is nothing for it to do. ~0.3s for all 20.
            disabled_services_state ;;
        etckeeper)
            [[ -d /etc/.git ]] && echo on || echo off ;;
        boot)
            val=$(stat -c '%a' /boot/grub/grub.cfg 2>/dev/null || stat -c '%a' /boot/grub2/grub.cfg 2>/dev/null || true)
            if [[ -n "$val" ]]; then
                [[ "$val" == "600" ]] && echo on || echo off
            else
                # No grub.cfg on this host at all (Alpine's extlinux, and any
                # non-GRUB bootloader) — the mode check can never be satisfied,
                # so apply_boot_secure()'s only real effect here is the USB
                # blacklist. Fall back to that, or the tag can never flip to
                # [enable] and the revert this module has is unreachable from
                # the menu. Confirmed live on uh-alpine.
                [[ -f /etc/modprobe.d/99-hardening-usb.conf ]] && echo on || echo off
            fi ;;
        grubpw)
            grep -qE '^[[:space:]]*password_pbkdf2' /etc/grub.d/40_custom 2>/dev/null \
                && echo on || echo off ;;
        docker)
            grep -q '"userns-remap"' /etc/docker/daemon.json 2>/dev/null \
                && echo on || echo off ;;
        modsec)
            # Enabled if the module is loadable by the local web server.
            # Captured rather than piped into grep -q: under pipefail the
            # producer takes SIGPIPE when grep exits early and the pipeline
            # reports 141, turning a match into a miss.
            local _httpd_mods
            _httpd_mods=$(apache2ctl -M 2>/dev/null || true)
            [[ -n "$_httpd_mods" ]] || _httpd_mods=$(httpd -M 2>/dev/null || true)
            if grep -q security2 <<< "$_httpd_mods" \
               || [[ -f /etc/modsecurity/modsecurity.conf ]]; then
                echo on
            else
                echo off
            fi ;;
        protocols)
            [[ -f /etc/modprobe.d/disable-unused-protocols.conf ]] && echo on || echo off ;;
        compiler)
            # On if every compiler present is already root-only (mode 700).
            local any=0 loose=0 p
            for c in gcc g++ clang clang++ cc c++; do
                p=$(command -v "$c" 2>/dev/null) || continue
                [[ -n "$p" ]] || continue
                any=1
                [[ "$(stat -c '%a' "$p" 2>/dev/null)" == "700" ]] || loose=1
            done
            { [[ "$any" == 1 ]] && [[ "$loose" == 0 ]]; } && echo on || echo off ;;
        syslog)
            grep -q '# ultimate-hardening: remote syslog' /etc/rsyslog.conf 2>/dev/null \
                && echo on || echo off ;;
        umask)
            [[ -f /etc/profile.d/hardening-umask.sh ]] \
                && grep -qE '^[[:space:]]*UMASK[[:space:]]+027' /etc/login.defs 2>/dev/null \
                && echo on || echo off ;;
        *)
            echo off ;;
    esac
}

# ------------------------------------------------------------------- state --
# Re-derive every module's state from the compliance checks. Call this before
# each menu redraw so the table reflects what just happened.
refresh_module_states() {
    local key
    for key in "${MOD_KEYS[@]}"; do MOD_STATE["$key"]=off; done

    # Quiet run: populates CHECK_RESULTS without printing or logging.
    UH_QUIET_CHECKS=true run_cis_checks >/dev/null 2>&1 || true

    # A module is [enable ] only if every check mapped to it passed.
    local -A covered=() failed=()
    local result label rest passed mod
    for result in "${CHECK_RESULTS[@]}"; do
        label="${result%%|*}"
        rest="${result#*|}"
        passed="${rest%%|*}"
        mod=$(cis_check_module "$label")
        [[ -z "$mod" ]] && continue
        covered["$mod"]=1
        [[ "$passed" == "true" ]] || failed["$mod"]=1
    done

    for mod in "${!covered[@]}"; do
        if [[ -n "${failed[$mod]:-}" ]]; then
            MOD_STATE["$mod"]=off
        else
            MOD_STATE["$mod"]=on
        fi
    done

    # Fill the pending-updates cache here, in this shell — the probe loop
    # below runs each probe in a command substitution, so a cache written
    # inside one would be lost with its subshell.
    [[ -z "$UH_PENDING_CACHE" ]] && UH_PENDING_CACHE=$(count_pending_updates)

    # Modules no compliance check covers fall back to a direct probe.
    for key in "${MOD_KEYS[@]}"; do
        [[ -n "${covered[$key]:-}" ]] && continue
        MOD_STATE["$key"]=$(module_probe_state "$key")
    done

    # Applicability wins over any state above: a module that cannot run here
    # is N/A, not "not applied yet". Checked last so it overrides both the
    # compliance-derived and probe-derived values.
    for key in "${MOD_KEYS[@]}"; do
        module_applicable "$key" || MOD_STATE["$key"]=na
    done
}

# ----------------------------------------------------------------- display --
# Both tags are padded to a fixed visible width so columns line up no matter
# which value each row takes. Colour codes are added after padding, never
# counted in it — printf's %-Ns would otherwise count the escape bytes.
_risk_tag() {
    case "$1" in
        safe)   printf '%b' "${GREEN}(Safe)  ${NC}" ;;
        medium) printf '%b' "${YELLOW}(Medium)${NC}" ;;
        high)   printf '%b' "${RED}(High)  ${NC}" ;;
    esac
}

_state_tag() {
    case "$1" in
        on) printf '%b' "${GREEN}[enable ]${NC}" ;;
        na) printf '%b' "${CYAN}[  N/A  ]${NC}" ;;
        *)  printf '%b' "${YELLOW}[disable]${NC}" ;;
    esac
}

# Visible width of one rendered row body:
#   "%2s" 2 + ") " 2 + label 32 + " " 1 + risk 8 + "  " 2 + state 9 = 56
# Both tags are fixed-width by construction, so a row is always exactly this
# many visible columns regardless of which risk or state it carries.
# -------------------------------------------------------------- box drawing --
# Fixed-width banner boxes, with the padding COMPUTED rather than typed into
# the string.
#
# Both header boxes used to be hand-padded, and both were wrong:
#
#   * the Platform line carried no closing edge at all, so the box never
#     closed on any system;
#   * the title line was padded on the assumption that the shield emoji
#     occupies two terminal columns. Plenty of fonts render it as one, which
#     left the right edge two columns short of the corners.
#
# The second is not fixable by re-counting. Terminals genuinely disagree
# about the width of that glyph, so a fixed-width box containing emoji is
# unalignable by construction. Decoration therefore stays outside the border,
# and everything variable inside it (UH_VERSION, DISTRO_TYPE) is padded at
# runtime.
UH_BOX_WIDTH=66

# Colour codes occupy no columns. Handles both the literal '\033[0;36m' form
# lib/core.sh defines and the expanded form left behind by an earlier echo -e.
box_strip() {
    printf '%s' "$1" | sed -e 's/\\033\[[0-9;]*m//g' -e $'s/\033\\[[0-9;]*m//g'
}

# Character count, independent of the locale.
#
# ${#s} counts CHARACTERS under a UTF-8 locale and BYTES under C/POSIX. A
# server with LC_ALL=C, a cron job, or a CI runner with no locale set therefore
# padded the header two columns short, because the em-dash in the title costs
# three bytes and one column. Counting continuation bytes (0x80-0xBF) and
# subtracting them gives the character count either way.
box_char_len() {
    local s="$1" bytes conts
    bytes=$(printf '%s' "$s" | wc -c)
    conts=$(printf '%s' "$s" | tr -dc '\200-\277' | wc -c)
    printf '%s' "$(( bytes - conts ))"
}

_box_rule() {
    local r
    printf -v r '%*s' "$UH_BOX_WIDTH" ''
    printf '%s' "${r// /═}"
}

box_top()    { echo -e "${CYAN}╔$(_box_rule)╗${NC}"; }
box_bottom() { echo -e "${CYAN}╚$(_box_rule)╝${NC}"; }

# box_line "<text>" — text may carry colour codes; they are not counted.
box_line() {
    local text="$1" plain pad
    plain=$(box_strip "$text")
    local plain_len; plain_len=$(box_char_len "$plain")
    if (( plain_len > UH_BOX_WIDTH )); then
        # Too long to fit. Drop the colours and truncate so the border still
        # closes — the Pro/Enterprise header interpolates $(hostname), which
        # on a long hostname ran straight through the right edge.
        plain="${plain:0:$((UH_BOX_WIDTH - 1))}…"
        text="$plain"
        plain_len=$(box_char_len "$plain")
    fi
    pad=$(( UH_BOX_WIDTH - plain_len ))
    # An `if`, not `(( pad < 0 )) && pad=0`: that compound returns 1 whenever
    # the condition is false, which under `set -e` ends the run.
    if (( pad < 0 )); then pad=0; fi
    echo -e "${CYAN}║${NC}${text}$(printf '%*s' "$pad" '')${CYAN}║${NC}"
}

MODULE_ROW_WIDTH=56

# A horizontal rule of $1 box-drawing characters (default: a snug box around
# one row plus two spaces of padding each side).
module_box_rule() {
    local n="${1:-$((MODULE_ROW_WIDTH + 4))}" i out=""
    for ((i = 0; i < n; i++)); do out+="─"; done
    printf '%s' "$out"
}

# Emit the 15 module rows.
#
# With no argument, rows are printed plain (Free tier). Pass a box's inner
# width to have each row wrapped in "│" borders and padded to fit — Pro and
# Enterprise use this to slot the table into their existing box layouts
# without either tier hardcoding column positions.
#
# Deliberately no emoji in these rows: terminals disagree on whether an
# emoji occupies one column or two, which is what made the old hardcoded
# box rows drift out of alignment.
render_module_list() {
    local inner="${1:-}"
    local i key body pad=""

    if [[ -n "$inner" ]]; then
        local n=$(( inner - MODULE_ROW_WIDTH - 2 ))
        (( n > 0 )) && printf -v pad '%*s' "$n" ''
    fi

    for i in "${!MOD_KEYS[@]}"; do
        key="${MOD_KEYS[$i]}"
        body=$(printf "%2s) %-32s %s  %s" \
            "$((i + 1))" "${MOD_LABEL[$key]}" \
            "$(_risk_tag "${MOD_RISK[$key]}")" \
            "$(_state_tag "${MOD_STATE[$key]:-off}")")
        if [[ -n "$inner" ]]; then
            echo -e "  ${WHITE}│${NC}  ${body}${pad}${WHITE}│${NC}"
        else
            echo -e "  ${body}"
        fi
    done
}

# One bordered, correctly-padded row for a tier's feature box:
#   menu_box_row 64 "A" "Auto-Fix All CIS Issues"
#
# Padding is computed from the row's real character count rather than
# hand-counted into a format string. The rows these replaced padded by eye
# assuming each emoji occupied two columns; terminals disagree about that,
# which is why those boxes rendered ragged.
menu_box_row() {
    local inner="$1" key="$2" label="$3"
    local body; body=$(printf "%3s) %s" "$key" "$label")
    local n=$(( inner - ${#body} - 2 )) pad=""
    (( n > 0 )) && printf -v pad '%*s' "$n" ''
    echo -e "  ${WHITE}│${NC}  ${body}${pad}${WHITE}│${NC}"
}

# =============================================================================
#  Revert submenu (the R) entry, shared by every tier)
# =============================================================================
# Full system revert, SUID/SGID-only, or revert to a specific dated backup —
# consolidated behind one menu entry so the top-level menu stays short.

revert_menu() {
    echo ""
    echo -e "  ${CYAN}Revert options${NC}"
    echo "    1) Full system revert (from backup) — restore everything to the original state"
    echo "    2) Revert SUID/SGID permissions only"
    echo "    3) Revert to a specific backup date"
    echo "    0) Back"
    local ans=""
    read -r -p "  Choice: " ans
    case "$ans" in
        1) confirm_risky "Revert ALL hardening to the original (genesis) state?" \
             && UH_REVERT_TARGET=genesis full_system_revert ;;
        2) confirm_risky "Restore all SUID/SGID bits to their originals?" \
             && undo_suid_hardening ;;
        3) revert_pick_date ;;
        0|"") return 0 ;;
        *) log_error "Invalid choice: '$ans'" ;;
    esac
    return 0
}

# List dated restore points (newest first, genesis last) and revert to the one
# chosen. Empties and cancels are no-ops.
revert_pick_date() {
    local -a paths=() labels=()
    local p l i
    while IFS=$'\t' read -r p l; do paths+=("$p"); labels+=("$l"); done < <(list_backup_points)
    if (( ${#paths[@]} == 0 )); then
        log_warning "No backups found to revert to."
        return 0
    fi
    echo ""
    echo -e "  ${CYAN}Restore points, newest first:${NC}"
    for i in "${!paths[@]}"; do printf '    %2d) %s\n' "$((i + 1))" "${labels[$i]}"; done
    echo "     0) Back"
    local ans=""
    read -r -p "  Revert to which? " ans
    [[ "$ans" =~ ^[0-9]+$ ]] || return 0
    (( ans >= 1 && ans <= ${#paths[@]} )) || return 0
    local chosen="${paths[$((ans - 1))]}"
    confirm_risky "Revert to: ${labels[$((ans - 1))]}?" \
        && UH_REVERT_TARGET="$chosen" full_system_revert
    return 0
}

# ------------------------------------------------------------ per-module revert --
# Revert ONE module on its own, from the menu — the counterpart to
# run_module()/apply_* that never existed until now. This file's own header
# comment already promised it ("revert it and the tag flips back"), but
# every menu choice called apply_* unconditionally regardless of the tag
# shown next to it; see dispatch_module_choice() below for where that
# actually gets wired up.
#
# Not every module is covered — some have no automated revert on purpose,
# not by oversight. A module backing a single config file via backup_file()
# (see MOD_REVERT_FILES above) reverts cleanly; suid/compiler use their own
# permission-mode inventories instead of a file copy; everything else either
# has no recorded original state to go back to, or (services) is documented
# as a deliberate manual step (SECURITY.md: re-enabling a service should be
# a conscious act, not automatic).
revert_module() {
    local key="$1"
    local label="${MOD_LABEL[$key]:-$key}"

    case "$key" in
        suid)
            confirm_risky "Revert ${label} — restore original SUID/SGID bits?" || { log_info "Revert cancelled"; return 0; }
            undo_suid_hardening
            return 0
            ;;
        compiler)
            confirm "Revert ${label} — restore original compiler permissions?" || { log_info "Revert cancelled"; return 0; }
            undo_compiler_restriction
            return 0
            ;;
        apparmor)
            # Split module: SELinux writes one file and can be reverted the
            # normal way; AppArmor enables a service and calls aa-enforce,
            # with no single settings file to restore.
            if [[ -f /etc/selinux/config ]] && command -v sestatus >/dev/null 2>&1; then
                confirm "Revert ${label} — restore /etc/selinux/config?" || { log_info "Revert cancelled"; return 0; }
                if revert_backed_up_file /etc/selinux/config; then
                    log_info "SELinux mode change takes effect after reboot, same as applying it did."
                else
                    log_info "${label}: nothing reverted — this module doesn't appear to have been applied by the tool on this host (already compliant by default)"
                fi
            else
                log_warning "${label}: not automated — AppArmor enables a service and sets profiles to enforce rather than writing one config file, so there's nothing for a file-based revert to restore. Run 'aa-complain /etc/apparmor.d/*' by hand if you need to back off enforcement."
            fi
            return 0
            ;;
        firewall)
            confirm_risky "Revert ${label} — remove the default-deny ruleset entirely, leaving no active firewall?" || { log_info "Revert cancelled"; return 0; }
            revert_firewall
            return 0
            ;;
        services)
            # SECURITY.md documented this as permanently manual — the user
            # explicitly asked to override that and get a real revert. Kept
            # behind the same strongest confirmation tier as SUID/GRUB
            # (type "yes"), since re-enabling services this tool disabled
            # is exactly the kind of action that stance existed to slow down.
            confirm_risky "Revert ${label} — re-enable and start whatever this tool disabled? This overrides SECURITY.md's own documented manual-only stance." || { log_info "Revert cancelled"; return 0; }
            undo_disabled_services
            return 0
            ;;
        aide)
            # module_probe_state's own check for this module (above) is
            # `command -v aide && aide.db[.gz] exists` — package presence
            # AND a baseline database, nothing about the cron job. Matches
            # every other revert this session: the PACKAGE stays installed
            # (same precedent as fail2ban/docker/avahi — revert undoes
            # config/generated content, not the install itself), but the
            # generated baseline and the daily check that depends on it are
            # removed, which is what actually flips the compliance check.
            confirm "Revert ${label} — remove the AIDE baseline database and the daily cron check? (aide itself stays installed)" || { log_info "Revert cancelled"; return 0; }
            local removed=false
            for f in /var/lib/aide/aide.db /var/lib/aide/aide.db.gz /etc/cron.daily/aide-check; do
                [[ -f "$f" ]] && { rm -f "$f"; log_info "  removed: $f"; removed=true; }
            done
            if [[ "$removed" == true ]]; then
                log_success "${label} reverted — baseline database and daily check removed (re-running this module rebuilds the baseline from scratch, which takes several minutes)"
            else
                log_info "${label}: nothing reverted — no baseline database or cron check found (this module doesn't appear to have been applied by the tool on this host)"
            fi
            return 0
            ;;
        perms)
            confirm "Revert ${label} — restore original permissions on the files this module changed?" || { log_info "Revert cancelled"; return 0; }
            undo_permission_hardening
            return 0
            ;;
        boot)
            confirm "Revert ${label} — restore grub.cfg's original permissions and remove the USB-storage blacklist?" || { log_info "Revert cancelled"; return 0; }
            undo_boot_secure
            return 0
            ;;
        modsec)
            # Split by distro, same reasoning as apparmor above. On Debian,
            # apply_modsecurity() itself calls `a2enmod security2` — a real
            # enable/disable toggle Debian ships for exactly this purpose —
            # so `a2dismod` cleanly undoes our own action, package stays
            # installed. On RHEL, confirmed on a real guest (rpm -ql
            # mod_security): the LoadModule directive ships unconditionally
            # inside the package's own /etc/httpd/conf.modules.d/10-mod_
            # security.conf — apply_modsecurity() never edits that file, so
            # there is no action of OURS to undo without editing untouched
            # package content, the same "not really ours to revert" problem
            # as rkhunter's cron.daily below.
            if command -v apache2 >/dev/null 2>&1 && [[ -f /etc/apache2/mods-enabled/security2.load ]]; then
                confirm "Revert ${label} — disable the security2 Apache module? (the modsecurity-crs package stays installed)" || { log_info "Revert cancelled"; return 0; }
                if command -v a2dismod >/dev/null 2>&1; then
                    a2dismod security2 >>"$LOG_FILE" 2>&1
                    restart_service apache2 || log_warning "Could not restart apache2"
                    log_success "${label} reverted — security2 module disabled"
                else
                    log_warning "a2dismod not found — cannot disable cleanly, leaving as-is"
                fi
            else
                log_warning "${label}: not automated on ${DISTRO_TYPE} — mod_security's LoadModule directive ships enabled by default inside the package's own config (confirmed via rpm -ql on a real guest); this module never edits that file itself, so there's nothing our own change record could undo without touching package-owned content."
            fi
            return 0
            ;;
        updates|rkhunter|etckeeper)
            local why=""
            case "$key" in
                updates)   why="installed packages aren't meaningfully revertible — there's nothing to restore them to" ;;
                rkhunter)  why="its on/off tag reflects the package being installed and its own shipped /etc/cron.daily/rkhunter (confirmed via dpkg -L on a real guest), not anything this module records — there's no revert action that would flip it back without uninstalling the package" ;;
                etckeeper) why="deleting /etc/.git would destroy real accumulated commit history (23 real commits on a lab guest that had only run this tool a handful of times) and its own package-shipped apt hook (/etc/apt/apt.conf.d/05etckeeper, confirmed via dpkg -L) silently re-initialises it on the next apt operation anyway — not a real, stable revert" ;;
            esac
            log_warning "${label}: no automated per-module revert — ${why}"
            return 0
            ;;
    esac

    local files="${MOD_REVERT_FILES[$key]:-}"
    if [[ -z "$files" ]]; then
        log_warning "${label}: no automated per-module revert available"
        return 0
    fi

    if [[ "${MOD_RISK[$key]:-safe}" == high ]]; then
        confirm_risky "Revert ${label}?" || { log_info "Revert cancelled"; return 0; }
    else
        confirm "Revert ${label}?" || { log_info "Revert cancelled"; return 0; }
    fi

    local f reverted=0
    for f in $files; do
        revert_backed_up_file "$f" && bump reverted
    done

    # A module can show [enable ] purely because the host was already
    # compliant by default (Rocky ships SELinux enforcing out of the box,
    # for one) — never actually run by this tool, never backed up anything.
    # revert_backed_up_file() correctly leaves those files untouched rather
    # than guessing (see its own comment for the real incident this fixes:
    # it used to delete a live, in-use /etc/selinux/config on exactly this
    # host shape). Reflect that honestly instead of claiming a revert and
    # restarting services for a change that never happened.
    if (( reverted == 0 )); then
        log_info "${label}: nothing reverted — this module doesn't appear to have been applied by the tool on this host (already compliant by default)"
        return 0
    fi

    # Make the reverted config take effect immediately rather than leaving
    # it sitting on disk until the next reboot or manual restart — the same
    # idea full_system_revert() already applies at its own end for sshd/
    # auditd/sysctl, scoped here to just the one module being reverted.
    case "$key" in
        ssh)      restart_sshd || true ;;
        fail2ban) is_service_active fail2ban && { restart_service fail2ban || true; } ;;
        kernel)   is_linux && { sysctl --system >>"$LOG_FILE" 2>&1 || true; } ;;
        audit)    is_service_active auditd && { restart_service auditd || true; } ;;
        docker)   is_service_active docker && { restart_service docker || true; } ;;
        syslog)   is_service_active rsyslog && { restart_service rsyslog || true; } ;;
        grubpw)
            update-grub >>"$LOG_FILE" 2>&1 \
                || grub2-mkconfig -o /boot/grub2/grub.cfg >>"$LOG_FILE" 2>&1 \
                || log_warning "GRUB config regeneration failed — run update-grub manually"
            ;;
    esac

    log_success "${label} reverted (${reverted} file$( [[ $reverted -eq 1 ]] && echo "" || echo "s" ) restored)"
}

# Selecting an already-[enable]'d module reverts it; a [disable]d or
# [  N/A  ] one applies it, same as always. Called from each tier's own
# show_menu() case statement in place of a bare run_module call.
dispatch_module_choice() {
    local key="$1" apply_fn="$2"
    if [[ "${MOD_STATE[$key]:-off}" == "on" ]]; then
        revert_module "$key"
    else
        run_module "$key" "$apply_fn"
    fi
}
