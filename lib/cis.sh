#!/bin/bash
# =============================================================================
#  lib/cis.sh — CIS-aligned compliance checks and revert logic
#
#  run_cis_checks populates three globals that reporting consumes:
#    CHECKS_PASSED   integer
#    CHECKS_FAILED   integer
#    CHECK_RESULTS   array of "label|true|false|detail"
#    CIS_SCORE       integer percentage
#
#  Checks are strictly read-only. Nothing here modifies the system.
#
#  A failed check's "detail" text has a suggested fix appended by
#  _cis_remediation_hint() before it's ever stored, so the fix travels
#  everywhere the detail column already goes — the terminal summary and the
#  Pro/Enterprise HTML report table — without changing the CHECK_RESULTS
#  "label|passed|detail" format anything downstream already parses.
# =============================================================================

CHECKS_PASSED=0
CHECKS_FAILED=0
CIS_SCORE=0
declare -a CHECK_RESULTS=()

# Maps a check's label back to the hardening module that governs it.
# Echoes a module key (matching MOD_KEYS in lib/menu.sh) or "" when no
# module owns that check.
#
# This is the SINGLE source of truth for the label -> module relationship.
# Both the remediation hints below and the menu's [enable ]/[disable] state
# indicators read from it, so the fix a failed check suggests and the module
# the menu shows as needing attention can never disagree.
cis_check_module() {
    local label="$1"
    case "$label" in
        *"separate partition"*)   echo "" ;;   # not fixable by any module
        *"filesystems blacklisted"*|*"protocols blacklisted"*) echo "protocols" ;;
        *"sshd_config present"*)  echo "ssh" ;;
        *"SSH"*)                  echo "ssh" ;;
        *"auditd is running"*)    echo "audit" ;;
        *"fail2ban is running"*)  echo "fail2ban" ;;
        *"Firewall is active"*)   echo "firewall" ;;
        *"ASLR"*|*"IP forwarding"*|*"SYN cookies"*|*"Kernel log restricted"*|*"Kernel pointers"*|*"SUID core dumps"*)
                                  echo "kernel" ;;
        *"Password max age"*)     echo "password" ;;
        *"permissions are"*)      echo "perms" ;;
        *"Mandatory access control"*|*"AppArmor is enforcing"*|*"SELinux is enforcing"*)
                                  echo "apparmor" ;;
        *)                        echo "" ;;
    esac
}

# Module key -> "module N (Name)", for remediation text.
_cis_module_hint_text() {
    case "$1" in
        ssh)      echo "run module 2 (SSH hardening)" ;;
        firewall) echo "run module 3 (Firewall)" ;;
        fail2ban) echo "run module 4 (Fail2Ban)" ;;
        perms)    echo "run module 5 (File permissions)" ;;
        kernel)   echo "run module 6 (Kernel & network)" ;;
        audit)    echo "run module 7 (Audit daemon)" ;;
        password) echo "run module 8 (Password policy)" ;;
        apparmor) echo "run module 13 (AppArmor / SELinux)" ;;
        protocols) echo "run module 19 (Unused kernel modules)" ;;
        *)        echo "" ;;
    esac
}

# Best effort by design — a check that maps to no module, or whose failure
# genuinely isn't fixable by re-running one (like disk partitioning), just
# gets no suggestion appended.
_cis_remediation_hint() {
    local label="$1"
    case "$label" in
        *"separate partition"*)
            echo "Not automated — separate partitions are an OS-install-time decision, not something a running system can safely repartition"
            return 0 ;;
        *"sshd_config present"*)
            echo "Suggested fix: install/reinstall openssh-server, then run module 2 (SSH hardening)"
            return 0 ;;
    esac
    local mod; mod=$(cis_check_module "$label")
    [[ -z "$mod" ]] && { echo ""; return 0; }
    local text; text=$(_cis_module_hint_text "$mod")
    [[ -z "$text" ]] && { echo ""; return 0; }
    echo "Suggested fix: ${text}"
}

# When UH_QUIET_CHECKS is true, checks still populate CHECKS_PASSED /
# CHECKS_FAILED / CHECK_RESULTS / CIS_SCORE but print and log nothing. The
# interactive menu uses this to derive each module's [enable ]/[disable]
# state from real compliance data without spamming the screen or the log
# file on every redraw.
record_check() {
    local label="$1" passed="$2" detail="${3:-}"
    if [[ "$passed" != "true" ]]; then
        local hint; hint=$(_cis_remediation_hint "$label")
        [[ -n "$hint" ]] && detail="${detail} — ${hint}"
    fi
    CHECK_RESULTS+=("${label}|${passed}|${detail}")
    if [[ "$passed" == "true" ]]; then
        bump CHECKS_PASSED
        [[ "${UH_QUIET_CHECKS:-false}" == true ]] || log_success "  $label"
    else
        bump CHECKS_FAILED
        [[ "${UH_QUIET_CHECKS:-false}" == true ]] || log_warning "  $label — $detail"
    fi
}

run_cis_checks() {
    [[ "${UH_QUIET_CHECKS:-false}" == true ]] || log_cis "Running CIS-aligned compliance checks (read-only)"
    CHECKS_PASSED=0
    CHECKS_FAILED=0
    CHECK_RESULTS=()

    # -- Filesystem separation -------------------------------------------------
    # `mount | grep -q` is unsafe under `set -o pipefail`, which every tier
    # sets: grep -q exits on its first match, mount takes SIGPIPE on its next
    # write and exits 141, and pipefail reports 141 for the whole pipeline —
    # so a matched partition reads as unmounted. It only stays hidden while
    # mount's output fits the pipe buffer. Capture once, match against the
    # string. (Same failure class as the virsh checks in the KVM lab harness.)
    local _mounts; _mounts=$(mount 2>/dev/null || true)
    for part in /home /tmp /var /var/log /var/tmp; do
        if grep -qE "on ${part} " <<< "$_mounts"; then
            record_check "$part is a separate partition" "true"
        else
            record_check "$part is a separate partition" "false" "Not a separate mount point"
        fi
    done

    # -- SSH -------------------------------------------------------------------
    local cfg="/etc/ssh/sshd_config"
    if [[ -f "$cfg" ]]; then
        local ssh_expect=(
            "PermitRootLogin:no:SSH root login disabled"
            "PasswordAuthentication:no:SSH password authentication disabled"
            "X11Forwarding:no:SSH X11 forwarding disabled"
            "PermitEmptyPasswords:no:SSH empty passwords rejected"
            "MaxAuthTries:3:SSH MaxAuthTries is 3 or fewer"
        )
        for spec in "${ssh_expect[@]}"; do
            local key="${spec%%:*}"; local rest="${spec#*:}"
            local want="${rest%%:*}"; local label="${rest#*:}"
            local actual
            actual=$(grep -iE "^[[:space:]]*${key}[[:space:]]" "$cfg" 2>/dev/null | tail -1 | awk '{print $2}' || true)
            if [[ "${actual,,}" == "${want,,}" ]]; then
                record_check "$label" "true"
            else
                record_check "$label" "false" "${key} is '${actual:-unset}', expected '${want}'"
            fi
        done
    else
        record_check "sshd_config present" "false" "File not found"
    fi

    # -- Security services -----------------------------------------------------
    for svc in auditd fail2ban; do
        if is_service_active "$svc"; then
            record_check "$svc is running" "true"
        else
            record_check "$svc is running" "false" "Service not active"
        fi
    done

    # ufw's systemd unit is a oneshot that applies the ruleset and exits —
    # `systemctl is-active ufw` reports "inactive" even while the firewall it
    # configured is genuinely enforcing. `is_service_active` (systemctl-based)
    # is correct for the other backends, which run as long-lived daemons, so
    # only ufw needs its own command consulted instead. Found by a real
    # dry-run showing "No active firewall service detected" against a guest
    # whose `ufw status` said "Status: active" with the correct rules applied
    # a moment earlier in the same session.
    local ufw_active=false
    command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active' && ufw_active=true

    if is_service_active nftables || [[ "$ufw_active" == true ]] \
       || is_service_active firewalld || is_service_active pf; then
        record_check "Firewall is active" "true"
    else
        record_check "Firewall is active" "false" "No active firewall service detected"
    fi

    # -- Kernel parameters -----------------------------------------------------
    if is_linux; then
        local sysctl_expect=(
            "kernel.randomize_va_space:2:ASLR fully enabled"
            "net.ipv4.ip_forward:0:IP forwarding disabled"
            "net.ipv4.tcp_syncookies:1:TCP SYN cookies enabled"
            "kernel.dmesg_restrict:1:Kernel log restricted to root"
            "kernel.kptr_restrict:2:Kernel pointers hidden"
            "fs.suid_dumpable:0:SUID core dumps disabled"
        )
        for spec in "${sysctl_expect[@]}"; do
            local key="${spec%%:*}"; local rest="${spec#*:}"
            local want="${rest%%:*}"; local label="${rest#*:}"
            local actual; actual=$(sysctl -n "$key" 2>/dev/null || echo "unavailable")
            if [[ "$actual" == "$want" ]]; then
                record_check "$label" "true"
            else
                record_check "$label" "false" "${key}=${actual}, expected ${want}"
            fi
        done
    fi

    # -- Password aging --------------------------------------------------------
    if [[ -f /etc/login.defs ]]; then
        local maxdays
        maxdays=$(grep -E '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' | head -1 || true)
        if [[ -n "$maxdays" ]] && [[ "$maxdays" -le 90 ]] 2>/dev/null; then
            record_check "Password max age is 90 days or fewer" "true"
        else
            record_check "Password max age is 90 days or fewer" "false" "Currently ${maxdays:-unset}"
        fi
    fi

    # -- File permissions ------------------------------------------------------
    local perm_expect=("/etc/passwd:644" "/etc/shadow:640" "/etc/group:644" "/etc/gshadow:640")
    for spec in "${perm_expect[@]}"; do
        local file="${spec%:*}" want="${spec##*:}"
        [[ -f "$file" ]] || continue
        local actual; actual=$(stat -c "%a" "$file" 2>/dev/null || stat -f "%Lp" "$file" 2>/dev/null)
        if [[ -n "$actual" ]] && [[ "$actual" -le "$want" ]] 2>/dev/null; then
            record_check "$file permissions are $want or stricter" "true"
        else
            record_check "$file permissions are $want or stricter" "false" "Currently $actual"
        fi
    done

    # -- Mandatory access control ---------------------------------------------
    if command -v aa-status >/dev/null 2>&1 && aa-status --enforced >/dev/null 2>&1; then
        record_check "AppArmor is enforcing" "true"
    elif command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
        record_check "SELinux is enforcing" "true"
    else
        record_check "Mandatory access control is enforcing" "false" "Neither AppArmor nor SELinux in enforce mode"
    fi

    # -- Unloadable kernel modules (CIS 1.1.1.x filesystems, 3.2.x protocols) --
    # Checks the effective modprobe configuration rather than our own file, so
    # a host that blacklists these somewhere else still passes. squashfs is
    # excluded when snapd needs it, matching what module 19 will actually do.
    if is_linux && command -v modprobe >/dev/null 2>&1; then
        local _m _missing _set
        # The sets live in lib/modules.sh, which every tier sources first. Guarded
        # anyway so sourcing cis.sh on its own cannot trip `set -u`.
        for _set in "protocols:${UH_BLACKLIST_PROTOCOLS[*]:-}" "filesystems:${UH_BLACKLIST_FILESYSTEMS[*]:-}"; do
            [[ -n "${_set#*:}" ]] || continue
            _missing=""
            for _m in ${_set#*:}; do
                [[ "$_m" == "squashfs" ]] && declare -F _squashfs_required >/dev/null && _squashfs_required && continue
                modprobe --showconfig 2>/dev/null \
                    | grep -qE "^(blacklist|install)[[:space:]]+${_m}([[:space:]]|$)" \
                    || _missing+="${_m} "
            done
            if [[ -z "$_missing" ]]; then
                record_check "Uncommon ${_set%%:*} blacklisted" "true"
            else
                record_check "Uncommon ${_set%%:*} blacklisted" "false" "Loadable: ${_missing% }"
            fi
        done
    fi

    print_cis_score
}

# The score line and its rules. Split out of run_cis_checks so anything that
# populates CHECKS_PASSED/CHECKS_FAILED by another route — the site generator
# renders this section with demo results — prints the identical footer instead
# of a second copy of the arithmetic that could disagree with this one.
print_cis_score() {
    local total=$((CHECKS_PASSED + CHECKS_FAILED))
    CIS_SCORE=$(( total > 0 ? CHECKS_PASSED * 100 / total : 0 ))

    [[ "${UH_QUIET_CHECKS:-false}" == true ]] && return 0

    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}  CIS Score: ${CIS_SCORE}%  (${CHECKS_PASSED}/${total} checks passed)${NC}"
    if [[ $CHECKS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}  ${CHECK_MARK} All checks passed${NC}"
    else
        echo -e "${YELLOW}  ${WARNING} ${CHECKS_FAILED} check(s) need attention${NC}"
    fi
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
    return 0
}

# =============================================================================
#  REVERT
# =============================================================================

undo_suid_hardening() {
    log_message "${UNDO} Restoring SUID/SGID permissions"

    local inv="$SUID_BACKUP_FILE"
    if [[ ! -f "$inv" ]]; then
        inv=$(find /root -name 'suid_sgid_original_perms.txt' -type f 2>/dev/null | sort | tail -1)
        [[ -n "$inv" ]] || { log_error "No SUID inventory found — cannot revert"; return 1; }
        log_info "Using inventory: $inv"
        log_info "  └─ written by: $(describe_backup "$(dirname "$inv")")"
    fi
    [[ "$DRY_RUN" == true ]] && { log_dry "Would restore SUID bits from $inv"; return 0; }

    local restored=0
    while read -r file mode; do
        [[ -f "$file" ]] || continue
        chmod "$mode" "$file" 2>/dev/null && bump restored || \
            log_warning "  could not restore $file"
    done < "$inv"

    log_success "Restored SUID/SGID on $restored binaries"
}

# Same shape as undo_suid_hardening() just above — a mode inventory, not a
# file backup, so it needs its own revert rather than revert_backed_up_file()
# (lib/core.sh). Used by full_system_revert() (inline, historically) and now
# also by revert_module() (lib/menu.sh) for reverting module 20 on its own.
undo_compiler_restriction() {
    log_message "${UNDO} Restoring compiler permissions"

    local inv; inv=$(find /root -name 'compiler_original_perms.txt' -type f 2>/dev/null | sort | tail -1)
    [[ -n "$inv" ]] || { log_error "No compiler-permissions inventory found — cannot revert"; return 1; }
    [[ "$DRY_RUN" == true ]] && { log_dry "Would restore compiler permissions from $inv"; return 0; }

    local restored=0
    while read -r cpath cmode; do
        [[ -f "$cpath" ]] || continue
        chmod "$cmode" "$cpath" 2>/dev/null && { log_info "  restored compiler mode: $cpath ($cmode)"; bump restored; } || \
            log_warning "  could not restore $cpath"
    done < "$inv"

    log_success "Restored permissions on $restored compiler(s)"
}

# Same shape again — a mode inventory for the handful of files
# apply_permission_hardening() actually loosened (files already at or
# stricter than the target were never recorded, since there's nothing to
# undo for those). Also strips the limits.conf line that module appended;
# chown root:root and /tmp's 1777 mode are deliberately left alone, since
# those are baseline hygiene rather than anything worth un-hardening.
undo_permission_hardening() {
    log_message "${UNDO} Restoring file permissions"

    local inv; inv=$(find /root -name 'perm_original_modes.txt' -type f 2>/dev/null | sort | tail -1)
    if [[ -z "$inv" ]]; then
        log_info "No permission changes were recorded — every file this module touches was already at or stricter than its target, so there's nothing to revert."
        remove_line "* hard core 0" /etc/security/limits.conf
        return 0
    fi
    [[ "$DRY_RUN" == true ]] && { log_dry "Would restore file permissions from $inv"; return 0; }

    local restored=0
    while read -r fpath fmode; do
        [[ -f "$fpath" ]] || continue
        chmod "$fmode" "$fpath" 2>/dev/null && { log_info "  restored: $fpath ($fmode)"; bump restored; } || \
            log_warning "  could not restore $fpath"
    done < "$inv"

    remove_line "* hard core 0" /etc/security/limits.conf

    log_success "Restored permissions on $restored file(s)"
}

# Same mode-inventory shape a third time, for grub.cfg. Also removes the
# USB-storage modprobe blacklist apply_boot_secure() writes — that file is
# in UH_TOOL_CREATED_PATHS (lib/core.sh), so revert_backed_up_file() always
# deletes it outright rather than looking for a "before" version, since
# there never was one.
undo_boot_secure() {
    log_message "${UNDO} Restoring boot configuration"

    local inv; inv=$(find /root -name 'boot_original_perms.txt' -type f 2>/dev/null | sort | tail -1)
    if [[ -z "$inv" ]]; then
        log_info "No grub.cfg permission change was recorded — it was already at 600 or stricter, so there's nothing to revert there."
    elif [[ "$DRY_RUN" == true ]]; then
        log_dry "Would restore grub.cfg permissions from $inv"
    else
        local restored=0
        while read -r cfg cmode; do
            [[ -f "$cfg" ]] || continue
            chmod "$cmode" "$cfg" 2>/dev/null && { log_info "  restored: $cfg ($cmode)"; bump restored; } || \
                log_warning "  could not restore $cfg"
        done < "$inv"
        log_success "Restored permissions on $restored grub config(s)"
    fi

    revert_backed_up_file /etc/modprobe.d/99-hardening-usb.conf
}

# Re-enables and starts exactly the services THIS TOOL disabled (per the
# inventory apply_disable_services() now records), not a blind re-enable of
# everything in UH_UNNEEDED_SERVICES — most of that list is inactive by
# default on a normal host and was never touched by this run.
#
# SECURITY.md previously documented this as permanently manual ("re-
# enabling services on a hardened box should be a conscious act"). That
# stayed the DEFAULT posture: revert_module() gates this behind the
# strongest confirmation tier (confirm_risky, typing "yes"), the same as
# SUID and GRUB password — the user explicitly asked to override the
# no-auto-revert stance for a real revert, and this is that revert, not a
# silent one-click toggle. SECURITY.md's own wording was updated to match
# — the manual `systemctl enable --now` path documented there still works
# and still applies to hosts that predate this feature, or if the
# inventory is missing.
undo_disabled_services() {
    log_message "${UNDO} Re-enabling services this tool disabled"

    local inv; inv=$(find /root -name 'disabled_services.txt' -type f 2>/dev/null | sort | tail -1)
    if [[ -z "$inv" ]]; then
        log_error "No disabled-services inventory found — cannot revert. Re-enable manually: systemctl enable --now <service>"
        return 1
    fi
    [[ "$DRY_RUN" == true ]] && { log_dry "Would re-enable and start services listed in $inv"; return 0; }

    local restored=0 svc
    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        enable_service "$svc" >/dev/null 2>&1 && { log_info "  re-enabled: $svc"; bump restored; } || \
            log_warning "  could not re-enable $svc — it may no longer be installed"
    done < "$inv"

    log_success "Re-enabled $restored service(s)"
    return 0
}

full_system_revert() {
    log_message "${UNDO} Full system revert"

    # Choose a restore point. UH_REVERT_TARGET comes from --revert-to; with no
    # target and an interactive session, offer the chooser. A specific per-run
    # backup pins a point in time (genesis is NOT preferred over it); "genesis"
    # or no choice keeps the historical restore-to-true-original behaviour.
    local _target="${UH_REVERT_TARGET:-}"
    # Only prompt when there is a real terminal — a piped/scripted --revert (and
    # the test suite) falls through to the default, it never blocks on input.
    if [[ -z "$_target" && "$AUTO_MODE" != true && -t 0 ]]; then
        _target=$(choose_backup_point) || { log_info "Revert cancelled."; return 0; }
    fi
    local _pin_perrun=false
    if [[ -n "$_target" ]]; then
        local _resolved; _resolved=$(resolve_revert_target "$_target") || _resolved=""
        if [[ -z "$_resolved" ]]; then
            log_error "No backup matches '${_target}'. Run --list-backups to see the options."
            return 1
        fi
        if [[ "$_resolved" != "$BACKUP_GENESIS_DIR" ]]; then
            BACKUP_DIR="$_resolved"
            SUID_BACKUP_FILE="$BACKUP_DIR/suid_sgid_original_perms.txt"
            _pin_perrun=true
            log_info "Reverting to chosen restore point:"
            log_info "  $BACKUP_DIR  ($(describe_backup "$BACKUP_DIR"))"
        fi
    fi

    # Genesis holds the first-ever captured copy of every file any tier's
    # run has touched — the true pre-hardening state, even across a
    # Free -> Pro -> Enterprise upgrade path where each tier's own
    # per-run backup only captures "state right before that run" (which by
    # then already includes earlier tiers' changes). Prefer it.
    # A pinned per-run choice restores exactly that point in time, so genesis
    # (the true original) is deliberately not preferred over it.
    local have_genesis=false
    if [[ "$_pin_perrun" != true ]] && [[ -d "$BACKUP_GENESIS_DIR/files" ]]; then
        have_genesis=true
    fi

    if [[ ! -d "$BACKUP_DIR" ]]; then
        local found; found=$(find_latest_backup) || {
            if [[ "$have_genesis" == true ]]; then
                found=""  # no per-run dir needed — genesis alone is enough
            else
                log_error "No backup directory found under /root — cannot revert"
                return 1
            fi
        }
        if [[ -n "$found" ]]; then
            BACKUP_DIR="$found"
            SUID_BACKUP_FILE="$BACKUP_DIR/suid_sgid_original_perms.txt"
            log_info "Using per-run backup: $BACKUP_DIR"
            log_info "  └─ written by: $(describe_backup "$BACKUP_DIR")"
        fi
    fi

    if [[ "$have_genesis" == true ]]; then
        log_info "Using genesis backup (true pre-hardening state): $BACKUP_GENESIS_DIR"
        local seeded_by
        seeded_by=$(cut -d'|' -f2 "$BACKUP_GENESIS_DIR/genesis_manifest.txt" 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//')
        [[ -n "$seeded_by" ]] && log_info "  └─ originals captured by: ${seeded_by} (see $BACKUP_GENESIS_DIR/genesis_manifest.txt)"
    elif [[ "$_pin_perrun" == true ]]; then
        log_info "Restoring to the chosen point in time; the original (genesis) state is not used."
    else
        log_warning "No genesis backup found — this host was hardened before genesis tracking existed. Falling back to the most recent per-run backup, which may only restore to the state before the LAST run, not the system's original defaults."
    fi

    if [[ "$DRY_RUN" == true ]]; then
        if [[ "$have_genesis" == true ]]; then
            log_dry "Would restore everything from $BACKUP_GENESIS_DIR (falling back to $BACKUP_DIR for anything genesis doesn't have)"
        else
            log_dry "Would restore everything from $BACKUP_DIR"
        fi
        return 0
    fi

    # Restore every file captured under genesis first (true originals)...
    local restored=0
    if [[ "$have_genesis" == true ]]; then
        while IFS= read -r stored; do
            local target="${stored#$BACKUP_GENESIS_DIR/files}"
            cp -a "$stored" "$target" 2>/dev/null && { log_info "  restored (genesis): $target"; bump restored; } || \
                log_warning "  could not restore $target"
        done < <(find "$BACKUP_GENESIS_DIR/files" -type f 2>/dev/null)
    fi

    # ...then fall back to the latest per-run backup for anything genesis
    # doesn't have (only relevant on hosts that predate genesis tracking).
    if [[ -n "${BACKUP_DIR:-}" ]] && [[ -d "$BACKUP_DIR/files" ]]; then
        while IFS= read -r stored; do
            local target="${stored#$BACKUP_DIR/files}"
            [[ -f "$BACKUP_GENESIS_DIR/files$target" ]] && continue  # already restored above
            cp -a "$stored" "$target" 2>/dev/null && { log_info "  restored (per-run): $target"; bump restored; } || \
                log_warning "  could not restore $target"
        done < <(find "$BACKUP_DIR/files" -type f 2>/dev/null)
    fi

    # Remove files the hardening added rather than modified. Files that
    # existed before are restored from backup above; these are ones the tool
    # created, so there is nothing to restore them to.
    rm -f /etc/sysctl.d/99-hardening.conf 2>/dev/null || true
    rm -f /etc/audit/rules.d/99-hardening.rules 2>/dev/null || true
    rm -f /etc/modprobe.d/99-hardening-usb.conf 2>/dev/null || true
    rm -f /etc/modprobe.d/disable-unused-protocols.conf 2>/dev/null || true
    rm -f /etc/modprobe.d/disable-unused-filesystems.conf 2>/dev/null || true
    rm -f /etc/profile.d/hardening-umask.sh 2>/dev/null || true

    # Compilers chmod'd by module 20 — restore their recorded original modes.
    local cinv="$BACKUP_DIR/compiler_original_perms.txt"
    [[ -f "$BACKUP_GENESIS_DIR/files$cinv" ]] && cinv="$BACKUP_GENESIS_DIR/files$cinv"
    if [[ -f "$cinv" ]]; then
        while read -r cpath cmode; do
            [[ -f "$cpath" ]] || continue
            chmod "$cmode" "$cpath" 2>/dev/null && log_info "  restored compiler mode: $cpath ($cmode)" || true
        done < "$cinv"
    fi

    is_linux && { sysctl --system >>"$LOG_FILE" 2>&1 || true; }
    restart_sshd || true
    is_service_active auditd && restart_service auditd || true

    [[ -f "$SUID_BACKUP_FILE" ]] && undo_suid_hardening

    log_success "Reverted $restored files from $BACKUP_DIR"
    log_warning "Disabled services are NOT re-enabled automatically."
    log_info    "Re-enable any you need with: systemctl enable --now <service>"
}
