#!/bin/bash
# What modules turn on or change must be recorded before their first run so a
# revert can put it back:
#   - fail2ban, auditd, apparmor: running / started at boot (service record)
#   - module 4 writes its SSH jail to a file of its own, never jail.local
#   - module 6: the live sysctl values, which removing the drop-in never reset
#
# Every system tool is a stub; systemctl is trapped so the host's real one is
# never reached. Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_statebefore_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT

run() {
    env DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent \
        bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        S='$W/svc'
        DRY_RUN=false; SKIP_BACKUP=false; LOG_FILE='$W/run.log'
        UH_BACKUP_ROOT='$W/backups'; BACKUP_GENESIS_DIR='$W/backups/genesis'; BACKUP_DIR='$W/backups/hardening_backup_1'
        UH_FAIL2BAN_JAIL='$W/jail.d/99-ultimate-hardening.local'
        count_fix() { :; }
        is_service_active() { [[ -f \"\$S/\$1.active\" ]]; }
        is_service_enabled() { [[ -f \"\$S/\$1.enabled\" ]]; }
        stop_service_now() { echo \"STOP \$1\" >> '$W/calls'; rm -f \"\$S/\$1.active\"; }
        disable_service_at_boot() { echo \"DISABLE \$1\" >> '$W/calls'; rm -f \"\$S/\$1.enabled\"; }
        enable_service() { touch \"\$S/\$1.active\" \"\$S/\$1.enabled\"; }
        install_package() { touch \"\$S/\$1.active\"; }   # Debian starts what it installs
        systemctl() { echo FORBIDDEN >> '$W/calls'; return 1; }
        sysctl() {
            case \"\$1\" in
                -n) grep -m1 \"^\$2=\" '$W/sysctl' | cut -d= -f2 ;;
                -w) echo \"SET \$2\" >> '$W/calls'; local k=\${2%%=*}; grep -v \"^\$k=\" '$W/sysctl' > '$W/s.tmp'; echo \"\$2\" >> '$W/s.tmp'; mv '$W/s.tmp' '$W/sysctl' ;;
                --system) echo 'SYSCTL-SYSTEM' >> '$W/calls' ;;
            esac
        }
        $1" >"$W/out" 2>&1
}
reset() { rm -rf "$W/svc" "$W/backups" "$W/jail.d"; mkdir -p "$W/svc"; : > "$W/calls"; }

# --- a service that was off: back off after revert -----------------------------
reset
run 'apply_fail2ban; restore_service_state fail2ban'
assert_file_contains "$W/backups/genesis/service_state_before.txt" '^fail2ban\|no\|no$' "fail2ban is recorded as off BEFORE the install started it"
assert_output_contains "$(cat "$W/calls")" '^STOP fail2ban$' "revert stops fail2ban, which was not running before"
assert_output_contains "$(cat "$W/calls")" '^DISABLE fail2ban$' "and turns it off at boot"

# --- a service that was on: left on, record not overwritten --------------------
reset; touch "$W/svc/auditd.active" "$W/svc/auditd.enabled"
run 'record_service_state auditd; rm -f "$S/auditd.active"; record_service_state auditd; restore_service_state auditd'
[[ "$(grep -c '^auditd|' "$W/backups/genesis/service_state_before.txt")" == 1 ]] && pass_msg "the first record wins" || fail "auditd recorded twice"
if grep -qE '^(STOP|DISABLE) auditd$' "$W/calls"; then fail "revert turned off auditd, which was on before"; else pass_msg "a service that was on before is left on"; fi

# --- no record: left as it is ---------------------------------------------------
reset; touch "$W/svc/apparmor.active"
run 'restore_service_state apparmor'
[[ -s "$W/calls" ]] && fail "a service with no record was changed" || pass_msg "with no record, nothing is changed"

# --- module 4 leaves jail.local alone -------------------------------------------
reset
run apply_fail2ban
assert_file_contains "$W/jail.d/99-ultimate-hardening.local" '^\[sshd\]$' "the SSH jail goes into a file of its own"
assert_file_not_contains "$W/jail.d/99-ultimate-hardening.local" '^\[DEFAULT\]' "which does not override the admin's [DEFAULT]"
run 'declare -f apply_fail2ban'
if grep -q 'jail\.local' "$W/out"; then
    fail "apply_fail2ban still writes jail.local"
else
    pass_msg "apply_fail2ban never touches jail.local"
fi

# --- module 6: live sysctl values come back ------------------------------------
reset; printf 'net.ipv4.ip_forward=1\nkernel.sysrq=176\n' > "$W/sysctl"
run "_record_sysctl_before '$W/none.conf'; restore_sysctl_before"
assert_file_contains "$W/backups/genesis/sysctl_before.txt" '^net\.ipv4\.ip_forward=1$' "ip_forward's live value before hardening is recorded"
assert_output_contains "$(cat "$W/calls")" '^SET net\.ipv4\.ip_forward=1$' "revert sets it back"
assert_output_contains "$(cat "$W/calls")" '^SET kernel\.sysrq=176$' "and sysrq"
[[ "$(tail -1 "$W/calls")" == SYSCTL-SYSTEM ]] && pass_msg "then re-reads the config files, so the distro's own win" || fail "sysctl --system did not run last"
reset; touch "$W/old-drop-in.conf"
run "_record_sysctl_before '$W/old-drop-in.conf'"
assert_file_absent "$W/backups/genesis/sysctl_before.txt" "on a host already hardened with no record, hardened values are not recorded as the originals"

grep -q FORBIDDEN "$W/calls" && fail "the host's real systemctl was reached" || pass_msg "no real service manager was reached"
finish
