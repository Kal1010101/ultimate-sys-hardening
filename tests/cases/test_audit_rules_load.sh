#!/bin/bash
# Module 7 must actually load its audit rules, and its revert must not leave
# them in the merged rules file that auditd loads at start.
#
# On Alpine, augenrules --load calls /sbin/auditctl by that path, which Alpine
# does not have (it is in /usr/sbin): the rules were written, never loaded, and
# the module still reported them as configured. Alpine's auditd loads
# /etc/audit/audit.rules at start and never rebuilds it, so after a revert that
# only removed rules.d/99-hardening.rules, the rules came back at every boot.
#
# auditctl and augenrules are stubs keeping the "kernel" rules in a file.
# Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_auditload_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT

new_host() {   # $1 = yes|no: a merged audit.rules exists before hardening
    rm -rf "$W/audit" "$W/backups"; mkdir -p "$W/audit/rules.d" "$W/backups"
    [[ "$1" == yes ]] && printf '## distro rules\n-D\n-w /etc/hosts -p wa -k distro\n' > "$W/audit/audit.rules"
    : > "$W/kernel"
}

run() {
    env DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent \
        bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        DRY_RUN=false; SKIP_BACKUP=false; LOG_FILE='$W/run.log'; UH_AUDIT_DIR='$W/audit'
        UH_BACKUP_ROOT='$W/backups'; BACKUP_GENESIS_DIR='$W/backups/genesis'; BACKUP_DIR='$W/backups/hardening_backup_1'
        relabel_path() { :; }
        is_service_active() { [[ \$1 == auditd ]]; }
        systemctl() { return 1; }
        auditctl() {
            case \"\$1\" in
                -R) grep -v '^-D' \"\$2\" | grep -v '^#' > '$W/kernel' ;;
                -l) cat '$W/kernel' ;;
                -D) : > '$W/kernel' ;;
            esac
        }
        augenrules() { cat '$W/audit/rules.d/'*.rules > '$W/audit/audit.rules' 2>/dev/null; return 0; }
        $1" >"$W/out" 2>&1
}
write_ours() { printf -- '-D\n-w /etc/passwd -p wa -k identity\n' > "$W/audit/rules.d/99-hardening.rules"; }

# --- Alpine-like: no merged file before ---------------------------------------
new_host no
run _backup_audit_rules_file
write_ours
run 'load_audit_rules && audit_rules_loaded && echo LOADED'
assert_output_contains "$(cat "$W/out")" '^LOADED$' "the rules are loaded in the kernel, not just written"
run _backup_audit_rules_file
assert_file_absent "$W/backups/genesis/files$W/audit/audit.rules" "a later run does not back up our own merged file as the original"
rm -f "$W/audit/rules.d/99-hardening.rules"
run restore_audit_rules
assert_file_absent "$W/audit/audit.rules" "revert removes the merged file hardening created"
[[ -s "$W/kernel" ]] && fail "rules are still loaded after revert" || pass_msg "and no rules are left loaded"

# --- Debian-like: a merged file existed --------------------------------------
new_host yes
orig=$(checksum "$W/audit/audit.rules")
run _backup_audit_rules_file
write_ours
run 'load_audit_rules && audit_rules_loaded && echo LOADED'
assert_output_contains "$(cat "$W/out")" '^LOADED$' "the rules are loaded"
rm -f "$W/audit/rules.d/99-hardening.rules"
run restore_audit_rules
assert_unchanged "$W/audit/audit.rules" "$orig" "revert restores the merged file byte for byte"
assert_file_contains "$W/kernel" '/etc/hosts -p wa' "the kernel gets the distro's rules back"
assert_file_not_contains "$W/kernel" '/etc/passwd -p wa' "and not ours"

# --- no auditctl: nothing is claimed ------------------------------------------
new_host no
write_ours
env bash -c "source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
    LOG_FILE='$W/run.log'; UH_AUDIT_DIR='$W/audit'; PATH=/nonexistent
    load_audit_rules && echo LOADED || echo NOT-LOADED" > "$W/out" 2>&1
assert_output_contains "$(cat "$W/out")" '^NOT-LOADED$' "without auditctl, loading reports failure"

finish
