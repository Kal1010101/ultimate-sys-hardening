#!/bin/bash
# A run that finds a file unchanged since an earlier backup takes no copy of it
# (backup_file's dedup). A full revert pinned to that run then had nothing to
# restore and left the file as it is now. The run now records which earlier
# backup holds the copy; the pinned revert restores from it, and pruning that
# earlier backup first copies the file into the run that points at it.
#
# Every path is under a temp dir and every service or kernel call is a stub.
# UH_TOOL_CREATED_PATHS and UH_SHARED_WRITTEN_PATHS are emptied. Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_pinunchanged_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT
F="$W/h/etc/demo.conf"

run() {   # $1 = shell, $2 = per-run backup name (BACKUP_DIR)
    env DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent \
        bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'; source '$REPO/lib/cis.sh'
        H='$W/h'
        DRY_RUN=false; SKIP_BACKUP=false; AUTO_MODE=true; LOG_FILE=\"\$H/run.log\"; UH_REVERT_TARGET=\"\${PIN:-}\"
        UH_NFT_CONF=\"\$H/nft.conf\"; UH_NFT_TABLE_FILE=\"\$H/table\"
        UH_BACKUP_ROOT=\"\$H/backups\"; BACKUP_GENESIS_DIR=\"\$H/backups/genesis\"; BACKUP_DIR=\"\$H/backups/$2\"
        SUID_BACKUP_FILE=\"\$H/suid.txt\"; UFW_CONF=\"\$H/ufw.conf\"
        UH_TOOL_CREATED_PATHS=(); UH_SHARED_WRITTEN_PATHS=()
        relabel_path() { :; }
        is_service_active() { return 1; }; is_service_enabled() { return 1; }
        enable_service_at_boot() { :; }; disable_service_at_boot() { :; }
        _has_openrc() { return 0; }; _has_systemd() { return 1; }
        rc-service() { :; }
        restore_sysctl_before() { :; }; restore_audit_rules() { :; }; restore_service_state() { :; }
        restart_sshd() { :; }; restart_service() { :; }; undo_suid_hardening() { :; }
        undo_apparmor_enforce() { :; }
        nft() { return 1; }; ufw() { return 1; }; firewall-cmd() { return 1; }; sysctl() { return 1; }
        systemctl() { echo \"FORBIDDEN systemctl \$*\" >> \"\$H/calls\"; return 1; }
        rc-update() { echo \"FORBIDDEN rc-update \$*\" >> \"\$H/calls\"; return 1; }
        $1" >"$W/out" 2>&1
}

# A module that writes "hardened" on every run: run 1 captures the original,
# run 2 the hardened file run 1 left, run 3 finds it unchanged since run 2.
new_host() {
    rm -rf "$W/h"; mkdir -p "$W/h/etc" "$W/h/backups"
    echo original > "$F"
    local n
    for n in 1 2 3; do
        run "backup_file '$F'; echo hardened > '$F'" "hardening_backup_2026010${n}_000000"
    done
}
R3="$W/h/backups/hardening_backup_20260103_000000"
R2="$W/h/backups/hardening_backup_20260102_000000"

new_host
assert_file_absent "$R3/files$F" "run 3 takes no copy of a file unchanged since run 2"
assert_file_contains "$R3/unchanged_files.txt" "^$F\|$R2\$" "and records that run 2 holds its copy"

# Run 3 already recorded the file: a second backup_file in that run, after the
# module changed it, must not replace the state before the run.
echo changed-mid-run > "$F"
run "backup_file '$F'" hardening_backup_20260103_000000
assert_file_absent "$R3/files$F" "a later backup_file in the same run takes no copy of the changed file"
[[ $(grep -c . "$R3/unchanged_files.txt") -eq 1 ]] && pass_msg "and does not record the file twice" \
                                                    || fail "recorded twice: $(cat "$R3/unchanged_files.txt")"

# --- pinned revert to run 3 --------------------------------------------------
echo "edited later" > "$F"
PIN="$R3" run full_system_revert hardening_backup_20260104_000000
assert_file_contains "$F" '^hardened$' "a revert pinned to run 3 restores the file from run 2's copy"
assert_output_contains "$(cat "$W/out")" 'restored \(unchanged since hardening_backup_20260102_000000\)' "and says where the copy came from"

# --- the backup holding the copy is pruned -----------------------------------
new_host
touch -d '200 days ago' "$R2"
run 'UH_BACKUP_RETENTION_DAYS=90; create_backup_dir' hardening_backup_20260105_000000
assert_file_absent "$R2" "run 2's backup is pruned"
assert_file_contains "$R3/files$F" '^hardened$' "its copy of the file was first copied into run 3, which points at it"
if grep -q . "$R3/unchanged_files.txt" 2>/dev/null; then fail "run 3 still points at the pruned backup"; else pass_msg "and run 3's record no longer points at it"; fi
echo "edited later" > "$F"
PIN="$R3" run full_system_revert hardening_backup_20260106_000000
assert_file_contains "$F" '^hardened$' "a revert pinned to run 3 still restores the file after the prune"

# --- a record pointing outside the backups is refused ------------------------
new_host
mkdir -p "$W/h/elsewhere/files$W/h/etc"; echo planted > "$W/h/elsewhere/files$F"
printf '%s|%s\n' "$F" "$W/h/elsewhere" > "$R3/unchanged_files.txt"
echo "edited later" > "$F"
PIN="$R3" run full_system_revert hardening_backup_20260107_000000
assert_file_contains "$F" '^edited later$' "a record naming a directory outside the backups restores nothing"
assert_output_contains "$(cat "$W/out")" 'could not restore .*demo.conf' "and says it could not restore the file"

if grep -q '^FORBIDDEN' "$W/h/calls" 2>/dev/null; then fail "a real service manager would have been called"; else pass_msg "no real service manager was reached"; fi

finish
