#!/bin/bash
# A full revert must restore files when the backup root's path holds glob
# characters (UH_BACKUP_ROOT is user-set, e.g. /mnt/backups[1]). The restore
# loops strip the backup prefix to get the live path; unquoted, that prefix
# was read as a pattern, nothing was stripped, and every file was "copied"
# onto its own backup and reported as "could not restore".
#
# Every path is under a temp dir and every service or kernel call is a stub.
# UH_TOOL_CREATED_PATHS and UH_SHARED_WRITTEN_PATHS are emptied: the full
# revert removes those real paths. Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_globroot_$$/b[1]*"; rm -rf "${W%/*}"; mkdir -p "$W"
trap 'rm -rf "${W%/*}"' EXIT

run() {   # $1 = backup holding the original: genesis | perrun
    rm -rf "$W/h"; mkdir -p "$W/h/live"
    local store="$W/h/backups/genesis/files"
    [[ "$1" == perrun ]] && store="$W/h/backups/hardening_backup_1/files"
    mkdir -p "$store$W/h/live"
    echo original > "$store$W/h/live/conf"
    echo hardened > "$W/h/live/conf"
    : > "$W/calls"
    env DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent \
        bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'; source '$REPO/lib/cis.sh'
        H='$W/h'
        DRY_RUN=false; SKIP_BACKUP=false; AUTO_MODE=true; LOG_FILE=\"\$H/run.log\"; UH_REVERT_TARGET=''
        UH_NFT_CONF=\"\$H/nft.conf\"; UH_NFT_TABLE_FILE=\"\$H/table\"
        UH_BACKUP_ROOT=\"\$H/backups\"; BACKUP_GENESIS_DIR=\"\$H/backups/genesis\"; BACKUP_DIR=\"\$H/backups/hardening_backup_1\"
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
        systemctl() { echo \"FORBIDDEN systemctl \$*\" >> '$W/calls'; return 1; }
        rc-update() { echo \"FORBIDDEN rc-update \$*\" >> '$W/calls'; return 1; }
        full_system_revert" >"$W/out" 2>&1
}

for kind in genesis perrun; do
    run "$kind"
    [[ "$(cat "$W/h/live/conf" 2>/dev/null)" == original ]] \
        && pass_msg "$kind: the file is restored under a backup root with glob characters" \
        || fail "$kind: expected 'original', got '$(cat "$W/h/live/conf" 2>/dev/null)'; log: $(grep -m2 'could not restore' "$W/h/run.log" "$W/out" 2>/dev/null | tr '\n' ' ')"
    if grep -q 'could not restore' "$W/h/run.log" "$W/out" 2>/dev/null; then
        fail "$kind: revert reported a file it could not restore"
    else
        pass_msg "$kind: no restore failure reported"
    fi
    if grep -q '^FORBIDDEN' "$W/calls"; then
        fail "$kind: a real service manager would have been called: $(grep -m2 '^FORBIDDEN' "$W/calls" | tr '\n' ';')"
    fi
done

finish
