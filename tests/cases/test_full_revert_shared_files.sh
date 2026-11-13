#!/bin/bash
# The full revert removes a shared file (UH_SHARED_WRITTEN_PATHS: jail.local,
# daemon.json, issue.net) only when it holds exactly the module's output and
# nothing shows an earlier version existed. A revert pinned to a per-run
# backup (--revert-to) still asks genesis: a per-run backup that predates the
# module has no copy, and that once deleted Debian's stock /etc/issue.net.
#
# Every path is under a temp dir and every service or kernel call is a stub.
# UH_TOOL_CREATED_PATHS is emptied and UH_SHARED_WRITTEN_PATHS points at a
# temp file. Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_fullrevshared_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT
BANNER="module banner"

# $1 = genesis copy of the file ("none" or its content), $2 = per-run copy
# ("none" or content), $3 = "pin" to revert to the per-run backup, $4 = "link"
# to record the file as a symlink in genesis.
run() {
    rm -rf "$W/h"; mkdir -p "$W/h/backups/genesis/files$W/h" "$W/h/backups/hardening_backup_1/files$W/h"
    [[ "$1" != none ]] && printf '%s\n' "$1" > "$W/h/backups/genesis/files$W/h/banner"
    [[ "$2" != none ]] && printf '%s\n' "$2" > "$W/h/backups/hardening_backup_1/files$W/h/banner"
    [[ "${4:-}" == link ]] && printf '%s|%s\n' "$W/h/banner" "../vendor/banner" > "$W/h/backups/genesis/symlinks.txt"
    printf '%s\n' "$BANNER" > "$W/h/banner"
    local target=""; [[ "${3:-}" == pin ]] && target="$W/h/backups/hardening_backup_1"
    env DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent \
        bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'; source '$REPO/lib/cis.sh'
        H='$W/h'
        DRY_RUN=false; SKIP_BACKUP=false; AUTO_MODE=true; LOG_FILE=\"\$H/run.log\"; UH_REVERT_TARGET='$target'
        UH_NFT_CONF=\"\$H/nft.conf\"; UH_NFT_TABLE_FILE=\"\$H/table\"
        UH_BACKUP_ROOT=\"\$H/backups\"; BACKUP_GENESIS_DIR=\"\$H/backups/genesis\"; BACKUP_DIR=\"\$H/backups/hardening_backup_1\"
        SUID_BACKUP_FILE=\"\$H/suid.txt\"; UFW_CONF=\"\$H/ufw.conf\"
        UH_TOOL_CREATED_PATHS=(); UH_SHARED_WRITTEN_PATHS=(\"\$H/banner\")
        tool_written_content() { [[ \"\$1\" == \"\$H/banner\" ]] && echo '$BANNER'; }
        restore_recorded_symlink() { [[ \"\$1\" == \"\$H/banner\" ]] && rm -f \"\$1\" && ln -s ../vendor/banner \"\$1\"; }
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
        full_system_revert" >"$W/out" 2>&1
}
state() {
    if [[ -L "$W/h/banner" ]]; then echo "link"
    elif [[ -f "$W/h/banner" ]]; then cat "$W/h/banner"
    else echo "absent"; fi
}
check() {   # <want> <description>
    local got; got=$(state)
    [[ "$got" == "$1" ]] && pass_msg "$2" || fail "$2: expected '$1', got '$got'"
    if grep -q '^FORBIDDEN' "$W/h/calls" 2>/dev/null; then fail "$2: a real service manager would have been called"; fi
}

run none none
check absent "no earlier version anywhere: the module's own file is removed (Alpine, Arch)"

run "stock banner" none
check "stock banner" "genesis holds the original: it is restored"

run "stock banner" none pin
check "$BANNER" "pinned to a per-run backup without a copy: the file is kept, not deleted"

run none "$BANNER" pin
check absent "pinned, and the only copy anywhere is the module's own output: removed"

run none none pin link
check "$BANNER" "pinned, genesis records the file as a symlink: the file is kept, not deleted"

run none none "" link
check link "genesis records a symlink: the link is put back"

finish
