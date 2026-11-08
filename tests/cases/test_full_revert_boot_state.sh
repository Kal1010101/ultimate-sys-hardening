#!/bin/bash
# The full revert must undo what module 3 and module 13 changed outside files.
#
# nftables: module 3 enables it at boot. A full revert put the dormant config
# back (Alpine's default, which drops SSH) but left nftables enabled, so the
# next boot loaded it and locked SSH out. Module 3's own revert already put
# the boot setting back; the full revert never did.
#
# AppArmor: profiles in complain mode before hardening stayed enforcing after a
# full revert. Restored profile files take effect only when reloaded, and
# force-complain links are not in the file backup.
#
# Every path is under a temp dir and every service or kernel call is a stub.
# UH_TOOL_CREATED_PATHS and UH_SHARED_WRITTEN_PATHS are emptied: the full
# revert removes those real paths. Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_fullrevboot_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT

new_host() {   # $1 = yes|no: AppArmor profiles were in complain mode before
    rm -rf "$W/h"; mkdir -p "$W/h/backups/genesis/files$W/h"
    printf '#!/usr/sbin/nft -f\nflush ruleset\n' > "$W/h/backups/genesis/files$W/h/conf"
    printf 'include "%s"\n' "$W/h/table" > "$W/h/conf"     # module 3's boot file
    touch "$W/h/enabled"                                     # module 3 enabled nftables
    [[ "$1" == yes ]] && echo "file|$W/h/profile|" > "$W/h/backups/genesis/apparmor_complain_before.txt"
    : > "$W/calls"
}

run() {
    env DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent \
        bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'; source '$REPO/lib/cis.sh'
        H='$W/h'
        DRY_RUN=false; SKIP_BACKUP=false; AUTO_MODE=true; LOG_FILE='$W/run.log'; UH_REVERT_TARGET=''
        UH_NFT_CONF=\"\$H/conf\"; UH_NFT_TABLE_FILE=\"\$H/table\"
        UH_BACKUP_ROOT=\"\$H/backups\"; BACKUP_GENESIS_DIR=\"\$H/backups/genesis\"; BACKUP_DIR=\"\$H/backups/hardening_backup_1\"
        SUID_BACKUP_FILE=\"\$H/suid.txt\"; UFW_CONF=\"\$H/ufw.conf\"
        UH_TOOL_CREATED_PATHS=(); UH_SHARED_WRITTEN_PATHS=()
        relabel_path() { :; }
        is_service_active() { return 1; }
        is_service_enabled() { [[ \"\$1\" == nftables && -f \"\$H/enabled\" ]]; }
        enable_service_at_boot() { echo \"BOOT-ENABLE \$1\" >> '$W/calls'; touch \"\$H/enabled\"; }
        disable_service_at_boot() { echo \"BOOT-DISABLE \$1\" >> '$W/calls'; rm -f \"\$H/enabled\"; }
        _has_openrc() { return 0; }; _has_systemd() { return 1; }
        rc-service() { echo \"RC-SERVICE \$*\" >> '$W/calls'; }
        restore_sysctl_before() { :; }; restore_audit_rules() { :; }; restore_service_state() { :; }
        restart_sshd() { :; }; restart_service() { :; }; undo_suid_hardening() { :; }
        undo_apparmor_enforce() { echo 'UNDO-APPARMOR' >> '$W/calls'; }
        nft() { return 1; }; ufw() { return 1; }; firewall-cmd() { return 1; }; sysctl() { return 1; }
        systemctl() { echo \"FORBIDDEN systemctl \$*\" >> '$W/calls'; return 1; }
        rc-update() { echo \"FORBIDDEN rc-update \$*\" >> '$W/calls'; return 1; }
        $1" >"$W/out" 2>&1
}

# nftables was neither running nor enabled at boot before module 3 (Alpine).
new_host yes
run 'is_service_enabled() { return 1; }; record_service_state nftables'
run full_system_revert
assert_output_contains "$(cat "$W/calls")" '^BOOT-DISABLE nftables$' "full revert disables nftables at boot again, as before hardening"
[[ -f "$W/h/enabled" ]] && fail "nftables still starts at boot with the restored dormant config" || pass_msg "so the restored dormant config is not loaded at the next boot"
assert_output_contains "$(cat "$W/calls")" '^RC-SERVICE nftables zap$' "OpenRC marks it stopped without flushing"
assert_file_contains "$W/h/conf" '^flush ruleset$' "the dormant config itself is back"
assert_output_contains "$(cat "$W/calls")" '^UNDO-APPARMOR$' "profiles in complain mode before are put back in complain mode"

# nftables was enabled at boot before: it stays enabled. No AppArmor record.
new_host no
run 'is_service_enabled() { return 0; }; record_service_state nftables'
run full_system_revert
if grep -q '^BOOT-DISABLE' "$W/calls"; then fail "nftables enabled before hardening was disabled"; else pass_msg "nftables enabled before stays enabled"; fi
if grep -q '^UNDO-APPARMOR$' "$W/calls"; then fail "AppArmor undo ran without a record"; else pass_msg "no AppArmor change without a record"; fi

if grep -q '^FORBIDDEN' "$W/calls"; then
    fail "a real service manager would have been called: $(grep '^FORBIDDEN' "$W/calls" | head -2 | tr '\n' ';')"
else
    pass_msg "no real systemctl or rc-update was reached"
fi

finish
