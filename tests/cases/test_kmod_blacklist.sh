#!/bin/bash
# Module 19 must make the CIS filesystem set unloadable as well as the
# protocols — and must not blacklist squashfs on a host that needs it.
#
# The uncommon filesystems (CIS 1.1.1.x) were simply absent: the module covered
# only DCCP/SCTP/RDS/TIPC, so cramfs, hfs, jffs2, udf and the rest stayed
# loadable on every hardened host. squashfs is the one entry on that list that
# breaks a working system — every snap package is a squashfs image, so
# blacklisting it on a host with snapd means no snap mounts after the next
# boot. CIS notes the exception; this pins that we detect it.
#
# Stubs are shell FUNCTIONS, deliberately. lib/core.sh prepends the system
# directories to PATH when it is sourced, so a stub directory put on PATH
# beforehand is shadowed by the real binaries — a trap that has already caused
# a test to run a real firewall command against the machine running it.
# Functions take precedence over PATH either way.
#
# Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_kmod_$$"; rm -rf "$W"; mkdir -p "$W/modprobe.d"
trap 'rm -rf "$W"' EXIT
export LOG_FILE="$W/run.log"

CIS_FS=(cramfs freevxfs hfs hfsplus jffs2 udf)

# Asserted before the test hook is required, so a library that predates the
# filesystem set fails here on behaviour rather than skipping.
dry=$(bash -c "set -uo pipefail
    source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
    DISTRO_TYPE=debian; DRY_RUN=true
    apply_unused_protocols" 2>&1)
assert_output_contains "$dry" 'cramfs' "module 19 covers the CIS uncommon filesystems at all"
assert_output_contains "$dry" 'dccp'   "and still covers the unused protocols"

# $1 = extra shell before the call (fake snapd, loaded modules, dry run).
# The module writes into UH_MODPROBE_DIR, which exists so this can run against
# a scratch directory instead of the host's /etc/modprobe.d.
if ! grep -q 'UH_MODPROBE_DIR' "$REPO/lib/modules.sh"; then
    skip "lib/modules.sh has no UH_MODPROBE_DIR test hook"
fi
run_mod() {
    rm -f "$W/modprobe.d"/*.conf; : > "$W/calls"
    bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        DISTRO_TYPE=debian; DRY_RUN=false; UH_MODPROBE_DIR='$W/modprobe.d'
        create_backup_dir() { :; }; backup_file() { :; }; count_fix() { :; }
        modprobe() { echo \"MODPROBE \$*\" >> '$W/calls'; return 0; }
        $1
        apply_unused_protocols" 2>&1
}

fs_conf="$W/modprobe.d/disable-unused-filesystems.conf"
proto_conf="$W/modprobe.d/disable-unused-protocols.conf"

# --- the normal case: a server with no snapd ---------------------------------
out=$(run_mod "_squashfs_required() { return 1; }")
assert_file_exists "$proto_conf" "the protocols file is still written"
assert_file_exists "$fs_conf"    "a filesystems file is written"
for fs in "${CIS_FS[@]}"; do
    assert_file_contains "$fs_conf" "^install ${fs} /bin/false$" "$fs autoload is disabled (install ... /bin/false)"
    assert_file_contains "$fs_conf" "^blacklist ${fs}$"          "$fs is blacklisted by name"
done
assert_file_contains "$fs_conf" "^blacklist squashfs$" "squashfs is blacklisted when nothing needs it"
for p in dccp sctp rds tipc; do
    assert_file_contains "$proto_conf" "^blacklist ${p}$" "$p is blacklisted by name"
done
# `install X /bin/false` alone still allows an explicit `modprobe X`; CIS asks
# for both lines, and the original file had only the first.
assert_file_contains "$proto_conf" "^install dccp /bin/false$" "protocols keep their install directive too"
assert_output_contains "$out" 'filesystems \(' "the summary names the filesystems it blacklisted"

# --- a host with snapd: squashfs must be left alone --------------------------
out=$(run_mod "_squashfs_required() { return 0; }")
if grep -qE '^(blacklist|install) squashfs' "$fs_conf"; then
    fail "squashfs was blacklisted on a host that needs it — every snap would stop mounting"
else
    pass_msg "squashfs is not blacklisted when snapd needs it"
fi
assert_file_contains "$fs_conf" "^blacklist cramfs$" "the other filesystems are still blacklisted"
assert_output_contains "$out" 'Left alone: squashfs' "and the operator is told which one was skipped, and why"
assert_file_contains "$fs_conf" "snapd" "the file itself records why squashfs is absent"

# --- modules already resident are unloaded where that is safe ---------------
out=$(run_mod "_squashfs_required() { return 1; }
    # cramfs is loaded and unused; udf is loaded and mounted.
    grep() { if [[ \"\$*\" == *'/proc/modules'* ]]; then return 0; fi; command grep \"\$@\"; }
    _kmod_in_use() { [[ \"\$1\" == udf ]]; }")
assert_output_contains "$(cat "$W/calls")" 'MODPROBE -r cramfs' "an unused loaded module is unloaded so the kernel matches the file"
if grep -q 'MODPROBE -r udf' "$W/calls"; then
    fail "tried to unload a filesystem that is mounted"
else
    pass_msg "a mounted filesystem is not unloaded out from under its mount"
fi
assert_output_contains "$out" 'still in use' "and the ones left loaded are reported"

# --- dry run previews the real set and writes nothing ------------------------
out=$(run_mod "DRY_RUN=true; _squashfs_required() { return 1; }")
assert_output_contains "$out" 'cramfs'  "the dry run names the filesystems"
assert_output_contains "$out" 'dccp'    "and the protocols"
assert_file_absent "$fs_conf" "a dry run writes no filesystems file"
out=$(run_mod "DRY_RUN=true; _squashfs_required() { return 0; }")
assert_output_contains "$out" 'squashfs' "a dry run on a snapd host says squashfs will be left alone"

finish
