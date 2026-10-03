#!/bin/bash
# Module 1 must never report success over a machine that will not boot.
#
# On 2026-09-05 an unattended `apk upgrade` inside module 1 moved Alpine from
# kernel 6.6.121 to 6.6.142 and never rebuilt the initramfs — apk ran the
# ca-certificates trigger and not mkinitfs's. The module printed "System
# packages updated". Nine days later the guest failed its first reboot at
# "Mounting root: failed": the new kernel had no virtio_blk in its initramfs.
# Every KVM result recorded in between said 0 failures.
#
# Alpine is the trap because it reuses ONE image (/boot/initramfs-virt) across
# kernel versions, so the file always exists and existence proves nothing.
# Debian and RHEL name the image after the kernel, so existence is enough there.
#
# Runs against a fake root with the package manager and image generators
# stubbed. Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"
require_cmd gzip

W="${TMPDIR:-/tmp}/uh_bootimg_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT
export LOG_FILE="$W/run.log"

# Stubs record their calls HERE, not on stdout. The code under test sends the
# image generators' output to LOG_FILE, so a stub that echoes to stdout is never
# seen — and an assertion that a generator was NOT called then passes no matter
# what. The first draft of this case did exactly that.
: > "$W/calls"

LIB='source "'"$REPO"'/lib/core.sh"; source "'"$REPO"'/lib/platform.sh";
     source "'"$REPO"'/lib/modules.sh"; source "'"$REPO"'/lib/cis.sh";
     source "'"$REPO"'/lib/menu.sh"'

# fake_initramfs <path> <kernel-version-whose-modules-it-holds>
fake_initramfs() {
    mkdir -p "$(dirname "$1")"
    printf 'init\nlib/modules/%s/kernel/drivers/block/virtio_blk.ko.gz\n' "$2" | gzip > "$1"
}

# ---------------------------------------------------------- Alpine: incident --
R="$W/alpine"; mkdir -p "$R/lib/modules/6.6.121-0-virt" "$R/usr/share/kernel/virt"
echo 6.6.121-0-virt > "$R/usr/share/kernel/virt/kernel.release"
fake_initramfs "$R/boot/initramfs-virt" 6.6.121-0-virt

out=$(bash -c "set -uo pipefail; $LIB
    DISTRO_TYPE=alpine; DRY_RUN=false; UH_BOOTCHECK_ROOT='$R'; UH_BOOTCHECK_RUNNING=6.6.121-0-virt
    # exactly what apk did: new modules and kernel.release, initramfs untouched
    update_packages() { mkdir -p '$R/lib/modules/6.6.142-0-virt'; echo 6.6.142-0-virt > '$R/usr/share/kernel/virt/kernel.release'; }
    mkinitfs() { echo \"MKINITFS \$1\" >> '$W/calls'; printf 'lib/modules/%s/x\n' \"\$1\" | gzip > '$R/boot/initramfs-virt'; }
    apply_system_updates; echo \"RC=\$?\"; cat '$W/calls' 2>/dev/null; : > '$W/calls'" 2>&1)
assert_output_contains "$out" 'MKINITFS 6.6.142-0-virt' "alpine: a stale initramfs is rebuilt for the upgraded kernel"
assert_output_contains "$out" 'RC=0'                    "alpine: module 1 succeeds once the image is rebuilt"
assert_output_contains "$out" 'System packages updated' "alpine: and only then reports success"
assert_output_contains "$out" 'reboot to use it'        "alpine: says a reboot is needed to use the new kernel"

# ------------------------------------------- Alpine: rebuild does not take --
fake_initramfs "$R/boot/initramfs-virt" 6.6.121-0-virt
out=$(bash -c "set -uo pipefail; $LIB
    DISTRO_TYPE=alpine; DRY_RUN=false; UH_BOOTCHECK_ROOT='$R'
    update_packages() { :; }
    mkinitfs() { return 0; }     # claims success, writes nothing
    apply_system_updates; echo \"RC=\$?\"; cat '$W/calls' 2>/dev/null; : > '$W/calls'" 2>&1)
assert_output_contains "$out" 'RC=1' "alpine: an image that is still stale after rebuilding fails the module"
if grep -q 'System packages updated' <<< "$out"; then
    fail "alpine: printed 'System packages updated' over an unbootable machine — the original bug"
else
    pass_msg "alpine: no success message when the next boot would fail"
fi
assert_output_contains "$out" 'Do NOT reboot' "alpine: tells the operator not to reboot"

# -------------------------------------- Alpine: breakage from an EARLIER run --
# Nothing is upgraded this time, but the image is already stale — the state the
# guest sat in, undetected, for nine days.
fake_initramfs "$R/boot/initramfs-virt" 6.6.121-0-virt
out=$(bash -c "set -uo pipefail; $LIB
    DISTRO_TYPE=alpine; DRY_RUN=false; UH_BOOTCHECK_ROOT='$R'
    update_packages() { :; }
    mkinitfs() { echo \"MKINITFS \$1\" >> '$W/calls'; printf 'lib/modules/%s/x\n' \"\$1\" | gzip > '$R/boot/initramfs-virt'; }
    apply_system_updates; echo \"RC=\$?\"; cat '$W/calls' 2>/dev/null; : > '$W/calls'" 2>&1)
assert_output_contains "$out" 'MKINITFS 6.6.142-0-virt' "alpine: a stale image left by an earlier run is caught and rebuilt"

# ----------------------------------------------- Alpine: already correct --
out=$(bash -c "set -uo pipefail; $LIB
    DISTRO_TYPE=alpine; DRY_RUN=false; UH_BOOTCHECK_ROOT='$R'; UH_BOOTCHECK_RUNNING=6.6.142-0-virt
    update_packages() { :; }
    mkinitfs() { echo MKINITFS-CALLED >> '$W/calls'; }
    apply_system_updates; echo \"RC=\$?\"; cat '$W/calls' 2>/dev/null; : > '$W/calls'" 2>&1)
if grep -q MKINITFS-CALLED <<< "$out"; then
    fail "alpine: rebuilt an initramfs that was already correct"
else
    pass_msg "alpine: a correct image is left alone"
fi
assert_output_contains "$out" 'RC=0' "alpine: a correct image is a successful run"

# ------------------------------------------------------------ Debian (apt) --
R="$W/debian"; mkdir -p "$R/lib/modules/6.1.0-52-amd64" "$R/boot"
: > "$R/boot/vmlinuz-6.1.0-52-amd64"; : > "$R/boot/initrd.img-6.1.0-52-amd64"
out=$(bash -c "set -uo pipefail; $LIB
    DISTRO_TYPE=debian; DRY_RUN=false; UH_BOOTCHECK_ROOT='$R'; UH_BOOTCHECK_RUNNING=6.1.0-52-amd64
    update_packages() { mkdir -p '$R/lib/modules/6.1.0-53-amd64'; : > '$R/boot/vmlinuz-6.1.0-53-amd64'; }
    update-initramfs() { echo \"UPDATE-INITRAMFS \$*\" >> '$W/calls'; : > '$R/boot/initrd.img-6.1.0-53-amd64'; }
    apply_system_updates; echo \"RC=\$?\"; cat '$W/calls' 2>/dev/null; : > '$W/calls'" 2>&1)
assert_output_contains "$out" 'UPDATE-INITRAMFS -c -k 6.1.0-53-amd64' "debian: a missing initrd for a new kernel is generated"
assert_output_contains "$out" 'RC=0' "debian: and the module succeeds"

rm -f "$R/boot/initrd.img-6.1.0-53-amd64"
out=$(bash -c "set -uo pipefail; $LIB
    DISTRO_TYPE=debian; DRY_RUN=false; UH_BOOTCHECK_ROOT='$R'
    update_packages() { :; }
    update-initramfs() { return 0; }
    apply_system_updates; echo \"RC=\$?\"; cat '$W/calls' 2>/dev/null; : > '$W/calls'" 2>&1)
assert_output_contains "$out" 'RC=1' "debian: an initrd that cannot be generated fails the module"

# -------------------------------------------------------------- RHEL (dnf) --
R="$W/rhel"; mkdir -p "$R/lib/modules/5.14.0-687.42.1.el9_8.x86_64" "$R/boot"
: > "$R/boot/vmlinuz-5.14.0-687.42.1.el9_8.x86_64"; : > "$R/boot/initramfs-5.14.0-687.42.1.el9_8.x86_64.img"
out=$(bash -c "set -uo pipefail; $LIB
    DISTRO_TYPE=rhel; DRY_RUN=false; UH_BOOTCHECK_ROOT='$R'
    command -v dnf >/dev/null 2>&1 || dnf() { :; }
    get_package_manager() { echo dnf; }
    update_packages() { mkdir -p '$R/lib/modules/5.14.0-687.44.1.el9_8.x86_64'; : > '$R/boot/vmlinuz-5.14.0-687.44.1.el9_8.x86_64'; }
    dracut() { echo \"DRACUT \$*\" >> '$W/calls'; : > '$R/boot/initramfs-5.14.0-687.44.1.el9_8.x86_64.img'; }
    apply_system_updates; echo \"RC=\$?\"; cat '$W/calls' 2>/dev/null; : > '$W/calls'" 2>&1)
assert_output_contains "$out" 'DRACUT --force .*initramfs-5.14.0-687.44.1.el9_8.x86_64.img 5.14.0-687.44.1.el9_8.x86_64' \
    "rhel: a missing initramfs for a new kernel is generated with dracut"
assert_output_contains "$out" 'RC=0' "rhel: and the module succeeds"

# ------------------------------------------------------------------ dry run --
# Start from a STALE image: with a correct one, a dry run that wrongly checked
# boot images would find nothing to rebuild and this would pass regardless.
fake_initramfs "$W/alpine/boot/initramfs-virt" 6.6.121-0-virt
out=$(bash -c "set -uo pipefail; $LIB
    DISTRO_TYPE=alpine; DRY_RUN=true; UH_BOOTCHECK_ROOT='$W/alpine'
    mkinitfs() { echo MKINITFS-CALLED >> '$W/calls'; }
    apply_system_updates; echo \"RC=\$?\"; cat '$W/calls' 2>/dev/null; : > '$W/calls'" 2>&1)
if grep -q MKINITFS-CALLED <<< "$out"; then
    fail "dry run rebuilt a boot image"
else
    pass_msg "dry run touches no boot image"
fi

# ------------------------------------------- the SIGPIPE class, on purpose --
# A real initramfs is tens of MB with module paths near the start. `grep -q`
# would exit early, gzip would take SIGPIPE, and pipefail would report a found
# module as missing — then this check would "rebuild" every image, every run.
big="$W/big-initramfs"
{ printf 'lib/modules/9.9.9-test/kernel/x.ko\n'; head -c 8000000 /dev/zero | tr '\0' 'x'; } | gzip > "$big"
rc=$(bash -c "set -euo pipefail; $LIB
    rc=0; boot_image_has_modules '$big' 9.9.9-test || rc=\$?; echo \$rc" 2>/dev/null)
assert_exit_code 0 "$rc" "a module path early in a large image is found under pipefail"

# ------------------------------------------------ through run_module --
R="$W/alpine"; fake_initramfs "$R/boot/initramfs-virt" 6.6.121-0-virt
out=$(bash -c "set -euo pipefail; $LIB
    DISTRO_TYPE=alpine; DRY_RUN=false; UH_BOOTCHECK_ROOT='$R'; FIXES_APPLIED=0
    update_packages() { :; }
    mkinitfs() { return 0; }
    UH_MODULE_FAILED=()
    run_module updates apply_system_updates
    report_module_results 'test'
    echo REACHED-END" 2>&1)
assert_output_contains "$out" 'did not complete: System updates' "the run summary names System updates as failed"
assert_output_contains "$out" 'REACHED-END' "and the run continues past it"

finish
