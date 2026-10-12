#!/bin/bash
# Module 15's USB storage blacklist must be on by default and switchable off
# with UH_USB_STORAGE_BLACKLIST=false, for hosts that need USB disks. A value
# that is neither true nor false must keep the blacklist rather than guess.
#
# Stubs are shell FUNCTIONS (lib/core.sh prepends the system PATH at source
# time, so PATH stubs would be shadowed). chmod is stubbed so the GRUB step
# never touches the real /boot even when this runs as root.
#
# Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_usbsw_$$"; rm -rf "$W"; mkdir -p "$W/modprobe.d"
trap 'rm -rf "$W"' EXIT
export LOG_FILE="$W/run.log"
conf="$W/modprobe.d/99-hardening-usb.conf"

if ! grep -q 'UH_USB_STORAGE_BLACKLIST' "$REPO/lib/modules.sh"; then
    fail "lib/modules.sh has no UH_USB_STORAGE_BLACKLIST switch"
    finish
fi

# $1 = shell run before the module (settings, dry run).
run_mod() {
    bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        DISTRO_TYPE=debian; DRY_RUN=false; SKIP_BACKUP=true; BACKUP_DIR='$W'
        UH_MODPROBE_DIR='$W/modprobe.d'
        create_backup_dir() { :; }; backup_file() { :; }; count_fix() { :; }
        chmod() { :; }
        $1
        apply_boot_secure" 2>&1
}

# --- default: blacklist written --------------------------------------------
rm -f "$conf"
out=$(run_mod "unset UH_USB_STORAGE_BLACKLIST")
assert_file_exists   "$conf" "by default the USB storage blacklist is written"
assert_file_contains "$conf" '^install usb-storage /bin/true$' "the default blacklist disables autoload"
assert_file_contains "$conf" '^blacklist usb-storage$'         "and blacklists usb-storage by name"

# --- explicitly true --------------------------------------------------------
rm -f "$conf"
run_mod "UH_USB_STORAGE_BLACKLIST=true" >/dev/null
assert_file_exists "$conf" "UH_USB_STORAGE_BLACKLIST=true writes the blacklist"

# --- false: nothing written -------------------------------------------------
rm -f "$conf"
out=$(run_mod "UH_USB_STORAGE_BLACKLIST=false")
assert_file_absent     "$conf" "UH_USB_STORAGE_BLACKLIST=false writes no blacklist"
assert_output_contains "$out" 'blacklist skipped' "and says it skipped the blacklist"

# --- false with an earlier blacklist present: left alone, but flagged --------
printf 'install usb-storage /bin/true\nblacklist usb-storage\n' > "$conf"
out=$(run_mod "UH_USB_STORAGE_BLACKLIST=false")
assert_file_exists     "$conf" "switching off does not delete an earlier run's blacklist (revert does that)"
assert_output_contains "$out" 'still in place' "but warns that an earlier blacklist is still active"

# --- an invalid value keeps the blacklist ------------------------------------
rm -f "$conf"
out=$(run_mod "UH_USB_STORAGE_BLACKLIST=no")
assert_file_exists     "$conf" "a value other than true/false keeps the blacklist"
assert_output_contains "$out" 'not true/false' "and warns about the value"

# --- dry run describes the choice and writes nothing --------------------------
rm -f "$conf"
out=$(run_mod "DRY_RUN=true; UH_USB_STORAGE_BLACKLIST=false")
assert_file_absent     "$conf" "a dry run writes nothing"
assert_output_contains "$out" 'blacklist off' "a dry run with the switch off says so"
out=$(run_mod "DRY_RUN=true")
assert_output_contains "$out" 'blacklist USB storage' "a default dry run says it would blacklist USB storage"

finish
