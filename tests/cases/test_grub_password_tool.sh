#!/bin/bash
# Module 16 must find GRUB's password tool under either name:
# grub-mkpasswd-pbkdf2 (Debian, Ubuntu, Arch) or grub2-mkpasswd-pbkdf2
# (Fedora, RHEL, openSUSE). It only looked for the first, so it skipped every
# RHEL-family host as "no GRUB on this system".
#
# PATH is cut down to a directory of stubs AFTER sourcing (lib/core.sh
# prepends the system directories at source time), so a real GRUB tool on the
# test image cannot answer for the stub. The GRUB config regeneration is
# stubbed as functions and 40_custom is redirected with UH_GRUB_CUSTOM, so
# nothing under /etc or /boot is touched even when this runs as root.
#
# Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_grubpw_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT
export LOG_FILE="$W/run.log"
STUB_HASH='grub.pbkdf2.sha512.10000.STUBSALT.STUBHASH'

# Builds $W/bin with the commands the module needs plus the named GRUB
# password tools, each printing a fixed hash the way the real tool does.
# $@ = tool names to provide.
make_bin() {
    rm -rf "${W:?}/bin"; mkdir -p "$W/bin"
    local c
    for c in tee date grep cat; do
        ln -s "$(command -v "$c")" "$W/bin/$c"
    done
    for c in "$@"; do
        printf '#!/bin/sh\ncat >/dev/null\necho "PBKDF2 hash of your password is %s"\n' \
            "$STUB_HASH" > "$W/bin/$c"
        chmod 755 "$W/bin/$c"
    done
}

# $1 = shell run before the module (DRY_RUN etc). Stdin is passed through.
run_mod() {
    bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        PATH='$W/bin'
        DISTRO_TYPE=rhel; AUTO_MODE=false; SKIP_BACKUP=true; BACKUP_DIR='$W'
        UH_GRUB_CUSTOM='$W/40_custom'
        create_backup_dir() { :; }; backup_file() { :; }; count_fix() { :; }
        confirm_risky() { return 0; }
        update-grub() { return 1; }
        grub2-mkconfig() { echo regenerated > '$W/mkconfig.ran'; }
        $1
        apply_grub_password" 2>&1
}

# --- Fedora/RHEL name only: found, not skipped -------------------------------
make_bin grub2-mkpasswd-pbkdf2
out=$(run_mod "DRY_RUN=true" </dev/null)
assert_output_contains "$out" 'Would generate a GRUB PBKDF2 hash with grub2-mkpasswd-pbkdf2' \
    "dry run finds grub2-mkpasswd-pbkdf2 when it is the only name present"

rm -f "$W/40_custom" "$W/mkconfig.ran"
out=$(run_mod "DRY_RUN=false" <<< $'secret\nsecret\n')
assert_file_contains "$W/40_custom" '^set superusers="root"$' \
    "with grub2-mkpasswd-pbkdf2 the superuser is written"
assert_file_contains "$W/40_custom" "^password_pbkdf2 root ${STUB_HASH//./\\.}\$" \
    "and the hash comes from grub2-mkpasswd-pbkdf2"
assert_file_exists "$W/mkconfig.ran" "and grub2-mkconfig regenerates the config when update-grub is absent"

# --- Debian name only: still found ------------------------------------------
make_bin grub-mkpasswd-pbkdf2
out=$(run_mod "DRY_RUN=true" </dev/null)
assert_output_contains "$out" 'Would generate a GRUB PBKDF2 hash with grub-mkpasswd-pbkdf2' \
    "dry run still finds grub-mkpasswd-pbkdf2"

# --- neither: skipped, nothing written --------------------------------------
make_bin
rm -f "$W/40_custom"
out=$(run_mod "DRY_RUN=false" <<< $'secret\nsecret\n')
assert_output_contains "$out" 'no GRUB on this system, skipping' \
    "with neither tool present the module skips"
assert_file_absent "$W/40_custom" "and writes nothing"

finish
