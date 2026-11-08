#!/bin/bash
# Module 13 (AppArmor) must switch only the profiles in complain mode to
# enforce, record each one first, and revert must put exactly those back.
#
# It used to run aa-enforce on everything in /etc/apparmor.d with no record,
# and its only advice for undoing that, aa-complain on everything, would also
# have weakened profiles that were enforcing before.
#
# aa-enforce and apparmor_parser are stubs working on a profile directory under
# the test's own folder. Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_aarec_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT

AA="$W/apparmor.d"
mkdir -p "$AA/force-complain" "$AA/abstractions"
printf 'profile p1 /usr/bin/p1 flags=(complain,attach_disconnected) {\n}\n' > "$AA/p1"
printf 'profile p2 /usr/bin/p2 {\n}\n' > "$AA/p2"
printf 'profile p3 /usr/bin/p3 {\n}\n' > "$AA/p3"
ln -s ../p3 "$AA/force-complain/p3"
p1_orig=$(checksum "$AA/p1"); p2_orig=$(checksum "$AA/p2")
: > "$W/calls"

run() {
    env DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent \
        bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        DRY_RUN=false; SKIP_BACKUP=false; LOG_FILE='$W/run.log'; UH_APPARMOR_DIR='$AA'
        UH_BACKUP_ROOT='$W/backups'; BACKUP_GENESIS_DIR='$W/backups/genesis'; BACKUP_DIR='$W/backups/hardening_backup_1'
        relabel_path() { :; }
        systemctl() { echo FORBIDDEN >> '$W/calls'; return 1; }
        aa-enforce() {
            local f
            for f in \"\$@\"; do
                echo \"ENFORCE \$f\" >> '$W/calls'
                sed -i 's/flags=(complain,/flags=(/' \"\$f\"
                rm -f '$AA'/force-complain/\"\$(basename \"\$f\")\"
            done
        }
        apparmor_parser() { echo \"PARSER \$*\" >> '$W/calls'; }
        $1" >"$W/out" 2>&1
}

run _apparmor_enforce_complain_profiles
assert_file_not_contains "$AA/p1" 'complain' "a profile with complain in its flags is enforced"
[[ -L "$AA/force-complain/p3" ]] && fail "the force-complain link is still there" || pass_msg "a force-complain profile is enforced"
if grep -q "ENFORCE $AA/p2\$" "$W/calls" || grep -q "ENFORCE $AA/abstractions" "$W/calls"; then
    fail "aa-enforce was run on a profile that was not in complain mode, or on a directory"
else
    pass_msg "aa-enforce runs only on the profiles that were in complain mode"
fi
assert_unchanged "$AA/p2" "$p2_orig" "an enforcing profile is untouched"
assert_file_contains "$W/backups/genesis/apparmor_complain_before.txt" "^file\\|$AA/p1\$" "the complain-flag profile is recorded"
assert_file_contains "$W/backups/genesis/apparmor_complain_before.txt" "^link\\|$AA/force-complain/p3\\|\\.\\./p3\$" "and the force-complain link"

run '_apparmor_enforce_complain_profiles'
[[ "$(wc -l < "$W/backups/genesis/apparmor_complain_before.txt")" == 2 ]] && pass_msg "a second run adds nothing to the record" \
    || fail "record has $(wc -l < "$W/backups/genesis/apparmor_complain_before.txt") lines after two runs"

run undo_apparmor_enforce
assert_unchanged "$AA/p1" "$p1_orig" "revert restores the complain-flag profile byte for byte"
[[ "$(readlink "$AA/force-complain/p3" 2>/dev/null)" == ../p3 ]] && pass_msg "revert puts the force-complain link back" || fail "force-complain link not restored"
assert_output_contains "$(cat "$W/calls")" "^PARSER -r $AA/p1\$" "the restored profile is reloaded"
assert_output_contains "$(cat "$W/calls")" "^PARSER -r -C $AA/force-complain/\\.\\./p3\$" "the force-complain profile is reloaded in complain mode"
assert_unchanged "$AA/p2" "$p2_orig" "the profile that was enforcing stays as it was"

grep -q FORBIDDEN "$W/calls" && fail "the host's real systemctl was reached" || pass_msg "no real service manager was reached"
finish
