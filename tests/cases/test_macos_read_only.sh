#!/bin/bash
# On macOS the tool runs its read-only checks and --dry-run but applies
# nothing: most modules write Linux configuration that does nothing there.
# A run that could change the host must stop right after the platform is
# chosen, before a backup directory or any change is made; a dry run must
# still reach the menu.
#
# Runs in the Linux containers by picking macOS (option 9) from the platform
# menu instead of auto-detecting. The bash 3.2 restart that real Macs need is
# covered by .github/workflows/macos.yml on a real macOS runner.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root

backups_before=$(find /root -maxdepth 1 -name 'hardening_backup_*' 2>/dev/null | wc -l)

# Answers: 2 = cis at the profile prompt, 9 = macOS at the platform prompt,
# then P and Q in case the hardening menu appears.
out=$(printf '2\n9\nP\nQ\n' | bash "$FREE_SCRIPT" 2>&1)
rc=$?
assert_output_contains "$out" 'Platform: macos' "picking option 9 selects macOS"
assert_output_contains "$out" 'Linux-only for now' "a run that would apply changes explains macOS is read-only"
[[ $rc -ne 0 ]] && pass_msg "it exits non-zero (rc=$rc)" || fail "it exited 0 although nothing was applied"
if grep -q 'Log file' <<<"$out"; then
    fail "the menu opened on macOS without --dry-run"
else
    pass_msg "the menu did not open"
fi

backups_after=$(find /root -maxdepth 1 -name 'hardening_backup_*' 2>/dev/null | wc -l)
[[ "$backups_after" -eq "$backups_before" ]] \
    && pass_msg "no backup directory was created" \
    || fail "a backup directory was created on macOS ($backups_before -> $backups_after)"

# A dry run is allowed: it reaches the menu; P goes back to the profile
# screen and Q quits from there.
out=$(printf '2\n9\nP\nQ\n' | bash "$FREE_SCRIPT" --dry-run 2>&1)
assert_output_contains "$out" 'Log file' "with --dry-run the menu opens on macOS"
if grep -q 'Linux-only for now' <<<"$out"; then
    fail "--dry-run was refused on macOS"
else
    pass_msg "--dry-run is not refused on macOS"
fi

finish
