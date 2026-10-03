#!/bin/bash
# You can pick which restore point --revert restores to: a date/timestamp, the
# original (genesis), or the latest. This tests the selection logic against a
# fixture; the picker's interactive prompt is guarded on a real terminal, so it
# never engages here.
#
# No root: UH_BACKUP_ROOT and BACKUP_GENESIS_DIR are pointed at a fixture.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_revpick_$$"; rm -rf "$W"; mkdir -p "$W/root" "$W/gen/files/etc"
trap 'rm -rf "$W"' EXIT
export LOG_FILE="$W/run.log"

for stamp in 20260910_120000_free 20260921_143000_pro; do
    d="$W/root/hardening_backup_$stamp"; mkdir -p "$d/files/etc"
    { echo "tier=${stamp##*_}"; echo "version=2.4.0"; echo "created=${stamp%_*}"; } > "$d/backup_info.txt"
done
: > "$W/gen/genesis_manifest.txt"; echo original > "$W/gen/files/etc/x"

LIB="source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh';
     source '$REPO/lib/modules.sh'; source '$REPO/lib/cis.sh'; source '$REPO/lib/menu.sh';
     UH_BACKUP_ROOT='$W/root'; BACKUP_GENESIS_DIR='$W/gen'; LOG_FILE='$W/run.log'; AUTO_MODE=true"

# --- listing: newest first, genesis last ------------------------------------
out=$(bash -c "$LIB; list_backup_points" 2>/dev/null)
first=$(head -1 <<<"$out"); last=$(tail -1 <<<"$out")
grep -q '20260921_143000_pro' <<<"$first" && pass_msg "newest per-run backup is listed first" \
    || fail "listing not newest-first: $first"
grep -q 'genesis' <<<"$last" && pass_msg "genesis is listed last (oldest state)" \
    || fail "genesis not last: $last"
n=$(bash -c "$LIB; list_backup_points" 2>/dev/null | grep -c .)
assert_exit_code 3 "$n" "all three restore points are listed"

# --- resolve_revert_target --------------------------------------------------
res() { bash -c "$LIB; resolve_revert_target '$1' 2>/dev/null || echo NONE"; }
grep -q '20260921_143000_pro' <<<"$(res latest)"   && pass_msg "'latest' resolves to the newest backup"   || fail "latest wrong"
grep -q '20260910_120000_free' <<<"$(res 20260910)" && pass_msg "a date substring resolves to that backup" || fail "date match wrong"
[[ "$(res genesis)" == "$W/gen" ]]                  && pass_msg "'genesis' resolves to the genesis dir"    || fail "genesis wrong"
[[ "$(res 19990101)" == NONE ]]                     && pass_msg "an unmatched target resolves to nothing"  || fail "bad target matched"

# --- a chosen dated backup pins that point in time (not genesis) -------------
out=$(bash -c "$LIB; DRY_RUN=true; UH_REVERT_TARGET='20260910'; full_system_revert" 2>&1)
assert_output_contains "$out" 'chosen restore point'      "a chosen backup is announced as the restore point"
assert_output_contains "$out" '20260910_120000_free'      "it restores from the chosen dir"
if grep -q 'hardened before genesis tracking existed' <<<"$out"; then
    fail "a deliberate point-in-time choice still shows the 'no genesis' warning"
else
    pass_msg "no misleading 'no genesis' warning for a deliberate choice"
fi

# --- default (no target) still restores to the true original -----------------
out=$(bash -c "$LIB; DRY_RUN=true; UH_REVERT_TARGET=''; full_system_revert" 2>&1)
assert_output_contains "$out" 'genesis' "with no target, revert defaults to the original (genesis)"

# --- an unknown target refuses rather than reverting to the wrong thing ------
out=$(bash -c "$LIB; DRY_RUN=true; UH_REVERT_TARGET='19990101'; full_system_revert; echo rc=\$?" 2>&1)
assert_output_contains "$out" 'No backup matches' "an unknown target is refused"
assert_output_contains "$out" 'rc=1'              "and returns non-zero"

finish
