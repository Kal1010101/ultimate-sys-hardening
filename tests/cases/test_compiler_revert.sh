#!/bin/bash
# Reverting module 20 must give compilers back their real mode, never 777.
# The inventory used to record `command -v cc`, a symlink, with stat's mode for
# the link itself (always 777); the revert's chmod followed the link and left
# the real compiler world-writable, so any local user could trojan it and wait
# for root's next build. Covers a fresh apply/revert round trip, an inventory
# written by the old code, and a line pointing at a path root does not control.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root
REPO="${REPO_ROOT:-/repo}"

FAKE_GCC=/usr/local/bin/gcc
FAKE_CC=/usr/local/bin/cc
[[ -e "$FAKE_GCC" || -e "$FAKE_CC" ]] && skip "$FAKE_GCC or $FAKE_CC already exists"
mkdir -p /usr/local/bin
cp /bin/true "$FAKE_GCC" && chmod 755 "$FAKE_GCC" || skip "cannot create a fake compiler"
ln -s gcc "$FAKE_CC"
W=$(mktemp -d)
BACKUP="/root/hardening_backup_compiler_test_$$"
trap 'rm -rf "$W" "$BACKUP"; rm -f "$FAKE_GCC" "$FAKE_CC"' EXIT

# Run lib code as the tool does, with module 20's inventory under /root where
# undo_compiler_restriction looks for it.
run_lib() {
    bash -c "set -euo pipefail
        LOG_FILE='$W/run.log'
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'
        source '$REPO/lib/modules.sh'; source '$REPO/lib/cis.sh'
        BACKUP_DIR='$BACKUP'; AUTO_MODE=true; DRY_RUN=false; SKIP_BACKUP=false
        $1" 2>&1
}

mode_of() { stat -c %a "$1"; }

# --- fresh round trip --------------------------------------------------------
run_lib apply_compiler_restriction >/dev/null
[[ "$(mode_of "$FAKE_GCC")" == 700 ]] && pass_msg "apply restricts the real compiler to 700" \
    || fail "apply left $FAKE_GCC at $(mode_of "$FAKE_GCC"), expected 700"
inv="$BACKUP/compiler_original_perms.txt"
if grep -q "^$FAKE_CC " "$inv" 2>/dev/null; then
    fail "inventory records the symlink $FAKE_CC instead of its target"
else
    pass_msg "inventory records no symlink path"
fi
[[ $(grep -c "^$FAKE_GCC " "$inv" 2>/dev/null) == 1 ]] && pass_msg "gcc and cc share one inventory line" \
    || fail "expected exactly one inventory line for $FAKE_GCC"

run_lib undo_compiler_restriction >/dev/null
[[ "$(mode_of "$FAKE_GCC")" == 755 ]] && pass_msg "revert puts the compiler back to 755" \
    || fail "revert left $FAKE_GCC at $(mode_of "$FAKE_GCC"), expected 755"

# --- inventory written by the old code ---------------------------------------
chmod 700 "$FAKE_GCC"
printf '%s 755\n%s 777\n' "$FAKE_GCC" "$FAKE_CC" > "$inv"
run_lib undo_compiler_restriction >/dev/null
[[ "$(mode_of "$FAKE_GCC")" == 755 ]] && pass_msg "old inventory's 777 symlink line does not make the compiler world-writable" \
    || fail "old inventory left $FAKE_GCC at $(mode_of "$FAKE_GCC"), expected 755"

# full_system_revert replays its inventory line by line through the same helper.
chmod 700 "$FAKE_GCC"
run_lib "restore_compiler_mode '$FAKE_CC' 777" >/dev/null
[[ "$(mode_of "$FAKE_GCC")" == 755 ]] && pass_msg "a lone 777 line restores 755, without group/other write" \
    || fail "a lone 777 line left $FAKE_GCC at $(mode_of "$FAKE_GCC"), expected 755"

# --- a path root does not control --------------------------------------------
mkdir -m 777 "$W/open"
cp /bin/true "$W/open/target" && chmod 700 "$W/open/target"
out=$(run_lib "restore_compiler_mode '$W/open/target' 755 && echo RESTORED || echo REFUSED")
assert_output_contains "$out" REFUSED "restore refuses a file in a world-writable directory"
[[ "$(mode_of "$W/open/target")" == 700 ]] && pass_msg "that file's mode is untouched" \
    || fail "restore changed $W/open/target to $(mode_of "$W/open/target")"

finish
