#!/bin/bash
# Flags that run to completion without a menu must not stop to ask which distro
# this is — and must not do it by borrowing AUTO_MODE.
#
# `--policy f --auto-fix`, `--openscap --scap-profile stig` and plain `--report`
# are the invocations people put in cron and CI, and each of them called
# show_distro_menu, which blocked on `read` unless AUTO_MODE was set. AUTO_MODE
# is the wrong lever: it also auto-answers every confirm() prompt, so reusing it
# would have an unattended flag silently saying "yes" to things it was never
# asked about. UH_AUTODETECT_PLATFORM skips only the distro question.
#
# Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

_lib='source "'"$REPO"'/lib/core.sh"; source "'"$REPO"'/lib/platform.sh"'
export LOG_FILE="${TMPDIR:-/tmp}/uh_autodetect_$$.log"

# --- the flag skips the menu --------------------------------------------------
out=$(bash -c "set -euo pipefail; $_lib
    UH_AUTODETECT_PLATFORM=true; AUTO_MODE=false
    show_distro_menu </dev/null
    echo \"DISTRO=\$DISTRO_TYPE\"" 2>&1) || true
assert_output_contains "$out" 'DISTRO=[a-z]+'              "UH_AUTODETECT_PLATFORM resolves the distro without a menu"
if grep -q 'SELECT YOUR OPERATING SYSTEM' <<<"$out"; then
    fail "the distro menu was shown despite UH_AUTODETECT_PLATFORM"
else
    pass_msg "no distro menu was shown"
fi

# --- and does it without turning on AUTO_MODE --------------------------------
auto=$(bash -c "set -euo pipefail; $_lib
    UH_AUTODETECT_PLATFORM=true; AUTO_MODE=false
    show_distro_menu </dev/null >/dev/null 2>&1
    echo \"AUTO_MODE=\$AUTO_MODE\"" 2>&1) || true
assert_output_contains "$auto" 'AUTO_MODE=false'            "AUTO_MODE is left alone (confirm() prompts still ask)"

# --- without the flag the interactive menu is unchanged ----------------------
menu=$(printf '2\n' | TERM=xterm bash -c "set -euo pipefail; $_lib
    box_top() { :; }; box_line() { :; }; box_bottom() { :; }
    AUTO_MODE=false; unset UH_AUTODETECT_PLATFORM
    show_distro_menu >/dev/null 2>&1
    echo \"DISTRO=\$DISTRO_TYPE\"" 2>&1) || true
assert_output_contains "$menu" 'DISTRO=rhel'                "without the flag, the menu still reads the operator's choice"

# --- AUTO_MODE keeps working -------------------------------------------------
am=$(bash -c "set -euo pipefail; $_lib
    AUTO_MODE=true; show_distro_menu </dev/null >/dev/null 2>&1; echo \"DISTRO=\$DISTRO_TYPE\"" 2>&1) || true
assert_output_contains "$am" 'DISTRO=[a-z]+'                "AUTO_MODE still skips the menu"

# --- a missing `clear` must not kill the menu --------------------------------
# Minimal servers ship without ncurses; `clear` then exits 127 and, under
# set -e, ended the dashboard and the distro menu with no message.
noclear=$(printf '1\n' | env -i LOG_FILE="$LOG_FILE" PATH=/nonexistent_bin_dir:/usr/bin:/bin TERM=xterm bash -c "
    set -euo pipefail; $_lib
    box_top() { :; }; box_line() { :; }; box_bottom() { :; }
    clear() { return 127; }; export -f clear
    AUTO_MODE=false; show_distro_menu >/dev/null 2>&1; echo \"DISTRO=\$DISTRO_TYPE\"" 2>&1) || true
assert_output_contains "$noclear" 'DISTRO=debian'           "a failing clear does not end the distro menu"

rm -f "$LOG_FILE"
finish
