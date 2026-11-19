#!/bin/bash
# Module 8 sets a 365-day password maximum age, not the old 90, and the
# --cis-only check passes at 365 days or fewer. Forced 90-day rotation is no
# longer recommended (current CIS Benchmarks use 365; NIST SP 800-63B advises
# against periodic changes).
#
# Edits the container's /etc/login.defs and puts it back at the end.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"
require_root

DEFS=/etc/login.defs
had_defs=false
if [[ -f "$DEFS" ]]; then
    had_defs=true
    cp -a "$DEFS" /tmp/login.defs.pmax.bak
fi
restore_defs() {
    if [[ "$had_defs" == true ]]; then
        cp -a /tmp/login.defs.pmax.bak "$DEFS"
    else
        rm -f "$DEFS"
    fi
}
trap restore_defs EXIT

strip() { sed 's/\x1b\[[0-9;]*m//g'; }

# $1 = PASS_MAX_DAYS value. Prints the --cis-only line for the max-age check.
max_age_line() {
    printf 'PASS_MAX_DAYS\t%s\nPASS_MIN_DAYS\t1\nPASS_WARN_AGE\t14\n' "$1" > "$DEFS"
    run_hardening --cis-only | strip | grep 'Password max age' | head -1
}

# --- the check ----------------------------------------------------------------
line=$(max_age_line 365)
assert_output_contains "$line" '✅ +Password max age is 365 days or fewer' \
    "365 days passes the check"
line=$(max_age_line 90)
assert_output_contains "$line" '✅ +Password max age is 365 days or fewer' \
    "a shorter max age still passes"
line=$(max_age_line 366)
assert_output_contains "$line" 'Password max age is 365 days or fewer — Currently 366' \
    "366 days fails the check"
line=$(max_age_line 99999)
assert_output_contains "$line" 'Currently 99999' \
    "the distribution default (no expiry) fails the check"

# --- the module ----------------------------------------------------------------
printf 'PASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\nPASS_WARN_AGE\t7\n' > "$DEFS"
out=$(bash -c 'source "'"$REPO"'/lib/core.sh"
               source "'"$REPO"'/lib/platform.sh"
               source "'"$REPO"'/lib/modules.sh"
               DRY_RUN=false LOG_FILE=/dev/null
               apply_password_policies' 2>&1 | strip)
assert_file_contains "$DEFS" '^PASS_MAX_DAYS	365$' "module 8 sets a 365-day max age"
assert_file_contains "$DEFS" '^PASS_WARN_AGE	14$' "module 8 still sets a 14-day warning"
assert_output_contains "$out" '365-day max' "module 8 reports the 365-day max"

finish
