#!/bin/bash
# run_cis_checks must print a parseable score. This is the regression test
# for the `return 0` that made the entire summary block unreachable.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root

out=$(run_hardening --cis-only)

assert_output_contains "$out" "CIS Score: [0-9]+%" "score line is printed"
assert_output_contains "$out" "checks passed"      "check tally is printed"

score=$(grep -oE 'CIS Score: [0-9]+' <<< "$out" | grep -oE '[0-9]+' | head -1)
if [[ -z "$score" ]]; then
    fail "score could not be parsed from output"
elif [[ "$score" -lt 0 || "$score" -gt 100 ]]; then
    fail "score $score is out of range"
else
    pass_msg "score parsed as ${score}% and in range"
fi

# --cis-only must be strictly read-only
[[ -f /etc/ssh/sshd_config ]] && {
    b=$(checksum /etc/ssh/sshd_config)
    run_hardening --cis-only >/dev/null
    assert_unchanged /etc/ssh/sshd_config "$b" "--cis-only modified nothing"
}

finish
