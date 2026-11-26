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

# One result is one line: a newline or carriage return in a label or detail
# becomes a space, in every state, so no export that reads results line by
# line (the Enterprise state DB pack) can be handed a forged extra row.
out=$(bash -c 'source "$1/lib/core.sh"; source "$1/lib/platform.sh"; source "$1/lib/modules.sh"; source "$1/lib/cis.sh"
               UH_QUIET_CHECKS=true LOG_FILE=/dev/null
               record_check $'"'"'two\nline'"'"' false $'"'"'one\r\nforged|false|row'"'"'
               record_check w waived $'"'"'a\nb'"'"'; record_check u unchecked $'"'"'c\rd'"'"'
               printf "%s\n" "${CHECK_RESULTS[@]}"' _ "${REPO_ROOT:-/repo}" 2>&1)
[[ "$(wc -l <<<"$out")" == 3 ]] && grep -q '^two line|false|one  forged|false|row' <<<"$out" \
    && grep -qx 'w|waived|a b' <<<"$out" && grep -qx 'u|unchecked|c d' <<<"$out" \
    && pass_msg "newlines in check labels and details become spaces (one result, one line)" \
    || fail "multi-line check result: $out"

finish
