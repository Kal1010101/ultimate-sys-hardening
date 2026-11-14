#!/bin/bash
# --json and --sarif print the compliance results on stdout and nothing else,
# as documents a script or code scanning can parse. Everything the run prints
# for a person goes to stderr. Read-only, like --cis-only.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"
require_root

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# --- JSON string escaping ---------------------------------------------------------
got=$(bash -c 'source "'"$REPO"'/lib/core.sh"; source "'"$REPO"'/lib/cis.sh"
    _json_string "$(printf "a\"b\\\\c\td\x01e")"; echo; _json_string "$(printf "x\ny")"' 2>&1)
[[ "$(sed -n 1p <<< "$got")" == '"a\"b\\c\td e"' || "$(sed -n 1p <<< "$got")" == '"a\"b\\c\tde"' ]] \
    && pass_msg "quotes, backslashes and tabs are escaped; other control characters dropped" \
    || fail "escaped as $(sed -n 1p <<< "$got")"
[[ "$(sed -n 2p <<< "$got")" == '"x\ny"' ]] \
    && pass_msg "a newline becomes \\n" \
    || fail "newline escaped as $(sed -n 2p <<< "$got")"

id=$(bash -c 'source "'"$REPO"'/lib/core.sh"; source "'"$REPO"'/lib/cis.sh"; _cis_check_id "/etc/passwd permissions are 644 or stricter"')
[[ "$id" == "etc-passwd-permissions-are-644-or-stricter" ]] \
    && pass_msg "check ids are stable slugs of the label" \
    || fail "id is '$id'"

# --- the documents --------------------------------------------------------------
sshd_before=$(checksum /etc/ssh/sshd_config 2>/dev/null)
bash "$FREE_SCRIPT" --json  > "$W/report.json"  2> "$W/json.err";  json_rc=$?
bash "$FREE_SCRIPT" --sarif > "$W/report.sarif" 2> "$W/sarif.err"; sarif_rc=$?

[[ $json_rc -eq 0 && $sarif_rc -eq 0 ]] \
    && pass_msg "both exit 0" || fail "exit codes: json $json_rc, sarif $sarif_rc"
[[ "$(head -c1 "$W/report.json")" == "{" && "$(tail -n1 "$W/report.json")" == "}" ]] \
    && pass_msg "--json: stdout is the document alone" \
    || fail "--json stdout starts '$(head -c 60 "$W/report.json")'"
[[ "$(head -c1 "$W/report.sarif")" == "{" && "$(tail -n1 "$W/report.sarif")" == "}" ]] \
    && pass_msg "--sarif: stdout is the document alone" \
    || fail "--sarif stdout starts '$(head -c 60 "$W/report.sarif")'"
assert_output_contains "$(cat "$W/json.err")" 'platform' "the platform line still reaches stderr"

assert_file_contains "$W/report.json" '"tool": "ultimate-hardening"' "JSON names the tool"
assert_file_contains "$W/report.json" '"id": "ssh-root-login-disabled"' "JSON lists the SSH root login check by id"
assert_file_contains "$W/report.sarif" '"version": "2.1.0"' "SARIF declares version 2.1.0"
assert_file_contains "$W/report.sarif" '"ruleId": "' "SARIF reports at least one failed check (a stock container fails several)"
if grep -q 'CIS Score:' "$W/report.json" "$W/report.sarif"; then
    fail "the terminal score summary leaked into a report"
else
    pass_msg "no terminal summary in either report"
fi

if [[ -n "$sshd_before" ]]; then
    assert_unchanged /etc/ssh/sshd_config "$sshd_before" "reports change nothing on the system"
fi

# Full parse and cross-checks wherever the image has python3.
if command -v python3 >/dev/null 2>&1; then
    if out=$(python3 - "$W/report.json" "$W/report.sarif" << 'PY' 2>&1
import json, sys
j = json.load(open(sys.argv[1]))
s = json.load(open(sys.argv[2]))
checks = j["checks"]
assert j["total"] == len(checks) == j["passed"] + j["failed"], "totals disagree"
assert j["failed"] == sum(1 for c in checks if not c["passed"]), "failed count disagrees"
assert all(" — Suggested fix" not in c["detail"] for c in checks), "fix left in detail"
run = s["runs"][0]
rules = {r["id"] for r in run["tool"]["driver"]["rules"]}
assert len(rules) == len(checks), "one rule per check"
assert len(run["results"]) == j["failed"], "one result per failed check"
for r in run["results"]:
    assert r["ruleId"] in rules, "result names an unknown rule"
    assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("file:///")
print("parsed")
PY
    ); then
        pass_msg "python3 parses both, and their counts, rules and locations agree"
    else
        fail "parse check: $out"
    fi
else
    echo "SKIP: python3 not in this image, so the documents were checked by pattern only"
fi

# --- the two flags together ------------------------------------------------------
out=$(bash "$FREE_SCRIPT" --json --sarif 2>&1); rc=$?
[[ $rc -ne 0 ]] && pass_msg "--json with --sarif is refused" || fail "--json --sarif exited 0"
assert_output_contains "$out" 'cannot be used together' "and the refusal says why"

finish
