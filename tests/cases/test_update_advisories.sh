#!/bin/bash
# The update check also reads the repo's published security advisories and
# warns when the running version is in an affected range. The response is
# JSON parsed without jq, so this feeds it GitHub-shaped input, minified and
# pretty-printed, with the awkward cases: a withdrawn advisory, a range that
# does not parse, a null fixed version, and description text that looks like
# the keys being read.
#
# Needs no root. curl is a function stub: core.sh prepends system dirs to
# PATH, so a PATH stub would be shadowed.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
export LOG_FILE="$W/run.log"

# --- range matching ----------------------------------------------------------
in_range() {
    bash -c "source '$REPO/lib/core.sh'; source '$REPO/lib/update.sh'
        rc=0; _uh_version_in_range \"\$1\" \"\$2\" || rc=\$?; echo \$rc" _ "$1" "$2" 2>/dev/null
}
while IFS='|' read -r ver range want; do
    got=$(in_range "$ver" "$range")
    [[ "$got" == "$want" ]] || fail "range '$range' for $ver: got $got, want $want"
done <<'EOF'
2.6.2|<= 2.6.2|0
2.6.3|<= 2.6.2|1
2.6.2|< 2.6.3|0
2.6.3|< 2.6.3|1
2.3.0|>= 2.3.0, <= 2.6.1|0
2.2.9|>= 2.3.0, <= 2.6.1|1
2.6.2|>= 2.3.0, <= 2.6.1|1
2.6.10|<= 2.6.9|1
2.6.0|2.6.0|0
2.6.1|= 2.6.0|1
2.6.0|> 2.5.9|0
2.6.0|~> 2.6|2
2.6.0||2
2.6.0|<= 2.6|2
EOF
pass_msg "affected ranges are matched bound by bound, and an unreadable one is reported as such"

# --- GitHub-shaped responses -------------------------------------------------
# Three real advisories (trimmed), then a withdrawn one that covers every
# version. The first description holds escaped look-alikes of the keys read.
cat > "$W/adv.json" <<'EOF'
[{"ghsa_id":"GHSA-x3vq-fxmf-vjh3","cve_id":null,"html_url":"https://github.com/Kal1010101/ultimate-sys-hardening/security/advisories/GHSA-x3vq-fxmf-vjh3","summary":"Root writes through a symlinked run log in /var/log","description":"Fake: {\"ghsa_id\":\"GHSA-2222-3333-4444\",\"severity\":\"critical\",\"vulnerable_version_range\":\">= 0.0.0\"}","severity":"medium","identifiers":[{"value":"GHSA-x3vq-fxmf-vjh3","type":"GHSA"}],"state":"published","withdrawn_at":null,"vulnerabilities":[{"package":{"ecosystem":"other","name":"ultimate-sys-hardening"},"vulnerable_version_range":"<= 2.6.2","patched_versions":"2.6.3","vulnerable_functions":[]}],"cvss_severities":{"cvss_v3":{"vector_string":"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H","score":6.7}}},{"ghsa_id":"GHSA-wff7-cm5c-jw75","cve_id":null,"summary":"Local privilege escalation through the compiler revert","description":"x","severity":"high","state":"published","withdrawn_at":null,"vulnerabilities":[{"package":{"ecosystem":"other","name":"ultimate-sys-hardening"},"vulnerable_version_range":">= 2.3.0, <= 2.6.1","patched_versions":"2.6.2","vulnerable_functions":[]}]},{"ghsa_id":"GHSA-q47v-xh3h-vfvv","cve_id":null,"summary":"Local privilege escalation through the SUID/SGID revert","description":"x","severity":"high","state":"published","withdrawn_at":null,"vulnerabilities":[{"package":{"ecosystem":"other","name":"ultimate-sys-hardening"},"vulnerable_version_range":"<= 2.5.0","patched_versions":"2.5.1","vulnerable_functions":[]}]},{"ghsa_id":"GHSA-9999-9999-9999","cve_id":null,"summary":"Withdrawn","description":"x","severity":"critical","state":"withdrawn","withdrawn_at":"2026-11-01T00:00:00Z","vulnerabilities":[{"package":{"ecosystem":"other","name":"ultimate-sys-hardening"},"vulnerable_version_range":">= 0.0.1","patched_versions":null,"vulnerable_functions":[]}]}]
EOF
# The same data as GitHub returns it to some clients: pretty-printed.
if command -v python3 >/dev/null 2>&1; then
    python3 -m json.tool "$W/adv.json" > "$W/adv-pretty.json"
else
    sed 's/,"/,\n  "/g' "$W/adv.json" > "$W/adv-pretty.json"
fi

check() {   # $1 = version, $2 = advisories file (or "FAIL"), then extra shell
    bash -c "set -euo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/update.sh'
        curl() { case \"\$*\" in
            *security-advisories*) [[ '$2' != FAIL ]] && cat '$2' || return 22 ;;
            *) echo '{\"tag_name\": \"v2.6.4\"}' ;; esac; }
        UH_VERSION='$1'
        ${3:-}
        check_for_updates
        echo REACHED" 2>&1
}
strip() { sed 's/\x1b\[[0-9;]*m//g'; }

for f in adv.json adv-pretty.json; do
    out=$(check 2.6.2 "$W/$f" | strip)
    grep -q 'v2.6.2 is affected by GHSA-x3vq-fxmf-vjh3 (medium): Root writes through a symlinked run log in /var/log' <<<"$out" \
        && grep -q 'Fixed in 2.6.3: https://github.com/Kal1010101/ultimate-sys-hardening/security/advisories/GHSA-x3vq-fxmf-vjh3' <<<"$out" \
        && pass_msg "$f: 2.6.2 is warned about the advisory that covers it, with the fixed version and link" \
        || fail "$f: 2.6.2 not warned about GHSA-x3vq-fxmf-vjh3: $out"
    n=$(grep -c 'is affected by' <<<"$out")
    [[ "$n" == 1 ]] && pass_msg "$f: and about nothing else" || fail "$f: $n advisories reported for 2.6.2: $out"
    grep -qE 'GHSA-2222|critical|GHSA-9999' <<<"$out" \
        && fail "$f: description text or a withdrawn advisory was reported: $out" \
        || pass_msg "$f: key look-alikes in a description and withdrawn advisories are ignored"
    grep -q REACHED <<<"$out" && pass_msg "$f: under set -euo pipefail the run carries on" \
                              || fail "$f: the check ended the run: $out"
done

out=$(check 2.5.0 "$W/adv.json" | strip)
for id in GHSA-x3vq-fxmf-vjh3 GHSA-wff7-cm5c-jw75 GHSA-q47v-xh3h-vfvv; do
    grep -q "affected by $id" <<<"$out" || fail "2.5.0 not warned about $id: $out"
done
pass_msg "an older version is warned about every advisory whose range covers it"

out=$(check 2.6.4 "$W/adv.json" | strip)
grep -q 'No published security advisory affects v2.6.4' <<<"$out" && ! grep -q 'affected by' <<<"$out" \
    && pass_msg "a fixed version is told no advisory affects it" || fail "2.6.4: $out"

# --- what cannot be read is said, not skipped --------------------------------
cat > "$W/odd.json" <<'EOF'
[{"ghsa_id":"GHSA-cfgh-jmpq-rvwx","summary":"Odd range \u001b[31mred\u001b[0m and \"quotes\"","severity":"low","withdrawn_at":null,"vulnerabilities":[{"vulnerable_version_range":"~> 2.6","patched_versions":null}]}]
EOF
out=$(check 2.6.2 "$W/odd.json")
grep -q 'Could not tell whether v2.6.2 is affected by GHSA-cfgh-jmpq-rvwx (low)' <<<"$out" \
    && grep -q 'Fixed in no release yet' <<<"$out" \
    && pass_msg "an unreadable range is reported as unknown, and a missing fix as no release yet" \
    || fail "odd range: $out"
summary_line=$(grep 'GHSA-cfgh' <<<"$out" | strip)
[[ "$summary_line" != *$'\x1b'* && "$summary_line" == *'Odd range [31mred[0m and "quotes"'* ]] \
    && pass_msg "escape sequences in advisory text never reach the terminal" \
    || fail "advisory text printed as: $(printf '%q' "$summary_line")"

out=$(check 2.6.2 FAIL)
grep -q 'Security advisory check skipped' <<<"$out" && grep -q REACHED <<<"$out" \
    && pass_msg "a failed advisory request is reported and does not stop the run" \
    || fail "failed advisory request: $out"

finish
