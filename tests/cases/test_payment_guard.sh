#!/bin/bash
# pre-push refuses commits whose message or added lines carry payment account
# details or payment test/error notes, and lets ordinary work through.
#
# Runs in a scratch repository with a scratch bare "remote". Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"
HOOKS="$REPO/scripts/hooks"
require_cmd git

[[ -x "$HOOKS/pre-push" && -f "$HOOKS/payment-guard.sh" ]] || { fail "payment guard hooks are missing"; finish; }

W="${TMPDIR:-/tmp}/uh_payguard_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT
git init -q --bare "$W/remote.git"
git init -q -b main "$W/work"
cd "$W/work" || exit 1
git config user.name t; git config user.email t@t; git config commit.gpgsign false
git config core.hooksPath "$HOOKS"
git remote add origin "$W/remote.git"
printf 'start\n' > base.txt; git add base.txt; git commit -q --no-verify -m "Start"
git push -q origin main >/dev/null 2>&1 || { fail "first clean push was refused"; finish; }

card_digits() { printf '%s' 4242; }

# $1 = expect (refuse|allow), $2 = description, $3 = message, $4 = file content
try_push() {
    printf '%s\n' "$4" > "change.txt"; git add change.txt
    git commit -q --no-verify -m "$3"
    if git push -q origin main >/dev/null 2>&1; then
        [[ "$1" == allow ]] && pass_msg "push allowed: $2" || fail "push let through: $2"
    else
        if [[ "$1" == refuse ]]; then pass_msg "push refused: $2"; else fail "push refused: $2"; fi
        git reset -q --hard HEAD~1
    fi
}

try_push refuse "a payment account ID in a file"   "Update notes" "acct_$(printf 'A%.0s' {1..16})"
try_push refuse "a payment link"                   "Update notes" "see https://buy.stripe.com/abc"
try_push refuse "a test card number"               "Update notes" "paid with $(card_digits) $(card_digits) $(card_digits) $(card_digits)"
try_push refuse "a test purchase in the message"   "Note the test purchase" "x"
try_push refuse "a tax mismatch note"              "Update notes" "the tax setting has a mismatch between tiers"
try_push refuse "a payment error note"             "Payment error on renewal" "x"
try_push allow  "git checkout and CI checkout"     "Pin checkout action" "run: git checkout v2; uses: actions/checkout@v5"
try_push allow  "list prices"                      "Update pricing" "Pro is \$9/month, Enterprise \$49/month"
try_push allow  "ordinary failing-test work"       "Fix a failing test" "the test failed on a stale checkout of the repo"

mkdir -p scripts/hooks
printf '%s\n' "see https://buy.stripe.com/abc" > scripts/hooks/payment-guard.sh
git add scripts/hooks/payment-guard.sh; git commit -q --no-verify -m "Update the guard"
git push -q origin main >/dev/null 2>&1 && pass_msg "push allowed: the guard's own pattern file" \
    || { fail "push refused: the guard's own pattern file"; git reset -q --hard HEAD~1; }
printf '%s\n' "see https://buy.stripe.com/abd" > scripts/hooks/payment-guard.sh
try_push refuse "the same text in another file of a commit that also touches the guard" "Update the guard" "see https://buy.stripe.com/abd"

git tag -a v9-m "Release with a test payment" HEAD 2>/dev/null
git push -q origin v9 >/dev/null 2>&1 && fail "push let through: a payment test note in a tag message" \
    || pass_msg "push refused: a payment test note in a tag message"

finish
