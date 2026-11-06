# shellcheck shell=bash
# Shared by pre-push: payment account details and payment test or error reports
# never leave this machine. Reads text on stdin, prints each offending line.

PAYMENT_ID_RE='\<(acct|prod|price|plink|cus|sub|pi|ch|in|cs|pm|seti|txr|txn)_(test_|live_)?[A-Za-z0-9]{14,}|\<txcd_[0-9]{8}|\<(sk|pk|rk)_(test|live)_[A-Za-z0-9]{8,}|\<whsec_[A-Za-z0-9]{8,}|(buy|checkout|dashboard|billing)\.stripe\.com'
PAYMENT_CARD_RE='(^|[^0-9])[2-6][0-9]{3}([ -]?[0-9]{4}){3}([^0-9]|$)'
PAYMENT_TOPIC_RE='\<(stripe|paddle|lemon ?squeezy|payments?|checkout (pages?|sessions?|links?|flow)|hosted checkout|billing|invoices?|charges?|charged|refunds?|refunded|subscriptions?|purchases?|merchant|tax|taxes)\>'
PAYMENT_PROBLEM_RE='\<(sandbox|mismatch(ed|es)?|inconsisten(t|cy)|bugs?|errors?|fail(s|ed|ure)?|wrong|broken|incorrect|leaks?|bypass(es|ed)?|workaround|weakness(es)?|exploits?|loophole|double[- ]charged?)\>'
PAYMENT_TEST_RE='\<test (cards?|purchases?|charges?|payments?|transactions?)\>|\<(sandbox|live) (checkout|purchase|charge|payment)s?\>'
PAYMENT_GUARD_FILES='scripts/hooks/payment-guard.sh scripts/hooks/pre-push tests/cases/test_payment_guard.sh'
PAYMENT_SAFE_RE='git checkout|actions/checkout|checkout@[a-z0-9.]+'

# payment_guard_scan -> prints offending lines from stdin; returns 1 if any.
payment_guard_scan() {
    local text hits
    text=$(cat)
    hits=$(
        grep -E -e "$PAYMENT_ID_RE" -e "$PAYMENT_CARD_RE" <<<"$text"
        grep -E -i -e "$PAYMENT_TEST_RE" <<<"$text"
        sed -E "s#($PAYMENT_SAFE_RE)##Ig" <<<"$text" | grep -E -i -e "$PAYMENT_TOPIC_RE" | grep -E -i -e "$PAYMENT_PROBLEM_RE"
    )
    [[ -z "$hits" ]] && return 0
    printf '%s\n' "$hits"
    return 1
}

# payment_added_lines COMMIT -> added lines of COMMIT, except in the guard's own files.
payment_added_lines() {
    git show --no-color --format= -p "$1" | awk -v skip=" $PAYMENT_GUARD_FILES " '
        /^\+\+\+ / { path = substr($0, 7); next }
        /^\+/ && index(skip, " " path " ") == 0 { print substr($0, 2) }'
}
