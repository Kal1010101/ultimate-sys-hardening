#!/bin/bash
# `cmd | grep -q pattern` is unreliable under `set -o pipefail`, which every
# tier runs with: grep -q exits on the first match, cmd can then be killed by
# SIGPIPE while still writing, and the pipeline reports failure although the
# pattern was found. It made module 3 report "nothing was applied" on a host
# where the rules had loaded. Capture first, then search:
#     grep -q pattern <<<"$(cmd)"
# A grep on a file (`grep -q pattern file`) is fine and not matched here.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

# Lines continued with a trailing `\` or `|` are joined first, so a pipe split
# across lines is still one pipeline. Then: a single `|` (not `||`) followed by
# grep with -q (or --quiet/--silent) among its flags, in any position
# (`grep -q`, `grep -Eq`, `grep -E -q`), on a line that is not a comment.
# Prints file:first-line:joined-text.
join_continued() {
    awk '
        FNR == 1 { if (buf != "") print file ":" start ":" buf; buf = "" }
        {
            line = $0
            if (buf == "") { start = FNR; file = FILENAME }
            if (line ~ /\\[[:space:]]*$/) { sub(/\\[[:space:]]*$/, " ", line); buf = buf line; next }
            if (line ~ /[^|]\|[[:space:]]*$/ && line !~ /^[[:space:]]*#/) { buf = buf line " "; next }
            print file ":" start ":" buf line; buf = ""
        }
        END { if (buf != "") print file ":" start ":" buf }
    ' "$@"
}
PIPE_INTO_GREP_Q='(^|[^|])\|[[:space:]]*grep([[:space:]]+-[A-Za-z]+|[[:space:]]+--[a-z-]+)*[[:space:]]+(-[A-Za-z]*q|--quiet|--silent)'
hits=$(join_continued "$REPO"/lib/*.sh "$REPO"/src/free/*.sh 2>/dev/null \
    | grep -E "$PIPE_INTO_GREP_Q" | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true)

# The detector itself: each form below must be caught, and the safe ones not.
caught() { join_continued <(printf '%s\n' "$@") | grep -qE "$PIPE_INTO_GREP_Q"; }
for bad in 'cmd | grep -q x' 'cmd | grep -Eq x' 'cmd | grep -E -q x' 'cmd | grep -E --quiet x' 'cmd |' 'cmd \'; do
    case "$bad" in
        'cmd |')  caught 'cmd |' '    grep -q x' ;;
        'cmd \') caught 'cmd \' '    | grep -E -q x' ;;
        *)        caught "$bad" ;;
    esac || fail "the check misses: $bad"
done
for good in 'cmd || grep -q x f' 'grep -q x <<<"$(cmd)"' 'cmd | grep -v x' 'cmd | grep -o q'; do
    caught "$good" && fail "the check wrongly flags: $good"
done

if [[ -n "$hits" ]]; then
    fail "pipe into grep -q (use grep -q ... <<<\"\$(cmd)\"): $(head -3 <<<"$hits" | tr '\n' ';')"
else
    pass_msg "no command is piped into grep -q in lib/ or src/free/"
fi

# The same SIGPIPE applies to every reader that stops early: head, grep -m N
# and awk with exit. There the output is still right, but the pipeline's
# status is not, and under `set -e` that ends the run. Each such pipe needs a
# `||` on the line to handle the status (usually `|| true`), or must read
# captured output instead: `head -n 1 <<<"$(cmd)"`.
EARLY_EXIT_READER='(^|[^|])\|[[:space:]]*(head([[:space:]]|\)|$)|grep([[:space:]]+-[A-Za-z]+)*[[:space:]]+-[A-Za-z]*m[[:space:]]*[0-9]|awk[[:space:]][^|]*[^A-Za-z_]exit([^A-Za-z_]|$))'
unguarded=$(join_continued "$REPO"/lib/*.sh "$REPO"/src/free/*.sh 2>/dev/null \
    | grep -E "$EARLY_EXIT_READER" | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' | grep -v '||' || true)

caught_early() { join_continued <(printf '%s\n' "$@") | grep -E "$EARLY_EXIT_READER" | grep -qv '||'; }
for bad in 'x=$(cmd | head -n 1)' 'x=$(cmd | head)' 'cmd | head -5' 'cmd | grep -m1 x' 'cmd | grep -E -m 1 x' \
           'cmd | awk "/x/ { print; exit }"'; do
    caught_early "$bad" || fail "the check misses: $bad"
done
for good in 'x=$(cmd | head -n 1 || true)' 'x=$(cmd | head -1) || return 0' 'head -n 1 <<<"$(cmd)"' \
            'grep -m1 x <<<"$response"' 'cmd | header' 'cmd | awk "{ print }"'; do
    caught_early "$good" && fail "the check wrongly flags: $good"
done

if [[ -n "$unguarded" ]]; then
    fail "early-exit reader on a pipe with no || (add || true, or read captured output): $(head -3 <<<"$unguarded" | tr '\n' ';')"
else
    pass_msg "every pipe into head, grep -m or awk exit in lib/ or src/free/ handles its status"
fi

finish
