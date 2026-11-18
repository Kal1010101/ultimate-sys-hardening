#!/bin/bash
# =============================================================================
#  scripts/pr-risk-check.sh — flag the parts of a pull request a reviewer must
#  read closely
#
#  Usage: scripts/pr-risk-check.sh <base-commit> <head-commit>
#
#  Compares head against its merge base with base, as a pull request does, and
#  reports:
#    BLOCK  hidden or bidirectional Unicode in added lines (text that reads
#           differently from what runs; the "Trojan Source" attack)
#    WARN   changes to files that control CI, packaging, installation or
#           updates; binary files; symlinks; files made executable; long
#           encoded blobs; new download or network calls; new eval/exec
#
#  Exit codes: 0 = nothing that blocks (warnings may be printed), 1 = at least
#  one BLOCK finding, 2 = usage error.
#
#  This flags; it does not decide. Code written to look harmless gets past any
#  pattern list, so a human still reads every code change. The point is that
#  the risky parts of a PR cannot go unnoticed.
#
#  It runs on untrusted PR content, so it only ever reads it: no file from the
#  PR is sourced or executed, and git's external diff and textconv drivers are
#  turned off. The workflow runs the copy of this script from the base branch,
#  so a PR cannot weaken the check it is being checked by.
# =============================================================================
set -euo pipefail

# Paths whose changes deserve a close read whatever the diff looks like. They
# decide what CI runs, what gets installed, how releases are built and how the
# tool updates itself.
SENSITIVE_PATH_PATTERN='^(\.github/|packaging/|scripts/|ansible/|tests/run\.sh$|tests/lib/|lib/update\.sh$|install\.sh$|uninstall\.sh$|\.gitattributes$)'

# Hidden and direction-changing characters, as UTF-8 byte sequences: zero-width
# space/joiners (U+200B-200D), bidi embeddings and overrides (U+202A-202E),
# word joiner (U+2060), bidi isolates (U+2066-2069), byte order mark (U+FEFF).
HIDDEN_UNICODE_PATTERN='\xE2\x80[\x8B-\x8D\xAA-\xAE]|\xE2\x81[\xA0\xA6-\xA9]|\xEF\xBB\xBF'

# A base64-like run this long is a blob, not prose or a hash (the CSP hashes
# in docs/demo.html are 44 characters).
ENCODED_BLOB_MIN_LENGTH=200
ENCODED_BLOB_PATTERN="[A-Za-z0-9+/=]{${ENCODED_BLOB_MIN_LENGTH},}"

NETWORK_CALL_PATTERN='(^|[^[:alnum:]_-])(curl|wget|nc|ncat|socat|telnet)([^[:alnum:]_-]|$)|/dev/(tcp|udp)/|\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da)?sh([^[:alnum:]_]|$)'
DYNAMIC_EXEC_PATTERN='(^|[^[:alnum:]_-])(eval|exec)([^[:alnum:]_-]|$)|(bash|sh)[[:space:]]+-c[[:space:]]|source[[:space:]]+<\('

block_count=0
warn_count=0
summary_rows=()

usage() {
    echo "Usage: $0 <base-commit> <head-commit>" >&2
    exit 2
}

# GitHub workflow-command property escaping, so a crafted file name cannot
# break out of the annotation and issue a command of its own.
escape_property() {
    local value=$1
    value=${value//'%'/'%25'}
    value=${value//$'\r'/'%0D'}
    value=${value//$'\n'/'%0A'}
    value=${value//':'/'%3A'}
    value=${value//','/'%2C'}
    printf '%s' "$value"
}

# Markdown table cell: keep file names inert in the job summary.
escape_cell() {
    local value=$1
    value=${value//'|'/'\|'}
    value=${value//'`'/"'"}
    printf '%s' "$value"
}

# report LEVEL FILE LINE TITLE MESSAGE. LINE may be empty. Never echoes PR
# content itself, only where it is and what kind of finding it is.
report() {
    local level=$1 file=$2 line=$3 title=$4 message=$5
    if [[ "$level" == BLOCK ]]; then
        block_count=$((block_count + 1))
    else
        warn_count=$((warn_count + 1))
    fi

    local location=$file${line:+:$line}
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        local command=warning
        [[ "$level" == BLOCK ]] && command=error
        local properties
        properties="file=$(escape_property "$file")"
        [[ -n "$line" ]] && properties+=",line=$line"
        properties+=",title=$(escape_property "$title")"
        echo "::${command} ${properties}::$(escape_property "$message")"
    else
        printf '%-5s %s: %s (%s)\n' "$level" "$title" "$message" "$location"
    fi
    summary_rows+=("| $level | $(escape_cell "$title") | \`$(escape_cell "$location")\` |")
}

# Git with every way of running repository-supplied programs turned off.
safe_git() {
    git -c core.quotePath=true -c diff.external= "$@"
}

# Added lines of text files as "<file>\t<line number>\t<content>".
added_lines() {
    safe_git diff --no-ext-diff --no-textconv --no-color -U0 "$merge_base" "$head" \
        | LC_ALL=C awk '
            /^\+\+\+ / {
                file = substr($0, 5)
                sub(/^b\//, "", file)
                next
            }
            /^@@ / {
                split($3, range, ",")
                line = substr(range[1], 2) + 0
                next
            }
            /^\+/ && file != "/dev/null" {
                print file "\t" line "\t" substr($0, 2)
                line++
            }'
}

check_changed_paths() {
    local status file
    while IFS=$'\t' read -r status file; do
        [[ "$status" == D ]] && continue
        if LC_ALL=C grep -qE "$SENSITIVE_PATH_PATTERN" <<<"$file"; then
            report WARN "$file" "" "Sensitive file changed" \
                "Controls CI, packaging, installation or updates; read every line"
        fi
    done < <(safe_git diff --no-ext-diff --name-status --no-renames "$merge_base" "$head")
}

check_binary_files() {
    local added deleted file
    while IFS=$'\t' read -r added deleted file; do
        [[ "$added" == - && "$deleted" == - ]] || continue
        report WARN "$file" "" "Binary file" \
            "Contents cannot be reviewed in the diff; confirm what it is and where it came from"
    done < <(safe_git diff --no-ext-diff --no-textconv --numstat --no-renames "$merge_base" "$head")
}

check_file_modes() {
    local summary_line file
    while IFS= read -r summary_line; do
        file=${summary_line##* }
        case "$summary_line" in
            *" mode 120000 "*)
                report WARN "$file" "" "Symlink added" \
                    "A symlink can point outside the repository" ;;
            *"create mode 100755 "*|*"=> 100755 "*)
                report WARN "$file" "" "Executable file" \
                    "New or newly executable file; check what runs it" ;;
        esac
    done < <(safe_git diff --no-ext-diff --summary --no-renames "$merge_base" "$head")
}

check_added_lines() {
    local file line content
    while IFS=$'\t' read -r file line content; do
        if LC_ALL=C grep -qP "$HIDDEN_UNICODE_PATTERN" <<<"$content"; then
            report BLOCK "$file" "$line" "Hidden Unicode" \
                "Zero-width or bidirectional control character; the text may not be what it looks like"
        fi
        if LC_ALL=C grep -qE "$ENCODED_BLOB_PATTERN" <<<"$content"; then
            report WARN "$file" "$line" "Encoded blob" \
                "Long base64-like string; decode it and check what it is"
        fi
        if LC_ALL=C grep -qE "$NETWORK_CALL_PATTERN" <<<"$content"; then
            report WARN "$file" "$line" "Network or download call" \
                "Downloads, connects out or pipes into a shell; check the destination"
        fi
        if LC_ALL=C grep -qE "$DYNAMIC_EXEC_PATTERN" <<<"$content"; then
            report WARN "$file" "$line" "Dynamic execution" \
                "eval, exec or sh -c can run text built at run time; check where it comes from"
        fi
    done < <(added_lines)
}

write_summary() {
    local verdict="No risky patterns found."
    (( warn_count > 0 )) && verdict="$warn_count item(s) to read closely."
    (( block_count > 0 )) && verdict="$block_count blocking finding(s), $warn_count warning(s)."

    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        {
            echo "## PR risk check"
            echo
            echo "$verdict This check flags; a person still reviews every code change."
            if (( ${#summary_rows[@]} > 0 )); then
                echo
                echo "| Level | Finding | Where |"
                echo "|---|---|---|"
                printf '%s\n' "${summary_rows[@]}"
            fi
        } >>"$GITHUB_STEP_SUMMARY"
    fi
    echo "PR risk check: $verdict"
}

main() {
    [[ $# -eq 2 ]] || usage
    local base=$1
    head=$2

    safe_git rev-parse --verify --quiet "$base^{commit}" >/dev/null \
        || { echo "ERROR: base commit '$base' not found in this repository" >&2; exit 2; }
    safe_git rev-parse --verify --quiet "$head^{commit}" >/dev/null \
        || { echo "ERROR: head commit '$head' not found in this repository" >&2; exit 2; }
    merge_base=$(safe_git merge-base "$base" "$head") \
        || { echo "ERROR: '$base' and '$head' share no history" >&2; exit 2; }

    check_changed_paths
    check_binary_files
    check_file_modes
    check_added_lines
    write_summary

    (( block_count == 0 ))
}

main "$@"
