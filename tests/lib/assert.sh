#!/bin/bash
# =============================================================================
#  tests/lib/assert.sh — assertions shared by every test case
#
#  Exit codes: 0 = pass, 1 = fail, 77 = skip (missing prerequisite)
# =============================================================================

REPO_ROOT="${REPO_ROOT:-/repo}"
FREE_SCRIPT="$REPO_ROOT/src/free/ultimate_hardening.sh"
PRO_SCRIPT="$REPO_ROOT/src/pro/ultimate-hardening-pro.sh"
ENTERPRISE_SCRIPT="$REPO_ROOT/src/enterprise/ultimate-hardening-enterprise.sh"

_ASSERT_FAILURES=0

pass_msg() { echo "OK: $*"; }

fail() {
    echo "ASSERT: $*" >&2
    _ASSERT_FAILURES=$((_ASSERT_FAILURES + 1))
}

skip() {
    echo "SKIP: $*"
    exit 77
}

finish() {
    [[ $_ASSERT_FAILURES -eq 0 ]] && exit 0
    echo "FAIL: $_ASSERT_FAILURES assertion(s) failed" >&2
    exit 1
}

# ------------------------------------------------------------- prerequisites --
require_cmd() {
    command -v "$1" >/dev/null 2>&1 || skip "'$1' not available in this image"
}

require_file() {
    [[ -f "$1" ]] || skip "'$1' not present in this image"
}

require_root() {
    [[ $EUID -eq 0 ]] || skip "test requires root"
}

# ---------------------------------------------------------------- assertions --
assert_file_contains() {
    local file="$1" pattern="$2"
    local msg="${3:-$file contains /$pattern/}"
    if [[ ! -f "$file" ]]; then
        fail "$msg — file does not exist"
        return 1
    fi
    if grep -qE "$pattern" "$file" 2>/dev/null; then
        pass_msg "$msg"
        return 0
    fi
    fail "$msg — pattern not found"
    return 1
}

assert_file_not_contains() {
    local file="$1" pattern="$2"
    local msg="${3:-$file does not contain /$pattern/}"
    [[ -f "$file" ]] || { pass_msg "$msg (file absent)"; return 0; }
    if grep -qE "$pattern" "$file" 2>/dev/null; then
        fail "$msg — pattern WAS found"
        return 1
    fi
    pass_msg "$msg"
    return 0
}

assert_file_exists() {
    local file="$1"
    local msg="${2:-$file exists}"
    [[ -e "$file" ]] && { pass_msg "$msg"; return 0; }
    fail "$msg — not found"
    return 1
}

assert_file_absent() {
    local file="$1"
    local msg="${2:-$file absent}"
    [[ ! -e "$file" ]] && { pass_msg "$msg"; return 0; }
    fail "$msg — file exists"
    return 1
}

assert_file_mode() {
    local file="$1" want="$2"
    local msg="${3:-$file mode is $want or stricter}"
    [[ -e "$file" ]] || { fail "$msg — file missing"; return 1; }
    local actual; actual=$(stat -c '%a' "$file" 2>/dev/null)
    if [[ -n "$actual" ]] && [[ "$actual" -le "$want" ]] 2>/dev/null; then
        pass_msg "$msg (actual $actual)"
        return 0
    fi
    fail "$msg — actual $actual"
    return 1
}

assert_unchanged() {
    local file="$1" before="$2"
    local msg="${3:-$file unchanged}"
    local after; after=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
    if [[ "$before" == "$after" ]]; then
        pass_msg "$msg"
        return 0
    fi
    fail "$msg — checksum changed ($before -> $after)"
    return 1
}

assert_changed() {
    local file="$1" before="$2"
    local msg="${3:-$file was modified}"
    local after; after=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
    if [[ "$before" != "$after" ]]; then
        pass_msg "$msg"
        return 0
    fi
    fail "$msg — checksum identical, nothing changed"
    return 1
}

assert_exit_code() {
    local want="$1" got="$2"
    local msg="${3:-exit code is $want}"
    [[ "$want" == "$got" ]] && { pass_msg "$msg"; return 0; }
    fail "$msg — got $got"
    return 1
}

assert_output_contains() {
    local output="$1" pattern="$2"
    local msg="${3:-output matches /$pattern/}"
    if grep -qE "$pattern" <<< "$output"; then
        pass_msg "$msg"
        return 0
    fi
    fail "$msg — not found in output"
    return 1
}

# ---------------------------------------------------------------- utilities --
checksum() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

# Run the free-tier script, capturing output. Never aborts the test on non-zero.
run_hardening() {
    bash "$FREE_SCRIPT" "$@" 2>&1 || true
}
