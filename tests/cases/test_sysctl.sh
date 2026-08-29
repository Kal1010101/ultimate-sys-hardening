#!/bin/bash
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root
[[ -d /etc/sysctl.d ]] || skip "/etc/sysctl.d not present"

run_hardening --auto-mode --skip-backup >/dev/null

f=/etc/sysctl.d/99-hardening.conf
assert_file_exists "$f" "sysctl drop-in created"
assert_file_contains "$f" '^kernel\.randomize_va_space = 2' "ASLR set"
assert_file_contains "$f" '^net\.ipv4\.tcp_syncookies = 1'  "SYN cookies set"
assert_file_contains "$f" '^kernel\.kptr_restrict = 2'      "kptr restricted"
assert_file_contains "$f" '^fs\.suid_dumpable = 0'          "SUID dumps disabled"

# Idempotency: second run must not duplicate entries
run_hardening --auto-mode --skip-backup >/dev/null
n=$(grep -c '^kernel\.randomize_va_space' "$f")
[[ "$n" -eq 1 ]] && pass_msg "idempotent: one randomize_va_space line" \
                 || fail "not idempotent: $n randomize_va_space lines"
finish
