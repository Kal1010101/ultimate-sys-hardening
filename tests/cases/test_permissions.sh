#!/bin/bash
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root

chmod 666 /etc/passwd 2>/dev/null || true
chmod 666 /etc/shadow 2>/dev/null || true

run_hardening --auto-mode --skip-backup >/dev/null

assert_file_mode /etc/passwd  644 "/etc/passwd tightened"
assert_file_mode /etc/shadow  640 "/etc/shadow tightened"
assert_file_mode /etc/group   644 "/etc/group tightened"
[[ -f /etc/gshadow ]] && assert_file_mode /etc/gshadow 640 "/etc/gshadow tightened"
finish
