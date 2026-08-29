#!/bin/bash
# Running twice must converge: the second run changes nothing further.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root

run_hardening --auto-mode --skip-backup >/dev/null

declare -A snap
for f in /etc/ssh/sshd_config /etc/sysctl.d/99-hardening.conf \
         /etc/login.defs /etc/fail2ban/jail.local; do
    [[ -f "$f" ]] && snap["$f"]=$(checksum "$f")
done

run_hardening --auto-mode --skip-backup >/dev/null

for f in "${!snap[@]}"; do
    assert_unchanged "$f" "${snap[$f]}" "$(basename "$f") stable across runs"
done
finish
