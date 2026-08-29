#!/bin/bash
# SSH module must apply settings AND leave a config sshd accepts.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root
require_file /etc/ssh/sshd_config

before=$(checksum /etc/ssh/sshd_config)
run_hardening --auto-mode --skip-backup >/dev/null

assert_changed /etc/ssh/sshd_config "$before" "sshd_config was modified"
assert_file_contains /etc/ssh/sshd_config '^PermitRootLogin[[:space:]]+no'        "root login disabled"
assert_file_contains /etc/ssh/sshd_config '^PasswordAuthentication[[:space:]]+no' "password auth disabled"
assert_file_contains /etc/ssh/sshd_config '^X11Forwarding[[:space:]]+no'          "X11 forwarding disabled"
assert_file_contains /etc/ssh/sshd_config '^MaxAuthTries[[:space:]]+3'            "MaxAuthTries set to 3"

# The config must be valid — a broken one locks operators out.
if command -v sshd >/dev/null 2>&1; then
    if sshd -t 2>/dev/null; then
        pass_msg "sshd -t accepts the hardened config"
    else
        fail "sshd -t REJECTS the hardened config — this would lock users out"
    fi
fi

# Running twice must not duplicate directives.
run_hardening --auto-mode --skip-backup >/dev/null
n=$(grep -cE '^PermitRootLogin[[:space:]]' /etc/ssh/sshd_config)
[[ "$n" -eq 1 ]] && pass_msg "idempotent: one PermitRootLogin line" \
                 || fail "not idempotent: $n PermitRootLogin lines after 2 runs"
finish
