#!/bin/bash
# Harden, then revert, and confirm files come back to their original content.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root
require_file /etc/ssh/sshd_config

orig_sshd=$(checksum /etc/ssh/sshd_config)
cp /etc/ssh/sshd_config /tmp/sshd_config.orig

# Harden WITH backup this time
run_hardening --auto-mode >/dev/null

assert_changed /etc/ssh/sshd_config "$orig_sshd" "hardening modified sshd_config"

backup=$(find /root -maxdepth 1 -type d -name 'hardening_backup_*' 2>/dev/null | sort | tail -1)
if [[ -z "$backup" ]]; then
    fail "no backup directory was created"
    finish
fi
pass_msg "backup created at $backup"
assert_file_exists "$backup/files/etc/ssh/sshd_config" "sshd_config captured in backup"

# Revert
run_hardening --revert >/dev/null

after_revert=$(checksum /etc/ssh/sshd_config)
if [[ "$after_revert" == "$orig_sshd" ]]; then
    pass_msg "revert restored sshd_config byte-for-byte"
else
    fail "revert did NOT restore sshd_config to its original content"
    diff /tmp/sshd_config.orig /etc/ssh/sshd_config | head -10 >&2
fi

assert_file_absent /etc/sysctl.d/99-hardening.conf "revert removed the sysctl drop-in"

finish
