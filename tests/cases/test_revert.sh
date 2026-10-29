#!/bin/bash
# Harden, then revert, and confirm files come back to their original content.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root
require_file /etc/ssh/sshd_config

orig_sshd=$(checksum /etc/ssh/sshd_config)
cp /etc/ssh/sshd_config /tmp/sshd_config.orig

mkdir -p /etc/docker
printf '{ "debug": true }\n' > /etc/docker/daemon.json
had_jail=false; [[ -f /etc/fail2ban/jail.local ]] && had_jail=true

# Harden WITH backup this time
run_hardening --auto-mode >/dev/null
# Where fail2ban could not be installed, put the module's own jail.local in
# place by hand, so the revert below still has one to remove.
if [[ "$had_jail" == false && ! -f /etc/fail2ban/jail.local ]]; then
    mkdir -p /etc/fail2ban
    bash -c 'R="${REPO_ROOT:-/repo}"; source "$R/lib/core.sh"; source "$R/lib/platform.sh"
             source "$R/lib/modules.sh"; _fail2ban_jail_local' > /etc/fail2ban/jail.local 2>/dev/null
fi
made_jail=false; [[ "$had_jail" == false && -s /etc/fail2ban/jail.local ]] && made_jail=true

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
assert_file_absent /etc/ssh/sshd_config.d/00-ultimate-hardening.conf "revert removed the sshd drop-in"
[[ "$made_jail" == true ]] && assert_file_absent /etc/fail2ban/jail.local "revert removed the jail.local it created"
[[ "$(cat /etc/docker/daemon.json 2>/dev/null)" == '{ "debug": true }' ]] \
    && pass_msg "revert left the admin's own daemon.json alone" \
    || fail "revert changed or removed an admin daemon.json it never wrote"

finish
