#!/bin/bash
# PAM modification once locked an eCryptfs box out of its login screen.
# It must never come back. This test is the guard.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root

if [[ ! -d /etc/pam.d ]]; then
    skip "/etc/pam.d not present in this image"
fi

# Snapshot every PAM file
declare -A before
while IFS= read -r f; do before["$f"]=$(checksum "$f"); done \
    < <(find /etc/pam.d -type f 2>/dev/null)

run_hardening --auto-mode --skip-backup >/dev/null

changed=0
for f in "${!before[@]}"; do
    after=$(checksum "$f")
    if [[ "${before[$f]}" != "$after" ]]; then
        fail "PAM file was MODIFIED: $f"
        changed=$((changed+1))
    fi
done
[[ $changed -eq 0 ]] && pass_msg "all ${#before[@]} PAM files untouched"

# No faillock/pwquality injection
assert_file_not_contains /etc/pam.d/common-auth 'pam_faillock' "no pam_faillock injected"
assert_file_absent /etc/security/pwquality.conf.uh-backup "no pwquality tampering"

finish
