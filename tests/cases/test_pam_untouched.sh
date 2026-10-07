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

[[ ${#before[@]} -gt 0 ]] || fail "no PAM files found to snapshot — the guard would check nothing"

# Module 1's package upgrade may legitimately replace a vendor PAM file
# (rockylinux:8: systemd 239-78 -> 239-82 rewrites systemd-user). Excused
# only when the package manager confirms the file is package-owned and
# byte-identical to the installed package; any edit by the tool fails that.
pkg_pristine() {
    local f="$1" pkg
    [[ -f "$f" ]] || return 1
    if command -v rpm >/dev/null 2>&1 && rpm -qf "$f" >/dev/null 2>&1; then
        ! rpm -Vf "$f" 2>/dev/null | awk -v f="$f" '$NF==f && substr($1,3,1)=="5"' | grep -q .
        return
    fi
    if command -v dpkg >/dev/null 2>&1; then
        pkg=$(dpkg -S "$f" 2>/dev/null | head -1 | cut -d: -f1)
        [[ -n "$pkg" ]] || return 1
        ! dpkg --verify "$pkg" 2>/dev/null | awk -v f="$f" '$NF==f && substr($1,3,1)=="5"' | grep -q .
        return
    fi
    return 1
}

run_hardening --auto-mode --skip-backup >/dev/null

changed=0
for f in "${!before[@]}"; do
    after=$(checksum "$f")
    if [[ "${before[$f]}" != "$after" ]]; then
        if pkg_pristine "$f"; then
            pass_msg "changed by a package upgrade and identical to its package: $f"
        else
            fail "PAM file was MODIFIED: $f"
            changed=$((changed+1))
        fi
    fi
done
[[ $changed -eq 0 ]] && pass_msg "all ${#before[@]} PAM files untouched by the tool"

# No faillock/pwquality injection
assert_file_not_contains /etc/pam.d/common-auth 'pam_faillock' "no pam_faillock injected"
assert_file_absent /etc/security/pwquality.conf.uh-backup "no pwquality tampering"

finish
