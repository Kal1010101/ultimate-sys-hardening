#!/bin/bash
# SUID hardening must strip non-essential bits but preserve the safe list.
# fusermount is explicitly guarded — stripping it breaks Flatpak and FUSE.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root

# Create a decoy SUID binary that SHOULD be stripped
cp /bin/true /usr/local/bin/uh-decoy 2>/dev/null || skip "cannot create decoy binary"
chmod 4755 /usr/local/bin/uh-decoy

# And a fake fusermount that must NOT be stripped
mkdir -p /usr/bin
cp /bin/true /usr/bin/fusermount 2>/dev/null || true
chmod 4755 /usr/bin/fusermount 2>/dev/null || true

run_hardening --auto-mode >/dev/null

# Decoy lost its SUID
if [[ -u /usr/local/bin/uh-decoy ]]; then
    fail "decoy binary still has SUID — hardening did not strip it"
else
    pass_msg "decoy binary SUID stripped"
fi

# fusermount kept its SUID (Flatpak regression guard)
if [[ -f /usr/bin/fusermount ]]; then
    if [[ -u /usr/bin/fusermount ]]; then
        pass_msg "fusermount SUID preserved (Flatpak safe)"
    else
        fail "fusermount lost SUID — this breaks Flatpak and FUSE mounts"
    fi
fi

# sudo must never lose SUID — that's an unrecoverable box
if [[ -f /usr/bin/sudo ]]; then
    [[ -u /usr/bin/sudo ]] && pass_msg "sudo SUID preserved" \
                           || fail "sudo lost SUID — system is now unrecoverable"
fi

# Inventory recorded for revert
inv=$(find /root -name 'suid_sgid_original_perms.txt' 2>/dev/null | head -1)
[[ -n "$inv" ]] && pass_msg "SUID inventory recorded" || fail "no SUID inventory written"
finish
