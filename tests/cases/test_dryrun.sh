#!/bin/bash
# =============================================================================
#  Dry-run must produce full output AND leave the system byte-identical.
#
#  This test snapshots every file the hardening can touch BEFORE the run and
#  compares afterwards, rather than relying on a file being absent to begin
#  with. The earlier version only checked the sysctl drop-in when it did not
#  already exist, so leftover state from a prior test silently disabled the
#  assertion — a real dry-run write escaped detection.
# =============================================================================
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root

# Every path the hardening modules can create or modify.
WATCHED=(
    /etc/ssh/sshd_config
    /etc/login.defs
    /etc/sysctl.d/99-hardening.conf
    /etc/audit/rules.d/99-hardening.rules
    /etc/modprobe.d/99-hardening-usb.conf
    /etc/fail2ban/jail.local
    /etc/security/limits.conf
    /etc/issue.net
    /etc/selinux/config
)

# Snapshot: record checksum, or the literal token ABSENT.
#
# Checksum alone is not enough: the hardening writes fixed, host-independent
# content (e.g. the sysctl drop-in), so a real write that a dry-run mutation
# incorrectly lets through can reproduce byte-identical content on a system
# that was already hardened once — checksum-before == checksum-after even
# though a real write (and, for sysctl, a real `sysctl -p` kernel apply) just
# happened. Back-date the mtime of every pre-existing watched file before the
# run so ANY write — content-changing or not — is caught by an mtime that
# moved forward, not just by a changed checksum.
declare -A SNAP SNAP_MTIME
for f in "${WATCHED[@]}"; do
    if [[ -f "$f" ]]; then
        touch -d '1 day ago' "$f" 2>/dev/null || true
        SNAP["$f"]=$(checksum "$f")
        SNAP_MTIME["$f"]=$(stat -c '%Y' "$f" 2>/dev/null)
    else
        SNAP["$f"]="ABSENT"
    fi
done

# Also snapshot SUID state — dry-run must not chmod anything.
suid_before=$(find / -xdev -perm -4000 -type f 2>/dev/null | sort | sha256sum | awk '{print $1}')

out=$(run_hardening --auto-mode --dry-run)

# ---- The run must reach the end, not die partway through --------------------
assert_output_contains "$out" "\[22/22\]"      "dry-run reaches the final module"
assert_output_contains "$out" "DRY.RUN"        "dry-run mode is announced"

# ---- And it must have changed absolutely nothing ----------------------------
for f in "${WATCHED[@]}"; do
    want="${SNAP[$f]}"
    if [[ "$want" == "ABSENT" ]]; then
        if [[ -e "$f" ]]; then
            fail "dry-run CREATED $f — it must not write anything"
        else
            pass_msg "$f still absent after dry-run"
        fi
    else
        got=$(checksum "$f")
        got_mtime=$(stat -c '%Y' "$f" 2>/dev/null)
        if [[ "$want" != "$got" ]]; then
            fail "dry-run MODIFIED $f"
        elif [[ "${SNAP_MTIME[$f]}" != "$got_mtime" ]]; then
            fail "dry-run REWROTE $f — content matches (idempotent write), but mtime advanced, proving a real write happened"
        else
            pass_msg "$(basename "$f") unchanged by dry-run"
        fi
    fi
done

suid_after=$(find / -xdev -perm -4000 -type f 2>/dev/null | sort | sha256sum | awk '{print $1}')
if [[ "$suid_before" == "$suid_after" ]]; then
    pass_msg "SUID bits unchanged by dry-run"
else
    fail "dry-run altered SUID bits on the filesystem"
fi

# No backup directory should be created either.
newest=$(find /root -maxdepth 1 -type d -name 'hardening_backup_*' -newermt '-1 minute' 2>/dev/null | head -1)
if [[ -n "$newest" ]]; then
    fail "dry-run created a backup directory: $newest"
else
    pass_msg "dry-run created no backup directory"
fi

finish
