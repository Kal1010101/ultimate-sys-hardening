#!/bin/bash
# The SSH banner goes in /etc/issue.net. On Fedora that path is a symlink to
# ../usr/lib/issue.net, a file fedora-release-common owns. Hardening must not
# write through the link, and revert must put both shapes back as they were:
# a link stays a link, a regular file gets its original bytes.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root
require_file /etc/ssh/sshd_config

# shellcheck source=/dev/null
source "$REPO_ROOT/lib/core.sh"

WORK=$(mktemp -d)
LOG_FILE="$WORK/test.log"
BACKUP_GENESIS_DIR="$WORK/genesis"
BACKUP_DIR="$WORK/run1"
UH_BACKUP_ROOT="$WORK"
DRY_RUN=false
SKIP_BACKUP=false
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# --- helpers on their own: a symlinked path ----------------------------------
mkdir -p "$WORK/etc" "$WORK/usr/lib"
echo "Vendor \\S" > "$WORK/usr/lib/issue.net"
ln -s ../usr/lib/issue.net "$WORK/etc/issue.net"
vendor=$(checksum "$WORK/usr/lib/issue.net")

backup_file_for_rewrite "$WORK/etc/issue.net"
echo "banner" > "$WORK/etc/issue.net"
[[ -f "$WORK/etc/issue.net" && ! -L "$WORK/etc/issue.net" ]] \
    && pass_msg "the link was replaced by a regular file" \
    || fail "the path is not a regular file after the rewrite"
assert_unchanged "$WORK/usr/lib/issue.net" "$vendor" "the vendor file behind the link was not written"

backup_file_for_rewrite "$WORK/etc/issue.net"
n=$(grep -c "^$WORK/etc/issue.net|" "$BACKUP_GENESIS_DIR/symlinks.txt" 2>/dev/null)
[[ "$n" == 1 ]] && pass_msg "the link is recorded once across two runs" \
                || fail "symlink record count is ${n:-0}, expected 1"
assert_file_absent "$BACKUP_GENESIS_DIR/files$WORK/etc/issue.net" \
    "genesis did not capture our own banner as the original"

revert_backed_up_file "$WORK/etc/issue.net" >/dev/null
if [[ -L "$WORK/etc/issue.net" && $(readlink "$WORK/etc/issue.net") == ../usr/lib/issue.net ]]; then
    pass_msg "revert restored the original symlink"
else
    fail "revert did not restore the symlink"
fi

# --- helpers on their own: a regular file ------------------------------------
echo "Debian GNU/Linux 12" > "$WORK/etc/plain.net"
orig=$(checksum "$WORK/etc/plain.net")
backup_file_for_rewrite "$WORK/etc/plain.net"
echo "banner" > "$WORK/etc/plain.net"
revert_backed_up_file "$WORK/etc/plain.net" >/dev/null
assert_unchanged "$WORK/etc/plain.net" "$orig" "revert restored a regular file's original bytes"

# --- the real run: harden, then --revert, on a Fedora-shaped host ------------
rm -f /etc/issue.net
mkdir -p /usr/lib
echo "Vendor \\S" > /usr/lib/issue.net
ln -s ../usr/lib/issue.net /etc/issue.net
vendor=$(checksum /usr/lib/issue.net)

run_hardening --auto-mode >/dev/null
assert_unchanged /usr/lib/issue.net "$vendor" "hardening left the package-owned file alone"
assert_file_contains /etc/issue.net 'Authorized access only' "the banner was written to /etc/issue.net"
[[ ! -L /etc/issue.net ]] && pass_msg "/etc/issue.net is a regular file while hardened" \
                          || fail "/etc/issue.net is still a symlink after hardening"

run_hardening --revert >/dev/null
if [[ -L /etc/issue.net && $(readlink /etc/issue.net) == ../usr/lib/issue.net ]]; then
    pass_msg "--revert restored /etc/issue.net as the original symlink"
else
    fail "--revert did not restore the /etc/issue.net symlink"
fi
assert_unchanged /usr/lib/issue.net "$vendor" "the package-owned file is unchanged after revert"

finish
