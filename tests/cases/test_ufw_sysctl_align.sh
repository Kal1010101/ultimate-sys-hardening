#!/bin/bash
# ufw loads its own sysctl file (IPT_SYSCTL in /etc/default/ufw) every time it
# starts, which at boot is after systemd-sysctl. Debian and Ubuntu ship it with
# log_martians=0, so module 6's log_martians=1 held until the first reboot and
# was then lost (seen on a real Debian 12 guest: 2 of 36 values back to the
# distro's after a reboot). Module 6, and module 3 when module 6 ran first,
# now set ufw's conflicting lines to the hardened values, and revert puts the
# file back.
#
# Runs against files in a temp directory; ufw is a stub. Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_ufwsysctl_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT

UFW_SYSCTL_STOCK='#
# Configuration file for setting network variables.
net/ipv4/conf/all/accept_redirects=0
net/ipv4/conf/default/accept_redirects=0
net/ipv4/icmp_echo_ignore_broadcasts=1
net/ipv4/icmp_echo_ignore_all=0
net/ipv4/conf/all/log_martians=0
net/ipv4/conf/default/log_martians=0'

new_host() {
    rm -rf "$W/host" "$W/backups"
    mkdir -p "$W/host/etc/ufw" "$W/host/etc/default" "$W/host/etc/sysctl.d" "$W/backups"
    printf '%s\n' "$UFW_SYSCTL_STOCK" > "$W/host/etc/ufw/sysctl.conf"
    printf '%s\n' "IPT_SYSCTL=$W/host/etc/ufw/sysctl.conf" > "$W/host/etc/default/ufw"
    printf '%s\n' '# hardened' 'net.ipv4.conf.all.accept_redirects = 0' \
        'net.ipv4.conf.all.log_martians = 1' 'net.ipv4.conf.default.log_martians = 1' \
        'kernel.randomize_va_space = 2' > "$W/host/etc/sysctl.d/99-hardening.conf"
    : > "$W/calls"
}

run() {   # $1 = shell after the libraries are loaded
    bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        H='$W/host'
        UFW_DEFAULTS=\"\$H/etc/default/ufw\"
        UH_SYSCTL_DROPIN=\"\$H/etc/sysctl.d/99-hardening.conf\"
        UFW_CONF=\"\$H/etc/ufw/ufw.conf\"
        UFW_STATE_FILES=(\"\$H/etc/ufw/user.rules\" \"\$H/etc/ufw/user6.rules\" \"\$H/etc/default/ufw\" \"\$UFW_CONF\")
        DRY_RUN=false; SKIP_BACKUP=false; LOG_FILE='$W/run.log'
        UH_BACKUP_ROOT='$W/backups'; BACKUP_GENESIS_DIR='$W/backups/genesis'; BACKUP_DIR='$W/backups/hardening_backup_1'
        count_fix() { :; }; relabel_path() { :; }
        systemctl() { echo \"FORBIDDEN systemctl \$*\" >> '$W/forbidden'; return 1; }
        sysctl() { echo \"FORBIDDEN sysctl \$*\" >> '$W/forbidden'; return 1; }
        ufw() {
            echo \"UFW \$* martians=\$(grep -c 'log_martians=1' \"\$H/etc/ufw/sysctl.conf\")\" >> '$W/calls'
            return 0
        }
        $1" >"$W/out" 2>&1
}

F="$W/host/etc/ufw/sysctl.conf"

# --- module 6 aligns only the keys that differ ------------------------------
new_host
inode_before=$(stat -c %i "$F")
run '_align_ufw_sysctl "$UH_SYSCTL_DROPIN"'
assert_file_contains "$F" '^net/ipv4/conf/all/log_martians=1$'     "ufw's all.log_martians set to the hardened 1"
assert_file_contains "$F" '^net/ipv4/conf/default/log_martians=1$' "and default.log_martians"
assert_file_contains "$F" '^net/ipv4/icmp_echo_ignore_all=0$'      "a key the hardening file does not set is left alone"
assert_file_contains "$F" '^net/ipv4/conf/all/accept_redirects=0$' "a key that already matches is left as it is"
assert_file_contains "$F" '^# Configuration file' "comments are kept"
[[ "$(stat -c %i "$F")" == "$inode_before" ]] && pass_msg "edited in place (same inode: owner, mode, label kept)" \
                                               || fail "ufw's sysctl file was replaced, not edited in place"
assert_file_contains "$W/out" 'log_martians' "the change is reported, naming the keys"
backup=$(find "$W/backups" -path '*files*' -name sysctl.conf | head -1)
[[ -n "$backup" ]] && grep -q 'log_martians=0' "$backup" && pass_msg "the original was backed up first" \
                   || fail "no backup of ufw's original sysctl file"

# --- revert restores ufw's file ---------------------------------------------
run 'revert_backed_up_file "$H/etc/ufw/sysctl.conf"'
[[ "$(cat "$F")" == "$UFW_SYSCTL_STOCK" ]] && pass_msg "revert puts ufw's sysctl file back byte for byte" \
                                            || fail "revert did not restore ufw's sysctl file: $(cat "$F")"

# --- nothing to align: no change, no backup ----------------------------------
new_host
sed -i 's/log_martians=0/log_martians=1/' "$F"
cp "$F" "$W/expected"
run '_align_ufw_sysctl "$UH_SYSCTL_DROPIN"'
cmp -s "$F" "$W/expected" && pass_msg "no conflicting key: the file is not touched" || fail "file changed with nothing to align"
[[ -z "$(find "$W/backups" -name sysctl.conf 2>/dev/null)" ]] && pass_msg "and no backup is taken" \
                                                           || fail "backup taken with nothing to change"

# --- dry run changes nothing and says what it would do ----------------------
new_host
run 'DRY_RUN=true; _align_ufw_sysctl <(cat "$UH_SYSCTL_DROPIN")'
[[ "$(cat "$F")" == "$UFW_SYSCTL_STOCK" ]] && pass_msg "dry run leaves ufw's file alone" || fail "dry run changed ufw's file"
assert_file_contains "$W/out" 'Would set 2 value' "dry run reports the two values it would set"

# --- no ufw, or no IPT_SYSCTL line ------------------------------------------
new_host
rm -f "$W/host/etc/default/ufw"
run '_align_ufw_sysctl "$UH_SYSCTL_DROPIN"; echo "RC=$?"'
assert_file_contains "$W/out" 'RC=0' "no /etc/default/ufw: nothing to do, no error"
[[ "$(cat "$F")" == "$UFW_SYSCTL_STOCK" ]] && pass_msg "and the file is untouched" || fail "changed without IPT_SYSCTL"

# --- module 3 aligns before ufw enable when module 6 ran first --------------
new_host
printf '%s\n' 'ENABLED=no' > "$W/host/etc/ufw/ufw.conf"
: > "$W/host/etc/ufw/user.rules"; : > "$W/host/etc/ufw/user6.rules"
run '_fw_ufw'
grep -q 'UFW --force enable martians=2' "$W/calls" && pass_msg "module 3 aligns ufw's sysctl file before enabling ufw" \
    || fail "ufw was enabled with its stock log_martians=0: $(cat "$W/calls")"

new_host
rm -f "$W/host/etc/sysctl.d/99-hardening.conf"
printf '%s\n' 'ENABLED=no' > "$W/host/etc/ufw/ufw.conf"
: > "$W/host/etc/ufw/user.rules"; : > "$W/host/etc/ufw/user6.rules"
run '_fw_ufw'
[[ "$(cat "$F")" == "$UFW_SYSCTL_STOCK" ]] && pass_msg "module 3 without module 6 leaves ufw's sysctl file alone" \
    || fail "module 3 changed ufw's sysctl file with no hardening drop-in"

# --- module 6's own revert covers the file ----------------------------------
kernel_files=$(bash -c "source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
    source '$REPO/lib/menu.sh'; LOG_FILE=/dev/null; echo \"\${MOD_REVERT_FILES[kernel]}\"" 2>/dev/null)
grep -qw '/etc/ufw/sysctl.conf' <<<"$kernel_files" && pass_msg "module 6's revert includes ufw's sysctl file" \
    || fail "module 6's revert list does not include /etc/ufw/sysctl.conf: '$kernel_files'"

[[ ! -s "$W/forbidden" ]] && pass_msg "no real systemctl or sysctl was reached" || fail "reached: $(cat "$W/forbidden")"
finish
