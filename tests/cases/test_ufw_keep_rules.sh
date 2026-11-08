#!/bin/bash
# Module 3 on ufw must keep the rules a host already has, and revert must put
# back the firewall from before: the same rules, and ufw on or off as it was.
#
# It used to start with `ufw --force reset`, which deleted every existing rule
# (a distro firewall GUI's included), and its revert reset and DISABLED ufw, so
# a distro that ships ufw enabled was left with no firewall after a revert.
#
# ufw is a stub that keeps its state in the same files the real one does, so
# backup and restore run for real against them. Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_ufwkeep_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT

GUI_RULE='### tuple ### allow tcp 8384 0.0.0.0/0 any 0.0.0.0/0 in'

new_host() {   # $1 = yes|no: ufw enabled before hardening
    rm -rf "$W/host" "$W/backups"; mkdir -p "$W/host/etc/ufw" "$W/host/etc/default" "$W/backups"
    printf '%s\n' "$GUI_RULE" > "$W/host/etc/ufw/user.rules"
    printf '%s\n' '### tuple ### allow tcp 8384 ::/0 any ::/0 in' > "$W/host/etc/ufw/user6.rules"
    printf '%s\n' 'DEFAULT_INPUT_POLICY="DROP"' 'DEFAULT_OUTPUT_POLICY="ACCEPT"' > "$W/host/etc/default/ufw"
    printf '%s\n' "ENABLED=$1" 'LOGLEVEL=low' > "$W/host/etc/ufw/ufw.conf"
    : > "$W/calls"
}

# $1 = shell to run after the libraries are loaded
run() {
    bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        H='$W/host'
        UFW_CONF=\"\$H/etc/ufw/ufw.conf\"
        UFW_STATE_FILES=(\"\$H/etc/ufw/user.rules\" \"\$H/etc/ufw/user6.rules\" \"\$H/etc/default/ufw\" \"\$UFW_CONF\")
        DRY_RUN=false; SKIP_BACKUP=false; LOG_FILE='$W/run.log'
        UH_BACKUP_ROOT='$W/backups'; BACKUP_GENESIS_DIR='$W/backups/genesis'; BACKUP_DIR='$W/backups/hardening_backup_1'
        count_fix() { :; }; relabel_path() { :; }
        # revert_firewall also looks at firewalld and nftables. Functions win
        # over PATH, so these keep the HOST's real firewall-cmd, nft and
        # systemctl out of reach: an earlier draft without them reached the
        # real firewall-cmd on a Fedora workstation (polkit prompts, refused).
        is_service_active() { return 1; }
        stop_service() { echo \"STOP \$*\" >> '$W/calls'; }
        firewall-cmd() { echo \"FORBIDDEN firewall-cmd \$*\" >> '$W/forbidden'; return 1; }
        nft() { [[ \"\$1\" == list ]] && return 1; echo \"FORBIDDEN nft \$*\" >> '$W/forbidden'; return 1; }
        systemctl() { echo \"FORBIDDEN systemctl \$*\" >> '$W/forbidden'; return 1; }
        sudo() { echo \"FORBIDDEN sudo \$*\" >> '$W/forbidden'; return 1; }
        ufw() {
            echo \"UFW \$*\" >> '$W/calls'
            case \"\$*\" in
                status) grep -q '^ENABLED=yes' \"\$UFW_CONF\" && echo 'Status: active' || echo 'Status: inactive' ;;
                '--force reset') : > \"\$H/etc/ufw/user.rules\"; : > \"\$H/etc/ufw/user6.rules\" ;;
                '--force enable') sed -i 's/^ENABLED=.*/ENABLED=yes/' \"\$UFW_CONF\" ;;
                disable) sed -i 's/^ENABLED=.*/ENABLED=no/' \"\$UFW_CONF\" ;;
                'default deny incoming') sed -i 's/^DEFAULT_INPUT_POLICY=.*/DEFAULT_INPUT_POLICY=\"DROP\"/' \"\$H/etc/default/ufw\" ;;
                'allow ssh') echo '### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in' >> \"\$H/etc/ufw/user.rules\" ;;
            esac
            return 0
        }
        $1" >"$W/out" 2>&1
}

# --- a host that ships ufw enabled, with a rule made in its firewall GUI -------
new_host yes
orig_rules=$(checksum "$W/host/etc/ufw/user.rules")
orig_conf=$(checksum "$W/host/etc/ufw/ufw.conf")
run _fw_ufw
if grep -q 'reset' "$W/calls"; then fail "apply still runs ufw reset"; else pass_msg "apply does not reset ufw"; fi
assert_file_contains "$W/host/etc/ufw/user.rules" 'allow tcp 8384 ' "the GUI's rule survives apply"
assert_file_contains "$W/host/etc/ufw/user.rules" 'allow tcp 22 '   "and SSH is allowed"
assert_file_exists "$W/backups/genesis/files$W/host/etc/ufw/user.rules" "the rules file was backed up before the change"

run revert_firewall
assert_unchanged "$W/host/etc/ufw/user.rules" "$orig_rules" "revert restores the rules from before hardening"
assert_unchanged "$W/host/etc/ufw/ufw.conf"   "$orig_conf"  "and ufw.conf"
assert_output_contains "$(cat "$W/calls")" '^UFW reload$' "the running ufw re-reads the restored rules"
if grep -qE '^UFW (disable|--force reset)$' "$W/calls"; then
    fail "revert disabled or reset a ufw that was on before hardening: $(tr '\n' ';' < "$W/calls")"
else
    pass_msg "ufw stays on, as it was before hardening"
fi
if grep -q 'no active firewall' "$W/out"; then fail "revert claims the host has no firewall"; else pass_msg "no false 'no active firewall' warning"; fi

# --- a host where ufw was installed but off -----------------------------------
new_host no
run '_fw_ufw; revert_firewall'
assert_file_contains "$W/host/etc/ufw/ufw.conf" '^ENABLED=no$' "ufw that was off before is off again after revert"
assert_output_contains "$(cat "$W/calls")" '^UFW disable$' "and it is stopped"
assert_file_not_contains "$W/host/etc/ufw/user.rules" 'allow tcp 22 ' "the SSH rule hardening added is gone"

# --- a host hardened by a release that took no backup -------------------------
new_host yes
run revert_firewall
assert_output_contains "$(cat "$W/calls")" '^UFW --force reset$' "with no backup, revert falls back to reset"
assert_output_contains "$(cat "$W/out")" 'no backup of its earlier rules' "and says why"

# --- re-run on a host hardened by 2.4.9 or earlier ----------------------------
# Those releases reset ufw, opened 22, 80 and 443, and kept no backup. Saving
# that now as "before hardening" made revert put 80/443 back instead of
# undoing them; without a backup, revert falls back to the reset.
old_release_rules() {
    printf '%s\n' '### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in' \
        '### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in' \
        '### tuple ### allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in' > "$W/host/etc/ufw/user.rules"
}
new_host yes; old_release_rules
mkdir -p "$W/backups/hardening_backup_0"     # the earlier release's own run
run _fw_ufw
assert_file_absent "$W/backups/genesis/files$W/host/etc/ufw/user.rules" "an earlier release's ufw rules are not saved as the state before hardening"
run revert_firewall
assert_output_contains "$(cat "$W/calls")" '^UFW --force reset$' "so revert resets them, as for any host that release hardened"

# The same rules on a host this tool never ran on are the admin's own (a web
# server): they are the state before hardening and are kept.
new_host yes; old_release_rules
orig_rules=$(checksum "$W/host/etc/ufw/user.rules")
run '_fw_ufw; revert_firewall'
assert_unchanged "$W/host/etc/ufw/user.rules" "$orig_rules" "a first run keeps an admin's own 80/443 rules through revert"

if [[ -s "$W/forbidden" ]]; then
    fail "a real system tool would have been called: $(head -2 "$W/forbidden" | tr '\n' ';')"
else
    pass_msg "no real firewall-cmd, nft or systemctl was reached"
fi

finish
