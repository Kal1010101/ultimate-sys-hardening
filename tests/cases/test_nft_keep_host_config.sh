#!/bin/bash
# Module 3 on nftables must leave the host's own nftables config in place, and
# its revert must actually find and remove the module's table.
#
# Earlier releases overwrote /etc/nftables.conf with this module's table alone,
# so the ruleset the host loaded at boot was gone after the next reboot. Their
# revert only looked for the old IPv4-only `ip filter` table, so on a host with
# the current `inet uh_filter` table it reported "nothing reverted"; and when it
# did run, it deleted the config instead of restoring it and stopped nftables
# (whose unit flushes every table, Docker's and fail2ban's included).
#
# nft and the service manager are stubs. Functions win over PATH; systemctl and
# rc-update are trapped so the host's real ones are never reached. Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_nftkeep_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT

HOST_CONF='#!/usr/sbin/nft -f
flush ruleset
table inet filter {
	chain input { type filter hook input priority 0; policy accept; }
}'

new_host() {   # $1 = yes|no: a host config exists, $2 = yes|no: nftables enabled at boot
    rm -rf "$W/h"; mkdir -p "$W/h/backups"
    [[ "$1" == yes ]] && printf '%s\n' "$HOST_CONF" > "$W/h/conf"
    [[ "$2" == yes ]] && touch "$W/h/enabled"
    : > "$W/calls"; : > "$W/forbidden"
}

run() {
    env DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent \
        bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        H='$W/h'
        DRY_RUN=false; SKIP_BACKUP=false; LOG_FILE='$W/run.log'; DISTRO_TYPE=arch
        UH_NFT_CONF=\"\$H/conf\"; UH_NFT_TABLE_FILE=\"\$H/table\"
        UH_BACKUP_ROOT=\"\$H/backups\"; BACKUP_GENESIS_DIR=\"\$H/backups/genesis\"; BACKUP_DIR=\"\$H/backups/hardening_backup_1\"
        count_fix() { :; }; relabel_path() { :; }
        is_service_active() { return 1; }
        is_service_enabled() { [[ \"\$1\" == nftables && -f \"\$H/enabled\" ]]; }
        enable_service_at_boot() { echo \"BOOT-ENABLE \$1\" >> '$W/calls'; touch \"\$H/enabled\"; }
        disable_service_at_boot() { echo \"BOOT-DISABLE \$1\" >> '$W/calls'; rm -f \"\$H/enabled\"; }
        stop_service() { echo \"STOP \$1\" >> '$W/calls'; }
        stop_service_now() { echo \"STOP \$1\" >> '$W/calls'; }
        enable_service() { echo \"START \$1\" >> '$W/calls'; }
        ufw() { return 1; }
        firewall-cmd() { return 1; }
        systemctl() { echo \"FORBIDDEN systemctl \$*\" >> '$W/forbidden'; return 1; }
        rc-update() { echo \"FORBIDDEN rc-update \$*\" >> '$W/forbidden'; return 1; }
        nft() {
            case \"\$*\" in
                'add table inet uh_filter') touch \"\$H/live\" ;;
                'delete table inet uh_filter') rm -f \"\$H/live\" ;;
                'list table inet uh_filter') [[ -f \"\$H/live\" ]] && echo 'table inet uh_filter { }' || return 1 ;;
                'list chain inet uh_filter input') [[ -f \"\$H/live\" ]] && printf 'policy drop;\\n\\t\\ttcp dport 22 accept\\n' || return 1 ;;
                'list tables') [[ -f \"\$H/live\" ]] && echo 'table inet uh_filter'; [[ -f \"\$H/ipfilter\" ]] && echo 'table ip filter' ;;
                'list chain ip filter INPUT') [[ -f \"\$H/ipfilter\" ]] && cat \"\$H/ipfilter\" || return 1 ;;
                'delete table ip filter') echo 'DELETE ip filter' >> '$W/calls'; rm -f \"\$H/ipfilter\" ;;
            esac
            return 0
        }
        $1" >"$W/out" 2>&1
}

# --- a host whose own config is in use (nftables enabled at boot) -------------
new_host yes yes
orig=$(checksum "$W/h/conf")
run _fw_nftables
assert_file_contains "$W/h/conf" '^table inet filter \{$' "the host's own ruleset stays in its config"
assert_file_contains "$W/h/conf" "^include \"$W/h/table\"\$" "and the module's table is included from it"
assert_file_contains "$W/h/table" '^delete table inet uh_filter$' "the table has a file of its own"
if grep -q '^START nftables$' "$W/calls"; then fail "nftables was started (its config may flush every table)"; else pass_msg "nftables is not started now"; fi

run revert_firewall
assert_output_contains "$(cat "$W/out")" "removed this module's table" "revert finds the current table"
[[ -f "$W/h/live" ]] && fail "the live table is still loaded" || pass_msg "the live table is removed"
assert_unchanged "$W/h/conf" "$orig" "the host config is byte-identical to before"
assert_file_absent "$W/h/table" "the table file is removed"
[[ -f "$W/h/enabled" ]] && pass_msg "nftables stays enabled at boot, as it was" || fail "revert disabled nftables that was enabled before"
if grep -q '^STOP' "$W/calls"; then fail "nftables was stopped (its unit flushes every table)"; else pass_msg "nftables is not stopped"; fi
if grep -q 'no active firewall' "$W/out"; then fail "claims no active firewall although the host's own ruleset stays"; else pass_msg "no 'no active firewall' warning"; fi

# --- a dormant host config (nftables NOT enabled at boot) ----------------------
# Enabling nftables would start loading it at boot. Alpine's default drops SSH:
# a lab guest came back from its reboot locked out.
new_host yes no
orig=$(checksum "$W/h/conf")
run _fw_nftables
assert_file_not_contains "$W/h/conf" '^table inet filter' "the dormant ruleset is not loaded at boot"
assert_file_contains "$W/h/conf" "^include \"$W/h/table\"\$" "only the module's table is"
assert_output_contains "$(cat "$W/calls")" '^BOOT-ENABLE nftables$' "nftables is enabled at boot"
run revert_firewall
assert_unchanged "$W/h/conf" "$orig" "revert puts the dormant config back byte for byte"
[[ -f "$W/h/enabled" ]] && fail "nftables still enabled at boot" || pass_msg "nftables is not enabled at boot again, as before"

# --- the admin edits the config after hardening: revert keeps the edit --------
# Revert copied the backup over the config, so a rule added after hardening
# was gone.
new_host yes yes
run _fw_nftables
printf '%s\n' '# added by the admin after hardening' 'table inet admin { }' >> "$W/h/conf"
run revert_firewall
assert_file_contains "$W/h/conf" '^table inet admin \{ \}$' "a config in use keeps a rule the admin added after hardening"
assert_file_contains "$W/h/conf" '^table inet filter \{$' "and the host's own ruleset"
assert_file_not_contains "$W/h/conf" '^include ' "only the include line comes out"

new_host yes no
orig_content=$(cat "$W/h/conf")
run _fw_nftables
printf '%s\n' 'table inet admin { }' >> "$W/h/conf"
run revert_firewall
assert_file_contains "$W/h/conf" '^table inet admin \{ \}$' "a boot file the admin added to after hardening is kept"
assert_file_not_contains "$W/h/conf" '^include |Ultimate Hardening' "without the module's include line and note"
[[ "$(cat "$W/h/conf.before-hardening" 2>/dev/null)" == "$orig_content" ]] \
    && pass_msg "the dormant config from before hardening is put next to it" \
    || fail "the config from before hardening was not saved as conf.before-hardening"
assert_output_contains "$(cat "$W/run.log" "$W/out")" 'edited after hardening' "and the user is told where it is"

# --- no config before, enabled at boot before; applied twice -----------------
new_host no yes
run '_fw_nftables; _fw_nftables'
assert_file_contains "$W/h/conf" "^include \"$W/h/table\"\$" "a config is created to include the table"
[[ "$(grep -c '^include' "$W/h/conf")" == 1 ]] && pass_msg "a second run adds no second include" || fail "include line added twice"
run revert_firewall
assert_file_absent "$W/h/conf" "a config the module created is removed again (genesis held only its own output)"
[[ -f "$W/h/enabled" ]] && pass_msg "nftables stays enabled at boot, as it was before" || fail "revert disabled nftables that was enabled before"

# --- ufw or Docker made `ip filter` (iptables-nft), nothing of module 3's ----
# Revert took any `ip filter` for the table of releases before 2.5.0: it
# deleted ufw's and Docker's live rules, removed the host config and stopped
# nftables. Only the table with the combined 22/80/443 accept is ours.
new_host yes yes
printf '%s\n' 'table ip filter {' '	chain INPUT {' '		type filter hook input priority filter; policy drop;' '		jump ufw-before-input' '	}' '}' > "$W/h/ipfilter"
orig=$(checksum "$W/h/conf")
run 'revert_firewall; echo "rc=$?"'
assert_output_contains "$(cat "$W/out")" '^rc=1$' "revert finds nothing of module 3's and says so"
if grep -q '^DELETE ip filter$' "$W/calls"; then fail "revert deleted a table ufw or Docker made"; else pass_msg "another tool's ip filter table is left alone"; fi
assert_unchanged "$W/h/conf" "$orig" "and the host's nftables config is untouched"
if grep -q '^STOP' "$W/calls"; then fail "nftables was stopped (its unit flushes every table)"; else pass_msg "and nftables is not stopped"; fi

# --- the table a release before 2.5.0 made is still removed ------------------
new_host no no
printf '%s\n' 'table ip filter {' '	chain INPUT {' '		type filter hook input priority filter; policy drop;' '		tcp dport { 22, 80, 443 } accept' '	}' '}' > "$W/h/ipfilter"
run revert_firewall
assert_output_contains "$(cat "$W/calls")" '^DELETE ip filter$' "an earlier release's ip filter table is still removed"

# --- --skip-backup with a dormant config: it cannot come back, so keep it -----
new_host yes no
orig=$(checksum "$W/h/conf")
run 'SKIP_BACKUP=true; _fw_nftables'
assert_unchanged "$W/h/conf" "$orig" "--skip-backup: the dormant config is not overwritten"
if grep -q '^BOOT-ENABLE' "$W/calls"; then fail "nftables enabled at boot with the dormant config in place (Alpine's drops SSH)"; else pass_msg "and nftables is not enabled at boot"; fi
assert_file_contains "$W/run.log" 'will NOT survive a reboot' "the user is told the rules last only until reboot"

# --- the menu survives a module 3 revert that finds nothing -----------------
# revert_firewall returns 1 then; called bare under set -e, it ended the program.
new_host yes yes
run "set -e; source '$REPO/lib/menu.sh'; confirm_risky() { return 0; }; revert_module firewall; echo SURVIVED"
assert_output_contains "$(cat "$W/out")" '^SURVIVED$' "a module 3 revert that finds nothing does not end the menu"

if [[ -s "$W/forbidden" ]]; then
    fail "a real service manager would have been called: $(head -2 "$W/forbidden" | tr '\n' ';')"
else
    pass_msg "no real systemctl or rc-update was reached"
fi

finish
