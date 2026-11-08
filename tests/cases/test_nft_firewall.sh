#!/bin/bash
# The nftables backend of module 3 must filter IPv6, and must leave other
# people's rules alone.
#
# Measured with real packets before this was fixed: with module 3 applied,
# TCP 8080 was dropped over IPv4 and ACCEPTED over IPv6 — the table was created
# in the `ip` family, so the "default-drop" firewall never saw an IPv6 packet.
# The same module began with `nft flush ruleset`, which also deleted Docker's
# NAT table and fail2ban's ban table in the same network namespace.
#
# This case checks the commands issued (nft is a stub); the packet-level proof
# is lab/uh-firewall-net-test.sh in the commercial repo. Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_nftfw_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT
export LOG_FILE="$W/run.log"

run_fw() {   # $1 = shell run before the module (e.g. LEGACY=1)
    : > "$W/calls"; rm -f "$W/conf" "$W/table" "$W/ssh"; : > "$LOG_FILE"
    bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        DRY_RUN=false; DISTRO_TYPE=alpine; UH_NFT_CONF='$W/conf'; UH_NFT_TABLE_FILE='$W/table'
        BACKUP_GENESIS_DIR='$W/genesis'
        backup_file() { :; }; count_fix() { echo counted >> '$W/calls'; }; enable_service() { :; }; is_service_active() { return 0; }
        # Never the host's real systemctl/rc-update (it would prompt for a password).
        is_service_enabled() { return 0; }; enable_service_at_boot() { echo \"BOOT-ENABLE \$1\" >> '$W/calls'; }
        systemctl() { echo FORBIDDEN >> '$W/calls'; return 1; }; rc-update() { echo FORBIDDEN >> '$W/calls'; return 1; }
        nft() {
            echo \"NFT \$*\" >> '$W/calls'
            [[ -n \"\${NFT_BROKEN:-}\" ]] && return 1
            if [[ \"\$*\" == 'add rule inet uh_filter input tcp dport 22 accept' ]]; then
                [[ -n \"\${NO_SSH:-}\" ]] && return 1
                touch '$W/ssh'
            fi
            if [[ \"\$*\" == 'list chain inet uh_filter input' ]]; then
                echo 'type filter hook input priority filter; policy drop;'
                [[ -f '$W/ssh' ]] && printf '\\t\\ttcp dport 22 accept\\n'
            fi
            if [[ \"\$*\" == 'list chain ip filter INPUT' && -n \"\${LEGACY:-}\" ]]; then
                echo 'tcp dport { 22, 80, 443 } accept'
            fi
            if [[ \"\$*\" == 'list table inet uh_filter' ]]; then echo 'table inet uh_filter { }'; fi
            return 0
        }
        $1
        _fw_nftables" >/dev/null 2>&1
}

calls() { cat "$W/calls"; }

run_fw ""
assert_output_contains "$(calls)" 'add table inet uh_filter'                           "the table is created in the inet family (IPv4 and IPv6)"
assert_output_contains "$(calls)" 'add chain inet uh_filter input .*policy drop'       "with a default-drop input chain"
assert_output_contains "$(calls)" 'add rule +inet uh_filter input tcp dport 22 accept'  "and SSH accepted"
if grep -qE 'dport .*(80|443)' "$W/calls"; then
    fail "ports 80/443 are opened; only SSH should be"
else
    pass_msg "ports 80/443 are not opened"
fi
assert_output_contains "$(calls)" 'ip6 nexthdr icmpv6 icmpv6 type .*nd-neighbor-solicit.*nd-neighbor-advert' \
    "ICMPv6 neighbour discovery is accepted (IPv6 cannot work without it)"
if grep -q 'flush ruleset' "$W/calls"; then
    fail "the module still runs 'nft flush ruleset', destroying other tables"
else
    pass_msg "no 'flush ruleset' — other tables are left alone"
fi
if grep -qE 'add (table|chain|rule) ip ' "$W/calls"; then
    fail "the module still builds rules in the IPv4-only 'ip' family"
else
    pass_msg "nothing is built in the IPv4-only family"
fi
if grep -q 'delete table ip filter' "$W/calls"; then
    fail "deleted the 'ip filter' table when it was not the legacy one"
else
    pass_msg "an unrelated 'ip filter' table is not deleted"
fi

# --- the persisted file holds our table only, and reloads idempotently -------
table=$(cat "$W/table" 2>/dev/null)
assert_output_contains "$table" '^table inet uh_filter$'          "the table file declares the table first..."
assert_output_contains "$table" '^delete table inet uh_filter$'   "...then deletes it, so a reload works whether or not it exists"
assert_output_contains "$(cat "$W/conf" 2>/dev/null)" "^include \"$W/table\"\$" "the host config includes the table file"
if grep -q 'list ruleset' "$W/calls"; then
    fail "persisted the whole ruleset, freezing other tools' rules into the boot file"
else
    pass_msg "only this module's table is persisted"
fi

# --- the legacy table from earlier releases is replaced, but only if ours ----
run_fw "export LEGACY=1"
assert_output_contains "$(calls)" 'delete table ip filter' \
    "the legacy IPv4-only table (recognised by its combined accept) is removed so its drop policy cannot linger"

run_fw "export NFT_BROKEN=1"
[[ -e "$W/conf" || -e "$W/table" ]] && fail "an empty ruleset was written to the boot file when nft could not load it" \
                   || pass_msg "nothing is persisted when nft cannot load the rules"
grep -q '^counted$' "$W/calls" && fail "a fix was counted although no rule was applied" \
                               || pass_msg "no fix is counted when nft cannot load the rules"
grep -q 'nftables: default-drop' "$LOG_FILE" && fail "success was reported although no rule was applied" \
                                             || pass_msg "no success is claimed when nft cannot load the rules"
assert_output_contains "$(cat "$LOG_FILE")" 'nftables could not load the firewall rules' "and it says so"

# --- the SSH accept did not load: default-drop must not stay, or be saved ----
run_fw "export NO_SSH=1"
assert_output_contains "$(calls)" 'NFT delete table inet uh_filter$' "the table is taken out again (if it stayed, new SSH logins would be dropped)"
if [[ "$(grep -n 'NFT delete table inet uh_filter$' "$W/calls" | tail -1 | cut -d: -f1)" -gt "$(grep -n 'NFT add table inet uh_filter' "$W/calls" | cut -d: -f1)" ]]; then
    pass_msg "and that happens after the table was built"
else
    fail "the table was not removed after it was built"
fi
[[ -e "$W/conf" || -e "$W/table" ]] && fail "a ruleset without SSH was saved to the boot file" \
                   || pass_msg "nothing is saved when the SSH accept is missing"
grep -q '^BOOT-ENABLE' "$W/calls" && fail "nftables was enabled at boot without the SSH accept" \
                                  || pass_msg "nftables is not enabled at boot"
grep -q '^counted$' "$W/calls" && fail "a fix was counted although the rules were removed" \
                               || pass_msg "no fix is counted"
assert_output_contains "$(cat "$LOG_FILE")" 'SSH accept rule did not load' "and it says so"

grep -q FORBIDDEN "$W/calls" && fail "the host's real systemctl or rc-update was reached" \
                              || pass_msg "no real service manager was reached"

finish
