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
    : > "$W/calls"; rm -f "$W/conf"
    bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        DRY_RUN=false; DISTRO_TYPE=alpine; UH_NFT_CONF='$W/conf'
        backup_file() { :; }; count_fix() { :; }; enable_service() { :; }; is_service_active() { return 0; }
        nft() {
            echo \"NFT \$*\" >> '$W/calls'
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
assert_output_contains "$(calls)" 'tcp dport \{ 22, 80, 443 \} accept'                 "and SSH/80/443 accepted"
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
conf=$(cat "$W/conf" 2>/dev/null)
assert_output_contains "$conf" '^table inet uh_filter$'          "the boot file declares the table first..."
assert_output_contains "$conf" '^delete table inet uh_filter$'   "...then deletes it, so a reload works whether or not it exists"
if grep -q 'list ruleset' "$W/calls"; then
    fail "persisted the whole ruleset, freezing other tools' rules into the boot file"
else
    pass_msg "only this module's table is persisted"
fi

# --- the legacy table from earlier releases is replaced, but only if ours ----
run_fw "export LEGACY=1"
assert_output_contains "$(calls)" 'delete table ip filter' \
    "the legacy IPv4-only table (recognised by its combined accept) is removed so its drop policy cannot linger"

finish
