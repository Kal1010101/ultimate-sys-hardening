#!/bin/bash
# Module 3 opens SSH inbound and nothing else, on the ufw and firewalld
# backends. Earlier releases also opened 80/443 on every host, desktops
# included. The nftables backend is covered by test_nft_firewall.sh.
#
# Stubs are shell FUNCTIONS: lib/core.sh prepends the system directories to
# PATH when it is sourced, so a stub directory on PATH would be shadowed.
#
# Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_fwssh_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT

run_backend() {   # $1 = backend function to call
    : > "$W/calls"
    bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        DRY_RUN=false; LOG_FILE='$W/run.log'
        count_fix() { :; }; enable_service() { :; }; is_service_active() { return 0; }
        ufw() { echo \"UFW \$*\" >> '$W/calls'; return 0; }
        fail2ban-client() { return 0; }
        firewall-cmd() {
            echo \"FWCMD \$*\" >> '$W/calls'
            case \"\$*\" in
                --state) echo running ;;
                --get-default-zone) echo drop ;;
            esac
            return 0
        }
        $1" >/dev/null 2>&1
}

run_backend _fw_ufw
assert_output_contains "$(cat "$W/calls")" '^UFW allow ssh$' "ufw: SSH is allowed"
if grep -qE '^UFW allow (80|443|http|https)' "$W/calls"; then
    fail "ufw: 80/443 are opened: $(grep -E '^UFW allow' "$W/calls" | tr '\n' ';')"
else
    pass_msg "ufw: 80/443 are not opened"
fi

run_backend _fw_firewalld
assert_output_contains "$(cat "$W/calls")" '^FWCMD --permanent --add-service=ssh$' "firewalld: the ssh service is added"
if grep -qE -- '--add-(service=https?|port=(80|443))' "$W/calls"; then
    fail "firewalld: http/https are opened: $(grep -E -- '--add-' "$W/calls" | tr '\n' ';')"
else
    pass_msg "firewalld: http/https are not opened"
fi

finish
