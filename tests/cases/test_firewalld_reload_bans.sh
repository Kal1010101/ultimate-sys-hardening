#!/bin/bash
# firewall-cmd --reload drops fail2ban's runtime ban rules while fail2ban keeps
# listing the addresses as banned, so every reload must be followed by a jail
# restart that re-applies them.
#
# Stubs are shell FUNCTIONS: lib/core.sh prepends the system directories to
# PATH when it is sourced, so a stub directory on PATH would be shadowed.
#
# Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_fwreload_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT

run_fw() {   # $1 = "active" or "inactive" for fail2ban
    : > "$W/calls"
    bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        DISTRO_TYPE=rhel; DRY_RUN=false; LOG_FILE='$W/run.log'
        count_fix() { :; }; enable_service() { :; }
        firewall-cmd() {
            echo \"FWCMD \$*\" >> '$W/calls'
            case \"\$*\" in
                --state) echo running ;;
                --get-default-zone) echo drop ;;
            esac
            return 0
        }
        fail2ban-client() { echo \"F2B \$*\" >> '$W/calls'; return 0; }
        is_service_active() { [[ \"\$1\" == fail2ban && '$1' == active ]] || [[ \"\$1\" == firewalld ]]; }
        _fw_firewalld" >/dev/null 2>&1
}

run_fw active
if grep -q '^FWCMD --reload$' "$W/calls" && grep -q '^F2B reload --restart$' "$W/calls"; then
    pass_msg "a firewalld reload is followed by a fail2ban jail restart"
else
    fail "calls: $(tr '\n' ' ' < "$W/calls")"
fi
if [[ "$(grep -n '^FWCMD --reload$' "$W/calls" | tail -1 | cut -d: -f1)" -lt "$(grep -n '^F2B reload --restart$' "$W/calls" | tail -1 | cut -d: -f1)" ]]; then
    pass_msg "the jails restart after the reload, not before"
else
    fail "fail2ban restarted before the last firewalld reload: $(tr '\n' ' ' < "$W/calls")"
fi

run_fw inactive
if grep -q '^F2B' "$W/calls"; then
    fail "fail2ban-client was called although fail2ban is not running"
else
    pass_msg "nothing is asked of fail2ban when it is not running"
fi

finish
