#!/bin/bash
# auditd's systemd unit sets RefuseManualStop=yes, so `systemctl stop auditd`
# is refused. A revert that had to put auditd back to "not running" (Arch,
# where it is installed but stopped) left it running and still reported it as
# done. stop_service_now signals such a unit instead, and restore_service_state
# checks the result rather than assuming it.
#
# systemctl is a shell function stub; nothing reaches the host. Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_stoprefused_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT

# $1 = refuse | stubborn | normal: how the unit answers. Runs restore_service_state
# for a service recorded as "not running, not started at boot".
run() {
    : > "$W/calls"; touch "$W/active"
    env DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent \
        bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'
        DRY_RUN=false; LOG_FILE='$W/run.log'; MODE='$1'
        _has_systemd() { return 0; }
        recorded_service_state() { echo 'no no'; }
        is_service_active() { [[ -f '$W/active' ]]; }
        disable_service_at_boot() { echo \"DISABLE \$1\" >> '$W/calls'; }
        systemctl() {
            echo \"SYSTEMCTL \$*\" >> '$W/calls'
            case \"\$1 \$MODE\" in
                'stop refuse'|'stop stubborn') return 1 ;;
                'stop normal') rm -f '$W/active' ;;
                'show refuse'|'show stubborn') echo yes ;;
                'kill refuse') rm -f '$W/active' ;;
                'kill stubborn') : ;;
            esac
        }
        restore_service_state auditd" >"$W/out" 2>&1
}

run refuse
assert_output_contains "$(cat "$W/calls")" '^SYSTEMCTL kill --signal=TERM auditd$' "a refused stop is followed by signalling the daemon"
[[ -f "$W/active" ]] && fail "auditd still running after the revert" || pass_msg "so auditd is no longer running"
assert_output_contains "$(cat "$W/out")" 'auditd: back to how it was before hardening' "and the revert reports it as restored"

run normal
if grep -q '^SYSTEMCTL kill' "$W/calls"; then fail "a unit that stops normally was signalled too"; else pass_msg "a unit that stops normally is not signalled"; fi

run stubborn
assert_output_contains "$(cat "$W/out")" 'still running after the revert' "a service that will not stop is reported, not claimed restored"
if grep -q 'back to how it was before hardening' "$W/out"; then fail "a service still running was reported as restored"; else pass_msg "no false success"; fi

finish
