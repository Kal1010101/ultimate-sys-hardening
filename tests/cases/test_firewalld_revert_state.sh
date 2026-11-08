#!/bin/bash
# Reverting module 3 on firewalld must put back what the host had: its default
# zone, the drop zone's SSH setting, and firewalld running or not.
#
# It used to set the default zone to "public" and stop firewalld on every host,
# so a distro that ships firewalld running (Fedora, with its FedoraWorkstation
# zone) was left with no firewall after a revert.
#
# firewall-cmd is a stub keeping zones in files. Functions win over PATH, and
# the stubs below keep the HOST's real firewall-cmd, nft and systemctl out of
# reach: an earlier test in this suite once reached the real firewall-cmd on a
# Fedora workstation. Run with no D-Bus too, as tests/run.sh does not need it.
# Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_fwdrev_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT

new_host() {   # $1 = yes|no running, $2 = default zone, $3 = services of that zone
    rm -rf "$W/fw" "$W/backups"; mkdir -p "$W/fw" "$W/backups"
    [[ "$1" == yes ]] && touch "$W/fw/active"
    echo "$2" > "$W/fw/default"
    printf '%s\n' $3 > "$W/fw/zone.$2"
    touch "$W/fw/zone.drop"
    : > "$W/calls"; : > "$W/forbidden"
}

run() {   # $1 = shell; $2 = SSH_CONNECTION value (empty = local console)
    env -u SSH_CONNECTION DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent \
        DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent ${2:+SSH_CONNECTION="$2"} \
        bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        F='$W/fw'
        DRY_RUN=false; SKIP_BACKUP=false; LOG_FILE='$W/run.log'
        UH_BACKUP_ROOT='$W/backups'; BACKUP_GENESIS_DIR='$W/backups/genesis'; BACKUP_DIR='$W/backups/hardening_backup_1'
        count_fix() { :; }
        is_service_active() { [[ \"\$1\" == firewalld && -f \"\$F/active\" ]] || [[ \"\$1\" == sshd && -f \"\$F/sshd\" ]]; }
        enable_service() { echo \"ENABLE \$1\" >> '$W/calls'; touch \"\$F/active\"; }
        stop_service() { echo \"STOP \$1\" >> '$W/calls'; rm -f \"\$F/active\"; }
        fail2ban-client() { return 0; }
        ufw() { return 1; }
        nft() { [[ \"\$1\" == list ]] && return 1; echo \"FORBIDDEN nft \$*\" >> '$W/forbidden'; return 1; }
        systemctl() { echo \"FORBIDDEN systemctl \$*\" >> '$W/forbidden'; return 1; }
        sudo() { echo \"FORBIDDEN sudo \$*\" >> '$W/forbidden'; return 1; }
        firewall-cmd() {
            echo \"FWCMD \$*\" >> '$W/calls'
            local zone=\$(cat \"\$F/default\") perm=false arg
            for arg in \"\$@\"; do
                case \"\$arg\" in
                    --permanent) perm=true ;;
                    --zone=*) zone=\${arg#--zone=} ;;
                esac
            done
            for arg in \"\$@\"; do
                case \"\$arg\" in
                    --state) [[ -f \"\$F/active\" ]] && echo running || echo 'not running' ;;
                    --get-default-zone) cat \"\$F/default\" ;;
                    --set-default-zone=*) echo \"\${arg#--set-default-zone=}\" > \"\$F/default\" ;;
                    --add-service=*) echo \"\${arg#--add-service=}\" >> \"\$F/zone.\$zone\" ;;
                    --remove-service=*) grep -vx \"\${arg#--remove-service=}\" \"\$F/zone.\$zone\" > \"\$F/t\"; mv \"\$F/t\" \"\$F/zone.\$zone\" ;;
                    --query-service=*) grep -qx \"\${arg#--query-service=}\" \"\$F/zone.\$zone\" 2>/dev/null; return ;;
                    --query-port=*) return 1 ;;
                esac
            done
            return 0
        }
        $1" >"$W/out" 2>&1
}

zone_has() { grep -qx "$2" "$W/fw/zone.$1" 2>/dev/null; }

# --- Fedora-like: firewalld running, FedoraWorkstation zone ------------------
new_host yes FedoraWorkstation "ssh dhcpv6-client"
run _fw_firewalld
[[ "$(cat "$W/fw/default")" == drop ]] && pass_msg "apply switches to the drop zone" || fail "apply left zone $(cat "$W/fw/default")"
assert_file_contains "$W/backups/genesis/firewalld_state.txt" '^default_zone=FedoraWorkstation$' "the zone before hardening is recorded"
assert_file_contains "$W/backups/genesis/firewalld_state.txt" '^was_active=yes$' "and that firewalld was running"
run revert_firewall
[[ "$(cat "$W/fw/default")" == FedoraWorkstation ]] && pass_msg "revert puts the FedoraWorkstation zone back" \
                                                    || fail "revert left zone $(cat "$W/fw/default")"
[[ -f "$W/fw/active" ]] && pass_msg "firewalld keeps running, as it did before" || fail "revert stopped a firewalld that was running before"
zone_has drop ssh && fail "the SSH service hardening added to the drop zone is still there" || pass_msg "the drop zone's SSH service is removed again"
zone_has FedoraWorkstation ssh && pass_msg "the original zone's own services are untouched" || fail "the original zone lost its ssh service"
if grep -q 'no active firewall' "$W/out"; then fail "revert claims the host has no firewall"; else pass_msg "no false 'no active firewall' warning"; fi

# --- firewalld installed but not running before ------------------------------
new_host no public "ssh dhcpv6-client"
run '_fw_firewalld; revert_firewall'
[[ ! -f "$W/fw/active" ]] && pass_msg "firewalld that was not running before is stopped again" || fail "firewalld left running"
[[ "$(cat "$W/fw/default")" == public ]] && pass_msg "and its default zone is back" || fail "zone is $(cat "$W/fw/default")"

# --- the drop zone already allowed SSH before hardening ----------------------
new_host yes public "ssh"
echo ssh > "$W/fw/zone.drop"
run '_fw_firewalld; revert_firewall'
zone_has drop ssh && pass_msg "an SSH service the drop zone already had is kept" || fail "revert removed SSH the host had in its drop zone"

# --- over SSH, to a zone without SSH: nothing is changed ---------------------
new_host yes home "dhcpv6-client"
run _fw_firewalld
run revert_firewall "10.0.0.5 50000 10.0.0.9 22"
[[ "$(cat "$W/fw/default")" == drop ]] && pass_msg "over SSH, revert does not switch to a zone that would lock SSH out" \
                                       || fail "switched to $(cat "$W/fw/default") from an SSH session"
assert_output_contains "$(cat "$W/out")" 'does not allow SSH.*firewall-cmd --set-default-zone=home' "and says what to run from a console"
run revert_firewall
[[ "$(cat "$W/fw/default")" == home ]] && pass_msg "from a console, the same revert goes ahead" || fail "console revert left $(cat "$W/fw/default")"

# --- sudo over SSH: env_reset drops SSH_CONNECTION, but sshd is running -------
new_host yes home "dhcpv6-client"
touch "$W/fw/sshd"
run _fw_firewalld
run revert_firewall
[[ "$(cat "$W/fw/default")" == drop ]] && pass_msg "with sshd running, revert does not switch to a zone without SSH, even with no SSH_CONNECTION (sudo)" \
                                       || fail "switched to $(cat "$W/fw/default") while sshd runs"
assert_output_contains "$(cat "$W/out")" 'sshd is running.*firewall-cmd --set-default-zone=home' "and says what to run from a console"

# --- a host hardened by 2.4.9 or earlier (http/https in drop): old revert ----
new_host yes drop "ssh http https"
run '_fw_firewalld'
assert_file_absent "$W/backups/genesis/firewalld_state.txt" "an earlier release's rules are not recorded as the original state"
run revert_firewall
assert_output_contains "$(cat "$W/calls")" '^STOP firewalld$' "with no record, revert falls back to stopping firewalld"

# --- hardened before the --set-default-zone fix: ssh/http/https in public ----
# That call always failed, so the services landed in the zone that was default
# then. Recorded as "before hardening", revert switched back to it and opened
# 80/443 again.
new_host yes public "ssh dhcpv6-client http https"
mkdir -p "$W/backups/hardening_backup_0"
run '_fw_firewalld'
assert_file_absent "$W/backups/genesis/firewalld_state.txt" "an earlier release's rules in the public zone are not recorded as the original state"
assert_file_contains "$W/backups/genesis/firewalld_earlier_release_zone.txt" '^public$' "the zone holding them is recorded"
run '_fw_firewalld'
assert_file_absent "$W/backups/genesis/firewalld_state.txt" "a second run does not record the hardened drop zone as the original state"
run revert_firewall
zone_has public http && fail "revert left http open in the public zone" || pass_msg "revert removes http from the zone an earlier release put it in"
zone_has public https && fail "revert left https open in the public zone" || pass_msg "and https"
zone_has public ssh && pass_msg "public keeps its own ssh service" || fail "revert removed ssh from the public zone"

# --- a web server's own public zone, no earlier run: recorded as usual -------
new_host yes public "ssh dhcpv6-client http https"
run '_fw_firewalld'
assert_file_contains "$W/backups/genesis/firewalld_state.txt" '^default_zone=public$' "without an earlier run, http/https in public are the host's own and recorded"
run revert_firewall
zone_has public http && pass_msg "and revert leaves them open" || fail "revert removed the host's own http service"

if [[ -s "$W/forbidden" ]]; then
    fail "a real system tool would have been called: $(head -2 "$W/forbidden" | tr '\n' ';')"
else
    pass_msg "no real nft or systemctl was reached"
fi

finish
