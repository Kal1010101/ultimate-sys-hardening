#!/bin/bash
# --verify: a health baseline is taken before an aggregate run, and the check
# afterwards fails (exit 20, with the reason) when sshd stopped or stopped
# listening, a systemd unit newly failed, or the firewall is gone — and passes
# on a healthy host. Units that were already failing do not count. Stubs stand
# in for systemctl, ss, sshd and the firewall; needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_verify_$$"; rm -rf "$W"; mkdir -p "$W/state"
trap 'rm -rf "$W"' EXIT

# Host state the stubs read, changed between baseline and check.
set_host() {   # $1 = failed units, $2 = sshd yes|no, $3 = listening yes|no, $4 = firewall yes|no
    printf '%s\n' "$1" > "$W/failed"; echo "$2" > "$W/sshd"; echo "$3" > "$W/listen"; echo "$4" > "$W/fw"
}

# $1 = shell to run after the stubs. Prints output and RC=<status>.
run() {
    bash -c "source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        DRY_RUN=false; LOG_FILE='$W/run.log'; UH_STATE_DIR='$W/state'
        _has_systemd() { return 0; }; _systemd_running() { return 0; }
        systemctl() { [[ \"\$1\" == --failed ]] && sed '/^\$/d; s/\$/ loaded failed failed x/' '$W/failed'; return 0; }
        is_service_active() {
            case \$1 in
                sshd|ssh) [[ \$(cat '$W/sshd') == yes ]] ;;
                nftables) [[ \$(cat '$W/fw') == yes ]] ;;
                *) return 1 ;;
            esac
        }
        ufw() { :; }; nft() { return 1; }
        _sshd_effective_settings() { printf 'port 2222\n'; }
        ss() { [[ \$(cat '$W/listen') == yes ]] && echo 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*'; return 0; }
        $1" 2>&1
}

# --- healthy host, nothing changed: passes ----------------------------------
set_host "old.service" yes yes yes
run 'record_health_snapshot' >/dev/null
assert_file_contains "$W/state/health-snapshot" '^failed_units=old.service $' "the baseline records units already failing"
out=$(run 'verify_health; echo RC=$?')
assert_output_contains "$out" 'RC=0' "a healthy host passes"
assert_output_contains "$out" 'listening on port 2222' "sshd is checked on its configured port"

# --- a unit fails after the run ----------------------------------------------
set_host "old.service
broken.service" yes yes yes
out=$(run 'verify_health; echo RC=$?')
assert_output_contains "$out" 'RC=1' "a newly failed unit fails the check"
assert_output_contains "$out" 'units failed since the run: broken.service' "and names only the new failure"

# --- sshd down ---------------------------------------------------------------
set_host "old.service" no no yes
out=$(run 'verify_health; echo RC=$?')
assert_output_contains "$out" 'RC=1' "sshd not running fails the check"
assert_output_contains "$out" 'sshd was running before hardening and is not running now' "with the reason"

# --- sshd up but not listening -------------------------------------------------
set_host "old.service" yes no yes
out=$(run 'verify_health; echo RC=$?')
assert_output_contains "$out" 'nothing listens on its port 2222' "sshd running without a listener fails the check"

# --- firewall gone -------------------------------------------------------------
set_host "old.service" yes yes no
out=$(run 'verify_health; echo RC=$?')
assert_output_contains "$out" 'no firewall is loaded' "a firewall loaded before and gone after fails the check"

# --- no firewall before, and module 3 did not run: not demanded ---------------
set_host "" yes yes no
run 'record_health_snapshot' >/dev/null
out=$(run 'verify_health; echo RC=$?')
assert_output_contains "$out" 'RC=0' "no firewall is demanded where none was and module 3 did not run"
# ...but after a run that included module 3, it is.
out=$(run 'record_health_snapshot; UH_MODULES_RUN=(firewall); record_health_after_run; verify_health; echo RC=$?')
assert_output_contains "$out" 'no firewall is loaded' "module 3 having run makes a missing firewall a failure"
out=$(run 'verify_health; echo RC=$?')
assert_output_contains "$out" 'no firewall is loaded' "and a later standalone --verify remembers module 3 ran"

# --- no baseline at all ----------------------------------------------------------
rm -f "$W/state/health-snapshot"
set_host "x.service" yes yes yes
out=$(run 'verify_health; echo RC=$?')
assert_output_contains "$out" 'No health baseline' "a missing baseline is said plainly"

# --- a dry run writes no baseline ------------------------------------------------
out=$(run 'DRY_RUN=true; record_health_snapshot')
assert_file_absent "$W/state/health-snapshot" "a dry run leaves the state dir alone"

# --- the free entry point: --help documents it, exit code 20 is defined --------
help=$(bash "$REPO/src/free/ultimate_hardening.sh" --help 2>&1)
assert_output_contains "$help" '[-]-verify ' "--help lists --verify"
assert_output_contains "$help" '20 the --verify health check' "--help documents exit status 20"
finish
