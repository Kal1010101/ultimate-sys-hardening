#!/bin/bash
# Module 4's jail file: progressive bans only where fail2ban has them (0.11+),
# a recidive jail reading wherever fail2ban logs, jails only for services that
# are installed with a log to read, and a fall back to the SSH jail alone when
# fail2ban rejects the rest. Stubs stand in for fail2ban; needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_f2bjails_$$"; rm -rf "$W"; mkdir -p "$W/f2b/fail2ban.d" "$W/f2b/jail.d"
trap 'rm -rf "$W"' EXIT
jail="$W/f2b/jail.d/99-ultimate-hardening.local"

# $1 = shell run before apply_fail2ban (stubs). Prints the module's output.
run_f2b() {
    rm -f "$jail"
    bash -c "source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        DRY_RUN=false; LOG_FILE='$W/run.log'
        UH_FAIL2BAN_JAIL='$jail'; UH_FAIL2BAN_DIR='$W/f2b'
        install_package() { return 0; }; record_service_state() { :; }; enable_service() { :; }
        is_service_active() { return 0; }; count_fix() { :; }; _has_systemd() { return 0; }
        fail2ban-client() {
            case \"\$1\" in
                --version) echo 'Fail2Ban v1.0.2' ;;
                -t) return 0 ;;
                *) return 0 ;;
            esac
        }
        nginx() { :; }; apache2() { :; }; httpd() { :; }; postfix() { :; }
        command() { if [[ \"\$1\" == -v && \"\$2\" =~ ^(nginx|apache2|httpd|postfix)\$ ]]; then [[ \" \${UH_TEST_SERVICES:-} \" == *\" \$2 \"* ]]; return; fi; builtin command \"\$@\"; }
        $1
        apply_fail2ban" 2>&1
}

# --- fail2ban 1.0, logging to a file, no web or mail server ------------------
printf '[Definition]\nlogtarget = /var/log/fail2ban.log\n' > "$W/f2b/fail2ban.conf"
out=$(run_f2b '')
assert_file_contains "$jail" '^\[sshd\]$' "the SSH jail is written"
assert_file_contains "$jail" '^bantime.increment = true$' "repeat bans grow longer on fail2ban 1.0"
assert_file_contains "$jail" '^bantime.maxtime   = 1w$' "and are capped at a week"
assert_file_contains "$jail" '^\[recidive\]$' "a recidive jail is written"
assert_file_contains "$jail" '^logpath  = /var/log/fail2ban.log$' "recidive reads fail2ban's own log file"
assert_file_not_contains "$jail" 'nginx|apache|postfix' "no service jails for services that are not installed"
assert_output_contains "$out" 'jails: sshd recidive' "the log names the jails"

# --- an override in fail2ban.local wins: the journal ------------------------
printf '[Definition]\nlogtarget = SYSTEMD-JOURNAL\n' > "$W/f2b/fail2ban.local"
run_f2b '' >/dev/null
assert_file_contains "$jail" '^journalmatch = _SYSTEMD_UNIT=fail2ban.service$' "recidive reads the journal when fail2ban logs there"
rm -f "$W/f2b/fail2ban.local"

# --- logging to syslog: nothing for recidive to read -------------------------
printf '[Definition]\nlogtarget = SYSLOG\n' > "$W/f2b/fail2ban.conf"
run_f2b '' >/dev/null
assert_file_not_contains "$jail" 'recidive' "no recidive jail when fail2ban logs to syslog"
printf '[Definition]\nlogtarget = /var/log/fail2ban.log\n' > "$W/f2b/fail2ban.conf"

# --- fail2ban 0.10: no bantime.increment ------------------------------------
run_f2b "fail2ban-client() { [[ \$1 == --version ]] && echo 'Fail2Ban v0.10.2'; return 0; }" >/dev/null
assert_file_not_contains "$jail" 'bantime.increment' "fail2ban 0.10 is not given keys it rejects"
assert_file_contains "$jail" '^\[sshd\]$' "and still gets the SSH jail"

# --- postfix installed on a systemd host ------------------------------------
UH_TEST_SERVICES="postfix" run_f2b '' >/dev/null
assert_file_contains "$jail" '^\[postfix\]$' "postfix gets a jail when it is installed"

# --- nginx installed but its log missing: no jail (it would stop fail2ban) ---
UH_TEST_SERVICES="nginx" run_f2b '' >/dev/null
if [[ -f /var/log/nginx/error.log ]]; then
    assert_file_contains "$jail" '^\[nginx-http-auth\]$' "nginx with its log gets a jail"
else
    assert_file_not_contains "$jail" 'nginx' "nginx without its error log gets no jail"
fi

# --- fail2ban rejects the extra jails: back to the SSH jail alone ------------
out=$(UH_TEST_SERVICES="postfix" run_f2b "fail2ban-client() { case \$1 in --version) echo 'Fail2Ban v1.0.2' ;; -t) ! grep -q recidive '$jail' ;; esac; }")
assert_file_not_contains "$jail" 'recidive|postfix' "a rejected config falls back to the SSH jail alone"
assert_file_contains "$jail" '^\[sshd\]$' "keeping the SSH jail"
assert_output_contains "$out" 'rejected the extra jails \(sshd recidive postfix\)' "and says which jails it dropped"

# --- even the SSH jail alone is rejected (no log for sshd): said plainly -----
out=$(run_f2b "fail2ban-client() { case \$1 in --version) echo 'Fail2Ban v1.0.2' ;; -t) return 1 ;; esac; return 0; }")
assert_output_contains "$out" 'even with the SSH jail alone' "a config failing on the SSH jail itself is not blamed on the extras"

# --- version parsing ----------------------------------------------------------
v=$(bash -c "source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'; LOG_FILE=/dev/null
    for x in 0.9.7 0.10.6 0.11.2 1.0.2 1.1.0 garbage; do _fail2ban_version_has_increment \$x && echo -n \"\$x:y \" || echo -n \"\$x:n \"; done" 2>/dev/null)
[[ "$v" == "0.9.7:n 0.10.6:n 0.11.2:y 1.0.2:y 1.1.0:y garbage:n " ]] && pass_msg "versions with bantime.increment are told apart" \
    || fail "version check got: $v"
finish
