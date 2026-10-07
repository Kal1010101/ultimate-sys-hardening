#!/bin/bash
# The tool's own attack surface, not the system's.
#
# This runs as root, sources a shell library by path, calls tools by bare name,
# writes a log naming every file it touched, and takes a remote-syslog
# destination from the environment. Each of those is a way for someone who is
# not root to influence what root does. None of it makes a root-run bash script
# "hacker proof" — nothing does — but each of these is a real, closable gap.
#
# Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

TMP="${TMPDIR:-/tmp}/uh_selfprot_$$"
mkdir -p "$TMP"
export LOG_FILE="$TMP/run.log"

_lib='source "'"$REPO"'/lib/core.sh"
      source "'"$REPO"'/lib/platform.sh"
      source "'"$REPO"'/lib/modules.sh"'

# --- PATH: system directories must come first --------------------------------
# A writable directory ahead of /usr/bin decides which `sed` root runs.
p=$(bash -c "PATH=/tmp/evil:/usr/bin:/bin; $_lib; printf '%s' \"\$PATH\"" 2>/dev/null)
case "$p" in
    /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin*)
        pass_msg "system directories are prepended to PATH" ;;
    *)  fail "PATH does not start with the system directories: $p" ;;
esac
if grep -q '/tmp/evil' <<< "$p"; then
    pass_msg "a caller's own PATH entries are kept, just demoted"
else
    fail "PATH was replaced rather than prepended — this breaks /opt tooling"
fi

# --- the run log must not be world-readable ----------------------------------
rm -f "$TMP/fresh.log"
bash -c "LOG_FILE='$TMP/fresh.log'; $_lib; log_info 'hello' >/dev/null" 2>/dev/null
if [[ -f "$TMP/fresh.log" ]]; then
    mode=$(stat -c '%a' "$TMP/fresh.log" 2>/dev/null)
    if [[ "$mode" == "600" ]]; then
        pass_msg "run log is created 600, not the ambient-umask 644"
    else
        fail "run log mode is $mode — it names every file touched and the SUID inventory"
    fi
else
    fail "no log file was created"
fi

# --- and must never touch a device or a symlink ------------------------------
# docs/build-terminals.sh sets LOG_FILE=/dev/null to silence logging, and
# test_module_count runs it — as root, on a real host. An unguarded chmod made
# /dev/null 0600 root:root there, which breaks every program on the machine
# that redirects to it. The VM lab caught it when the harness could no longer
# copy its own report back.
# Asserted by stubbing chmod rather than by reading /dev/null's mode: as a
# non-root user the chmod simply fails and the mode is unchanged either way, so
# the mode check passes whether or not the guard exists. This asks the only
# question that matters — was the chmod even attempted.
attempt=$(bash -c "chmod() { echo \"CHMOD-CALLED \$*\"; }
                   LOG_FILE=/dev/null; $_lib; true" 2>&1) || true
if grep -q 'CHMOD-CALLED.*/dev/null' <<< "$attempt"; then
    fail "the library tried to chmod /dev/null — as root that makes it 0600 and breaks the host"
else
    pass_msg "LOG_FILE=/dev/null is never chmod-ed"
fi

before=$(stat -c '%a' /dev/null 2>/dev/null)
bash -c "LOG_FILE=/dev/null; $_lib; true" 2>/dev/null
after=$(stat -c '%a' /dev/null 2>/dev/null)
if [[ "$before" == "$after" ]]; then
    pass_msg "/dev/null's mode is unchanged after sourcing ($after)"
else
    fail "sourcing the library with LOG_FILE=/dev/null changed /dev/null from $before to $after"
fi

# A symlinked LOG_FILE must not have its TARGET touched. `-e` and `-f` both
# follow symlinks, so without an explicit -L test the chmod lands on whatever
# the link points at — and LOG_FILE is a predictable path under /var/log.
# Asserted on the target's mode, which is the effect that actually occurs;
# asserting on its contents proved nothing, because the creation step is
# already skipped for an existing target.
printf 'keep me' > "$TMP/target"; chmod 644 "$TMP/target"
ln -sf "$TMP/target" "$TMP/link.log"
bash -c "LOG_FILE='$TMP/link.log'; $_lib; true" 2>/dev/null
tmode=$(stat -c '%a' "$TMP/target" 2>/dev/null)
if [[ "$tmode" == "644" ]]; then
    pass_msg "a symlinked LOG_FILE leaves its target's mode alone"
else
    fail "a symlinked LOG_FILE was followed — target mode is now $tmode"
fi
if [[ "$(cat "$TMP/target" 2>/dev/null)" == "keep me" ]]; then
    pass_msg "and its target's contents are intact"
else
    fail "a symlinked LOG_FILE was truncated through"
fi

# A DANGLING symlink is the case where the creation step does fire: `-e` is
# false, so `: >` would create the file the link points at.
rm -f "$TMP/dangling-target" "$TMP/dangling.log"
ln -s "$TMP/dangling-target" "$TMP/dangling.log"
bash -c "LOG_FILE='$TMP/dangling.log'; $_lib; true" 2>/dev/null
if [[ ! -e "$TMP/dangling-target" ]]; then
    pass_msg "a dangling symlinked LOG_FILE does not create its target"
else
    fail "a dangling symlinked LOG_FILE created $TMP/dangling-target"
fi

# --- remote syslog destination is validated ----------------------------------
# It is appended to rsyslog.conf verbatim, and rsyslog's config can run
# programs. A newline plus a directive would be root code at the next restart.
# Tested through the predicate, not through apply_remote_syslog. Calling the
# module meant a real create_backup_dir and a real append to /etc/rsyslog.conf,
# which made the NEXT case (test_dryrun) fail on "dry-run created a backup
# directory" — on Rocky only, because Debian and Alpine have no
# /etc/rsyslog.conf so the module returned early. A pure predicate has no such
# reach.
bad_count=0
for bad in 'host
$ModLoad omprog' 'host;rm -rf /' 'host $x' '../../etc/passwd' '' '-flag' 'a/b'; do
    if bash -c "set -uo pipefail; $_lib; valid_syslog_destination '$bad'" 2>/dev/null; then
        fail "remote syslog would accept a destination it should not: $(printf '%q' "$bad")"
        bad_count=$((bad_count + 1))
    fi
done
[[ $bad_count -eq 0 ]] && pass_msg "malformed remote-syslog destinations are all refused"

for good in 'logs.example.com' '10.0.0.5' 'syslog01' 'fd00::1' 'a-b.c_d.example'; do
    if bash -c "set -uo pipefail; $_lib; valid_syslog_destination '$good'" 2>/dev/null; then
        :
    else
        fail "a legitimate destination was refused — the pattern is too strict: $good"
    fi
done
pass_msg "legitimate hostnames and IPs are still accepted"

# And the module must actually use it, or the predicate guards nothing.
if grep -q 'valid_syslog_destination "\$server"' "$REPO/lib/modules.sh"; then
    pass_msg "apply_remote_syslog validates through that predicate"
else
    fail "apply_remote_syslog no longer calls valid_syslog_destination"
fi

# --- the update check must not be redirected to another host -----------------
for bad in 'evil.com/x/../..' 'a/b/c' '/etc/passwd' 'user@host/repo' ''; do
    out=$(bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/update.sh'
        UH_UPDATE_REPO='$bad'
        check_for_updates" 2>&1) || true
    if ! grep -q 'not a valid owner/repo' <<< "$out"; then
        fail "update check accepted a malformed repo: $(printf '%q' "$bad")"
    fi
done
pass_msg "the update check refuses anything that is not owner/repo"

# Validation must not refuse real repos. curl is a function stub: core.sh
# prepends system dirs to PATH, so a PATH stub would be shadowed.
for good in 'Kal1010101/ultimate-sys-hardening' 'a-b/c.d_e'; do
    out=$(bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/update.sh'
        curl() { echo '{\"tag_name\": \"v0.0.1\"}'; }
        UH_UPDATE_REPO='$good'
        check_for_updates" 2>&1) || true
    if grep -q 'not a valid owner/repo' <<< "$out"; then
        fail "update check refused a legitimate repo: $good"
    elif ! grep -q 'ahead of the latest tagged release' <<< "$out"; then
        fail "update check did not reach the version compare for $good: $out"
    fi
done
pass_msg "legitimate owner/repo values still reach the API call"

# --- the library-trust check must actually fire ------------------------------
# Simulated rather than requiring root: check_lib_trust returns early unless
# EUID is 0, so the logic is exercised through a stubbed EUID.
fakelib="$TMP/lib"; mkdir -p "$fakelib"; : > "$fakelib/core.sh"
chmod 777 "$fakelib/core.sh"
out=$(bash -c "$_lib; _uh_euid() { echo 0; }; SUDO_UID=99999; check_lib_trust '$fakelib'" 2>&1) || true
assert_output_contains "$out" 'writable by someone other than root or you' \
    "a world-writable lib file is reported"

chmod 644 "$fakelib/core.sh"
out=$(bash -c "$_lib; _uh_euid() { echo 0; }; SUDO_UID=$(id -u); check_lib_trust '$fakelib'" 2>&1) || true
if grep -q 'writable by someone' <<< "$out"; then
    fail "your own checkout, run under your own sudo, warns — this would be noise on every dev run"
else
    pass_msg "your own non-writable checkout produces no warning"
fi

out=$(bash -c "$_lib; _uh_euid() { echo 0; }; SUDO_UID=99999; UH_TRUST_LIB=1; check_lib_trust '$fakelib'" 2>&1) || true
if [[ -z "$out" ]]; then
    pass_msg "UH_TRUST_LIB=1 silences it"
else
    fail "UH_TRUST_LIB=1 did not silence the warning"
fi

rm -rf "$TMP"
finish
