#!/bin/bash
# Module 2 must not lock the operator out. It turns off password login and
# root login only when an account other than root can still log in by key;
# otherwise it applies the other 11 settings and says how to finish.
#
# Runs the module on its own, with the restart stubbed, so each scenario
# starts from the same sshd_config.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"
require_root
require_file /etc/ssh/sshd_config
require_cmd ssh-keygen

W=$(mktemp -d)
cp -a /etc/ssh/sshd_config "$W/sshd_config.orig"
trap 'cp -a "$W/sshd_config.orig" /etc/ssh/sshd_config; rm -rf "$W"' EXIT
export LOG_FILE="$W/test.log"
dropin=/etc/ssh/sshd_config.d/00-ultimate-hardening.conf

# $1 = extra shell lines to run before the module (env settings, DRY_RUN).
# EXTRA_SSHD_CONFIG goes at the TOP of sshd_config: sshd keeps the first value
# it reads, and Fedora and Alpine already set AuthorizedKeysFile further down.
run_ssh_module() {
    cp -a "$W/sshd_config.orig" /etc/ssh/sshd_config
    if [[ -n "${EXTRA_SSHD_CONFIG:-}" ]]; then
        { printf '%s\n' "$EXTRA_SSHD_CONFIG"; cat "$W/sshd_config.orig"; } > /etc/ssh/sshd_config
    fi
    rm -f "$dropin" "$W/restarted"
    rm -rf "$W/genesis" "$W/run"
    bash -c '
        source "'"$REPO"'/lib/core.sh"
        source "'"$REPO"'/lib/platform.sh"
        source "'"$REPO"'/lib/modules.sh"
        DRY_RUN=false SKIP_BACKUP=false FIXES_APPLIED=0
        BACKUP_GENESIS_DIR="'"$W"'/genesis" BACKUP_DIR="'"$W"'/run" UH_BACKUP_ROOT="'"$W"'"
        restorecon() { :; }
        sshd_config_valid() { return 0; }
        restart_sshd() { return 0; }
        is_service_active() { return 0; }
        '"${1:-}"'
        apply_ssh_hardening
        echo "RC=$?"
    ' 2>&1
}

login_lines() { grep -cE '^(PermitRootLogin|PasswordAuthentication)[[:space:]]+no' "$1" 2>/dev/null; }

# $1 = output, $2 = scenario. Login settings must be left alone.
expect_kept() {
    assert_output_contains "$1" 'RC=0' "$2: the module still succeeds"
    assert_output_contains "$1" 'left as they are' "$2: the run says password and root login were kept"
    assert_output_contains "$1" '11 settings' "$2: it reports 11 settings, not 13"
    [[ "$(login_lines /etc/ssh/sshd_config)" == 0 ]] \
        && pass_msg "$2: sshd_config does not turn off password or root login" \
        || fail "$2: sshd_config turned off password or root login with no key to log in by"
    assert_file_contains /etc/ssh/sshd_config '^X11Forwarding[[:space:]]+no' "$2: the other settings are still applied"
    if [[ -f "$dropin" ]]; then
        [[ "$(login_lines "$dropin")" == 0 ]] \
            && pass_msg "$2: the drop-in does not turn them off either" \
            || fail "$2: the drop-in turned off password or root login"
        assert_file_contains "$dropin" '^MaxAuthTries 3$' "$2: the drop-in keeps the other settings"
    fi
}

# $1 = output, $2 = scenario. All 13 settings applied.
expect_locked_down() {
    assert_output_contains "$1" 'RC=0' "$2: the module succeeds"
    assert_output_contains "$1" '13 settings' "$2: it reports all 13 settings"
    [[ "$(login_lines /etc/ssh/sshd_config)" == 2 ]] \
        && pass_msg "$2: password and root login are turned off" \
        || fail "$2: password and root login were not both turned off"
    if [[ -f "$dropin" ]]; then
        [[ "$(login_lines "$dropin")" == 2 ]] \
            && pass_msg "$2: the drop-in turns them off too" \
            || fail "$2: the drop-in is missing the login settings"
    fi
}

add_login_user uhplain /bin/sh
add_login_user uhsvc /sbin/nologin
add_login_user uhadmin /bin/sh

# --- no way in by key ------------------------------------------------------------
expect_kept "$(run_ssh_module)" "no keys anywhere"

out=$(run_ssh_module 'DRY_RUN=true')
assert_output_contains "$out" 'Would apply 11 hardened settings' "dry run: it previews 11 settings"
assert_output_contains "$out" 'left as they are' "dry run: it warns before anything is written"
assert_unchanged /etc/ssh/sshd_config "$(checksum "$W/sshd_config.orig")" "dry run: sshd_config is untouched"

mkdir -p /root/.ssh
cp -a /root/.ssh "$W/root-ssh.orig"
add_ssh_key /root/.ssh/authorized_keys
expect_kept "$(run_ssh_module)" "a key for root only"
rm -rf /root/.ssh; cp -a "$W/root-ssh.orig" /root/.ssh

add_ssh_key /home/uhsvc/.ssh/authorized_keys
expect_kept "$(run_ssh_module)" "a key for a nologin account only"

mkdir -p /home/uhplain/.ssh
printf '# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAcommentedout old key\n\n' > /home/uhplain/.ssh/authorized_keys
expect_kept "$(run_ssh_module)" "an authorized_keys file holding only a comment"

out=$(run_ssh_module 'UH_SSH_LOCKOUT_CHECK=maybe')
assert_output_contains "$out" "UH_SSH_LOCKOUT_CHECK='maybe' is not true/false" "a bad UH_SSH_LOCKOUT_CHECK value is reported"
expect_kept "$out" "a bad UH_SSH_LOCKOUT_CHECK value keeps the check"

# --- the check is switched off ---------------------------------------------------
expect_locked_down "$(run_ssh_module 'UH_SSH_LOCKOUT_CHECK=false')" "UH_SSH_LOCKOUT_CHECK=false"

# --- keys sshd finds elsewhere ---------------------------------------------------
if command -v sshd >/dev/null 2>&1; then
    mkdir -p /etc/ssh/uh-test-keys
    add_ssh_key /etc/ssh/uh-test-keys/uhplain
    expect_locked_down "$(EXTRA_SSHD_CONFIG='AuthorizedKeysFile /etc/ssh/uh-test-keys/%u' run_ssh_module)" \
        "a key in a custom AuthorizedKeysFile"
    rm -rf /etc/ssh/uh-test-keys

    add_ssh_key "$W/user_ca.pub"
    expect_locked_down "$(EXTRA_SSHD_CONFIG="TrustedUserCAKeys $W/user_ca.pub" run_ssh_module)" \
        "a TrustedUserCAKeys CA"

    # Stock Arch sets userdbctl as AuthorizedKeysCommand whether or not it
    # serves anyone a key, so a key command alone must not count.
    expect_kept "$(EXTRA_SSHD_CONFIG=$'AuthorizedKeysCommand /bin/true\nAuthorizedKeysCommandUser nobody' run_ssh_module)" \
        "an AuthorizedKeysCommand alone"
else
    echo "SKIP: sshd not installed, so the AuthorizedKeysFile, CA and AuthorizedKeysCommand cases do not run"
fi

# --- a real key for a login account ----------------------------------------------
add_ssh_key "$W/admin.pub"
mkdir -p /home/uhadmin/.ssh
{ printf 'from="10.0.0.0/8",no-agent-forwarding '; cat "$W/admin.pub"; } > /home/uhadmin/.ssh/authorized_keys
expect_locked_down "$(run_ssh_module)" "a key with an options prefix for a login account"

finish
