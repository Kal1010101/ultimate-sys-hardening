#!/bin/bash
# UH_SKIP_SETTINGS leaves single settings alone without skipping their whole
# module: one conflicting sshd keyword or sysctl no longer costs every other
# setting the module applies.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W=$(mktemp -d)
export LOG_FILE="$W/test.log"
_lib='source "'"$REPO"'/lib/core.sh"; source "'"$REPO"'/lib/platform.sh"; source "'"$REPO"'/lib/modules.sh"'

# --- matching ---------------------------------------------------------------------
out=$(bash -c "$_lib
    UH_SKIP_SETTINGS='X11Forwarding, net.ipv6.*  maxauthtries'
    for k in X11Forwarding x11forwarding net.ipv6.conf.all.accept_ra MaxAuthTries net.ipv4.ip_forward PermitRootLogin; do
        setting_skipped \"\$k\" && echo \"SKIP \$k\" || echo \"KEEP \$k\"
    done" 2>&1)
assert_output_contains "$out" '^SKIP X11Forwarding$'               "an exact name is skipped"
assert_output_contains "$out" '^SKIP x11forwarding$'               "names match without regard to case, as sshd reads them"
assert_output_contains "$out" '^SKIP net.ipv6.conf.all.accept_ra$' "a shell pattern skips every key it matches"
assert_output_contains "$out" '^SKIP MaxAuthTries$'                "commas and spaces both separate entries"
assert_output_contains "$out" '^KEEP net.ipv4.ip_forward$'         "a key the pattern does not match is kept"
assert_output_contains "$out" '^KEEP PermitRootLogin$'             "an unlisted key is kept"

out=$(bash -c "$_lib
    UH_SKIP_SETTINGS='*'
    cd '$W'; touch PermitRootLogin
    setting_skipped X11Forwarding && echo SKIPPED" 2>&1)
assert_output_contains "$out" '^SKIPPED$' "a pattern is matched against the key, never expanded against files"

out=$(bash -c "$_lib
    UH_SKIP_SETTINGS='net.ipv4.ip_forward MaxAuthTries'
    printf '# comment\nnet.ipv4.ip_forward = 0\nkernel.kptr_restrict = 2\nMaxAuthTries 3\n  indented line\n\n' | drop_skipped_settings
    echo \"---\"
    printf 'net.ipv4.ip_forward = 0\nMaxAuthTries 3\nX11Forwarding no\n' | skipped_settings_in" 2>&1)
assert_output_contains "$out" '^# comment$'                  "comments pass through the filter"
assert_output_contains "$out" '^kernel.kptr_restrict = 2$'   "unlisted settings pass through"
assert_output_contains "$out" '^  indented line$'            "indented lines pass through"
if grep -qE '^(net.ipv4.ip_forward|MaxAuthTries)' <<< "${out%%---*}"; then
    fail "the filter kept a skipped setting"
else
    pass_msg "the filter drops skipped settings in both key=value and keyword forms"
fi
assert_output_contains "$out" '^net.ipv4.ip_forward MaxAuthTries$' "the skipped keys are listed for the log"

# --- set_config ---------------------------------------------------------------------
printf 'PASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\n' > "$W/login.defs"
out=$(bash -c "$_lib
    DRY_RUN=false UH_SKIP_SETTINGS=PASS_MAX_DAYS
    set_config PASS_MAX_DAYS 90 '$W/login.defs' '	'
    set_config PASS_MIN_DAYS 1  '$W/login.defs' '	'
    echo \"COUNT=\$UH_SETTINGS_SKIPPED_COUNT\"" 2>&1)
assert_file_contains "$W/login.defs" '^PASS_MAX_DAYS	99999$' "set_config leaves a skipped key as it was"
assert_file_contains "$W/login.defs" '^PASS_MIN_DAYS	1$'     "and still sets the others"
assert_output_contains "$out" 'Left PASS_MAX_DAYS as it is' "the skip is logged"
assert_output_contains "$out" '^COUNT=1$'                   "and counted"

# --- the SSH module, end to end -----------------------------------------------------
if [[ $EUID -eq 0 && -f /etc/ssh/sshd_config ]] && command -v ssh-keygen >/dev/null 2>&1; then
    cp -a /etc/ssh/sshd_config "$W/sshd_config.orig"
    # Start from a value the module would change, because some distros (Alpine)
    # already ship X11Forwarding no, which would hide whether the skip worked.
    { echo "X11Forwarding yes"; grep -vE '^X11Forwarding[[:space:]]' "$W/sshd_config.orig"; } > "$W/sshd_config.start"
    dropin=/etc/ssh/sshd_config.d/00-ultimate-hardening.conf
    add_login_user uhadmin /bin/sh
    add_ssh_key /home/uhadmin/.ssh/authorized_keys

    ssh_run() {  # $1 = extra settings
        cp "$W/sshd_config.start" /etc/ssh/sshd_config
        rm -f "$dropin"; rm -rf "$W/genesis" "$W/run"
        bash -c "$_lib
            DRY_RUN=false SKIP_BACKUP=false FIXES_APPLIED=0
            BACKUP_GENESIS_DIR='$W/genesis' BACKUP_DIR='$W/run' UH_BACKUP_ROOT='$W'
            restorecon() { :; }; sshd_config_valid() { return 0; }
            restart_sshd() { return 0; }; is_service_active() { return 0; }
            $1
            apply_ssh_hardening" 2>&1
    }

    out=$(ssh_run 'UH_SKIP_SETTINGS="X11Forwarding AllowTcpForwarding"')
    assert_output_contains "$out" '11 settings' "two skipped keywords leave 11 of 13 settings"
    if grep -qE '^X11Forwarding[[:space:]]+yes$' /etc/ssh/sshd_config \
        && ! grep -qE '^X11Forwarding[[:space:]]+no' /etc/ssh/sshd_config; then
        pass_msg "sshd_config keeps the skipped keyword as it was"
    else
        fail "sshd_config changed X11Forwarding although it was skipped"
    fi
    assert_file_contains /etc/ssh/sshd_config '^MaxAuthTries[[:space:]]+3' "the module's other settings still apply"
    if [[ -f "$dropin" ]]; then
        if grep -qE '^(X11Forwarding|AllowTcpForwarding)' "$dropin"; then
            fail "the drop-in sets a skipped keyword, which would win over sshd_config"
        else
            pass_msg "the drop-in leaves the skipped keywords out too"
        fi
        assert_file_contains "$dropin" '^PasswordAuthentication no$' "the drop-in keeps the unskipped settings"
    fi

    out=$(ssh_run 'DRY_RUN=true; UH_SKIP_SETTINGS=X11Forwarding')
    assert_output_contains "$out" 'Would apply 12 hardened settings' "dry run counts the skip"
    assert_output_contains "$out" 'Left as they are \(UH_SKIP_SETTINGS\): X11Forwarding' "and names it"

    cp -a "$W/sshd_config.orig" /etc/ssh/sshd_config
else
    echo "SKIP: SSH part needs root, sshd_config and ssh-keygen"
fi

# --- the kernel module's generated file ----------------------------------------------
out=$(bash -c "$_lib
    UH_SKIP_SETTINGS='net.ipv6.* kernel.kptr_restrict'
    _kernel_sysctl_settings" 2>&1)
if grep -qE '^(net\.ipv6\.|kernel\.kptr_restrict)' <<< "$out"; then
    fail "the sysctl file still sets a skipped key"
else
    pass_msg "the sysctl file leaves out skipped keys and patterns"
fi
assert_output_contains "$out" '^kernel.randomize_va_space' "and keeps the rest"

out=$(bash -c "$_lib
    is_linux() { return 0; }
    DRY_RUN=true UH_SKIP_SETTINGS=kernel.kptr_restrict
    apply_kernel_hardening" 2>&1)
total=$(bash -c "$_lib; _kernel_sysctl_conf | grep -c '^[a-z]'")
assert_output_contains "$out" "Would write $((total - 1)) sysctl parameters" "the dry run counts what will really be written"
assert_output_contains "$out" 'Left as they are \(UH_SKIP_SETTINGS\): kernel.kptr_restrict' "and names the skipped key"

rm -rf "$W"
finish
