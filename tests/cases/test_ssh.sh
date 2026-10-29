#!/bin/bash
# SSH module must apply settings AND leave a config sshd accepts.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root
require_file /etc/ssh/sshd_config

printf '#Match User anoncvs\n#\tX11Forwarding no\n#\tAllowTcpForwarding no\n' >> /etc/ssh/sshd_config
vendor=""
if [[ -d /etc/ssh/sshd_config.d ]] && grep -qE '^Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config; then
    vendor=/etc/ssh/sshd_config.d/50-vendor-test.conf
    printf 'X11Forwarding yes\nAllowTcpForwarding yes\n' > "$vendor"
fi

before=$(checksum /etc/ssh/sshd_config)
run_hardening --auto-mode --skip-backup >/dev/null

assert_changed /etc/ssh/sshd_config "$before" "sshd_config was modified"
assert_file_contains /etc/ssh/sshd_config '^PermitRootLogin[[:space:]]+no'        "root login disabled"
assert_file_contains /etc/ssh/sshd_config '^PasswordAuthentication[[:space:]]+no' "password auth disabled"
assert_file_contains /etc/ssh/sshd_config '^X11Forwarding[[:space:]]+no'          "X11 forwarding disabled"
assert_file_contains /etc/ssh/sshd_config '^MaxAuthTries[[:space:]]+3'            "MaxAuthTries set to 3"

# The config must be valid — a broken one locks operators out. Checked
# independently of the lib helper; a throwaway key stands in on images
# (RHEL, Alpine) that only create host keys when sshd first starts.
if command -v sshd >/dev/null 2>&1; then
    hk=()
    if ! compgen -G '/etc/ssh/ssh_host_*_key' >/dev/null; then
        kd=$(mktemp -d); ssh-keygen -q -t ed25519 -N '' -f "$kd/k" && hk=(-h "$kd/k")
    fi
    if sshd -t "${hk[@]}" 2>/dev/null; then
        pass_msg "sshd -t accepts the hardened config"
    else
        fail "sshd -t REJECTS the hardened config — this would lock users out"
    fi
    err=$(mktemp)
    eff=$(sshd -T "${hk[@]}" 2>"$err")
    if [[ -z "$eff" ]]; then
        fail "sshd -T printed no settings: $(head -c 300 "$err")"
    else
        for kv in "permitrootlogin no" "passwordauthentication no" "x11forwarding no" "allowtcpforwarding no"; do
            grep -qx "$kv" <<< "$eff" && pass_msg "sshd runs with $kv${vendor:+ despite a vendor drop-in}" \
                                      || fail "sshd does not run with $kv (got: $(grep "^${kv% *} " <<< "$eff"))"
        done
    fi
    rm -f "$err"
fi

n=$(grep -cE '^#[[:space:]]+(X11Forwarding|AllowTcpForwarding)' /etc/ssh/sshd_config)
[[ "$n" -ge 2 ]] && pass_msg "the commented Match example stays commented" \
                 || fail "the commented Match example lines were uncommented"

# Running twice must not duplicate directives.
run_hardening --auto-mode --skip-backup >/dev/null
n=$(grep -cE '^PermitRootLogin[[:space:]]' /etc/ssh/sshd_config)
[[ "$n" -eq 1 ]] && pass_msg "idempotent: one PermitRootLogin line" \
                 || fail "not idempotent: $n PermitRootLogin lines after 2 runs"
finish
