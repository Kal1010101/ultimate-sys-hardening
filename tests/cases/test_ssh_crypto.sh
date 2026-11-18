#!/bin/bash
# Module 2's crypto allowlist: only allowlisted algorithms this OpenSSH build
# supports, no CBC ciphers or non-etm MACs left, a config sshd -t accepts,
# UH_SKIP_SETTINGS honoured, and a full revert puts sshd_config back.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root
require_file /etc/ssh/sshd_config
require_cmd sshd

add_login_user uhcrypto /bin/sh
add_ssh_key /home/uhcrypto/.ssh/authorized_keys

hk=()
if ! compgen -G '/etc/ssh/ssh_host_*_key' >/dev/null; then
    kd=$(mktemp -d); ssh-keygen -q -t ed25519 -N '' -f "$kd/k" && hk=(-h "$kd/k")
fi
effective() { sshd -T "${hk[@]}" 2>/dev/null | awk -v k="$1" 'tolower($1) == k { print $2 }'; }

if [[ -f /etc/crypto-policies/back-ends/opensshserver.config ]]; then
    out=$(run_hardening --auto-mode)
    assert_output_contains "$out" "system crypto policy" "crypto-policies host: allowlist left to the policy"
    assert_file_not_contains /etc/ssh/sshd_config '^Ciphers[[:space:]]' "no Ciphers line on a crypto-policies host"
    finish
fi
# ssh -Q answers which algorithms this build has.
require_cmd ssh

original=$(checksum /etc/ssh/sshd_config)
run_hardening --auto-mode >/dev/null

if sshd -t "${hk[@]}" 2>/dev/null; then
    pass_msg "sshd -t accepts the config with the allowlist"
else
    fail "sshd -t rejects the config with the allowlist"
fi

ciphers=$(effective ciphers)
kex=$(effective kexalgorithms)
macs=$(effective macs)
[[ -n "$ciphers" && -n "$kex" && -n "$macs" ]] && pass_msg "sshd reports ciphers, kex and MACs" \
    || fail "sshd -T missing a crypto keyword (ciphers='$ciphers' kex='$kex' macs='$macs')"

grep -q 'cbc' <<< "$ciphers" && fail "a CBC cipher is still allowed: $ciphers" || pass_msg "no CBC cipher allowed"
grep -q '3des\|arcfour' <<< "$ciphers" && fail "a legacy cipher is still allowed" || pass_msg "no 3DES/arcfour"
bad_mac=$(tr ',' '\n' <<< "$macs" | grep -v -- '-etm@openssh.com$' || true)
[[ -z "$bad_mac" ]] && pass_msg "only encrypt-then-MAC MACs" || fail "non-etm MACs allowed: $bad_mac"
grep -q 'sha1' <<< "$kex" && fail "a SHA-1 kex is still allowed: $kex" || pass_msg "no SHA-1 kex"

# Every name written must be one this build lists.
for name in $(tr ',' ' ' <<< "$ciphers"); do
    ssh -Q cipher | grep -qxF -- "$name" || fail "cipher $name is not supported by this build"
done
if ssh -Q kex | grep -qx 'sntrup761x25519-sha512@openssh.com'; then
    grep -q 'sntrup761x25519' <<< "$kex" && pass_msg "post-quantum kex kept where supported" \
        || fail "sntrup761x25519 supported but not in KexAlgorithms"
fi

# The drop-in wins first-value parsing, so it must carry the allowlist too.
dropin=/etc/ssh/sshd_config.d/00-ultimate-hardening.conf
[[ -f "$dropin" ]] && assert_file_contains "$dropin" '^Ciphers ' "drop-in carries the Ciphers allowlist"

# Idempotent.
run_hardening --auto-mode >/dev/null
n=$(grep -cE '^Ciphers[[:space:]]' /etc/ssh/sshd_config)
[[ "$n" -eq 1 ]] && pass_msg "idempotent: one Ciphers line" || fail "$n Ciphers lines after two runs"

# A full revert restores the original sshd_config and removes the drop-in.
run_hardening --revert --auto-mode >/dev/null
[[ "$(checksum /etc/ssh/sshd_config)" == "$original" ]] && pass_msg "revert restores sshd_config" \
    || fail "sshd_config differs from the original after --revert"
assert_file_absent "$dropin" "revert removes the drop-in"

# UH_SKIP_SETTINGS leaves a keyword alone.
UH_SKIP_SETTINGS="Ciphers HostKeyAlgorithms" run_hardening --auto-mode --skip-backup >/dev/null
assert_file_not_contains /etc/ssh/sshd_config '^Ciphers[[:space:]]' "UH_SKIP_SETTINGS=Ciphers leaves Ciphers alone"
assert_file_contains /etc/ssh/sshd_config '^MACs[[:space:]]' "other crypto keywords still written"
finish
