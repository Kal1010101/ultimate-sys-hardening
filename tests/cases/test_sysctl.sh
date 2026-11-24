#!/bin/bash
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root
[[ -d /etc/sysctl.d ]] || skip "/etc/sysctl.d not present"

run_hardening --auto-mode --skip-backup >/dev/null

f=/etc/sysctl.d/99-hardening.conf
assert_file_exists "$f" "sysctl drop-in created"
assert_file_contains "$f" '^kernel\.randomize_va_space = 2' "ASLR set"
assert_file_contains "$f" '^net\.ipv4\.tcp_syncookies = 1'  "SYN cookies set"
assert_file_contains "$f" '^kernel\.kptr_restrict = 2'      "kptr restricted"
assert_file_contains "$f" '^fs\.suid_dumpable = 0'          "SUID dumps disabled"
assert_file_contains "$f" '^net\.core\.bpf_jit_harden = 2'   "BPF JIT hardened"
assert_file_contains "$f" '^net\.ipv4\.conf\.all\.secure_redirects = 0' "secure redirects refused"
assert_file_contains "$f" '^net\.ipv4\.conf\.default\.send_redirects = 0' "default send_redirects off"
assert_file_contains "$f" '^net\.ipv6\.conf\.default\.accept_source_route = 0' "IPv6 default source route off"
assert_file_contains "$f" '^net\.ipv6\.conf\.all\.forwarding = 0' "IPv6 forwarding off"

# Every parameter has its source on the comment line above it.
uncited=$(awk '/^[a-z]/ && prev !~ /^# / && prevkey == "" { print $1 }
               { if ($0 ~ /^[a-z]/) prevkey = $1; else { prevkey = ""; prev = $0 } }' "$f")
[[ -z "$uncited" ]] && pass_msg "every parameter group carries a source comment" \
                    || fail "parameters with no source comment: $uncited"

# accept_ra: written unless the host has an address from router adverts.
lib="source '${REPO_ROOT:-/repo}/lib/core.sh'; source '${REPO_ROOT:-/repo}/lib/platform.sh'; source '${REPO_ROOT:-/repo}/lib/modules.sh'; LOG_FILE=/dev/null"
slaac=$(bash -c "$lib; ip() { echo '2: eth0    inet6 2001:db8::5/64 scope global dynamic mngtmpaddr'; }; _kernel_sysctl_settings" 2>/dev/null)
static=$(bash -c "$lib; ip() { :; }; _kernel_sysctl_settings" 2>/dev/null)
grep -q 'accept_ra' <<< "$slaac" && fail "accept_ra written on a host using router adverts" \
                                 || pass_msg "accept_ra left alone where router adverts give the address"
grep -q '^net.ipv6.conf.all.accept_ra = 0' <<< "$static" && pass_msg "accept_ra = 0 written on a host without them" \
                                 || fail "accept_ra missing on a host without router adverts"

# ufw re-applies its own sysctl file at start (after systemd-sysctl at boot);
# its stock log_martians=0 must not survive to undo the drop-in.
if [[ -f /etc/ufw/sysctl.conf ]]; then
    grep -q '^net/ipv4/conf/all/log_martians=0' /etc/ufw/sysctl.conf \
        && fail "ufw's sysctl file still sets log_martians=0, which undoes the drop-in at every boot" \
        || pass_msg "ufw's sysctl file does not set log_martians back to 0"
fi

# Idempotency: second run must not duplicate entries
run_hardening --auto-mode --skip-backup >/dev/null
n=$(grep -c '^kernel\.randomize_va_space' "$f")
[[ "$n" -eq 1 ]] && pass_msg "idempotent: one randomize_va_space line" \
                 || fail "not idempotent: $n randomize_va_space lines"
finish
