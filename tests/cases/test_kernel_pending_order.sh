#!/bin/bash
# With a kernel upgrade pending, the firewall and Fail2Ban must be applied
# before system updates, and Fail2Ban's ban action run once, so the kernel
# modules both need are loaded before the upgrade removes them from disk.
#
# Stubs are shell FUNCTIONS: lib/core.sh prepends the system directories to
# PATH when it is sourced, so a stub directory on PATH would be shadowed.
#
# Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_kpend_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT

run() {   # $1 = extra shell before the call
    : > "$W/calls"
    bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        DISTRO_TYPE=alpine; DRY_RUN=false; LOG_FILE='$W/run.log'
        run_module() { echo \"MOD \$1\" >> '$W/calls'; }
        fail2ban-client() { echo \"F2B \$*\" >> '$W/calls'; return 0; }
        is_service_active() { [[ \"\$1\" == fail2ban ]]; }
        sleep() { :; }
        $1
        _run_first_four_modules" >/dev/null 2>&1
    grep -v '^F2B status' "$W/calls" | tr '\n' '|'
}

out=$(run "kernel_update_pending() { return 1; }")
[[ "$out" == "MOD updates|MOD ssh|MOD firewall|MOD fail2ban|" ]] \
    && pass_msg "no kernel update pending: the usual order, Fail2Ban left alone" || fail "normal order: $out"

out=$(run "kernel_update_pending() { return 0; }")
[[ "$out" == "MOD firewall|MOD fail2ban|F2B set sshd banip 192.0.2.1|F2B set sshd unbanip 192.0.2.1|F2B set sshd banip 2001:db8::1|F2B set sshd unbanip 2001:db8::1|MOD updates|MOD ssh|" ]] \
    && pass_msg "kernel update pending: firewall and Fail2Ban first, ban action run for IPv4 and IPv6, then updates" \
    || fail "pending order: $out"

out=$(run "kernel_update_pending() { return 0; }; DRY_RUN=true")
[[ "$out" != *F2B* && "$out" == "MOD firewall|MOD fail2ban|MOD updates|MOD ssh|" ]] \
    && pass_msg "a dry run previews the same order and bans nothing" || fail "dry run: $out"

out=$(run "kernel_update_pending() { return 0; }; is_service_active() { return 1; }")
[[ "$out" != *F2B* ]] && pass_msg "nothing is asked of Fail2Ban when it is not running" || fail "inactive fail2ban: $out"

n=$(grep -c '^    _run_first_four_modules$' "$REPO/lib/modules.sh")
[[ "$n" -eq 2 ]] && pass_msg "both apply-all runs use the kernel-aware order" || fail "expected 2 callers, found $n"

finish
