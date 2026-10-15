#!/bin/bash
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"
export LOG_FILE="${TMPDIR:-/tmp}/uh_svc_hint_$$.log"
trap 'rm -f "$LOG_FILE"' EXIT

hint() {
    bash -c "source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'
        $1
        printf '%s|%s' \"\$(service_status_hint nftables)\" \"\$(service_enable_hint crond)\"" 2>/dev/null
}

out=$(hint '_has_systemd() { return 1; }; _has_openrc() { return 0; }')
[[ "$out" == "rc-service nftables status|rc-update add crond default && rc-service crond start" ]] \
    && pass_msg "OpenRC hosts get rc-service/rc-update hints" || fail "OpenRC hint was: $out"

out=$(hint '_has_systemd() { return 0; }; _has_openrc() { return 1; }')
[[ "$out" == "systemctl status nftables|systemctl enable --now crond" ]] \
    && pass_msg "systemd hosts get systemctl hints" || fail "systemd hint was: $out"

out=$(hint '_has_systemd() { return 1; }; _has_openrc() { return 1; }')
[[ "$out" == "service nftables status|service crond start" ]] \
    && pass_msg "other hosts get service hints" || fail "fallback hint was: $out"

n=$(grep -nE '(log_[a-z]+|echo|printf)[^#]*"[^"]*systemctl (status|enable)' "$REPO/lib/"*.sh | wc -l)
[[ "$n" -eq 0 ]] && pass_msg "no hard-coded systemctl hints left in lib/" \
                 || fail "$n hard-coded systemctl hint(s) remain in lib/"

finish
