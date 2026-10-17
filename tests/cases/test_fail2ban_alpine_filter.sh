#!/bin/bash
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_f2b_alpine_$$"; rm -rf "$W"; mkdir -p "$W/f2b/filter.d"
trap 'rm -rf "$W"' EXIT
export LOG_FILE="$W/run.log"

FN=$(sed -n '/^apply_fail2ban() {/,/^}/p' "$REPO/lib/modules.sh" | sed "s#/etc/fail2ban#$W/f2b#g")
[[ -n "$FN" ]] || { fail "apply_fail2ban not found"; finish; }

run_f2b() {
    rm -f "$W/f2b/filter.d/alpine-sshd.local"
    bash -c "source '$REPO/lib/core.sh'
        DRY_RUN=false
        install_package() { return 0; }; backup_file() { :; }; enable_service() { :; }
        is_service_active() { return 0; }; count_fix() { :; }; _has_systemd() { return 1; }
        $FN
        apply_fail2ban" >/dev/null 2>&1
}

L="$W/f2b/filter.d/alpine-sshd.local"

touch "$W/f2b/filter.d/alpine-sshd.conf"
run_f2b
if [[ -f "$L" ]]; then
    pass_msg "with Alpine's alpine-sshd filter present, an override is written"
    n=$(grep -c 'sshd(?:-session)?(?:\\.pam)?\\\[' "$L")
    [[ "$n" -eq 3 ]] && pass_msg "all three sshd patterns accept sshd.pam and sshd-session" \
                     || fail "expected 3 sshd(?:-session)?(?:\\.pam)? patterns, found $n"
else
    fail "no alpine-sshd.local was written although alpine-sshd.conf exists"
fi

if command -v python3 >/dev/null 2>&1 && [[ -f "$L" ]]; then
    m=$(python3 - "$L" <<'PY'
import re, sys
text = open(sys.argv[1]).read().split("failregex =", 1)[1]
pats = [p.strip().replace("<HOST>", r"(?P<host>\S+)") for p in text.strip().splitlines() if p.strip()]
lines = ["host1 auth.info sshd.pam[8873]: Invalid user admin from 192.0.2.9 port 57070",
         "host1 auth.info sshd-session.pam[8432]: Invalid user admin from 192.0.2.9 port 56848"]
print(min(sum(1 for p in pats if re.search(p, l)) for l in lines))
PY
)
    [[ "${m:-0}" -ge 1 ]] && pass_msg "real Alpine sshd.pam and sshd-session.pam log lines are matched" \
                          || fail "the override does not match an Alpine sshd.pam or OpenSSH 10 sshd-session.pam log line"
fi

rm -f "$W/f2b/filter.d/alpine-sshd.conf"
run_f2b
[[ -e "$L" ]] && fail "an Alpine override was written on a host without alpine-sshd.conf" \
              || pass_msg "no override is written where Alpine's filter is absent"

out=$(bash -c "source '$REPO/lib/core.sh'; _is_tool_created_path /etc/fail2ban/filter.d/alpine-sshd.local && echo yes")
[[ "$out" == yes ]] && pass_msg "revert treats the override as tool-created" \
                    || fail "the override is not in UH_TOOL_CREATED_PATHS"
grep -q '\[fail2ban\]=.*alpine-sshd.local' "$REPO/lib/menu.sh" \
    && pass_msg "module 4's revert covers the override" \
    || fail "module 4's per-module revert does not list the override"

finish
