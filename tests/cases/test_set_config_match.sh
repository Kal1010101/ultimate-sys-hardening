#!/bin/bash
# set_config edits only the global section of sshd_config: settings inside a
# Match block stay as the admin wrote them, and a new key never lands in one.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
f="$W/sshd_config"

run_set() {
    bash -c '
        source "'"$REPO"'/lib/core.sh"
        DRY_RUN=false LOG_FILE="'"$W"'/log"
        set_config "$1" "$2" "$3"
    ' _ "$@" >/dev/null 2>&1
}

cat > "$f" << 'EOF'
Include /etc/ssh/sshd_config.d/*.conf
#AllowTcpForwarding yes
AllowTcpForwarding yes

Match User alice
    AllowTcpForwarding local
    PermitOpen localhost:5901
EOF
run_set AllowTcpForwarding no "$f"
[[ "$(sed -n 3p "$f")" == "AllowTcpForwarding no" ]] \
    && pass_msg "the global line is rewritten" \
    || fail "global line not rewritten: $(sed -n 3p "$f")"
grep -qx '    AllowTcpForwarding local' "$f" \
    && pass_msg "the Match block's own line is kept" \
    || fail "the Match block's AllowTcpForwarding was changed"
[[ "$(grep -c '^[[:space:]]*AllowTcpForwarding' "$f")" == 2 ]] \
    || fail "expected 2 AllowTcpForwarding lines, got $(grep -c '^[[:space:]]*AllowTcpForwarding' "$f")"

run_set MaxAuthTries 3 "$f"
awk '/^MaxAuthTries 3$/ { k = NR } /^Match / { m = NR } END { exit !(k && k < m) }' "$f" \
    && pass_msg "a new key goes above the Match block" \
    || fail "MaxAuthTries landed inside the Match block: $(tr '\n' '|' < "$f")"

cat > "$f" << 'EOF'
#X11Forwarding yes
match Address 10.0.0.0/8
	X11Forwarding yes
EOF
run_set X11Forwarding no "$f"
[[ "$(head -1 "$f")" == "X11Forwarding no" ]] && grep -qx '	X11Forwarding yes' "$f" \
    && pass_msg "lowercase match ends the global section too" \
    || fail "lowercase match block changed: $(tr '\n' '|' < "$f")"

cat > "$f" << 'EOF'
#PermitRootLogin prohibit-password
# Match User anoncvs
#	PermitRootLogin yes
EOF
run_set PermitRootLogin no "$f"
[[ "$(head -1 "$f")" == "PermitRootLogin no" && "$(grep -c '^PermitRootLogin' "$f")" == 1 ]] \
    && pass_msg "only the first commented default is replaced" \
    || fail "commented defaults handled wrongly: $(tr '\n' '|' < "$f")"

printf 'PASS_MAX_DAYS\t99999\n' > "$W/login.defs"
bash -c 'source "'"$REPO"'/lib/core.sh"; DRY_RUN=false LOG_FILE="'"$W"'/log"; set_config PASS_MAX_DAYS 90 "$1" "	"' \
    _ "$W/login.defs" >/dev/null 2>&1
[[ "$(cat "$W/login.defs")" == "PASS_MAX_DAYS	90" ]] \
    && pass_msg "files without Match blocks work as before" \
    || fail "login.defs: $(cat "$W/login.defs")"

: > "$W/empty"
run_set Banner /etc/issue.net "$W/empty"
[[ "$(cat "$W/empty")" == "Banner /etc/issue.net" ]] \
    && pass_msg "an empty file gets the key" \
    || fail "empty file: $(cat "$W/empty")"

finish
