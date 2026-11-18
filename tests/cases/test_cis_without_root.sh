#!/bin/bash
# --cis-only, --json and --sarif run as a normal user. A check that needs root
# to see its answer reports "not checked" instead of failing, and stays out of
# the score; every other mode still refuses to run without root.
#
# Needs root, to set up the files and the account, then runs the tool as an
# unprivileged user with runuser. The repository is copied somewhere that user
# can read, since /repo is a bind mount whose parents it may not traverse.
# nft and aa-status are stubbed in /usr/local/bin with commands that fail, as
# the real ones do without root, so the firewall and AppArmor branches are
# reached on every image.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"
require_root
require_cmd runuser

USER_NAME=uhcheck
COPY=/opt/uh_noroot_copy
rm -rf "$COPY"; mkdir -p "$COPY"
cp -a "$REPO/lib" "$REPO/src" "$COPY/"
chmod -R a+rX "$COPY"
add_login_user "$USER_NAME" /bin/bash
SCRIPT="$COPY/src/free/ultimate_hardening.sh"

mkdir -p /etc/ssh /usr/local/bin
printf 'PermitRootLogin no\nPasswordAuthentication no\n' > /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
for stub in nft aa-status; do
    printf '#!/bin/sh\nexit 1\n' > "/usr/local/bin/$stub"
    chmod 755 "/usr/local/bin/$stub"
done
trap 'rm -f /usr/local/bin/nft /usr/local/bin/aa-status' EXIT

# $@ = tool arguments. Runs as the test user with a clean environment, so
# LOG_FILE from the harness does not leak in. Output on stdout, stderr mixed.
as_user() {
    runuser -u "$USER_NAME" -- env -i HOME="/home/$USER_NAME" \
        PATH=/usr/local/bin:/usr/bin:/bin bash "$SCRIPT" "$@" 2>&1
}
strip() { sed 's/\x1b\[[0-9;]*m//g'; }

# --- --cis-only as a normal user ---------------------------------------------
raw=$(as_user --cis-only); rc=$?
out=$(strip <<< "$raw")
assert_exit_code 0 "$rc" "--cis-only runs without root"
if grep -q 'must be run as root' <<< "$out"; then
    fail "--cis-only refused to run without root"
else
    pass_msg "--cis-only does not ask for root"
fi
assert_output_contains "$out" 'SSH root login disabled — not checked: /etc/ssh/sshd_config can only be read as root' \
    "an unreadable sshd_config makes the SSH checks not checked"
assert_output_contains "$out" 'Firewall is active — not checked' \
    "a firewall that only root can list is not checked"
assert_output_contains "$out" 'Mandatory access control is enforcing — not checked' \
    "AppArmor's profiles, root-only, are not checked"
assert_output_contains "$out" '7 check\(s\) not checked: they need root' \
    "the score footer counts the 7 not-checked checks"
if grep -qE 'SSH .*—.*(expected|Suggested fix)' <<< "$out"; then
    fail "an SSH check failed instead of being not checked"
else
    pass_msg "no SSH check is reported as failed"
fi

# --- log in the user's state directory ---------------------------------------
logdir="/home/$USER_NAME/.local/state/ultimate-hardening"
if compgen -G "$logdir/ultimate_hardening_*.log" >/dev/null; then
    pass_msg "the run log goes to ~/.local/state/ultimate-hardening"
else
    fail "no run log under $logdir"
fi
assert_file_mode "$logdir" 700 "the log directory is private to the user"

# --- JSON and SARIF ------------------------------------------------------------
json=$(runuser -u "$USER_NAME" -- env -i HOME="/home/$USER_NAME" \
    PATH=/usr/local/bin:/usr/bin:/bin bash "$SCRIPT" --json 2>/dev/null)
assert_output_contains "$json" '"not_checked": 7,' "JSON counts 7 not-checked checks"
assert_output_contains "$json" '"id": "ssh-root-login-disabled".*"status": "not_checked"' \
    "JSON marks the SSH checks not_checked"
# Not-checked results are out of the score: passed + failed = total.
json_count() { grep -oE "\"$1\": [0-9]+" <<< "$json" | head -1 | grep -oE '[0-9]+$'; }
passed=$(json_count passed); failed=$(json_count failed); total=$(json_count total)
if [[ -n "$total" ]] && (( passed + failed == total )); then
    pass_msg "the score counts passed and failed checks only ($passed + $failed = $total)"
else
    fail "JSON total '$total' is not passed '$passed' + failed '$failed'"
fi

sarif=$(runuser -u "$USER_NAME" -- env -i HOME="/home/$USER_NAME" \
    PATH=/usr/local/bin:/usr/bin:/bin bash "$SCRIPT" --sarif 2>/dev/null)
assert_output_contains "$sarif" '"ruleId": "ssh-root-login-disabled", "level": "note"' \
    "SARIF lists a not-checked check as a note, not a warning"

# --- as root, the same checks are answered -----------------------------------
root_out=$(LOG_FILE=/dev/null bash "$SCRIPT" --cis-only 2>&1 | strip)
if grep -q 'not checked' <<< "$root_out"; then
    fail "a check was not checked although the run had root"
else
    pass_msg "as root nothing is not checked"
fi
assert_output_contains "$root_out" '✅ +SSH root login disabled' \
    "as root the SSH checks read sshd_config"
assert_output_contains "$root_out" 'Firewall is active — No active firewall service detected' \
    "as root a missing firewall fails, as before"

# --- every other mode still needs root ---------------------------------------
for args in "--auto-mode --dry-run" "--verify" "--cis-only --revert" "--json --aide-verify x" "--revert"; do
    # shellcheck disable=SC2086  # args is a list of flags, split on purpose
    out=$(as_user $args </dev/null); rc=$?
    if [[ $rc -eq 1 ]] && grep -q 'must be run as root' <<< "$out"; then
        pass_msg "$args still needs root"
    else
        fail "$args ran without root (exit $rc)"
    fi
done

finish
