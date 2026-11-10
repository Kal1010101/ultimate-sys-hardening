#!/bin/bash
# SUID inventory: names with newlines, the v2 header, and what the revert
# restores. find is stubbed to scan a temp dir instead of /, and every chmod
# hits files this test created. The recording checks need no root; the
# restore checks need root, because only root-owned paths are restored.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_suidinv_$$"; rm -rf "$W"; mkdir -p "$W/root" "$W/backup"
t="/uh_suidinv_t_$$"                # restore checks: root-owned dir, root-owned parent
trap 'rm -rf "$W"; [[ $EUID -eq 0 ]] && rm -rf "$t"' EXIT

run() {   # $1 = AUTO_MODE, $2 = commands; stdin is passed through for prompts
    bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'; source '$REPO/lib/cis.sh'
        DRY_RUN=false; SKIP_BACKUP=false; AUTO_MODE=$1; LOG_FILE='$W/run.log'
        BACKUP_DIR='$W/backup'; SUID_BACKUP_FILE='$W/backup/suid.txt'
        UH_SUID_SAFELIST=('$W/root/safe')
        confirm_risky() { [[ \$AUTO_MODE == true ]] && return 0; local r; read -r r; [[ \$r == yes ]]; }
        find() { [[ \$1 == / ]] && { shift; set -- '$W/root' \"\$@\"; }; command find \"\$@\"; }
        $2" >"$W/out" 2>&1
}
mode_of() { stat -c %a "$1"; }

# --- module 9 with a newline in a SUID file's name ----------------------------
other="$W/root/other"
cp /bin/true "$other"; chmod 755 "$other"
cp /bin/true "$W/root/safe"; chmod 4755 "$W/root/safe"   # safe-listed
cp /bin/true "$W/root/real"; chmod 4755 "$W/root/real"
ln -s . "$W/root/alias"
odd=$'x\n'"$other"$' 4755\n'"$W/root/alias/safe"$'\n'
mkdir -p "$W/root/$odd"; touch "$W/root/$odd/y"; chmod 4755 "$W/root/$odd/y"

run true apply_suid_hardening
[[ $(head -1 "$W/backup/suid.txt") == '# uh-suid-inventory v2' ]] \
    && pass_msg "inventory starts with the v2 header" || fail "inventory has no v2 header"
if grep -qxF "$other 4755" "$W/backup/suid.txt"; then
    fail "a name with newlines was split into extra records"
else
    pass_msg "a name with newlines added no records"
fi
grep -qxF "$W/root/real 4755" "$W/backup/suid.txt" \
    && pass_msg "ordinary SUID file recorded" \
    || fail "ordinary SUID file missing from inventory: $(tr '\n' '|' < "$W/backup/suid.txt")"
grep -q 'newline in its name' "$W/out" \
    && pass_msg "skipped file reported" || fail "no warning for the skipped file"
[[ -u "$W/root/safe" ]] \
    && pass_msg "safe-listed binary kept SUID" || fail "safe-listed binary lost SUID"
if [[ $EUID -ne 0 ]]; then
    # the test's own files: not root-owned, so module 9 leaves them and says so
    [[ -u "$W/root/real" ]] && grep -qF "review by hand): $W/root/real" "$W/out" \
        && pass_msg "file outside root's control left and reported" \
        || fail "file outside root's control was stripped or not reported"
fi

run true undo_suid_hardening
[[ $(mode_of "$other") == 755 ]] \
    && pass_msg "revert left an unrecorded file alone" || fail "revert changed $other to $(mode_of "$other")"

# --- restore checks: only the stripped SUID bit comes back --------------------
[[ $EUID -eq 0 ]] || { echo "SKIP: restore checks need root (run them with tests/run.sh)"; finish; }
reset_files() {
    rm -rf "$t"; mkdir -p "$t"
    touch "$t/plain" "$t/legit" "$t/with space" "$t/changed"
    chmod 640 "$t/plain"; chmod 755 "$t/legit" "$t/with space"; chmod 700 "$t/changed"
}
records() {
    printf '%s\n' "$t/plain 666" "$t/legit 4755" "$t/with space 4755" "$t/changed 4755" \
        "$t/legit \$(touch $W/ran)"
}

reset_files
{ echo '# uh-suid-inventory v2'; records; } > "$W/backup/suid.txt"
run true undo_suid_hardening
[[ $(mode_of "$t/plain") == 640 ]] \
    && pass_msg "recorded mode without SUID not applied" || fail "plain file changed to $(mode_of "$t/plain")"
[[ $(mode_of "$t/legit") == 4755 ]] \
    && pass_msg "SUID put back where only u+s was missing" || fail "legit file is $(mode_of "$t/legit")"
[[ $(mode_of "$t/with space") == 4755 ]] \
    && pass_msg "path with a space restored" || fail "path with a space is $(mode_of "$t/with space")"
[[ $(mode_of "$t/changed") == 700 ]] \
    && pass_msg "file whose mode changed since was left alone" || fail "changed file is $(mode_of "$t/changed")"
[[ ! -e $W/ran ]] \
    && pass_msg "malformed mode field not evaluated" || fail "malformed mode field was evaluated"

# --- older inventory (no header): never unattended, otherwise after "yes" -----
reset_files
records > "$W/backup/suid.txt"
run true undo_suid_hardening </dev/null
[[ $(mode_of "$t/legit") == 755 ]] \
    && pass_msg "older inventory not applied in auto mode" || fail "older inventory applied unattended"
grep -q 'Not restoring SUID from an older inventory unattended' "$W/out" \
    && pass_msg "auto-mode refusal explained" || fail "no explanation for the refusal"

run false undo_suid_hardening <<<"no"
[[ $(mode_of "$t/legit") == 755 ]] \
    && pass_msg "older inventory not applied when declined" || fail "older inventory applied after 'no'"
grep -qF "$t/legit" "$W/out" \
    && pass_msg "files listed before asking" || fail "files not listed before the prompt"

run false undo_suid_hardening <<<"yes"
[[ $(mode_of "$t/legit") == 4755 && $(mode_of "$t/plain") == 640 ]] \
    && pass_msg "older inventory restored after 'yes', same checks applied" \
    || fail "after 'yes': legit $(mode_of "$t/legit"), plain $(mode_of "$t/plain")"

reset_files
{ records; echo '# uh-suid-inventory v2'; } > "$W/backup/suid.txt"
run true undo_suid_hardening </dev/null
[[ $(mode_of "$t/legit") == 755 ]] \
    && pass_msg "header after the first line ignored" || fail "header on a later line counted"

finish
