#!/bin/bash
# The two hardening profiles (modern / cis), 2.8.0.
#
#   * the interactive run opens on the profile screen, then the OS menu (first
#     pass only), then the hardening menu; P goes back to the profile screen
#     and only Q there quits; --profile skips the first profile screen
#   * which profile an unattended run uses: --profile, then UH_PROFILE, then
#     the profile recorded on the host, then cis; invalid values fail
#   * modules 8 and 22 apply each profile's settings and revert cleanly,
#     including the directory modes and ACLs UH_SHARED_DIRS sets
#   * modern falls back to umask 027 where users share a primary group
#   * a module applied under the other profile shows as [modern ]/[cis    ]
#   * "apply all" leaves module 20 out under modern
#
# Changes /etc/login.defs, /etc/bash.bashrc, /etc/profile.d and /srv in a
# throwaway container. Runs as root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"
require_root

W=$(mktemp -d)
DEFS=/etc/login.defs
UMASK_DROPIN=/etc/profile.d/hardening-umask.sh
BASHRC=/etc/bash.bashrc
SHARED_DIR=/srv/uh-profile-team
GENESIS=/root/.ultimate_hardening_genesis
RECORD="$GENESIS/profile-record"

for f in "$DEFS" "$BASHRC"; do
    [[ -f "$f" ]] && cp -a "$f" "$W/$(basename "$f").orig"
done
cleanup() {
    for f in "$DEFS" "$BASHRC"; do
        if [[ -f "$W/$(basename "$f").orig" ]]; then cp -a "$W/$(basename "$f").orig" "$f"; else rm -f "$f"; fi
    done
    rm -rf "$W" "$SHARED_DIR"
}
trap cleanup EXIT

strip() { sed 's/\x1b\[[0-9;]*m//g'; }
count() { grep -c -- "$2" <<<"$1" || true; }
# Exact mode: assert_file_mode accepts anything numerically lower.
mode_is() {
    local actual; actual=$(stat -c '%a' "$1" 2>/dev/null)
    [[ "$actual" == "$2" ]] && pass_msg "$3 ($actual)" || fail "$3 — actual $actual"
}

# A login.defs every distribution image can use (Alpine ships none).
printf 'PASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\nPASS_WARN_AGE\t7\nUMASK\t\t022\nUSERGROUPS_ENAB yes\n' > "$DEFS"
mkdir -p /etc/profile.d
[[ -f "$BASHRC" ]] || : > "$BASHRC"

# --- interactive flow -----------------------------------------------------------
out=$(printf 'Q\n' | bash "$FREE_SCRIPT" 2>&1 | strip); rc=$?
assert_output_contains "$out" 'SELECT HARDENING PROFILE' "the program opens on the profile screen"
[[ "$(count "$out" 'SELECT YOUR OPERATING SYSTEM')" -eq 0 ]] \
    && pass_msg "Q on the profile screen quits before the OS menu" \
    || fail "Q on the profile screen still showed the OS menu"
assert_output_contains "$out" 'differ in three modules' "the profile screen says which modules differ"

# cis, auto-detect, back (P), modern, back, quit.
out=$(printf '2\n0\nP\n1\nP\nQ\n' | bash "$FREE_SCRIPT" 2>&1 | strip); rc=$?
[[ $rc -eq 0 ]] && pass_msg "quitting from the profile screen exits 0" || fail "the loop exited $rc"
[[ "$(count "$out" 'SELECT HARDENING PROFILE')" -eq 3 ]] \
    && pass_msg "P returns to the profile screen each time" \
    || fail "profile screen shown $(count "$out" 'SELECT HARDENING PROFILE') times, expected 3"
[[ "$(count "$out" 'SELECT YOUR OPERATING SYSTEM')" -eq 1 ]] \
    && pass_msg "the OS menu appears on the first pass only" \
    || fail "OS menu shown $(count "$out" 'SELECT YOUR OPERATING SYSTEM') times, expected 1"
assert_output_contains "$out" 'Profile: cis' "the hardening menu header names the cis profile"
assert_output_contains "$out" 'Profile: modern' "after P and 1 the header names the modern profile"
assert_output_contains "$out" 'P\) Back to profile selection' "the hardening menu offers P"

out=$(printf 'x\nQ\n' | bash "$FREE_SCRIPT" 2>&1 | strip)
assert_output_contains "$out" "Invalid choice: 'x'" "an invalid profile choice is refused and asked again"

out=$(printf '0\nP\nQ\n' | bash "$FREE_SCRIPT" --profile modern 2>&1 | strip)
first_screen=$(grep -m1 -oE 'SELECT (HARDENING PROFILE|YOUR OPERATING SYSTEM)' <<<"$out")
[[ "$first_screen" == "SELECT YOUR OPERATING SYSTEM" ]] \
    && pass_msg "--profile skips the first profile screen" \
    || fail "--profile still opened on: $first_screen"
assert_output_contains "$out" 'Profile: modern' "--profile modern reaches the menu as modern"
[[ "$(count "$out" 'SELECT HARDENING PROFILE')" -eq 1 ]] \
    && pass_msg "P after --profile still returns to the profile screen" \
    || fail "profile screen count after --profile: $(count "$out" 'SELECT HARDENING PROFILE')"

# --- which profile an unattended run uses ---------------------------------------
profile_of() { "$@" 2>&1 | strip | grep -oE 'Profile: [a-z]+' | tail -1; }
rm -f "$RECORD"
[[ "$(profile_of bash "$FREE_SCRIPT" --cis-only)" == "Profile: cis" ]] \
    && pass_msg "nothing set: cis" || fail "default profile is not cis"
[[ "$(profile_of env UH_PROFILE=modern bash "$FREE_SCRIPT" --cis-only)" == "Profile: modern" ]] \
    && pass_msg "UH_PROFILE=modern is used" || fail "UH_PROFILE was ignored"
[[ "$(profile_of env UH_PROFILE=modern bash "$FREE_SCRIPT" --cis-only --profile cis)" == "Profile: cis" ]] \
    && pass_msg "--profile wins over UH_PROFILE" || fail "UH_PROFILE won over --profile"
mkdir -p "$GENESIS"; printf 'profile=modern\n' > "$RECORD"
[[ "$(profile_of bash "$FREE_SCRIPT" --cis-only)" == "Profile: modern" ]] \
    && pass_msg "the profile recorded on the host is the default" || fail "the recorded profile was ignored"
[[ "$(profile_of env UH_PROFILE=cis bash "$FREE_SCRIPT" --cis-only)" == "Profile: cis" ]] \
    && pass_msg "UH_PROFILE wins over the recorded profile" || fail "the recorded profile won over UH_PROFILE"
json=$(bash "$FREE_SCRIPT" --json 2>/dev/null)
assert_output_contains "$json" '"profile": "modern"' "--json names the profile"
assert_output_contains "$json" '"status": "waived"' "--json reports the password check as waived under modern"
rm -f "$RECORD"

status=0; out=$(bash "$FREE_SCRIPT" --cis-only --profile strict 2>&1) || status=$?
[[ $status -ne 0 ]] && pass_msg "an invalid --profile exits non-zero" || fail "--profile strict exited 0"
assert_output_contains "$out" "Invalid --profile 'strict'" "the invalid --profile value is named"
status=0; out=$(UH_PROFILE=strict bash "$FREE_SCRIPT" --cis-only 2>&1) || status=$?
[[ $status -ne 0 ]] && pass_msg "an invalid UH_PROFILE exits non-zero" || fail "UH_PROFILE=strict exited 0"

# --- "apply all" and module 20 --------------------------------------------------
out=$(bash "$FREE_SCRIPT" --auto-mode --dry-run --profile modern 2>&1 | strip)
assert_output_contains "$out" 'Module 20 \(Compiler access restriction\) left out: modern profile' \
    "apply all leaves module 20 out under modern"
out=$(bash "$FREE_SCRIPT" --auto-mode --dry-run --profile cis 2>&1 | strip)
grep -q 'left out: modern profile' <<<"$out" \
    && fail "apply all left module 20 out under cis" \
    || pass_msg "apply all keeps module 20 under cis"
[[ ! -f "$RECORD" ]] && pass_msg "a dry run records no profile" || fail "a dry run wrote $RECORD"

# --- shared primary groups -------------------------------------------------------
# Local accounts only unless a case says otherwise, whatever the image ships.
printf 'passwd: files systemd\ngroup: files [SUCCESS=merge] systemd\n' > "$W/nsswitch.local"
export UH_NSSWITCH_FILE="$W/nsswitch.local" UH_SSSD_CONF_PATHS="$W/sssd/sssd.conf $W/sssd/conf.d"
umask_for() {   # $1 profile, $2 passwd file, $3 group file
    bash -c 'source "$1/lib/core.sh"; source "$1/lib/platform.sh"; source "$1/lib/modules.sh"
             UH_PROFILE=$2 UH_PASSWD_FILE=$3 UH_GROUP_FILE=$4 profile_umask_value' _ "$REPO" "$@"
}
printf 'root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\n' > "$W/passwd.private"
printf 'root:x:0:\nalice:x:1000:\nbob:x:1001:\n' > "$W/group.private"
printf 'root:x:0:0::/root:/bin/sh\nalice:x:1000:100::/home/alice:/bin/sh\nbob:x:1001:100::/home/bob:/bin/sh\n' > "$W/passwd.shared"
printf 'root:x:0:\nusers:x:100:\n' > "$W/group.shared"
[[ "$(umask_for modern "$W/passwd.private" "$W/group.private")" == 007 ]] \
    && pass_msg "modern with private groups: umask 007" || fail "modern with private groups is not 007"
[[ "$(umask_for modern "$W/passwd.shared" "$W/group.shared")" == 027 ]] \
    && pass_msg "modern with a shared primary group falls back to 027" || fail "modern with a shared group is not 027"
# A private group with another member is shared: www-data added to alice's
# group would get write access to alice's new files under 007.
printf 'root:x:0:\nalice:x:1000:www-data\nbob:x:1001:\n' > "$W/group.member"
[[ "$(umask_for modern "$W/passwd.private" "$W/group.member")" == 027 ]] \
    && pass_msg "modern: a private group with another member falls back to 027" || fail "group with a member is not 027"
printf 'root:x:0:\nalice:x:1000:alice\nbob:x:1001:\n' > "$W/group.self"
[[ "$(umask_for modern "$W/passwd.private" "$W/group.self")" == 007 ]] \
    && pass_msg "modern: a group listing only its own user stays private (007)" || fail "self-member group is not 007"
printf 'root:x:0:\nalice:x:1000:\nbob:x:1001:\nprojects:x:1000:carol\n' > "$W/group.dupgid"
[[ "$(umask_for modern "$W/passwd.private" "$W/group.dupgid")" == 027 ]] \
    && pass_msg "modern: a second group with the same GID counts as shared (027)" || fail "duplicate GID is not 027"
# Accounts from a directory service: their primary groups are not in the
# files, so modern falls back to 027. "sss" alone (RHEL's default
# nsswitch.conf) counts only when SSSD has a domain configured.
nss_umask() {   # $1 nsswitch.conf content
    printf '%b' "$1" > "$W/nsswitch.case"
    UH_NSSWITCH_FILE="$W/nsswitch.case" umask_for modern "$W/passwd.private" "$W/group.private"
}
[[ "$(nss_umask 'passwd: files [SUCCESS=merge] systemd\ngroup: files [ NOTFOUND=return ] systemd\n')" == 007 ]] \
    && pass_msg "nsswitch actions in brackets are not sources: local accounts, 007" || fail "nsswitch actions read as sources"
[[ "$(nss_umask 'passwd: sss files systemd\ngroup: sss files systemd\n')" == 007 ]] \
    && pass_msg "sss listed but no SSSD domain configured (RHEL default): 007" || fail "sss without a domain is not 007"
mkdir -p "$W/sssd/conf.d"; printf '[sssd]\ndomains = corp.example\n[domain/corp.example]\nid_provider = ad\n' > "$W/sssd/conf.d/50-corp.conf"
[[ "$(nss_umask 'passwd: sss files systemd\ngroup: sss files systemd\n')" == 027 ]] \
    && pass_msg "sss with an SSSD domain configured: falls back to 027" || fail "sss with a domain is not 027"
rm -rf "$W/sssd"
[[ "$(nss_umask 'passwd: files ldap\ngroup: files ldap\n')" == 027 ]] \
    && pass_msg "ldap in nsswitch.conf: falls back to 027" || fail "ldap is not 027"
[[ "$(nss_umask 'passwd: files\ngroup: files winbind\n')" == 027 ]] \
    && pass_msg "a directory source for groups only also counts (027)" || fail "group-only winbind is not 027"
# Forms glibc accepts although no tool writes them.
[[ "$(nss_umask 'passwd:files ldap\ngroup:files\n')" == 027 ]] \
    && pass_msg "no space after the colon (passwd:files ldap): still seen, 027" || fail "passwd:files ldap is not 027"
[[ "$(nss_umask 'passwd : files\ngroup\t: files ldap\n')" == 027 ]] \
    && pass_msg "spaces before the colon: still seen, 027" || fail "group\\t: files ldap is not 027"
[[ "$(nss_umask 'passwd: files\ngroup: files [NOTFOUND=return]ldap\n')" == 027 ]] \
    && pass_msg "a source glued to an action ([NOTFOUND=return]ldap): still seen, 027" || fail "glued action source is not 027"
[[ "$(nss_umask 'passwd files ldap\ngroup: files\n')" == 027 ]] \
    && pass_msg "no colon at all (passwd files ldap): still seen, 027" || fail "colonless passwd line is not 027"
[[ "$(nss_umask 'passwd: files\ngroup\f: files ldap\n')" == 027 ]] \
    && pass_msg "a form feed before the colon: still seen, 027" || fail "form-feed group line is not 027"
[[ "$(nss_umask 'passwd: files\npasswd_compat: nis\npasswdx ldap\ngroup: files\n')" == 007 ]] \
    && pass_msg "other databases (passwd_compat, passwdx) are not read as passwd: 007" || fail "passwd_compat or passwdx read as passwd"
[[ "$(nss_umask 'passwd: files systemd\r\ngroup: files systemd\r\n')" == 007 ]] \
    && pass_msg "CRLF line endings: local sources stay local, 007" || fail "CRLF lines read as directory"
[[ "$(nss_umask 'passwd: files[SUCCESS=merge]systemd # ldap in a comment\ngroup: files\n')" == 007 ]] \
    && pass_msg "glued actions between local sources, and comments, are not sources: 007" || fail "glued local sources read as directory"
cp "$W/passwd.private" "$W/passwd.compat"; echo '+::::::' >> "$W/passwd.compat"
[[ "$(umask_for modern "$W/passwd.compat" "$W/group.private")" == 027 ]] \
    && pass_msg "a +/- compat line in passwd: falls back to 027" || fail "compat + line is not 027"
out=$(printf 'passwd: files ldap\ngroup: files ldap\n' > "$W/nsswitch.case"
      bash -c 'source "$1/lib/core.sh"; source "$1/lib/platform.sh"; source "$1/lib/modules.sh"
               DRY_RUN=true AUTO_MODE=true LOG_FILE=/dev/null UH_PROFILE=modern UH_SHARED_DIRS=""
               UH_PASSWD_FILE="$2/passwd.private" UH_GROUP_FILE="$2/group.private" UH_NSSWITCH_FILE="$2/nsswitch.case"
               apply_umask_hardening' _ "$REPO" "$W" 2>&1 | strip)
grep -q 'Accounts also come from a directory service here (ldap)' <<<"$out" && grep -q 'Would set a default umask of 027' <<<"$out" \
    && pass_msg "the fallback says which directory source caused it" || fail "directory warning: $out"
[[ "$(umask_for cis "$W/passwd.private" "$W/group.private")" == 027 ]] \
    && pass_msg "cis: umask 027" || fail "cis is not 027"
sed -i 's/^USERGROUPS_ENAB.*/USERGROUPS_ENAB no/' "$DEFS"
[[ "$(umask_for modern "$W/passwd.private" "$W/group.private")" == 027 ]] \
    && pass_msg "USERGROUPS_ENAB no falls back to 027" || fail "USERGROUPS_ENAB no is not 027"
sed -i 's/^USERGROUPS_ENAB.*/USERGROUPS_ENAB yes/' "$DEFS"

# --- apply and revert modules 8 and 22 under each profile ------------------------
# $1 = profile, $2 = apply | revert | tags. One fresh shell per step, as a menu
# session restarted between steps would be. Private groups throughout.
step() {
    bash -c '
        source "$1/lib/core.sh"; source "$1/lib/platform.sh"
        source "$1/lib/modules.sh"; source "$1/lib/cis.sh"; source "$1/lib/menu.sh"
        DRY_RUN=false AUTO_MODE=true SKIP_BACKUP=false LOG_FILE="$2/run.log"
        UH_PROFILE=$3 UH_PASSWD_FILE="$2/passwd.private" UH_GROUP_FILE="$2/group.private"
        UH_SHARED_DIRS='"$SHARED_DIR"'
        case "$4" in
            apply)  create_backup_dir && run_module password apply_password_policies \
                        && run_module umask apply_umask_hardening ;;
            revert) revert_module password; revert_module umask ;;
            tags)   refresh_module_states
                    echo "TAG password $(_state_tag "${MOD_STATE[password]}" "${MOD_APPLIED_PROFILE[password]:-}")"
                    echo "TAG umask $(_state_tag "${MOD_STATE[umask]}" "${MOD_APPLIED_PROFILE[umask]:-}")" ;;
        esac
    ' _ "$REPO" "$W" "$1" "$2" 2>&1 | strip
}
snapshot() { for f in "$DEFS" "$BASHRC" "$UMASK_DROPIN"; do
    if [[ -e "$f" ]]; then echo "$f $(checksum "$f")"; else echo "$f absent"; fi; done; }

mkdir -p "$SHARED_DIR"; chmod 755 "$SHARED_DIR"
before=$(snapshot)

step modern apply >"$W/out"
assert_file_contains "$DEFS" '^PASS_MAX_DAYS	99999$' "modern: module 8 sets no forced expiry"
assert_file_contains "$DEFS" '^UMASK +007$' "modern: module 22 sets UMASK 007 in login.defs"
assert_file_contains "$UMASK_DROPIN" '^umask 007$' "modern: profile.d sets umask 007"
mode_is "$SHARED_DIR" 2770 "modern: UH_SHARED_DIRS directory is setgid 2770"
if command -v getfacl >/dev/null 2>&1; then
    getfacl -p "$SHARED_DIR" 2>/dev/null | grep -q '^default:group::rwx' \
        && pass_msg "modern: the shared directory has a group-writable default ACL" \
        || fail "modern: no default ACL on $SHARED_DIR"
fi
for key in profile password umask; do
    assert_file_contains "$RECORD" "^${key}=modern$" "modern: the host records ${key}=modern"
done

tags=$(step cis tags)
assert_output_contains "$tags" 'TAG password \[modern \]' "under cis, module 8 applied as modern shows [modern ]"
assert_output_contains "$tags" 'TAG umask \[modern \]' "under cis, module 22 applied as modern shows [modern ]"

step modern revert >"$W/out"
[[ "$(snapshot)" == "$before" ]] && pass_msg "modern: revert puts every file back" \
    || fail "modern: files differ after revert: $(diff <(echo "$before") <(snapshot) | tr '\n' ' ')"
mode_is "$SHARED_DIR" 755 "modern: revert puts the shared directory's mode back"
if command -v getfacl >/dev/null 2>&1; then
    getfacl -p "$SHARED_DIR" 2>/dev/null | grep -q '^default:' \
        && fail "modern: revert left a default ACL on $SHARED_DIR" \
        || pass_msg "modern: revert removes the default ACL"
fi
grep -qE '^(password|umask)=' "$RECORD" 2>/dev/null \
    && fail "revert left the module entries in the profile record" \
    || pass_msg "revert drops the module entries from the profile record"

step cis apply >"$W/out"
assert_file_contains "$DEFS" '^PASS_MAX_DAYS	365$' "cis: module 8 sets a 365-day max age"
assert_file_contains "$UMASK_DROPIN" '^umask 027$' "cis: profile.d sets umask 027"
mode_is "$SHARED_DIR" 755 "cis: UH_SHARED_DIRS is ignored"
step modern apply >"$W/out"
[[ "$(grep -cE '^umask 0[0-7]{2}$' "$BASHRC")" -eq 1 ]] \
    && pass_msg "switching profiles leaves one umask line in bash.bashrc" \
    || fail "bash.bashrc has $(grep -cE '^umask 0[0-7]{2}$' "$BASHRC") umask lines after a profile switch"
step modern revert >"$W/out"
[[ "$(snapshot)" == "$before" ]] && pass_msg "cis then modern: revert puts every file back" \
    || fail "cis then modern: files differ after revert"
mode_is "$SHARED_DIR" 755 "cis then modern: the shared directory's mode is back"

finish
