#!/bin/bash
# UH_SHARED_DIRS must never let a user who can write a parent directory make
# root change another file. The attack: after module 22 makes /x/proj a group
# workspace, the user moves proj away and puts a symlink to /etc/sudoers (or
# any file) in its place; on revert, root used to run `setfacl --restore`
# through that path, which chowned the target to the directory's recorded
# owner and set its recorded mode. Revert now acts only on the very directory
# that was recorded (same device, inode and owner), from inside it; apply does
# its chmod from inside the directory after checking the physical path.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"
require_root
require_cmd setfacl
require_cmd getfacl

G=/root/.ultimate_hardening_genesis
B=/srv/uh-sd
OWNER=4242   # a numeric owner, as a user's own directory would have

# $1 = shell, run with the library and the modern profile.
step() {
    bash -c '
        source "$1/lib/core.sh"; source "$1/lib/platform.sh"; source "$1/lib/modules.sh"
        DRY_RUN=false AUTO_MODE=true SKIP_BACKUP=false LOG_FILE=/dev/null UH_PROFILE=modern
        eval "$2"' _ "$REPO" "$1" 2>&1
}
mode_of()  { stat -c '%a' "$1"; }
owner_of() { stat -c '%u:%g' "$1"; }
fresh() {
    rm -rf "$B" "$G"
    mkdir -p "$B/parent/proj"
    chmod 750 "$B/parent/proj"; chown "$OWNER:$OWNER" "$B/parent/proj"
    printf 'secret\n' > "$B/victim"; chmod 600 "$B/victim"
}

# --- the attack: symlink swapped in before revert ---------------------------------
fresh
step "UH_SHARED_DIRS='$B/parent/proj' apply_shared_dirs" >/dev/null
[[ "$(mode_of "$B/parent/proj")" == 2770 ]] && pass_msg "apply: workspace is 2770" || fail "apply mode: $(mode_of "$B/parent/proj")"
mv "$B/parent/proj" "$B/parent/proj.moved"
ln -s "$B/victim" "$B/parent/proj"
out=$(step 'undo_shared_dirs')
[[ "$(owner_of "$B/victim")" == 0:0 && "$(mode_of "$B/victim")" == 600 ]] \
    && pass_msg "symlink swapped in before revert: the target keeps its owner and mode" \
    || fail "target changed: owner $(owner_of "$B/victim"), mode $(mode_of "$B/victim")"
[[ -z "$(getfacl --omit-header -p "$B/victim" 2>/dev/null | grep -vE '^(user|group|other)::|^$')" ]] \
    && pass_msg "no ACL entries were written to the target" || fail "target ACL: $(getfacl -p "$B/victim")"
grep -q "$B/parent/proj is not the directory that was recorded" <<<"$out" \
    && pass_msg "revert says the path is not the recorded directory" || fail "revert log: $out"
[[ ! -e "$G/shared-dirs.record" && ! -e "$G/shared-dirs.acl" ]] \
    && pass_msg "the records are consumed either way" || fail "records left behind"

# --- a different real directory put in its place -----------------------------------
fresh
step "UH_SHARED_DIRS='$B/parent/proj' apply_shared_dirs" >/dev/null
mv "$B/parent/proj" "$B/parent/proj.moved"; mkdir "$B/parent/proj"; chmod 700 "$B/parent/proj"
step 'undo_shared_dirs' >/dev/null
[[ "$(mode_of "$B/parent/proj")" == 700 ]] && pass_msg "a replacement directory at the path is left alone" || fail "replacement changed: $(mode_of "$B/parent/proj")"

# --- normal revert still restores mode and ACL exactly -----------------------------
fresh
setfacl -m u:4243:rx "$B/parent/proj"
before=$(getfacl --omit-header -p "$B/parent/proj")
step "UH_SHARED_DIRS='$B/parent/proj' apply_shared_dirs" >/dev/null
getfacl -p "$B/parent/proj" | grep -q '^default:group::rwx' && pass_msg "apply: default ACLs set" || fail "apply ACL"
step 'undo_shared_dirs' >/dev/null
[[ "$(getfacl --omit-header -p "$B/parent/proj")" == "$before" ]] \
    && pass_msg "revert: the ACL is exactly as before (named entry back, no default ACL)" \
    || fail "ACL after revert: $(getfacl --omit-header -p "$B/parent/proj")"
[[ "$(mode_of "$B/parent/proj")" == 750 ]] && pass_msg "revert: mode 750 back, setgid cleared" || fail "mode after revert: $(mode_of "$B/parent/proj")"
[[ "$(owner_of "$B/parent/proj")" == "$OWNER:$OWNER" ]] && pass_msg "revert never changes the owner" || fail "owner: $(owner_of "$B/parent/proj")"
! grep -qE '^# (owner|group|flags):' "$G/shared-dirs.acl" 2>/dev/null \
    && pass_msg "the record holds no owner, group or flags to restore" || fail "record has owner lines"

# --- apply: a path that is a symlink by the time of the chmod ----------------------
fresh
ln -s "$B/victim" "$B/parent/link"
out=$(step "_apply_shared_dir '$B/parent/link'")
[[ "$(mode_of "$B/victim")" == 600 ]] && grep -q "skipped '$B/parent/link' — it changed while being checked" <<<"$out" \
    && pass_msg "apply through a symlinked path: refused, target untouched" || fail "apply via symlink: $out / $(mode_of "$B/victim")"
mkdir -p "$B/real"; ln -s "$B/real" "$B/parent/dirlink"
out=$(step "_apply_shared_dir '$B/parent/dirlink'")
[[ "$(mode_of "$B/real")" == 755 ]] && pass_msg "apply through a symlink to a directory: refused" || fail "dir symlink: $(mode_of "$B/real")"

rm -rf "$B" "$G"
finish
