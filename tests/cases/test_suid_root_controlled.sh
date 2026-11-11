#!/bin/bash
# suid_path_is_root_controlled on fixed paths, and the menu's module 9 probe
# (UH_SUID_SCAN=1) that relies on it. Needs root: only root can build the
# root-owned paths the check accepts.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"
[[ $EUID -eq 0 ]] || skip "needs root to create root-owned paths (run with tests/run.sh)"

t="/uh_rootctl_$$"
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/sys" "$t/open" "$t/group" "$t/sticky" "$t/user"
chmod 755 "$t" "$t/sys" "$t/user"; chmod 777 "$t/open"; chmod 775 "$t/group"; chmod 1777 "$t/sticky"
chown 65534 "$t/user"
for d in sys open group sticky user; do touch "$t/$d/f"; chmod 4755 "$t/$d/f"; done
touch "$t/sys/other"; chown 65534 "$t/sys/other"; chmod 4755 "$t/sys/other"
ln -s "$t/sys/f" "$t/sys/link"
ln -s sys "$t/dirlink"

lib="source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'"

accepts() { bash -c "$lib; suid_path_is_root_controlled \"\$1\"" _ "$1"; }
expect() {   # $1 = yes|no, $2 = path, $3 = description
    if accepts "$2"; then got=yes; else got=no; fi
    [[ $got == "$1" ]] && pass_msg "$3" || fail "$3 (path $2: expected $1, got $got)"
}

expect yes "$t/sys/f"       "root-owned file under root-owned 755 dirs accepted"
expect no  "$t/sys/link"    "symlink to an accepted file rejected"
expect no  "$t/dirlink/f"   "path through a symlinked directory rejected"
expect no  "$t/sys/other"   "file not owned by root rejected"
expect no  "$t/open/f"      "file in a world-writable dir rejected"
expect no  "$t/sticky/f"    "file in a sticky world-writable dir rejected"
expect no  "$t/group/f"     "file in a group-writable dir rejected"
expect no  "$t/user/f"      "file in a dir owned by another user rejected"
expect no  "$t/sys/missing" "missing file rejected"

# --- menu probe: off only while a root-controlled, non-safe-listed SUID file remains
probe() {   # $@ = files the stubbed find reports
    bash -c "$lib; source '$REPO/lib/cis.sh'; source '$REPO/lib/menu.sh'
        UH_SUID_SAFELIST=('$t/sys/safe')
        find() { printf '%s\0' \"\${FILES[@]}\"; }
        FILES=(\"\$@\"); suid_scan_state" _ "$@" 2>/dev/null
}
touch "$t/sys/safe"; chmod 4755 "$t/sys/safe"

[[ $(probe "$t/sys/safe") == on ]] \
    && pass_msg "probe: only safe-listed SUID file reads as on" || fail "probe: safe-listed file read as off"
[[ $(probe "$t/sys/safe" "$t/sys/f") == off ]] \
    && pass_msg "probe: root-controlled SUID file reads as off" || fail "probe: root-controlled file read as on"
[[ $(probe "$t/open/f" "$t/user/f" "$t/sys/other") == on ]] \
    && pass_msg "probe: files module 9 leaves alone read as on" || fail "probe: files module 9 leaves read as off"

finish
