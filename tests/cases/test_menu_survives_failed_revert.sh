#!/bin/bash
# A revert that finds nothing to revert must report it and go back to the
# menu. The tool runs under `set -euo pipefail`, so a revert function that
# returns 1 straight into a menu `case` used to end the whole program: on a
# host the tool had never hardened, menu choices R, S and 12 printed an error
# and dropped the user at the shell. This reproduces exactly that host (no
# backups, no genesis, no inventories) with the same shell options.
#
# The full-revert error also used to send free-tier users to --list-backups,
# an option only Pro and Enterprise accept. It now lists the restore points
# itself, which every tier can do.
#
# No root: backups and genesis point at an empty fixture. The SUID, compiler
# and services inventories are looked up under /root, which holds none in a
# fresh test container and is unreadable without root, so they are absent too.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_menu_revert_$$"; rm -rf "$W"; mkdir -p "$W/root"
trap 'rm -rf "$W"' EXIT

LIB="set -euo pipefail
     LOG_FILE='$W/run.log'
     source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'
     source '$REPO/lib/modules.sh'; source '$REPO/lib/cis.sh'; source '$REPO/lib/menu.sh'
     UH_BACKUP_ROOT='$W/root'; BACKUP_GENESIS_DIR='$W/no-genesis'
     BACKUP_DIR='$W/root/hardening_backup_none'; SUID_BACKUP_FILE='$W/none.txt'
     AUTO_MODE=false; DRY_RUN=false"

# Run one menu path with the given answers on stdin; print its output, then
# REACHED_END only if control came back to the caller.
menu_path() {
    local call="$1" answers="$2"
    printf '%b' "$answers" | bash -c "$LIB
        $call
        echo REACHED_END" 2>&1
}

# --- per-module reverts (free menu 9/12/20, every tier) -----------------------
for key in suid services compiler; do
    out=$(menu_path "revert_module $key" 'yes\n')
    assert_output_contains "$out" 'cannot revert' "revert_module $key: reports there is nothing to revert"
    assert_output_contains "$out" 'REACHED_END' "revert_module $key: returns to the menu instead of exiting"
done

# --- the shared revert menu (Pro/Enterprise R, options 1 and 2) ---------------
out=$(menu_path revert_menu '1\nyes\n')
assert_output_contains "$out" 'No backup matches' "revert_menu 1: reports there is no backup"
assert_output_contains "$out" 'REACHED_END' "revert_menu 1: returns to the menu instead of exiting"

out=$(menu_path revert_menu '2\nyes\n')
assert_output_contains "$out" 'No SUID inventory' "revert_menu 2: reports there is no SUID inventory"
assert_output_contains "$out" 'REACHED_END' "revert_menu 2: returns to the menu instead of exiting"

# --- the free tier's own menu (R and S live in show_menu, not in lib/) --------
# show_menu is lifted out of the free script the way docs/build-terminals.sh
# does it, with the screen-clearing and state probe stubbed (the probe needs
# root). After the choice, Enter dismisses "Press Enter", and P (back to the
# profile screen) leaves the redrawn menu: reaching MENU_RETURNED proves the
# menu came back.
free_menu() {
    printf '%b' "$1" | bash -c "$LIB
        UH_VERSION=test; DISTRO_TYPE=debian
        clear() { :; }
        refresh_module_states() { :; }
        eval \"\$(sed -n '/^show_menu() {/,/^}/p' '$REPO/src/free/ultimate_hardening.sh')\"
        show_menu; echo MENU_RETURNED" 2>&1
}

out=$(free_menu 'R\nyes\n\nP\n')
assert_output_contains "$out" 'No backup' "free menu R: reports there is no backup"
assert_output_contains "$out" 'MENU_RETURNED' "free menu R: returns to the menu instead of exiting"

out=$(free_menu 'S\n\nP\n')
assert_output_contains "$out" 'No SUID inventory' "free menu S: reports there is no SUID inventory"
assert_output_contains "$out" 'MENU_RETURNED' "free menu S: returns to the menu instead of exiting"

# --- the full-revert error points at something the free tier has ---------------
out=$(UH_REVERT_TARGET=genesis menu_path full_system_revert '' || true)
if grep -q -- '--list-backups' <<<"$out"; then
    fail "full revert error mentions --list-backups, which the free tier does not accept"
else
    pass_msg "full revert error does not point free-tier users at --list-backups"
fi
assert_output_contains "$out" 'No backups found' "full revert error says no backups exist on this host"

finish
