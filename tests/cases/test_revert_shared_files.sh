#!/bin/bash
# jail.local and daemon.json are removed by a revert only while they hold
# exactly what the module wrote and no earlier version was kept; an admin's
# own file is restored or left alone.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"
require_root

W=$(mktemp -d)
J=/etc/fail2ban/jail.local
D=/etc/docker/daemon.json
saved="$W/saved"; mkdir -p "$saved"
for f in "$J" "$D"; do [[ -f "$f" ]] && cp -a "$f" "$saved/${f##*/}"; done
cleanup() {
    for f in "$J" "$D"; do
        rm -f "$f"
        [[ -f "$saved/${f##*/}" ]] && cp -a "$saved/${f##*/}" "$f"
    done
    rm -rf "$W"
}
trap cleanup EXIT
mkdir -p /etc/fail2ban /etc/docker

# $1 = file to revert, $2 = genesis copy to seed (or "none"), $3 = live content
# ("ours" = what the module writes).
revert_case() {
    rm -rf "$W/root" && mkdir -p "$W/root/genesis/files$(dirname "$1")"
    [[ "$2" != none ]] && printf '%s\n' "$2" > "$W/root/genesis/files$1"
    bash -c '
        source "'"$REPO"'/lib/core.sh"
        source "'"$REPO"'/lib/platform.sh"
        source "'"$REPO"'/lib/modules.sh"
        DRY_RUN=false LOG_FILE="'"$W"'/log"
        UH_BACKUP_ROOT="'"$W"'/root" BACKUP_GENESIS_DIR="'"$W"'/root/genesis"
        if [[ "$2" == ours ]]; then tool_written_content "$1" > "$1"; else printf "%s\n" "$2" > "$1"; fi
        revert_backed_up_file "$1"
    ' _ "$1" "$3" >/dev/null 2>&1
}

for f in "$J" "$D"; do
    revert_case "$f" none ours
    assert_file_absent "$f" "${f##*/}: the module's own file with no backup is removed"

    ours=$(bash -c 'source "'"$REPO"'/lib/core.sh"; source "'"$REPO"'/lib/platform.sh"; source "'"$REPO"'/lib/modules.sh"; tool_written_content "$1"' _ "$f" 2>/dev/null)
    revert_case "$f" "$ours" ours
    assert_file_absent "$f" "${f##*/}: a backup holding only the module's output is not restored"

    revert_case "$f" "# admin original" ours
    [[ "$(cat "$f" 2>/dev/null)" == "# admin original" ]] \
        && pass_msg "${f##*/}: the admin's earlier version is restored" \
        || fail "${f##*/}: expected the admin's original back, got '$(head -c 80 "$f" 2>/dev/null)'"

    revert_case "$f" none "# admin own, module never ran"
    [[ "$(cat "$f" 2>/dev/null)" == "# admin own, module never ran" ]] \
        && pass_msg "${f##*/}: an admin file with no backup is left alone" \
        || fail "${f##*/}: an admin file with no backup was changed or removed"
done

grep -q '"${UH_TOOL_CREATED_PATHS\[@\]}"' "$REPO/lib/cis.sh" \
    && pass_msg "full revert removes every path in UH_TOOL_CREATED_PATHS" \
    || fail "full_system_revert does not use UH_TOOL_CREATED_PATHS"
for p in $(sed -n '/^UH_TOOL_CREATED_PATHS=(/,/^)/p' "$REPO/lib/core.sh" | grep -o '"/[^"]*"' | tr -d '"'); do
    grep -rqF "${p##*/}" "$REPO/lib/modules.sh" \
        || fail "UH_TOOL_CREATED_PATHS lists $p, which no module writes"
done
pass_msg "every tool-created path is written by a module"

finish
