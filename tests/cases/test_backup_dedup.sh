#!/bin/bash
# backup_file skips the per-run copy when the file holds the same bytes as its
# last backup, and must copy it when any byte differs. Minimal RHEL-family and
# Arch images have no cmp (diffutils), so this runs on both kinds of image: the
# output says which compare was used.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"

# shellcheck source=/dev/null
source "$REPO_ROOT/lib/core.sh"

WORK=$(mktemp -d)
LOG_FILE="$WORK/test.log"
BACKUP_GENESIS_DIR="$WORK/genesis"
UH_BACKUP_ROOT="$WORK"
DRY_RUN=false
SKIP_BACKUP=false
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

if command -v cmp >/dev/null 2>&1; then echo "compare: cmp"; else echo "compare: sha256sum fallback (no cmp)"; fi

SRC="$WORK/etc/demo.conf"
mkdir -p "$WORK/etc"
run=0
backup_run() {
    run=$((run + 1))
    BACKUP_DIR="$WORK/hardening_backup_2026010${run}_000000"
    mkdir -p "$BACKUP_DIR"
    backup_file "$SRC"
}

printf 'key value\n' > "$SRC"
backup_run
assert_file_exists "$BACKUP_DIR/files$SRC" "the first run copies the file"

backup_run
assert_file_absent "$BACKUP_DIR/files$SRC" "an unchanged file is not copied again"

printf '\n' >> "$SRC"
backup_run
assert_file_exists "$BACKUP_DIR/files$SRC" "a file that only gained a trailing newline is copied"

printf 'a\0b' > "$SRC"
backup_run
printf 'ab' > "$SRC"
backup_run
assert_file_exists "$BACKUP_DIR/files$SRC" "a file that only lost a NUL byte is copied"

finish
