#!/bin/bash
# --aide-refresh must never replace the baseline unless the new database is whole,
# matches the hash AIDE reported, and someone typed ACCEPT. Each failure below is a
# way a refresh can silently end monitoring.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root
require_cmd gzip
require_cmd openssl
require_cmd pgrep

REPO="${REPO_ROOT:-/repo}"
export LOG_FILE="${TMPDIR:-/tmp}/uh_aide_refresh_$$.log"
_lib='source "'"$REPO"'/lib/core.sh"
      source "'"$REPO"'/lib/platform.sh"
      source "'"$REPO"'/lib/modules.sh"'
DIR=/var/lib/aide
LIVE="$DIR/aide.db.gz"
NEW="$DIR/aide.db.new.gz"
CONF=/etc/aide.conf
stub_dir=$(mktemp -d)
[[ -e "$CONF" || -e /etc/aide/aide.conf ]] && skip "a real AIDE config is present"
mkdir -p "$DIR"
printf '@@define DBDIR %s\ndatabase_in=file:@@{DBDIR}/aide.db.gz\ndatabase_out=file:@@{DBDIR}/aide.db.new.gz\n' "$DIR" > "$CONF"

# Stand-in for aide --update: BODY writes the database, then it prints a report in
# AIDE's format with the hash of the uncompressed database, wrapped over two lines.
write_stub() {   # <body> <exit status>
    cat > "$stub_dir/aide" << EOF
#!/bin/bash
$1
hash=\$(zcat -f "$NEW" 2>/dev/null | openssl dgst -sha256 -binary | base64)
echo "  Added entries:  1"
echo "$NEW"
echo " SHA256    : \${hash:0:32}"
echo "             \${hash:32}"
exit $2
EOF
    chmod +x "$stub_dir/aide"
}
GOOD_NEW="printf '@@begin_db\n/new 0\n@@end_db\n' | gzip -c > '$NEW'"
refresh() {   # <typed answer>; prints the output and the exit status
    printf '%s\n' "$1" | bash -c "set -euo pipefail; $_lib
        PATH='$stub_dir':\$PATH; DRY_RUN=false
        aide_refresh; echo \"RC=\$?\"" 2>&1 || echo 'RC=1'
}
reset() {
    rm -f "$DIR"/aide.db* 2>/dev/null
    printf '@@begin_db\n/old 0\n@@end_db\n' | gzip -c > "$LIVE"; chmod 600 "$LIVE"
    before=$(checksum "$LIVE")
}
assert_refused() {   # <output> <label>
    assert_output_contains "$1" 'RC=1' "$2: exits non-zero"
    [[ $(checksum "$LIVE") == "$before" ]] && pass_msg "$2: baseline unchanged" || fail "$2: baseline was replaced"
}

reset; write_stub "$GOOD_NEW" 1
out=$(refresh ACCEPT)
assert_output_contains "$out" 'RC=0' "accepted: exits zero"
assert_output_contains "$out" 'Added entries' "accepted: the changes were shown"
assert_output_contains "$out" 'AIDE baseline replaced' "accepted: reported"
zcat "$LIVE" | grep -q '^/new' && pass_msg "accepted: new baseline in place" || fail "accepted: baseline not replaced"
assert_file_absent "$NEW"
backup=$(ls "$LIVE".bak-* 2>/dev/null | head -n 1)
if [[ -n "$backup" ]] && [[ $(checksum "$backup") == "$before" ]]; then
    pass_msg "accepted: old baseline backed up"
else
    fail "accepted: no backup of the old baseline"
fi
assert_file_mode "$LIVE" 600

reset; write_stub "$GOOD_NEW" 1
out=$(refresh no); assert_refused "$out" "not accepted"
assert_file_exists "$NEW" "not accepted: new database kept"

reset; write_stub "$GOOD_NEW" 1
out=$(printf '' | bash -c "set -euo pipefail; $_lib
    PATH='$stub_dir':\$PATH; DRY_RUN=false; aide_refresh; echo RC=\$?" 2>&1 || echo RC=1)
assert_refused "$out" "no input"

reset; write_stub ": > '$NEW'" 1
out=$(refresh ACCEPT); assert_refused "$out" "empty new database"
assert_output_contains "$out" 'empty or corrupt' "empty new database: named"

reset; write_stub "$GOOD_NEW" 14
out=$(refresh ACCEPT); assert_refused "$out" "aide error"
assert_output_contains "$out" 'exit 14' "aide error: status named"

# The report's hash is of another file: the database on disk is not what AIDE reported.
reset; write_stub "$GOOD_NEW
printf '  Added entries:  1\n$NEW\n SHA256    : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n             AAAAAAAAAAA=\n'
exit 1" 1
out=$(refresh ACCEPT); assert_refused "$out" "hash mismatch"
assert_output_contains "$out" 'does not match' "hash mismatch: named"

# A finished database waiting to be reviewed must survive the new run.
reset; printf 'earlier' > "$NEW"; write_stub "$GOOD_NEW" 1
out=$(refresh no)
if grep -q earlier "$NEW".bak-* 2>/dev/null; then pass_msg "earlier new database kept"; else fail "earlier new database lost"; fi

reset; rm -f "$LIVE"; : > "$LIVE"; before=$(checksum "$LIVE"); write_stub "$GOOD_NEW" 1
out=$(refresh ACCEPT); assert_refused "$out" "empty baseline"
assert_file_absent "$NEW" "empty baseline: aide not run"

# A running AIDE is writing its database: refuse before touching anything.
reset; printf '#!/bin/sh\nwhile :; do sleep 1; done\n' > "$stub_dir/aide"; chmod +x "$stub_dir/aide"; "$stub_dir/aide" & running=$!
sleep 1
out=$(refresh ACCEPT); kill "$running" 2>/dev/null; wait "$running" 2>/dev/null
assert_refused "$out" "aide running"
assert_output_contains "$out" 'already running' "aide running: named"

# AIDE 0.16 names the input database "database", not "database_in".
reset; sed -i 's/^database_in=/database=/' "$CONF"; write_stub "$GOOD_NEW" 1
out=$(refresh ACCEPT)
assert_output_contains "$out" 'RC=0' "AIDE 0.16 config: refreshed"
sed -i 's/^database=/database_in=/' "$CONF"

# Module 10 run again: a good baseline stays, unread changes are not accepted.
reset; printf '#!/bin/sh\necho INIT-RAN > /tmp/uh_init_ran; exit 0\n' > "$stub_dir/aide"; chmod +x "$stub_dir/aide"; rm -f /tmp/uh_init_ran
out=$(bash -c "set -euo pipefail; $_lib
    PATH='$stub_dir':\$PATH; DISTRO_TYPE=debian; DRY_RUN=false
    command() { [[ \"\${2:-}\" == aideinit ]] && return 1; builtin command \"\$@\"; }
    count_fix() { echo FIX-COUNTED; }
    apply_aide" 2>&1 || true)
assert_output_contains "$out" 'already present, kept' "module re-run: says the baseline was kept"
assert_file_absent /tmp/uh_init_ran "module re-run: no new init"
[[ $(checksum "$LIVE") == "$before" ]] && pass_msg "module re-run: baseline unchanged" || fail "module re-run: baseline changed"

rm -f "$DIR"/aide.db* "$CONF" /etc/cron.daily/aide-check; rm -rf "$stub_dir"
finish
