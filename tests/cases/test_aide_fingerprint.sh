#!/bin/bash
# The AIDE fingerprint is only worth something if it really is the database's
# hash, reaches syslog, can be copied to a drive without root ever writing over
# an existing file, and --aide-verify tells a match from a changed database.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root
require_cmd gzip
require_cmd openssl

REPO="${REPO_ROOT:-/repo}"
export LOG_FILE="${TMPDIR:-/tmp}/uh_aide_fingerprint_$$.log"
DIR=/var/lib/aide
LIVE="$DIR/aide.db.gz"
CONF=/etc/aide.conf
[[ -e "$CONF" || -e /etc/aide/aide.conf ]] && skip "a real AIDE config is present"
# A drive has to be another filesystem than / and the database: /dev/shm is a tmpfs.
DRIVE=/dev/shm/uh_fingerprint_drive
[[ $(stat -c %d /dev/shm 2>/dev/null) != "$(stat -c %d /)" ]] || skip "/dev/shm is not a separate filesystem"

STATE=$(mktemp -d)
stub_dir=$(mktemp -d)
export UH_STATE_DIR="$STATE"
FP="$STATE/aide-fingerprint"
mkdir -p "$DIR"
printf '@@define DBDIR %s\ndatabase_in=file:@@{DBDIR}/aide.db.gz\ndatabase_out=file:@@{DBDIR}/aide.db.new.gz\n' "$DIR" > "$CONF"
printf '#!/bin/sh\necho "$*" >> %s/logger.out\n' "$stub_dir" > "$stub_dir/logger"; chmod +x "$stub_dir/logger"

# Runs lib code with INPUT on stdin; TERMINAL=true makes it act as if a person is there.
run() {   # <terminal: true|false> <input> <commands>
    printf '%s' "$2" | bash -c "set -euo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        PATH='$stub_dir':\$PATH; DRY_RUN=false; AUTO_MODE=\${AUTO_MODE:-false}
        _uh_stdin_is_terminal() { $1; }
        $3; echo \"RC=\$?\"" 2>&1 || echo 'RC=1'
}
new_db() {   # <content>
    rm -f "$DIR"/aide.db*
    printf '@@begin_db\n%s\n@@end_db\n' "$1" | gzip -c > "$LIVE"; chmod 600 "$LIVE"
}
fresh_drive() { rm -rf "$DRIVE"; mkdir -p "$DRIVE"; }
drive_files() { find "$DRIVE" -name 'aide-fingerprint-*.txt' 2>/dev/null | wc -l; }

new_db '/etc/passwd 1'
hash=$(zcat "$LIVE" | openssl dgst -sha256 -binary | base64)
# The assertions grep with -E, and base64 may contain +
ere() { printf '%s' "$1" | sed 's/[][\.*^$+?(){}|]/\\&/g'; }
hash_re=$(ere "$hash")

# --- recording ------------------------------------------------------------
out=$(run false '' "aide_record_fingerprint '$LIVE'")
assert_output_contains "$out" 'RC=0' "record: exits zero"
assert_file_contains "$FP" "sha256=$hash_re" "record: the hash of the uncompressed database"
assert_file_contains "$FP" "database=$LIVE" "record: names the database"
assert_file_contains "$FP" "host=$(uname -n)" "record: names the host"
assert_file_mode "$FP" 644
assert_output_contains "$out" "aide-verify $hash_re" "record: prints the verify command"
assert_output_contains "$out" "scp [^ ]+:$FP " "record: prints the pull command"
if [[ -n "$( { hostname -I 2>/dev/null; ip -o addr show scope global 2>/dev/null; } | tr -d '[:space:]')" ]]; then
    grep -qF "scp $(uname -n):" <<< "$out" && fail "the pull command relies on the hostname resolving" || pass_msg "record: the pull command does not rely on the hostname resolving"
else
    echo "  ⏭️  SKIP: neither 'hostname -I' nor 'ip' reports an address in this image"
fi

# The pull command logs in as an ordinary account, so a 027 umask must not
# leave the folder closed to it.
rm -rf "$STATE"
out=$(run false '' "umask 027; aide_record_fingerprint '$LIVE'")
[[ $(( 8#$(stat -c %a "$STATE") & 8#001 )) -ne 0 ]] && pass_msg "record, umask 027: others can reach the file" || fail "state folder is $(stat -c %a "$STATE")"
[[ $(( 8#$(stat -c %a "$STATE") & 8#004 )) -eq 0 ]] && pass_msg "record, umask 027: others still can't list the folder" || fail "state folder is $(stat -c %a "$STATE")"
out=$(run false '' "SUDO_USER=alice aide_scp_source")
assert_output_contains "$out" "^alice@[^ ]+$" "pull command: names the account that ran sudo"
out=$(run false '' "SUDO_USER=root aide_scp_source")
grep -qF "root@" <<< "$out" && fail "the pull command names root: $out" || pass_msg "pull command: never names root"
out=$(run false '' "hostname() { echo 'fe80::1 10.0.0.2'; }; aide_scp_source")
assert_output_contains "$out" '^\[fe80::1\]$' "pull command: an IPv6 address is in brackets"
out=$(run false '' "hostname() { return 1; }; ip() { echo '2: eth0    inet 192.0.2.5/24 brd 192.0.2.255 scope global eth0'; }; aide_scp_source")
assert_output_contains "$out" '^192\.0\.2\.5$' "pull command: without hostname -I, the address comes from ip"
out=$(run false '' "hostname() { return 1; }; ip() { return 1; }; aide_scp_source")
assert_output_contains "$out" "^$(uname -n)$" "pull command: with neither tool, falls back to the hostname"
assert_file_contains "$stub_dir/logger.out" "sha256=$hash_re" "record: sent to syslog"
assert_file_absent "$STATE/aide-fingerprint-destination" "record unattended: no folder saved"

# --- the drive prompt -------------------------------------------------------
fresh_drive
out=$(run true $'\n' "aide_record_fingerprint '$LIVE'")
[[ $(drive_files) -eq 0 ]] && pass_msg "prompt, Enter with nothing saved: skipped" || fail "Enter wrote a file"
assert_file_absent "$STATE/aide-fingerprint-destination" "prompt skipped: no folder saved"

out=$(run true "$DRIVE"$'\n' "aide_record_fingerprint '$LIVE'")
copy=$(find "$DRIVE" -name 'aide-fingerprint-*.txt' | head -n 1)
if [[ -n "$copy" ]] && [[ $(checksum "$copy") == "$(checksum "$FP")" ]]; then pass_msg "prompt, folder typed: copy written"; else fail "no copy on the drive: $out"; fi
assert_file_contains "$STATE/aide-fingerprint-destination" "$DRIVE" "prompt, folder typed: remembered"
assert_file_mode "$STATE/aide-fingerprint-destination" 600
assert_file_contains "$stub_dir/logger.out" "destination set to $DRIVE" "prompt, folder typed: change sent to syslog"

out=$(run true $'\n' "aide_record_fingerprint '$LIVE'")
assert_output_contains "$out" "Fingerprint folder: $DRIVE" "saved folder: shown"
[[ $(drive_files) -eq 2 ]] && pass_msg "saved folder, Enter: second copy written" || fail "Enter did not reuse the saved folder: $out"

out=$(run true $'skip\n' "aide_record_fingerprint '$LIVE'")
[[ $(drive_files) -eq 2 ]] && pass_msg "skip: nothing written" || fail "skip wrote a file"

out=$(run true $'/nonexistent/drive\nskip\n' "aide_record_fingerprint '$LIVE'")
assert_output_contains "$out" 'missing or not writable' "missing folder: named, asked again"
assert_file_contains "$STATE/aide-fingerprint-destination" "$DRIVE" "missing folder: saved folder kept"

mkdir -p /root/uh_not_a_drive
out=$(run true $'/root/uh_not_a_drive\nn\nskip\n' "aide_record_fingerprint '$LIVE'")
assert_output_contains "$out" "own disk" "system disk: warned"
[[ -z $(ls /root/uh_not_a_drive) ]] && pass_msg "system disk, declined: nothing written" || fail "system disk: written after no"

out=$(AUTO_MODE=true run false '' "aide_record_fingerprint '$LIVE'")
[[ $(drive_files) -eq 3 ]] && pass_msg "unattended: copied to the saved folder" || fail "unattended did not copy: $out"

printf '/root/uh_not_a_drive\n' > "$STATE/aide-fingerprint-destination"
out=$(AUTO_MODE=true run false '' "aide_record_fingerprint '$LIVE'")
assert_output_contains "$out" "own disk" "unattended, saved folder on the system disk: refused"
[[ -z $(ls /root/uh_not_a_drive) ]] && pass_msg "unattended: never writes to the system disk" || fail "unattended wrote to the system disk"

printf 'relative/path\n' > "$STATE/aide-fingerprint-destination"
out=$(run true $'skip\n' "aide_record_fingerprint '$LIVE'")
if grep -q 'Fingerprint folder:' <<<"$out"; then fail "an invalid saved folder was offered"; else pass_msg "invalid saved folder: ignored"; fi

# Links planted under every name the copy will try must not be followed, whether
# they point at a file or at nothing yet. date and RANDOM are fixed so the names
# are known in advance.
fresh_drive; echo victim > /root/uh_victim; rm -f /root/uh_dangling
for n in $(bash -c 'RANDOM=7; for i in 1 2 3 4 5; do echo $RANDOM; done'); do
    ln -s /root/uh_victim "$DRIVE/aide-fingerprint-$(uname -n)-FIXED-$n.txt"
done
ln -sf /root/uh_dangling "$DRIVE/aide-fingerprint-$(uname -n)-FIXED-$n.txt"
out=$(run true "$DRIVE"$'\nskip\n' "date() { echo FIXED; }; RANDOM=7; aide_record_fingerprint '$LIVE'")
assert_output_contains "$out" 'Could not create a new file' "planted links: every attempt refused"
assert_file_contains /root/uh_victim '^victim$' "planted link: its target not written"
assert_file_absent /root/uh_dangling "planted dangling link: its target not created"

# --- verifying --------------------------------------------------------------
out=$(run false '' "aide_verify '$hash'")
assert_output_contains "$out" 'RC=0' "verify hash: matches"
cp "$FP" /root/uh_saved_fp
out=$(run false '' "aide_verify /root/uh_saved_fp")
assert_output_contains "$out" 'RC=0' "verify file: matches"

sed "s/^host=.*/host=some-other-host/" "$FP" > /root/uh_other_host
out=$(run false '' "aide_verify /root/uh_other_host")
assert_output_contains "$out" 'some-other-host' "verify, another host's file: named"
assert_output_contains "$out" 'RC=1' "verify, another host's file: refused"
out=$(run false '' "aide_verify 'not-a-hash'")
assert_output_contains "$out" 'Not a fingerprint' "verify, malformed: refused"

new_db '/etc/passwd 2'
out=$(run false '' "aide_verify '$hash'")
assert_output_contains "$out" 'does NOT match' "verify, changed database: reported"
assert_output_contains "$out" 'RC=1' "verify, changed database: exits non-zero"
status=0; printf '' | bash -c "set -euo pipefail
    source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
    aide_verify '$hash'" >/dev/null 2>&1 || status=$?
[[ $status -eq 1 ]] && pass_msg "verify: mismatch exits 1" || fail "verify: mismatch exited $status"
status=0; printf '' | bash -c "set -euo pipefail
    source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
    aide_verify bad" >/dev/null 2>&1 || status=$?
[[ $status -eq 2 ]] && pass_msg "verify: unusable input exits 2" || fail "verify: unusable input exited $status"

# --- --aide-fingerprint for a baseline accepted by hand ---------------------
rm -f "$FP"
out=$(AUTO_MODE=true run false '' "aide_fingerprint_current")
assert_output_contains "$out" 'RC=0' "--aide-fingerprint: exits zero"
assert_file_contains "$FP" "sha256=$(ere "$(zcat "$LIVE" | openssl dgst -sha256 -binary | base64)")" "--aide-fingerprint: records the current baseline"
out=$(run false $'n\n' "aide_fingerprint_current")
assert_output_contains "$out" 'Nothing recorded' "--aide-fingerprint declined: nothing recorded"

rm -rf "$DIR"/aide.db* "$CONF" "$STATE" "$stub_dir" "$DRIVE" /root/uh_not_a_drive /root/uh_victim /root/uh_dangling /root/uh_other_host /root/uh_saved_fp
finish
