#!/bin/bash
# Module 23 (base system): the /dev/shm fstab line, the sudo drop-in written
# only after visudo accepts it and only where sudoers reads sudoers.d, time
# sync left alone when a daemon already runs, UH_SKIP_SETTINGS honoured, and
# the per-module revert putting fstab back and removing the drop-in.
#
# fstab and sudoers.d are scratch copies (UH_FSTAB, UH_SUDOERS_DIR); findmnt,
# mount and visudo are stubs where noted. Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_basesys_$$"; rm -rf "$W"; mkdir -p "$W/sudoers.d" "$W/backups"
trap 'rm -rf "$W"' EXIT

reset_host() {
    printf '# <file system> <mount point> <type> <options> <dump> <pass>\nUUID=abcd / ext4 defaults 0 1\n' > "$W/fstab"
    printf 'Defaults env_reset\n@includedir /etc/sudoers.d\n' > "$W/sudoers"
    rm -rf "$W/sudoers.d"/* "$W/backups"/*
    : > "$W/calls"
}

# $1 = shell run before the call, $2 = function to call (default: apply).
run() {
    bash -c "source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        DRY_RUN=false; SKIP_BACKUP=false; LOG_FILE='$W/run.log'; DISTRO_TYPE=debian
        UH_BACKUP_ROOT='$W/backups'; BACKUP_GENESIS_DIR='$W/backups/genesis'; BACKUP_DIR='$W/backups/hardening_backup_1'
        UH_FSTAB='$W/fstab'; UH_SUDOERS_DIR='$W/sudoers.d'; UH_SUDOERS_FILE='$W/sudoers'
        is_linux() { return 0; }; relabel_path() { :; }; count_fix() { :; }
        findmnt() {
            case \"\$*\" in
                *'-no OPTIONS /dev/shm'*) echo 'rw,nosuid,nodev,inode64' ;;
                *--verify*) return 0 ;;
            esac
        }
        mount() { echo \"MOUNT \$*\" >> '$W/calls'; return 0; }
        visudo() { echo \"VISUDO \$*\" >> '$W/calls'; return 0; }
        install() { local src=\"\${@: -2:1}\" dst=\"\${@: -1}\"; cp \"\$src\" \"\$dst\"; }
        is_service_active() { [[ \$1 == chronyd ]]; }
        $1
        ${2:-apply_base_system}" 2>&1
}

dropin="$W/sudoers.d/50-ultimate-hardening"

# --- a plain host -------------------------------------------------------------
reset_host
out=$(run '')
assert_file_contains "$W/fstab" '^tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0$' "fstab gets a hardened /dev/shm line"
assert_file_contains "$W/fstab" '^UUID=abcd / ext4 defaults 0 1$' "the rest of fstab is untouched"
assert_output_contains "$(cat "$W/calls")" 'MOUNT -o remount,nodev,nosuid,noexec /dev/shm' "/dev/shm is remounted with the options"
assert_file_contains "$W/backups/genesis/shm_options_before.txt" 'rw,nosuid,nodev,inode64' "the options before are recorded for revert"
assert_file_contains "$dropin" '^Defaults use_pty$' "sudo uses a pty"
assert_file_contains "$dropin" '^Defaults logfile="/var/log/sudo.log"$' "sudo logs to a file"
assert_output_contains "$(cat "$W/calls")" "VISUDO -cf " "the drop-in was checked with visudo -cf before it was installed"
assert_output_contains "$out" 'Time sync already running: chronyd' "a running time daemon is kept"

# --- idempotent: a second run adds nothing ------------------------------------
before=$(checksum "$W/fstab")
run '' >/dev/null
assert_unchanged "$W/fstab" "$before" "a second run leaves fstab alone"
n=$(grep -c '^[^#].*/dev/shm' "$W/fstab"); [[ "$n" -eq 1 ]] && pass_msg "one /dev/shm line after two runs" || fail "$n /dev/shm lines"

# --- per-module revert ------------------------------------------------------
run '' undo_base_system >/dev/null
assert_file_not_contains "$W/fstab" '/dev/shm' "revert puts fstab back"
assert_file_absent "$dropin" "revert removes the sudo drop-in"
assert_output_contains "$(cat "$W/calls")" 'MOUNT -o remount,nodev,nosuid,exec /dev/shm' "revert remounts /dev/shm with its earlier options"

# --- an existing /dev/shm line gets only the missing options -----------------
reset_host
echo 'tmpfs /dev/shm tmpfs defaults,nosuid 0 0' >> "$W/fstab"
run '' >/dev/null
assert_file_contains "$W/fstab" '^tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0$' "an existing line keeps its options and gains the missing ones"
n=$(grep -c '^[^#].*/dev/shm' "$W/fstab"); [[ "$n" -eq 1 ]] && pass_msg "no second /dev/shm line is added" || fail "$n /dev/shm lines"

# --- visudo rejects the drop-in: nothing written ------------------------------
reset_host
out=$(run 'visudo() { return 1; }')
assert_file_absent "$dropin" "nothing is installed when visudo rejects it"
assert_output_contains "$out" 'visudo rejected' "and the reason is logged"

# --- sudoers without an includedir: /etc/sudoers is never edited --------------
reset_host
printf 'Defaults env_reset\n' > "$W/sudoers"
out=$(run '')
assert_file_absent "$dropin" "no drop-in where sudoers does not read sudoers.d"
assert_output_contains "$out" 'no includedir' "and it says why"

# --- settings already present elsewhere are not repeated ----------------------
reset_host
printf 'Defaults use_pty\n' > "$W/sudoers.d/admin"
run '' >/dev/null
assert_file_not_contains "$dropin" 'use_pty' "use_pty already set elsewhere is not repeated"
assert_file_contains "$dropin" 'logfile' "logfile is still added"

# --- fstab verification gets worse: fstab left alone --------------------------
reset_host
before=$(checksum "$W/fstab")
out=$(run "findmnt() { case \"\$*\" in *'-no OPTIONS /dev/shm'*) echo rw,nosuid,nodev ;; *--verify*\"$W/fstab\"*) return 0 ;; *--verify*) echo '   [E] bad'; return 1 ;; esac; }")
assert_unchanged "$W/fstab" "$before" "a line that fails findmnt --verify is not written"

# --- UH_SKIP_SETTINGS -----------------------------------------------------------
reset_host
out=$(run 'UH_SKIP_SETTINGS="dev_shm use_pty"')
assert_file_not_contains "$W/fstab" '/dev/shm' "UH_SKIP_SETTINGS=dev_shm leaves fstab alone"
assert_file_not_contains "$dropin" 'use_pty' "UH_SKIP_SETTINGS=use_pty leaves use_pty out"

# --- no time daemon: timesyncd where systemd has it ---------------------------
reset_host
out=$(run 'is_service_active() { [[ $1 == systemd-timesyncd && -f '"'$W/enabled'"' ]]; }
           _has_timesyncd() { return 0; }; record_service_state() { echo "REC $1" >> '"'$W/calls'"'; }
           enable_service() { touch '"'$W/enabled'"'; echo "ENABLE $1" >> '"'$W/calls'"'; }')
assert_output_contains "$(cat "$W/calls")" 'REC systemd-timesyncd' "the time daemon's earlier state is recorded"
assert_output_contains "$(cat "$W/calls")" 'ENABLE systemd-timesyncd' "systemd-timesyncd is enabled when nothing syncs time"
rm -f "$W/enabled"

# --- dry run writes nothing ----------------------------------------------------
reset_host
before=$(checksum "$W/fstab")
out=$(run 'DRY_RUN=true')
assert_unchanged "$W/fstab" "$before" "a dry run leaves fstab alone"
assert_file_absent "$dropin" "a dry run writes no sudo drop-in"
assert_output_contains "$out" 'Would mount /dev/shm' "the dry run says what it would do"
finish
