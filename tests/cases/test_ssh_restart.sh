#!/bin/bash
# set_config edits only the first commented default; every restore relabels
# what it copied back; the SSH module puts the old config back when a running
# sshd does not come back after the restart.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
export LOG_FILE="$W/test.log"

# --- set_config ---------------------------------------------------------------
cat > "$W/a.conf" << 'EOF'
#AllowTcpForwarding yes
#X11Forwarding no
#PermitRootLogin prohibit-password
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
EOF
cp "$W/a.conf" "$W/b.conf"
sed -i '2s/.*/X11Forwarding yes/' "$W/b.conf"
printf 'PASS_MAX_DAYS\t99999\n' > "$W/c.conf"
ino=$(stat -c %i "$W/a.conf")

bash -c '
    source "'"$REPO"'/lib/core.sh"
    DRY_RUN=false
    set_config X11Forwarding no "'"$W"'/a.conf"
    set_config AllowTcpForwarding no "'"$W"'/a.conf"
    set_config X11Forwarding no "'"$W"'/b.conf"
    set_config PASS_MAX_DAYS 90 "'"$W"'/c.conf" "	"
    set_config Banner /etc/issue.net "'"$W"'/c.conf"
' >/dev/null 2>&1

[[ "$(sed -n 1p "$W/a.conf")" == "AllowTcpForwarding no" && "$(sed -n 2p "$W/a.conf")" == "X11Forwarding no" ]] \
    && pass_msg "the first commented default is set in place" \
    || fail "lines 1-2 are '$(sed -n 1,2p "$W/a.conf" | tr '\n' '|')'"
[[ "$(sed -n 5,6p "$W/a.conf" | tr '\n' '|')" == "#	X11Forwarding no|#	AllowTcpForwarding no|" ]] \
    && pass_msg "the commented Match example stays commented" \
    || fail "the example block changed: $(sed -n 4,6p "$W/a.conf" | tr '\n' '|')"
[[ "$(stat -c %i "$W/a.conf")" == "$ino" ]] \
    && pass_msg "the file keeps its inode, so its mode and label stay" \
    || fail "set_config replaced the file"
n=$(grep -cE '^[[:space:]]*#?[[:space:]]*X11Forwarding' "$W/b.conf")
[[ "$(sed -n 2p "$W/b.conf")" == "X11Forwarding no" && "$n" == 2 ]] \
    && pass_msg "an active line is replaced and commented ones are left alone" \
    || fail "b.conf: $(tr '\n' '|' < "$W/b.conf")"
assert_file_contains "$W/c.conf" '^PASS_MAX_DAYS	90$' "a tab-separated key is replaced"
assert_file_contains "$W/c.conf" '^Banner /etc/issue.net$' "a missing key is appended"

# --- every restore relabels what it copied back --------------------------------
bash -c '
    source "'"$REPO"'/lib/core.sh"
    restorecon() { echo "RELABEL $*" >> "'"$W"'/relabel.log"; }
    DRY_RUN=false SKIP_BACKUP=false
    BACKUP_GENESIS_DIR="'"$W"'/genesis" BACKUP_DIR="'"$W"'/run" UH_BACKUP_ROOT="'"$W"'"
    mkdir -p "'"$W"'/etc"
    echo orig > "'"$W"'/etc/r.conf"
    backup_file "'"$W"'/etc/r.conf"
    echo changed > "'"$W"'/etc/r.conf"
    restore_file "'"$W"'/etc/r.conf"
    echo changed > "'"$W"'/etc/r.conf"
    revert_backed_up_file "'"$W"'/etc/r.conf"
    ln -s target "'"$W"'/etc/l.net"
    backup_file_for_rewrite "'"$W"'/etc/l.net"
    echo banner > "'"$W"'/etc/l.net"
    restore_recorded_symlink "'"$W"'/etc/l.net"
' >/dev/null 2>&1
out=$(cat "$W/relabel.log" 2>/dev/null)
n=$(grep -c "^RELABEL $W/etc/r.conf\$" <<< "$out")
[[ "$n" == 2 ]] && pass_msg "restore_file and revert_backed_up_file relabel the restored file" \
                || fail "relabel ran $n time(s) for the restored file, expected 2"
assert_output_contains "$out" "RELABEL $W/etc/l.net" "a restored symlink is relabelled"

for f in lib/core.sh lib/cis.sh; do
    bad=$(grep -A1 -E 'cp -a "\$(src|stored)" "\$target"' "$REPO/$f" | grep -v '^--$' | paste - - \
          | grep -vc relabel_path || true)
    [[ "$bad" == 0 ]] && pass_msg "$f: every copy back into a live path relabels it" \
                      || fail "$f: $bad restore copy(ies) without relabel_path"
done

# --- the SSH module checks that sshd came back -----------------------------------
[[ $EUID -eq 0 && -f /etc/ssh/sshd_config ]] || { echo "SKIP: restart part needs root and sshd_config"; finish; }
cp -a /etc/ssh/sshd_config "$W/sshd_config.orig"
orig=$(checksum /etc/ssh/sshd_config)
dropin=/etc/ssh/sshd_config.d/00-ultimate-hardening.conf

run_ssh_module() {
    rm -rf "$W/genesis" "$W/run" "$W/restarted"
    cp -a "$W/sshd_config.orig" /etc/ssh/sshd_config
    bash -c '
        source "'"$REPO"'/lib/core.sh"
        source "'"$REPO"'/lib/platform.sh"
        source "'"$REPO"'/lib/modules.sh"
        DRY_RUN=false SKIP_BACKUP=false FIXES_APPLIED=0
        BACKUP_GENESIS_DIR="'"$W"'/genesis" BACKUP_DIR="'"$W"'/run" UH_BACKUP_ROOT="'"$W"'"
        restorecon() { :; }
        sshd_config_valid() { return 0; }
        restart_sshd() { touch "'"$W"'/restarted"; return 0; }
        case "'"$1"'" in
            dies)  is_service_active() { [[ ! -f "'"$W"'/restarted" ]]; } ;;
            ok)    is_service_active() { return 0; } ;;
            off)   is_service_active() { return 1; } ;;
        esac
        apply_ssh_hardening
        echo "RC=$?"
    ' 2>&1
}

out=$(run_ssh_module dies)
assert_output_contains "$out" 'RC=1' "a running sshd that does not come back fails the module"
assert_output_contains "$out" 'did not come back' "the failure says sshd did not come back"
assert_unchanged /etc/ssh/sshd_config "$orig" "the previous sshd_config is restored"
assert_file_absent "$dropin" "the drop-in written by this run is removed"

out=$(run_ssh_module ok)
assert_output_contains "$out" 'RC=0' "a restart that leaves sshd running passes"
assert_output_contains "$out" 'daemon restarted' "success is reported only after sshd is seen running"

out=$(run_ssh_module off)
assert_output_contains "$out" 'RC=0' "a host where sshd was not running is still hardened"
assert_output_contains "$out" 'not running' "it says sshd is not running instead of claiming a restart"

cp -a "$W/sshd_config.orig" /etc/ssh/sshd_config
finish
