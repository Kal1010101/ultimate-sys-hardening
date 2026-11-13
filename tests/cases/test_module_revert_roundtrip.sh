#!/bin/bash
# Each file-based module, applied on its own and then reverted on its own (the
# menu entry of a module that is already on), must leave every file it lists
# in MOD_REVERT_FILES exactly as it found it: same content, or still absent.
#
# test_revert.sh covers one full harden-then-revert; nothing else exercised
# the per-module revert path in the container matrix.
#
# Modules here only write files listed in MOD_REVERT_FILES. Modules that
# install packages or reach the network (fail2ban, syslog, grubpw, docker)
# have their own cases. Runs in a throwaway container as root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"
require_root
require_file /etc/ssh/sshd_config

ROUNDTRIP_MODULES=(
    "ssh apply_ssh_hardening"
    "kernel apply_kernel_hardening"
    "password apply_password_policies"
    "protocols apply_unused_protocols"
    "umask apply_umask_hardening"
)

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# Prints "<path> <sha256|absent>" for each file, one per line.
snapshot() {
    local f
    for f in "$@"; do
        if [[ -e "$f" ]]; then printf '%s %s\n' "$f" "$(checksum "$f")"
        else printf '%s absent\n' "$f"; fi
    done
}

# $1 = key, $2 = apply function, $3 = apply | revert. One fresh shell per step,
# as a menu session that is restarted between the two would be.
module_step() {
    bash -c '
        source "$1/lib/core.sh"; source "$1/lib/platform.sh"
        source "$1/lib/modules.sh"; source "$1/lib/cis.sh"; source "$1/lib/menu.sh"
        DRY_RUN=false AUTO_MODE=true SKIP_BACKUP=false LOG_FILE="$2/run.log"
        detect_platform >/dev/null 2>&1 || true
        if [[ "$5" == apply ]]; then
            create_backup_dir && run_module "$3" "$4"
        else
            revert_module "$3"
        fi
    ' _ "$REPO" "$W" "$1" "$2" "$3" >>"$W/out" 2>&1
}

for entry in "${ROUNDTRIP_MODULES[@]}"; do
    read -r key fn <<<"$entry"
    read -r -a files <<<"$(bash -c 'source "$1/lib/core.sh"; source "$1/lib/menu.sh"; echo "${MOD_REVERT_FILES[$2]}"' _ "$REPO" "$key" 2>/dev/null)"
    if [[ ${#files[@]} -eq 0 ]]; then
        fail "$key: MOD_REVERT_FILES lists no files"
        continue
    fi

    before=$(snapshot "${files[@]}")
    module_step "$key" "$fn" apply
    after_apply=$(snapshot "${files[@]}")
    if [[ "$after_apply" == "$before" ]]; then
        echo "NOTE: $key: apply changed none of its files here (already compliant?); revert still checked"
    fi
    module_step "$key" "$fn" revert
    after_revert=$(snapshot "${files[@]}")

    if [[ "$after_revert" == "$before" ]]; then
        pass_msg "$key: apply then revert leaves all ${#files[@]} file(s) as they were"
    else
        # No diff(1): busybox prints a different format and Arch's image has none.
        fail "$key: files differ after revert: $(paste -d'|' <(echo "$before") <(echo "$after_revert") | awk -F'|' '$1 != $2 { print "was " $1 ", now " $2 }' | tr '\n' ';')"
    fi
done

finish
