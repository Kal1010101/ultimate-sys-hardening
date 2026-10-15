#!/bin/bash
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_reboot_$$"; rm -rf "$W"; mkdir -p "$W/root/lib/modules/6.6.30-0-virt"
trap 'rm -rf "$W"' EXIT
export LOG_FILE="$W/run.log"

run() {
    bash -c "source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        reboot() { echo REBOOTED; }; confirm() { echo CONFIRM-ASKED; return 0; }
        $1" 2>&1 </dev/null
}

out=$(run 'DISTRO_TYPE=alpine; apk() { echo "linux-virt-6.6.30-r0 < 6.6.40-r0"; }; kernel_update_pending && echo PENDING')
[[ "$out" == *PENDING* ]] && pass_msg "Alpine: a pending linux-virt upgrade is detected" || fail "pending kernel not detected: $out"
out=$(run 'DISTRO_TYPE=alpine; apk() { echo "busybox-1.36.1-r29 < 1.36.1-r30"; }; kernel_update_pending && echo PENDING')
[[ "$out" != *PENDING* ]] && pass_msg "Alpine: other upgrades are not mistaken for a kernel" || fail "false kernel detection: $out"
out=$(run 'DISTRO_TYPE=debian; apk() { echo "linux-virt-6.6.30-r0 < 6.6.40-r0"; }; kernel_update_pending && echo PENDING')
[[ "$out" != *PENDING* ]] && pass_msg "the pending-kernel check is Alpine-only" || fail "non-Alpine flagged: $out"

mod1() {   # <what update_packages does> -> prints the flag
    run "DRY_RUN=false; DISTRO_TYPE=alpine; UH_BOOTCHECK_ROOT='$W/root'; UH_BOOTCHECK_RUNNING=6.6.30-0-virt
        apk() { :; }; installed_kernel_versions() { :; }; verify_boot_chain() { return 0; }; count_fix() { :; }
        update_packages() { $1; }
        apply_system_updates; echo \"FLAG=\$UH_REBOOT_REQUIRED STATUS=\$(uh_exit_status)\""
}
out=$(mod1 "rm -rf '$W/root/lib/modules/6.6.30-0-virt'")
grep -q 'FLAG=true STATUS=10' <<<"$out" && grep -q "removed the running kernel's modules" <<<"$out" \
    && pass_msg "an upgrade that removes the running kernel's modules marks a reboot as required (exit 10)" \
    || fail "in-run kernel removal: $out"
mkdir -p "$W/root/lib/modules/6.6.30-0-virt"
out=$(mod1 ":")
grep -q 'FLAG=false STATUS=0' <<<"$out" && pass_msg "an upgrade that keeps them does not" || fail "no-kernel upgrade: $out"
rm -rf "$W/root/lib/modules"
out=$(mod1 ":")
grep -q 'FLAG=false' <<<"$out" && pass_msg "a host with no module tree for the running kernel (a container) is not flagged" \
    || fail "container false positive: $out"

out=$(run 'UH_REBOOT_REQUIRED=true; AUTO_MODE=true; offer_reboot_if_required')
grep -q 'REBOOT REQUIRED' <<<"$out" && ! grep -qE 'REBOOTED|CONFIRM-ASKED' <<<"$out" \
    && pass_msg "an unattended run never reboots and says a reboot is required" || fail "auto mode: $out"
out=$(run 'UH_REBOOT_REQUIRED=true; AUTO_MODE=false; offer_reboot_if_required')
grep -q 'REBOOT REQUIRED' <<<"$out" && ! grep -qE 'REBOOTED|CONFIRM-ASKED' <<<"$out" \
    && pass_msg "a run with no terminal never reboots either" || fail "no-tty run: $out"
out=$(run 'UH_REBOOT_REQUIRED=true; DRY_RUN=true; offer_reboot_if_required')
! grep -qE 'REBOOTED|CONFIRM-ASKED|REBOOT REQUIRED' <<<"$out" && pass_msg "a dry run does nothing" || fail "dry run: $out"
out=$(run 'offer_reboot_if_required; echo "STATUS=$(uh_exit_status)"')
grep -qx 'STATUS=0' <<<"$out" && pass_msg "no reboot needed: nothing is said and the status is 0" || fail "default: $out"

grep -q 'exit "$(uh_exit_status)"' "$REPO/src/free/ultimate_hardening.sh" \
    && pass_msg "--auto-mode exits with the reboot-required status" || fail "free tier --auto-mode still exits 0 unconditionally"

finish
