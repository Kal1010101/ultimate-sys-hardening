#!/bin/bash
# Two container-host checks. (1) Module 6 leaves out any sysctl key that a
# Kubernetes sysctl file also sets (RKE2's 60-rke2-cis.conf, the guides'
# 90-kubelet.conf): our drop-in loads later and would override it, and
# kubelet with protect-kernel-defaults then refuses to start. It also warns
# when RKE2 asks for its CIS profile without that file installed. (2) The CIS
# run checks /tmp's nodev, nosuid and noexec when /tmp is its own mount, and
# waives a missing noexec on a container or Kubernetes host. Everything here
# runs on stubs, so it needs no root and changes nothing.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/bin" "$W/rke2"
printf '#!/bin/sh\nexit 0\n' > "$W/bin/uh-fake-kubelet"
chmod +x "$W/bin/uh-fake-kubelet"

LIB="source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
     source '$REPO/lib/cis.sh'
     LOG_FILE=/dev/null; UFW_DEFAULTS='$W/no-ufw'; UH_SYSCTL_CONF_PATHS='$W/none'
     UH_FORWARDING_RUNTIMES=uh-no-such-runtime; ip() { :; }
     UH_K8S_SYSCTL_FILES='$W/none'; UH_RKE2_CONFIG='$W/none.yaml'; UH_RKE2_CIS_SYSCTL='$W/none.conf'"
lib() { env PATH="$W/bin:$PATH" bash -c "$LIB
    $1" 2>&1 </dev/null; }

# --- Kubernetes sysctl files --------------------------------------------------------
plain=$(lib '_kernel_sysctl_settings')
printf 'vm.overcommit_memory = 1\nkernel.panic=10\n  kernel/kptr_restrict = 1\n# kernel.dmesg_restrict = 0\n' > "$W/60-rke2-cis.conf"
owned=$(lib "UH_K8S_SYSCTL_FILES='$W/60-rke2-cis.conf'; _kernel_sysctl_settings")
if ! grep -q '^kernel\.kptr_restrict' <<<"$owned" && grep -q '^kernel\.dmesg_restrict = 1' <<<"$owned" \
   && [[ $(grep -c '^[a-z]' <<<"$owned") == $(( $(grep -c '^[a-z]' <<<"$plain") - 1 )) ]]; then
    pass_msg "a key set in a Kubernetes sysctl file is left out (slash form too), a commented one is not"
else
    fail "k8s-owned keys: $owned"
fi
out=$(lib "UH_K8S_SYSCTL_FILES='$W/60-rke2-cis.conf'; _k8s_owned_keys_in_conf")
[[ "$out" == kernel.kptr_restrict ]] && pass_msg "the overlap is named for the log" || fail "overlap list: $out"
out=$(lib "UH_K8S_SYSCTL_FILES='$W/60-rke2-cis.conf'; DRY_RUN=true; AUTO_MODE=true; DISTRO_TYPE=debian
           is_linux() { return 0; }; apply_kernel_hardening")
grep -q 'Left to Kubernetes (set in its sysctl file, which this drop-in would override): kernel.kptr_restrict' <<<"$out" \
    && pass_msg "module 6 logs the keys it leaves to Kubernetes" || fail "k8s log: $out"
[[ "$(lib '_k8s_owned_keys_in_conf')" == "" ]] && pass_msg "no Kubernetes file: nothing left out" || fail "no k8s file"

# Today's RKE2 CIS values do not overlap with module 6; if they ever did, this says so.
printf 'vm.panic_on_oom=0\nvm.overcommit_memory=1\nkernel.panic=10\nkernel.panic_on_oops=1\n' > "$W/rke2-cis-values.conf"
out=$(lib "UH_K8S_SYSCTL_FILES='$W/rke2-cis-values.conf'; _k8s_owned_keys_in_conf")
[[ -z "$out" ]] && pass_msg "RKE2's documented CIS kernel values do not overlap with module 6" || fail "overlap with RKE2 CIS values: $out"

# --- RKE2 CIS profile without its sysctl file --------------------------------------
printf 'token: x\nprofile: "cis"\n' > "$W/rke2/config.yaml"
out=$(lib "UH_RKE2_CONFIG='$W/rke2/config.yaml'; DRY_RUN=true; AUTO_MODE=true; DISTRO_TYPE=debian
           is_linux() { return 0; }; apply_kernel_hardening")
grep -q "RKE2 is set to its CIS profile, but $W/none.conf is missing" <<<"$out" && grep -q 'rke2-cis-sysctl.conf' <<<"$out" \
    && pass_msg "RKE2 CIS profile without its sysctl file: warned, with the fix" || fail "rke2 warning: $out"
out=$(lib "UH_RKE2_CONFIG='$W/rke2/config.yaml'; UH_RKE2_CIS_SYSCTL='$W/60-rke2-cis.conf'; rke2_cis_sysctl_missing && echo missing || echo fine")
[[ "$out" == fine ]] && pass_msg "RKE2 CIS profile with its sysctl file: no warning" || fail "rke2 with file: $out"
rm "$W/rke2/config.yaml"; mkdir -p "$W/rke2/config.yaml.d"; printf 'profile: cis-1.23\n' > "$W/rke2/config.yaml.d/50-cis.yaml"
out=$(lib "UH_RKE2_CONFIG='$W/rke2/config.yaml'; rke2_cis_sysctl_missing && echo missing || echo fine")
[[ "$out" == missing ]] && pass_msg "the profile set in config.yaml.d counts too" || fail "rke2 config.yaml.d: $out"
printf 'profile: none\n' > "$W/rke2/config.yaml.d/50-cis.yaml"
out=$(lib "UH_RKE2_CONFIG='$W/rke2/config.yaml'; rke2_cis_sysctl_missing && echo missing || echo fine")
[[ "$out" == fine ]] && pass_msg "RKE2 without the CIS profile: no warning" || fail "rke2 no cis: $out"

# --- /tmp mount options in the CIS run ---------------------------------------------
# $1 = mountinfo lines after the root mount ("" for no /tmp mount), $2 = runtimes.
tmp_checks() {
    { echo '22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw'; [[ -n "$1" ]] && printf '%s\n' "$1"; } > "$W/mountinfo"
    lib "UH_MOUNTINFO='$W/mountinfo'; UH_FORWARDING_RUNTIMES='$2'; UH_QUIET_CHECKS=true; is_linux() { return 0; }
         run_cis_checks >/dev/null 2>&1
         printf '%s\n' \"\${CHECK_RESULTS[@]}\" | grep '^/tmp mounted ' || true"
}
out=$(tmp_checks '30 22 8:3 / /tmp rw,nosuid,nodev,noexec,relatime shared:5 - ext4 /dev/sda3 rw' uh-no-such-runtime)
[[ "$out" == $'/tmp mounted nodev|true|\n/tmp mounted nosuid|true|\n/tmp mounted noexec|true|' ]] \
    && pass_msg "/tmp with nodev,nosuid,noexec: three passes" || fail "/tmp hardened: $out"
out=$(tmp_checks '30 22 0:32 / /tmp rw,nosuid,nodev,relatime shared:5 - tmpfs tmpfs rw,size=1048576k' uh-no-such-runtime)
grep -q '^/tmp mounted noexec|false|Mounted with: rw,nosuid,nodev,relatime — Not automated — add nodev,nosuid,noexec' <<<"$out" \
    && grep -q '^/tmp mounted nodev|true|' <<<"$out" \
    && pass_msg "/tmp without noexec fails, with its options and the manual fix" || fail "/tmp no noexec: $out"
out=$(tmp_checks '30 22 0:32 / /tmp rw,nosuid,nodev shared:5 - tmpfs tmpfs rw' uh-fake-kubelet)
grep -q '^/tmp mounted noexec|waived|container or Kubernetes host (uh-fake-kubelet is installed)' <<<"$out" \
    && pass_msg "container or Kubernetes host: a missing noexec is waived, with the reason" || fail "/tmp container: $out"
out=$(tmp_checks '30 22 0:32 / /tmp rw,nodev shared:5 - tmpfs tmpfs rw' uh-fake-kubelet)
grep -q '^/tmp mounted nosuid|false|' <<<"$out" \
    && pass_msg "container host: only noexec is waived, nosuid still fails" || fail "/tmp container nosuid: $out"
out=$(tmp_checks '' uh-no-such-runtime)
[[ -z "$out" ]] && pass_msg "/tmp not its own mount: no option checks (the partition check covers it)" || fail "/tmp not mounted: $out"
out=$(tmp_checks $'30 22 0:32 / /tmp rw,nosuid,nodev shared:5 - tmpfs tmpfs rw\n31 30 8:17 / /tmp rw,nosuid,nodev,noexec shared:6 - ext4 /dev/sdb1 rw' uh-no-such-runtime)
grep -q '^/tmp mounted noexec|true|' <<<"$out" && pass_msg "the last mount on /tmp is the one checked" || fail "/tmp overmount: $out"
# A user's FUSE mount whose source name reads like a hardened /tmp. In `mount`
# output it printed as "... on /tmp type tmpfs (rw,nodev,nosuid,noexec) on
# /home/eve/m type fuse.sshfs (...)", which the old parser took for /tmp.
spoof='45 22 0:40 / /home/eve/m rw,nosuid,nodev,relatime shared:9 - fuse.sshfs x\040on\040/tmp\040type\040tmpfs\040(rw,nodev,nosuid,noexec) rw,user_id=1000'
out=$(tmp_checks "$spoof" uh-no-such-runtime)
[[ -z "$out" ]] && pass_msg "a FUSE mount named like /tmp does not count as a /tmp mount" || fail "spoof alone: $out"
out=$(tmp_checks $'30 22 0:32 / /tmp rw,nosuid,nodev shared:5 - tmpfs tmpfs rw\n'"$spoof" uh-no-such-runtime)
grep -q '^/tmp mounted noexec|false|Mounted with: rw,nosuid,nodev' <<<"$out" \
    && pass_msg "with a real /tmp lacking noexec, the spoofed name does not make it pass" || fail "spoof after real: $out"
out=$(lib "UH_MOUNTINFO='$W/no-such-mountinfo'; _tmp_mount_options; echo rc=\$?")
[[ "$out" == rc=0 ]] && pass_msg "no readable mountinfo: no options, no error" || fail "missing mountinfo: $out"
out=$(lib 'cis_check_module "/tmp mounted noexec"')
[[ -z "$out" ]] && pass_msg "no module claims the /tmp checks (the menu marks none for them)" || fail "module mapping: $out"

# --- audit buffer (module 7) --------------------------------------------------------
out=$(lib 'audit_backlog_limit')
[[ "$out" == 8192 ]] && pass_msg "audit buffer: 8192 (CIS) on a plain host" || fail "plain backlog: $out"
out=$(lib 'UH_FORWARDING_RUNTIMES=uh-fake-kubelet; audit_backlog_limit; _audit_rules_content | grep "^-b "')
[[ "$out" == $'32768\n-b 32768' ]] && pass_msg "audit buffer: 32768 on a container or Kubernetes host, written to the rules" || fail "busy backlog: $out"
out=$(lib 'UH_AUDIT_BACKLOG=65536; audit_backlog_limit')
[[ "$out" == 65536 ]] && pass_msg "UH_AUDIT_BACKLOG sets the buffer" || fail "override: $out"
for bad in lots 4096; do
    out=$(lib "UH_AUDIT_BACKLOG=$bad; audit_backlog_limit")
    grep -q "UH_AUDIT_BACKLOG='$bad' is not a number of at least 8192" <<<"$out" && grep -qx 8192 <<<"$out" \
        && pass_msg "UH_AUDIT_BACKLOG=$bad: warned, chosen automatically" || fail "bad override $bad: $out"
done
out=$(lib 'UH_AUDIT_BACKLOG=4096; _audit_rules_content | grep "^-b "')
[[ "$out" == "-b 8192" ]] && pass_msg "a bad override never puts a warning into the rules file" || fail "rules with bad override: $out"
out=$(lib 'UH_FORWARDING_RUNTIMES=uh-fake-kubelet; DRY_RUN=true; DISTRO_TYPE=debian; is_linux() { return 0; }; apply_audit_config')
grep -q 'Audit buffer 32768 events, not 8192: container or Kubernetes host (uh-fake-kubelet is installed)' <<<"$out" \
    && pass_msg "module 7 says why the buffer is bigger" || fail "module 7 log: $out"

# --- lost audit events in the CIS run -------------------------------------------------
# $1 = auditctl -s output, $2 = root or user.
lost_check() {
    lib "UH_QUIET_CHECKS=true; is_linux() { return 0; }
         is_service_active() { [[ \$1 == auditd ]]; }
         auditctl() { [[ \$1 == -s ]] && printf '%b' '$1'; }
         _cis_running_as_root() { [[ $2 == root ]]; }
         run_cis_checks >/dev/null 2>&1
         printf '%s\n' \"\${CHECK_RESULTS[@]}\" | grep '^No audit events lost|' || true"
}
out=$(lost_check 'enabled 1\nbacklog_limit 8192\nlost 0\nbacklog 3\n' root)
[[ "$out" == "No audit events lost|true|" ]] && pass_msg "no events lost: passes" || fail "lost 0: $out"
out=$(lost_check 'enabled 1\nbacklog_limit 8192\nlost 42\nbacklog 8190\n' root)
grep -q '^No audit events lost|false|42 lost since boot (buffer 8192, 8190 queued now) — Not automated — a busy host needs a bigger buffer: UH_AUDIT_BACKLOG=32768' <<<"$out" \
    && pass_msg "lost events: fails with the count, buffer, queue and the fix" || fail "lost 42: $out"
out=$(lost_check 'enabled 1\n' root)
[[ "$out" == "No audit events lost|unchecked|auditctl -s did not report a lost count" ]] && pass_msg "no lost count reported: not checked" || fail "no count: $out"
out=$(lost_check 'lost 0\n' user)
[[ "$out" == "No audit events lost|unchecked|auditctl -s needs root" ]] && pass_msg "as a normal user: not checked (needs root)" || fail "non-root: $out"
out=$(lib 'UH_QUIET_CHECKS=true; is_linux() { return 0; }; is_service_active() { return 1; }
           run_cis_checks >/dev/null 2>&1; printf "%s\n" "${CHECK_RESULTS[@]}" | grep -c "^No audit events lost" || true')
[[ "$out" == 0 ]] && pass_msg "auditd not running: no lost-events check (the running check fails instead)" || fail "auditd off: $out"
out=$(lib 'cis_check_module "No audit events lost"')
[[ -z "$out" ]] && pass_msg "the lost-events check marks no module (module 7 on a quiet host would not clear it)" || fail "mapping: $out"

finish
