#!/bin/bash
# Module 6 and IP forwarding. A container host, Kubernetes node, VPN gateway
# or router needs forwarding on; module 6 used to write ip_forward = 0
# everywhere, which Docker hides (its daemon turns it back on) but which can
# break Kubernetes networking at the next reboot. Now: such a host keeps both
# forwarding settings as they are, with a log line; an interactive run asks;
# UH_KEEP_FORWARDING=yes|no overrides; the CIS check reports the kept
# forwarding as waived with the reason; a plain host is hardened as before;
# revert works in both cases.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/bin" "$W/conf" "$W/empty"
printf '#!/bin/sh\nexit 0\n' > "$W/bin/uh-fake-dockerd"
chmod +x "$W/bin/uh-fake-dockerd"

# The library with nothing from the real host leaking in: no runtimes on the
# list, no interfaces, no sysctl files, no ufw.
LIB="source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
     source '$REPO/lib/cis.sh'
     LOG_FILE=/dev/null; UFW_DEFAULTS='$W/no-ufw'; UH_SYSCTL_CONF_PATHS='$W/empty'
     UH_FORWARDING_RUNTIMES=uh-no-such-runtime; ip() { :; }"
lib() {   # <shell>; stdin passes through for the interactive cases
    env PATH="$W/bin:$PATH" bash -c "$LIB
        $1" 2>&1
}
FWD_LINES='^net\.(ipv4\.ip_forward|ipv6\.conf\.all\.forwarding) = 0$'

# --- detection --------------------------------------------------------------------
out=$(lib 'forwarding_needed_reasons; AUTO_MODE=true; decide_forwarding; echo "decision=$UH_FORWARDING_DECISION"' </dev/null)
[[ "$out" == "decision=off" ]] && pass_msg "plain host: no reason found, forwarding is turned off" || fail "plain host: $out"
plain=$(lib '_kernel_sysctl_settings' </dev/null)
[[ $(grep -cE "$FWD_LINES" <<<"$plain") == 2 ]] && pass_msg "plain host: both forwarding settings written" || fail "plain settings: $plain"

out=$(lib 'UH_FORWARDING_RUNTIMES="uh-no-such-runtime uh-fake-dockerd"; forwarding_keep_reason' </dev/null)
[[ "$out" == "uh-fake-dockerd is installed" ]] && pass_msg "an installed container runtime is a reason" || fail "runtime reason: $out"

kept=$(lib 'UH_FORWARDING_RUNTIMES=uh-fake-dockerd; AUTO_MODE=true; decide_forwarding; _kernel_sysctl_settings' </dev/null)
if ! grep -qE '^net\.(ipv4\.ip_forward|ipv6\.conf\.all\.forwarding)' <<<"$kept" \
   && [[ $(grep -c '^[a-z]' <<<"$kept") == $(( $(grep -c '^[a-z]' <<<"$plain") - 2 )) ]]; then
    pass_msg "container host, unattended: both forwarding settings left out, every other one kept"
else
    fail "container host settings: $kept"
fi

out=$(lib "ip() { [[ \"\$*\" == *wireguard* ]] && echo '5: wg0: <POINTOPOINT,NOARP,UP> mtu 1420 qdisc noqueue'; return 0; }
           forwarding_keep_reason" </dev/null)
[[ "$out" == "WireGuard interface wg0" ]] && pass_msg "a WireGuard interface is a reason" || fail "wireguard: $out"
out=$(lib "ip() { [[ \"\$*\" == *'type tun'* ]] && echo '7: tun0: <POINTOPOINT,UP> mtu 1500'; return 0; }
           forwarding_keep_reason" </dev/null)
[[ "$out" == "tunnel interface tun0 (OpenVPN or similar)" ]] && pass_msg "a tun interface is a reason" || fail "tun: $out"

printf '# net.ipv4.ip_forward = 1\nnet.ipv4.ip_forward = 0\n' > "$W/conf/10-off.conf"
out=$(lib "UH_SYSCTL_CONF_PATHS='$W/conf'; forwarding_keep_reason || echo none" </dev/null)
[[ "$out" == none ]] && pass_msg "a commented or zero forwarding line is not a reason" || fail "commented line: $out"
printf 'net.ipv4.ip_forward=1\n' > "$W/conf/99-hardening.conf"
out=$(lib "UH_SYSCTL_CONF_PATHS='$W/conf'; UH_SYSCTL_DROPIN='$W/conf/99-hardening.conf'; forwarding_keep_reason || echo none" </dev/null)
[[ "$out" == none ]] && pass_msg "this module's own drop-in is never read as a reason" || fail "own drop-in: $out"
rm -f "$W/conf/99-hardening.conf"
printf 'net.ipv4.ip_forward = 1\n' > "$W/conf/50-router.conf"
out=$(lib "UH_SYSCTL_CONF_PATHS='$W/conf'; forwarding_keep_reason" </dev/null)
[[ "$out" == "forwarding is turned on in $W/conf/50-router.conf" ]] && pass_msg "a sysctl file turning forwarding on is a reason, named" || fail "config reason: $out"
printf 'IPT_SYSCTL=%s\n' "$W/ufw-sysctl.conf" > "$W/ufw-defaults"
printf 'net/ipv4/ip_forward=1\n' > "$W/ufw-sysctl.conf"
out=$(lib "UFW_DEFAULTS='$W/ufw-defaults'; forwarding_keep_reason" </dev/null)
[[ "$out" == "forwarding is turned on in $W/ufw-sysctl.conf" ]] && pass_msg "ufw's sysctl file turning forwarding on is a reason" || fail "ufw reason: $out"

# --- overrides --------------------------------------------------------------------
out=$(lib 'UH_KEEP_FORWARDING=no; UH_FORWARDING_RUNTIMES=uh-fake-dockerd; AUTO_MODE=true; decide_forwarding; echo "decision=$UH_FORWARDING_DECISION"' </dev/null)
[[ "$out" == "decision=off" ]] && pass_msg "UH_KEEP_FORWARDING=no turns forwarding off on a container host" || fail "keep=no: $out"
out=$(lib 'UH_KEEP_FORWARDING=yes; AUTO_MODE=false; decide_forwarding; echo "decision=$UH_FORWARDING_DECISION why=$UH_FORWARDING_WHY"' </dev/null)
[[ "$out" == "decision=keep why=UH_KEEP_FORWARDING=yes" ]] && pass_msg "UH_KEEP_FORWARDING=yes keeps it anywhere, without asking" || fail "keep=yes: $out"
out=$(lib 'UH_KEEP_FORWARDING=maybe; AUTO_MODE=true; decide_forwarding; echo "decision=$UH_FORWARDING_DECISION"' </dev/null)
grep -q "UH_KEEP_FORWARDING='maybe' is not auto, yes or no" <<<"$out" && grep -q 'decision=off' <<<"$out" \
    && pass_msg "an unknown UH_KEEP_FORWARDING warns and falls back to auto" || fail "keep=maybe: $out"

# --- interactive ------------------------------------------------------------------
# read -p prints its prompt only to a terminal, so "asked once" shows as the
# second answer still waiting on stdin.
out=$(printf 'n\ny\n' | lib 'UH_FORWARDING_RUNTIMES=uh-fake-dockerd; AUTO_MODE=false; decide_forwarding; decide_forwarding
                               read -r rest; echo "decision=$UH_FORWARDING_DECISION unread=$rest"')
grep -q 'decision=off unread=y' <<<"$out" \
    && pass_msg "interactive: answering n turns it off, and the question is asked once" || fail "interactive n: $out"
out=$(printf '\n' | lib 'UH_FORWARDING_RUNTIMES=uh-fake-dockerd; AUTO_MODE=false; decide_forwarding; echo "decision=$UH_FORWARDING_DECISION"')
grep -q 'decision=keep' <<<"$out" && pass_msg "interactive: Enter keeps forwarding (the default)" || fail "interactive default: $out"
grep -qF 'confirm "This host looks like it routes traffic (${UH_FORWARDING_WHY}). Leave IP forwarding as it is?" Y' "$REPO/lib/modules.sh" \
    && pass_msg "interactive: the question names the reason" || fail "question text changed"

# --- dry run ----------------------------------------------------------------------
out=$(lib 'UH_FORWARDING_RUNTIMES=uh-fake-dockerd; DRY_RUN=true; AUTO_MODE=false; DISTRO_TYPE=debian
           is_linux() { return 0; }; apply_kernel_hardening' </dev/null)
grep -q 'Would leave IP forwarding as it is: uh-fake-dockerd is installed' <<<"$out" && ! grep -q 'Leave IP forwarding as it is?' <<<"$out" \
    && pass_msg "dry run says forwarding would be left, and asks nothing" || fail "dry run: $out"

# --- CIS check --------------------------------------------------------------------
cis_forwarding() {   # <live ip_forward value> <runtimes>
    lib "UH_FORWARDING_RUNTIMES='$2'; UH_QUIET_CHECKS=true
         sysctl() { if [[ \"\$*\" == *net.ipv4.ip_forward* ]]; then echo $1; else command sysctl \"\$@\"; fi; }
         is_linux() { return 0; }
         run_cis_checks >/dev/null 2>&1
         printf '%s\n' \"\${CHECK_RESULTS[@]}\" | grep '^IP forwarding disabled|'" </dev/null
}
out=$(cis_forwarding 1 uh-fake-dockerd)
[[ "$out" == "IP forwarding disabled|waived|this host routes traffic (uh-fake-dockerd is installed); module 6 leaves forwarding on" ]] \
    && pass_msg "CIS: forwarding on a container host is waived, with the reason" || fail "cis container: $out"
out=$(cis_forwarding 1 uh-no-such-runtime)
[[ "$out" == "IP forwarding disabled|false|"* ]] && pass_msg "CIS: forwarding on a plain host still fails" || fail "cis plain: $out"
out=$(cis_forwarding 0 uh-fake-dockerd)
[[ "$out" == "IP forwarding disabled|true|"* ]] && pass_msg "CIS: forwarding off on a container host passes" || fail "cis off: $out"

# --- apply and revert as root -----------------------------------------------------
if [[ $EUID -ne 0 || ! -d /etc/sysctl.d ]]; then
    echo "  SKIP: apply/revert needs root and /etc/sysctl.d"
    finish
fi
G=/root/.ultimate_hardening_genesis
module_step() {   # <apply|revert> <runtimes>
    env PATH="$W/bin:$PATH" bash -c '
        source "$1/lib/core.sh"; source "$1/lib/platform.sh"
        source "$1/lib/modules.sh"; source "$1/lib/cis.sh"; source "$1/lib/menu.sh"
        DRY_RUN=false AUTO_MODE=true SKIP_BACKUP=false LOG_FILE="$2/run.log" UH_FORWARDING_RUNTIMES="$4"
        detect_platform >/dev/null 2>&1 || true
        if [[ "$3" == apply ]]; then create_backup_dir && run_module kernel apply_kernel_hardening
        else revert_module kernel; fi
    ' _ "$REPO" "$W" "$1" "$2" 2>&1
}
f=/etc/sysctl.d/99-hardening.conf
for host in container plain; do
    rm -rf "$G" "$f"
    runtimes=uh-no-such-runtime; [[ $host == container ]] && runtimes=uh-fake-dockerd
    out=$(module_step apply "$runtimes")
    assert_file_exists "$f" "$host: drop-in written"
    if [[ $host == container ]]; then
        assert_file_not_contains "$f" '^net\.ipv4\.ip_forward' "container: ip_forward not written"
        assert_file_not_contains "$f" '^net\.ipv6\.conf\.all\.forwarding' "container: IPv6 forwarding not written"
        grep -q 'IP forwarding left as it is: uh-fake-dockerd is installed' <<<"$out" \
            && pass_msg "container: the log says why forwarding was left" || fail "container log: $out"
        ! grep -q '^net.ipv4.ip_forward=' "$G/sysctl_before.txt" 2>/dev/null \
            && pass_msg "container: forwarding not recorded, so revert never touches it" || fail "container record: $(cat "$G/sysctl_before.txt")"
    else
        assert_file_contains "$f" '^net\.ipv4\.ip_forward = 0' "plain: ip_forward = 0 written"
        assert_file_contains "$f" '^net\.ipv6\.conf\.all\.forwarding = 0' "plain: IPv6 forwarding = 0 written"
        grep -q '^net.ipv4.ip_forward=' "$G/sysctl_before.txt" 2>/dev/null \
            && pass_msg "plain: forwarding's value before is recorded for revert" || fail "plain record missing"
    fi
    module_step revert "$runtimes" >/dev/null
    assert_file_absent "$f" "$host: revert removes the drop-in"
done
finish
