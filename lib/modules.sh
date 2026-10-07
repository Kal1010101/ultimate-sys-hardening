#!/bin/bash
# =============================================================================
#  lib/modules.sh — the 22 core hardening modules
#
#  Every tier sources this. There is exactly one implementation of each module;
#  a fix here reaches Free, Pro, and Enterprise simultaneously.
#
#  Contract for every module:
#    - Honours DRY_RUN (prints intent, changes nothing)
#    - Backs up any file it modifies via backup_file()
#    - Never exits non-zero on a benign failure (set -e safe)
#    - Idempotent: running twice produces the same state as running once
#
#  Requires: lib/core.sh and lib/platform.sh sourced first.
# =============================================================================

# --- 1. System updates -------------------------------------------------------
apply_system_updates() {
    log_message "${GEAR} [1/22] System Updates"

    local kernels_before=""
    if [[ "$DRY_RUN" != true ]]; then
        kernels_before=$(installed_kernel_versions)
    fi

    update_packages
    # The menu caches the pending-upgrade count; this run just changed it.
    declare -F invalidate_pending_updates_cache >/dev/null && invalidate_pending_updates_cache

    # An upgrade that leaves the next boot broken is not a successful upgrade,
    # and this module used to say it was: on Alpine a kernel upgrade whose
    # initramfs was never rebuilt reported "System packages updated" and the
    # machine failed its next reboot. verify_boot_chain (lib/platform.sh)
    # rebuilds a stale boot image where it can.
    #
    # Where it cannot, this returns 1 — deliberately breaking the "never exit
    # non-zero" contract at the top of this file, because this is not a benign
    # failure. run_module records it and the run continues, so the summary
    # names "System updates" as failed instead of printing a green tick over a
    # machine that will not boot.
    if [[ "$DRY_RUN" != true ]] && ! verify_boot_chain "$kernels_before"; then
        log_error "Packages were upgraded, but the next boot would fail (see above). Do NOT reboot until that is fixed."
        return 1
    fi

    log_success "System packages updated"
    count_fix
}

# --- 2. SSH hardening --------------------------------------------------------
apply_ssh_hardening() {
    log_message "${LOCK} [2/22] SSH Hardening"
    local cfg="/etc/ssh/sshd_config"

    if [[ ! -f "$cfg" ]]; then
        log_warning "sshd_config not found — SSH not installed, skipping"
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would apply 13 hardened settings to $cfg"
        return 0
    fi

    backup_file "$cfg"

    set_config "PermitRootLogin"                 "no"              "$cfg"
    set_config "PasswordAuthentication"          "no"              "$cfg"
    set_config "ChallengeResponseAuthentication" "no"              "$cfg"
    set_config "X11Forwarding"                   "no"              "$cfg"
    set_config "AllowTcpForwarding"              "no"              "$cfg"
    set_config "PermitEmptyPasswords"            "no"              "$cfg"
    set_config "MaxAuthTries"                    "3"               "$cfg"
    set_config "LoginGraceTime"                  "30"              "$cfg"
    set_config "ClientAliveInterval"             "300"             "$cfg"
    set_config "ClientAliveCountMax"             "2"               "$cfg"
    set_config "UsePAM"                          "yes"             "$cfg"
    set_config "PrintLastLog"                    "yes"             "$cfg"
    set_config "Banner"                          "/etc/issue.net"  "$cfg"

    echo "Authorized access only. All activity is monitored and logged." \
        > /etc/issue.net 2>/dev/null || true

    # sshd_config uses first-obtained-value-wins: whichever value for a
    # keyword it parses FIRST is the one that applies, and every later
    # setting of that same keyword — including everything just written above
    # — is silently ignored. On Debian/Ubuntu, `Include
    # /etc/ssh/sshd_config.d/*.conf` sits near the TOP of the main file, well
    # before these settings, so any drop-in dropped there is parsed first and
    # wins outright. Cloud-init ships exactly such a drop-in
    # (sshd_config.d/50-cloud-init.conf, PasswordAuthentication yes) on every
    # stock cloud image — meaning on a real cloud VM, the password-auth
    # setting above was being written to the file but never actually taking
    # effect. Found by an attacker-simulation test logging in over SSH with a
    # real password on a guest this had already "hardened".
    #
    # The fix mirrors the file it's racing against: our own drop-in, sorted
    # to glob-expand before any other (a two-digit prefix starting at 00
    # comes before cloud-init's 50-, and before any other vendor drop-in
    # likely to use a higher prefix), carrying the security-relevant subset
    # of the same settings so it wins the same way cloud-init's does. The
    # main-file settings above are left in place too, both as the effective
    # config on any host with no conflicting drop-in and as a visible record
    # of intent for anyone reading sshd_config directly.
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        local dropin="/etc/ssh/sshd_config.d/00-ultimate-hardening.conf"
        cat > "$dropin" << 'EOF'
# Written by Ultimate Hardening. Named to sort first among
# /etc/ssh/sshd_config.d/*.conf so it wins sshd's first-value-wins parsing
# over drop-ins (e.g. cloud-init's 50-cloud-init.conf) that would otherwise
# silently override the settings below.
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
EOF
        chmod 600 "$dropin" 2>/dev/null || true
    fi

    # sshd -t itself needs /run/sshd (privilege separation) to exist, which a
    # normal boot creates but a host where sshd has never once started (a
    # freshly `apt install`'d package, a minimal container) has not — sshd -t
    # then fails on a missing directory, not the config, and this safety
    # check would wrongly restore the backup and skip hardening entirely on
    # an otherwise-fine host. Harmless and idempotent to ensure it exists.
    mkdir -p /run/sshd 2>/dev/null || true

    # Validate before restarting — a bad config must never lock the operator out.
    if sshd_config_valid; then
        restart_sshd
        log_success "SSH hardened (13 settings) and daemon restarted"
    else
        log_error "sshd config failed validation — restoring backup, no restart"
        restore_file "$cfg" || log_error "Restore failed. Inspect $cfg manually before disconnecting."
        return 1
    fi
    count_fix
}

# --- 3. Firewall -------------------------------------------------------------
# Picks the firewall that belongs on THIS platform instead of assuming ufw.
# The old fallback hardcoded `install_package ufw`, which cannot succeed on
# rhel/suse (ufw is not in their default repos) — and then returned 1, which
# under `set -euo pipefail` aborted apply_safe_modules() and silently skipped
# modules 4-22. A firewall that cannot be installed must degrade this module
# only; see the set -e contract at the top of this file.
apply_firewall() {
    log_message "${FIRE} [3/22] Firewall"
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would configure firewall: default-deny inbound, allow SSH/80/443"
        return 0
    fi

    local distro="${DISTRO_TYPE:-$(detect_platform)}"

    # Configure whatever is already installed, in platform-preference order:
    # a stray ufw on RHEL should not win over firewalld, and vice versa.
    case "$distro" in
        rhel|suse)
            command -v firewall-cmd >/dev/null 2>&1 && { _fw_firewalld; return 0; }
            command -v nft          >/dev/null 2>&1 && { _fw_nftables;  return 0; }
            command -v ufw          >/dev/null 2>&1 && { _fw_ufw;       return 0; }
            ;;
        debian)
            command -v ufw          >/dev/null 2>&1 && { _fw_ufw;       return 0; }
            command -v nft          >/dev/null 2>&1 && { _fw_nftables;  return 0; }
            command -v firewall-cmd >/dev/null 2>&1 && { _fw_firewalld; return 0; }
            ;;
        *)
            command -v nft          >/dev/null 2>&1 && { _fw_nftables;  return 0; }
            command -v ufw          >/dev/null 2>&1 && { _fw_ufw;       return 0; }
            command -v firewall-cmd >/dev/null 2>&1 && { _fw_firewalld; return 0; }
            ;;
    esac

    if command -v pfctl >/dev/null 2>&1; then
        log_warning "BSD pf detected — configure /etc/pf.conf manually (not automated)"
        return 0
    fi

    # Nothing installed: install the one this platform actually ships.
    local pkg; pkg=$(firewall_package_for "$distro")

    log_warning "No firewall found — installing $pkg"
    if ! install_package "$pkg"; then
        log_error "Could not install $pkg — firewall left unconfigured, continuing"
        return 0
    fi

    case "$pkg" in
        firewalld) _fw_firewalld ;;
        ufw)       _fw_ufw ;;
        nftables)  _fw_nftables ;;
    esac
    return 0
}

# Which firewall this platform actually ships. Read by apply_firewall AND by
# the preflight pass in platform.sh, so what preflight promises to install and
# what the module installs cannot drift — the same reason cis_check_module()
# exists for the check/module mapping.
firewall_package_for() {
    case "${1:-${DISTRO_TYPE:-}}" in
        rhel|suse)                     echo "firewalld" ;;
        debian)                        echo "ufw" ;;
        alpine|arch|void|gentoo|nixos) echo "nftables" ;;
        *)                             echo "nftables" ;;
    esac
}

# Each backend counts its own fix, so a module that configured nothing does
# not inflate FIXES_APPLIED.
_fw_ufw() {
    ufw --force reset          >>"$LOG_FILE" 2>&1 || true
    ufw default deny incoming  >>"$LOG_FILE" 2>&1 || true
    ufw default allow outgoing >>"$LOG_FILE" 2>&1 || true
    ufw allow ssh              >>"$LOG_FILE" 2>&1 || true
    ufw allow 80/tcp           >>"$LOG_FILE" 2>&1 || true
    ufw allow 443/tcp          >>"$LOG_FILE" 2>&1 || true
    ufw --force enable         >>"$LOG_FILE" 2>&1 || true
    log_success "UFW: deny inbound, allow outbound, SSH/80/443 open"
    count_fix
}

_fw_firewalld() {
    enable_service firewalld >/dev/null 2>&1 || true

    # systemctl reports the unit "active" as soon as the process starts,
    # which can be before firewalld has finished registering its own D-Bus
    # service — especially right after installing the package in this same
    # run. Wait for firewalld's own readiness signal (--state prints
    # "running") instead of trusting the service manager's, up to 5 seconds
    # — still relevant even after the fix below, since --set-default-zone
    # genuinely needs the D-Bus service up.
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        [[ "$(firewall-cmd --state 2>/dev/null)" == "running" ]] && break
        sleep 0.5
    done

    # --set-default-zone is a "stand-alone option" in firewall-cmd's own
    # parser and cannot be combined with --permanent at all — firewall-cmd
    # rejects it outright ("Can't use stand-alone options with other
    # options.", exit 2). The original code passed both together, so this
    # call has failed on every single invocation, on every host, silently
    # swallowed by `|| true` — not an intermittent D-Bus race, an
    # unconditional bug. --set-default-zone is inherently both immediate
    # and permanent on its own; no --permanent needed or accepted. Found by
    # testing this module for real on a freshly-installed Rocky guest,
    # where the "wait for firewalld to be ready" fix above made no
    # difference — the command was malformed regardless of timing.
    firewall-cmd --set-default-zone=drop         >>"$LOG_FILE" 2>&1 || true
    firewall-cmd --permanent --add-service=ssh   >>"$LOG_FILE" 2>&1 || true
    firewall-cmd --permanent --add-service=http  >>"$LOG_FILE" 2>&1 || true
    firewall-cmd --permanent --add-service=https >>"$LOG_FILE" 2>&1 || true
    firewall-cmd --reload                        >>"$LOG_FILE" 2>&1 || true

    # Verify the zone change actually took rather than trusting firewall-
    # cmd's own exit code. One retry before giving an honest warning — the
    # readiness wait above still matters for this retry, since
    # --set-default-zone genuinely does need firewalld's D-Bus service up.
    local zone; zone=$(firewall-cmd --get-default-zone 2>/dev/null)
    if [[ "$zone" != "drop" ]]; then
        firewall-cmd --set-default-zone=drop >>"$LOG_FILE" 2>&1 || true
        firewall-cmd --reload >>"$LOG_FILE" 2>&1 || true
        zone=$(firewall-cmd --get-default-zone 2>/dev/null)
    fi

    # enable_service logs "enabled" unconditionally (systemctl start's own
    # exit code is thrown away) — the same false-positive shape apply_fail2ban
    # already guards against. Same fix here: only claim success once the
    # service is actually confirmed running.
    if is_service_active firewalld; then
        if [[ "$zone" == "drop" ]]; then
            log_success "firewalld: default zone drop, SSH/80/443 open"
            count_fix
        else
            log_warning "firewalld default zone is '$zone', not 'drop', after a retry — check: firewall-cmd --get-default-zone"
        fi
    else
        log_warning "firewalld was configured but is not running — check: systemctl status firewalld"
    fi
}

# Unlike the ufw and firewalld backends, raw nft rules do not survive a reboot
# on their own — they are written out and the service enabled, or the hardening
# silently lapses at the next boot.
_fw_nftables() {
    # This module owns ONE table, `inet uh_filter`, and touches nothing else.
    #
    # The previous version ran `nft flush ruleset`, which destroyed every table
    # that belonged to someone else — Docker's NAT, fail2ban's f2b-table, a
    # hand-written ruleset — and then built its own in the `ip` family only.
    # Two consequences, both measured with real packets: the host's IPv6 was
    # never filtered at all (default-drop on v4, wide open on v6), and anything
    # sharing the netns lost its rules the moment this ran.
    #
    # `inet` covers v4 and v6 in one table. IPv6 cannot work without ICMPv6
    # neighbour discovery, so those types are accepted explicitly; IPv4 keeps
    # its old behaviour (no ICMP beyond what conntrack already relates).
    nft delete table inet uh_filter 2>/dev/null || true
    # The table earlier releases created. A packet must be accepted by EVERY
    # base chain at a hook, so leaving its drop policy in place would keep
    # dropping whatever this table accepts. Removed only when it is recognisably
    # ours (the combined 22/80/443 accept), never a table that merely shares
    # the name.
    if nft list chain ip filter INPUT 2>/dev/null | grep -q 'dport { 22, 80, 443 } accept'; then
        nft delete table ip filter 2>/dev/null || true
    fi

    nft add table inet uh_filter 2>/dev/null || true
    nft add chain inet uh_filter input '{ type filter hook input priority 0; policy drop; }' 2>/dev/null || true
    nft add rule  inet uh_filter input ct state established,related accept 2>/dev/null || true
    nft add rule  inet uh_filter input ct state invalid drop 2>/dev/null || true
    nft add rule  inet uh_filter input iif lo accept 2>/dev/null || true
    nft add rule  inet uh_filter input ip6 nexthdr icmpv6 icmpv6 type \
        '{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }' \
        accept 2>/dev/null || true
    nft add rule  inet uh_filter input tcp dport '{ 22, 80, 443 }' accept 2>/dev/null || true

    # Persist OUR table only. `nft list ruleset` would freeze whatever else is
    # loaded right now (Docker's rules, fail2ban's bans) into a boot file.
    # `table X` then `delete table X` is the idiom that makes reloading the file
    # idempotent whether or not the table already exists.
    local conf="${UH_NFT_CONF:-}"   # test hook: lets the suite write somewhere harmless
    if [[ -z "$conf" ]]; then
        conf=/etc/nftables.conf
        command -v rc-update >/dev/null 2>&1 && conf=/etc/nftables.nft
    fi
    [[ -f "$conf" ]] && backup_file "$conf"
    {
        echo '#!/usr/sbin/nft -f'
        echo
        echo 'table inet uh_filter'
        echo 'delete table inet uh_filter'
        nft list table inet uh_filter 2>/dev/null
    } > "$conf" 2>/dev/null || true
    enable_service nftables >/dev/null 2>&1 || true

    # The rules above are live in the kernel already — that part does not
    # depend on the nftables service. What the service gates is persistence:
    # without it the ruleset does not survive a reboot, silently undoing this
    # module the next time the host restarts. enable_service logs "enabled"
    # unconditionally, so check the real state before claiming "(persisted)".
    count_fix
    if is_service_active nftables; then
        log_success "nftables: default-drop inbound (IPv4 and IPv6), SSH/80/443 accepted (persisted)"
    else
        log_success "nftables: default-drop inbound (IPv4 and IPv6), SSH/80/443 accepted (active now)"
        log_warning "nftables service is not running — this ruleset will NOT survive a reboot; check: systemctl status nftables"
    fi
}

# Revert module 3 on whichever backend is actually configured right now —
# detected the same way apply_firewall() picks one to apply to, not
# re-derived from DISTRO_TYPE, since what is live is the ground truth.
# There is no captured "before" ruleset to restore: SECURITY.md already
# documents that firewall config resets existing rules rather than backing
# up live kernel state ("If you have a hand-built ruleset, back it up
# separately"), so "revert" here can only mean the same thing apply's own
# --force reset / delete already means — back to that backend's own clean,
# inactive default, not a guess at whatever was there before.
#
# nftables specifically: `nft delete table ip filter` rather than `nft
# flush ruleset` (what apply uses) — flush would wipe every table on the
# system, including anything unrelated to this tool; delete removes
# exactly the one table this module (and the paid rate-limit module, which
# only ever adds rules inside this same table) created, and nothing else.
revert_firewall() {
    local acted=false

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
        ufw --force reset  >>"$LOG_FILE" 2>&1 || true
        ufw disable        >>"$LOG_FILE" 2>&1 || true
        log_success "ufw: reset to defaults and disabled"
        acted=true
    fi

    if command -v firewall-cmd >/dev/null 2>&1 && is_service_active firewalld; then
        # Services were meant to land in the "drop" zone (apply sets that as
        # default BEFORE adding them) but read the REAL current default
        # rather than assuming "drop": found by testing this for real that
        # --set-default-zone=drop can silently not take effect right after
        # firewalld was just installed and started in the same run (a timing
        # race between the daemon coming up and the very next D-Bus call),
        # leaving ssh/http/https added to "public" instead — a real,
        # separate bug in apply's own _fw_firewalld(), not fixed here, but
        # this read-the-actual-zone approach means revert still finds and
        # removes them correctly either way.
        # A REAL SSH lockout, caused by this exact code, on a real guest:
        # the first version called --reload here before stopping the
        # service. --permanent edits don't take effect until reload (or a
        # restart) — but this session's earlier apply had (separately,
        # see the timing-race note above) put ssh in the "public" zone,
        # so reloading a "public" zone with ssh just removed from it, WHILE
        # firewalld was still actively enforcing, cut the live SSH session
        # off immediately. Had to recover over the serial console. Fixed by
        # never reloading the now-more-restrictive config into a still-
        # running daemon: the --permanent edits are written (correct for
        # if firewalld ever gets started again later) but never applied
        # live — stop_service() below tears down enforcement entirely
        # instead, which is unconditionally safe for the current session
        # regardless of what the pending zone edits would have done.
        local zone; zone=$(firewall-cmd --get-default-zone 2>/dev/null || echo drop)
        firewall-cmd --permanent --zone="$zone" --remove-service=ssh   >>"$LOG_FILE" 2>&1 || true
        firewall-cmd --permanent --zone="$zone" --remove-service=http  >>"$LOG_FILE" 2>&1 || true
        firewall-cmd --permanent --zone="$zone" --remove-service=https >>"$LOG_FILE" 2>&1 || true
        firewall-cmd --permanent --set-default-zone=public >>"$LOG_FILE" 2>&1 || true
        # Matching ufw's own revert above: apply_firewall() only ever
        # installs+enables a backend when none was already active, so "no
        # firewall was here before" means the service itself should stop,
        # not just have its rules emptied — otherwise the compliance check
        # (which reads service state, not rule content) still shows
        # [enable ] and the log's own "no active firewall" claim is false.
        # stop_service() (lib/platform.sh), not a hardcoded systemctl call —
        # this codebase runs on OpenRC hosts too.
        stop_service firewalld
        log_success "firewalld: removed the hardened services and stopped the service"
        acted=true
    fi

    if command -v nft >/dev/null 2>&1 && nft list tables 2>/dev/null | grep -q 'ip filter'; then
        nft delete table ip filter 2>>"$LOG_FILE" || true
        if command -v rc-update >/dev/null 2>&1; then
            rm -f /etc/nftables.nft
        else
            rm -f /etc/nftables.conf
        fi
        # The CIS check behind this module's [enable ]/[disable] tag reads
        # `is_service_active nftables`, not rule content (see lib/cis.sh) —
        # deleting the table alone leaves the tag showing [enable ] even
        # with no rules left, same inconsistency the firewalld branch above
        # was found to have. stop_service() rather than a hardcoded
        # systemctl call — Alpine (nftables' main real-world use here) runs
        # OpenRC, not systemd.
        stop_service nftables
        log_success "nftables: removed the filter table, its persisted ruleset file, and stopped the service"
        acted=true
    fi

    if [[ "$acted" != true ]]; then
        log_info "Firewall: nothing reverted — no active ufw/firewalld configuration or nftables filter table from this tool was found"
        return 1
    fi

    log_warning "The host now has no active firewall — the same unprotected state as before module 3 ever ran, not a restored prior ruleset (see SECURITY.md: live kernel firewall state was never backed up, only config files are)."
    return 0
}

# --- 4. Fail2Ban -------------------------------------------------------------
apply_fail2ban() {
    log_message "${SHIELD} [4/22] Fail2Ban"
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would install fail2ban with an SSH jail (3 tries, 2h ban)"
        return 0
    fi

    install_package fail2ban || { log_warning "fail2ban unavailable — skipping"; return 0; }

    # The sshd jail's default backend reads /var/log/auth.log, which does not
    # exist on a journald-only host (no rsyslog installed) — increasingly the
    # default on modern Debian/Ubuntu cloud images. Without a log source the
    # whole fail2ban daemon fails to start at all (not just the sshd jail),
    # so enable_service below would report "enabled" for a service that is
    # actually dead. On a systemd host, reading the journal directly sidesteps
    # the missing-file problem entirely; on a non-systemd host (e.g. Alpine's
    # OpenRC) the traditional file-based backend is left as-is.
    local backend="auto"
    _has_systemd && backend="systemd"

    backup_file /etc/fail2ban/jail.local
    mkdir -p /etc/fail2ban 2>/dev/null || true
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled  = true
port     = ssh
maxretry = 3
bantime  = 7200
backend  = ${backend}
EOF

    enable_service fail2ban
    if is_service_active fail2ban; then
        log_success "Fail2Ban active: SSH jail bans for 2h after 3 failures"
        count_fix
    else
        log_warning "fail2ban was configured but is not running — check: systemctl status fail2ban"
    fi
}

# --- 5. File permissions -----------------------------------------------------
apply_permission_hardening() {
    log_message "${LOCK} [5/22] File Permissions"
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would restrict permissions on 7 sensitive files and /tmp"
        return 0
    fi

    local targets=(
        "/etc/passwd:644" "/etc/group:644"
        "/etc/shadow:640" "/etc/gshadow:640"
        "/etc/ssh/sshd_config:600"
        "/etc/crontab:600"
        "/boot/grub/grub.cfg:600"
    )

    create_backup_dir
    local inventory="$BACKUP_DIR/perm_original_modes.txt"
    for entry in "${targets[@]}"; do
        local file="${entry%:*}" mode="${entry##*:}"
        [[ -f "$file" ]] || continue
        local orig; orig=$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file" 2>/dev/null)
        [[ -n "$orig" && "$orig" != "$mode" && "$SKIP_BACKUP" == false ]] && printf '%s %s\n' "$file" "$orig" >> "$inventory"
        chmod "$mode" "$file" 2>/dev/null && log_info "  chmod $mode $file" || true
    done

    chown root:root /etc/passwd /etc/group /etc/shadow /etc/gshadow 2>/dev/null || true
    chmod 1777 /tmp 2>/dev/null || true

    append_once "* hard core 0" /etc/security/limits.conf

    log_success "Sensitive file permissions restricted"
    count_fix
}

# --- 6. Kernel / network -----------------------------------------------------
apply_kernel_hardening() {
    log_message "${GEAR} [6/22] Kernel & Network Hardening"

    if ! is_linux; then
        log_warning "sysctl hardening is Linux-specific — skipping on ${DISTRO_TYPE}"
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would write 27 sysctl parameters to /etc/sysctl.d/99-hardening.conf"
        return 0
    fi

    local sysctl_file="/etc/sysctl.d/99-hardening.conf"
    backup_file "$sysctl_file"
    mkdir -p /etc/sysctl.d 2>/dev/null || true

    cat > "$sysctl_file" << 'EOF'
# Ultimate Hardening — kernel and network parameters
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
EOF

    sysctl -p "$sysctl_file" >>"$LOG_FILE" 2>&1 || true
    local n; n=$(grep -c '^[a-z]' "$sysctl_file" 2>/dev/null || echo 0)
    log_success "Kernel hardening applied ($n parameters)"
    count_fix
}

# --- 7. Auditd ---------------------------------------------------------------
apply_audit_config() {
    log_message "${SHIELD} [7/22] Audit Daemon"

    if ! is_linux; then
        log_warning "auditd is Linux-specific — skipping on ${DISTRO_TYPE}"
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would install auditd and write comprehensive audit rules"
        return 0
    fi

    install_package auditd || install_package audit || {
        log_warning "auditd unavailable — skipping"; return 0; }

    mkdir -p /etc/audit/rules.d 2>/dev/null || true
    backup_file /etc/audit/rules.d/99-hardening.rules

    cat > /etc/audit/rules.d/99-hardening.rules << 'EOF'
-D
-b 8192
-f 1
-w /etc/passwd          -p wa -k identity
-w /etc/group           -p wa -k identity
-w /etc/shadow          -p wa -k identity
-w /etc/gshadow         -p wa -k identity
-w /etc/sudoers         -p wa -k sudoers
-w /etc/sudoers.d       -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/crontab         -p wa -k cron
-w /etc/cron.d          -p wa -k cron
-w /var/spool/cron      -p wa -k cron
-w /var/log/lastlog     -p wa -k logins
-w /sbin/insmod         -p x  -k modules
-w /sbin/rmmod          -p x  -k modules
-w /sbin/modprobe       -p x  -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b64 -S setuid -S setgid -F exit=0 -k privesc
-a always,exit -F arch=b64 -S mount -k mounts
EOF

    enable_service auditd
    command -v augenrules >/dev/null 2>&1 && { augenrules --load >>"$LOG_FILE" 2>&1 || true; }
    # enable_service logs "enabled" unconditionally — verify the daemon is
    # actually up before claiming the rules are in effect, same as
    # apply_fail2ban.
    if is_service_active auditd; then
        log_success "Auditd configured with 17 audit rules"
        count_fix
    else
        log_warning "Audit rules written but auditd is not running — check: systemctl status auditd"
    fi
}

# --- 8. Password policy (login.defs only — PAM is never touched) --------------
apply_password_policies() {
    log_message "${LOCK} [8/22] Password Policy"

    # PAM modification was removed after it locked an eCryptfs system out of its
    # own login screen. Policy is set through login.defs only. See SECURITY.md.
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would set password aging in /etc/login.defs (PAM untouched)"
        return 0
    fi

    local defs="/etc/login.defs"
    if [[ ! -f "$defs" ]]; then
        log_warning "login.defs not found — skipping"
        return 0
    fi

    backup_file "$defs"
    set_config "PASS_MAX_DAYS" "90" "$defs" "	"
    set_config "PASS_MIN_DAYS" "1"  "$defs" "	"
    set_config "PASS_WARN_AGE" "14" "$defs" "	"

    log_success "Password aging set: 90-day max, 14-day warning (PAM untouched)"
    count_fix
}

# --- 9. SUID/SGID ------------------------------------------------------------
# Binaries that legitimately need SUID. fusermount/fusermount3 are here
# because stripping them breaks Flatpak and any FUSE mount.
#
# Module-level, not local to apply_suid_hardening(), so the menu's state
# probe can re-run the module's own selection logic read-only instead of
# keeping a second copy that could silently drift out of sync.
UH_SUID_SAFELIST=(
    /usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/newgrp
    /usr/bin/gpasswd /bin/mount /bin/umount /usr/bin/mount /usr/bin/umount
    /usr/bin/fusermount /usr/bin/fusermount3
    /sbin/unix_chkpwd /usr/sbin/unix_chkpwd
    /usr/lib/openssh/ssh-keysign
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /usr/libexec/dbus-1/dbus-daemon-launch-helper
    /usr/sbin/pam_timestamp_check
    /usr/bin/pkexec /usr/lib/polkit-1/polkit-agent-helper-1
)

apply_suid_hardening() {
    log_message "${FIRE} [9/22] SUID/SGID Hardening ${RED}(HIGH RISK)${NC}"

    if ! confirm_risky "Remove SUID from non-essential binaries?"; then
        log_info "Skipped SUID hardening"
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would record a SUID inventory then strip SUID outside the safe list"
        return 0
    fi

    create_backup_dir
    if [[ "$SKIP_BACKUP" == false ]]; then
        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \
            -exec stat --format="%n %a" {} \; 2>/dev/null > "$SUID_BACKUP_FILE" || true
        log_info "SUID inventory recorded: $SUID_BACKUP_FILE"
    fi

    local -a safe=("${UH_SUID_SAFELIST[@]}")

    local removed=0
    while IFS= read -r bin; do
        local keep=false
        for s in "${safe[@]}"; do
            [[ "$bin" == "$s" ]] && { keep=true; break; }
        done
        if [[ "$keep" == false ]]; then
            chmod u-s "$bin" 2>/dev/null && { log_info "  stripped SUID: $bin"; bump removed; } || true
        fi
    done < <(find / -xdev -perm -4000 -type f 2>/dev/null)

    log_success "SUID removed from $removed binaries (restore: --revert-suid)"
    count_fix
}

# --- 10. AIDE ----------------------------------------------------------------
apply_aide() {
    log_message "${SHIELD} [10/22] AIDE File Integrity"
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would install AIDE and initialise its baseline database"
        return 0
    fi

    install_package aide || { log_warning "AIDE unavailable — skipping"; return 0; }

    log_info "Building AIDE baseline (this can take several minutes)..."
    if command -v aideinit >/dev/null 2>&1; then
        aideinit >>"$LOG_FILE" 2>&1 || true
    else
        aide --init >>"$LOG_FILE" 2>&1 || true
    fi
    # aideinit (Debian) writes the uncompressed .new; RHEL-family hosts have
    # no aideinit and aide.conf's own default is a compressed .new.gz — miss
    # that variant and aide.db.gz never exists, so both this module's own
    # compliance tag and the daily cron check above (which reads aide.db.gz)
    # stay broken forever. Found by testing this module for real on Rocky.
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
    elif [[ -f /var/lib/aide/aide.db.new.gz ]]; then
        mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null || true
    fi

    if [[ -d /etc/cron.daily ]]; then
        cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/sh
/usr/bin/aide --check 2>&1 | logger -t aide-check
EOF
        chmod +x /etc/cron.daily/aide-check 2>/dev/null || true
    fi

    log_success "AIDE baseline created, daily integrity check scheduled"
    count_fix
}

# --- 11. rkhunter ------------------------------------------------------------
apply_rkhunter() {
    log_message "${SHIELD} [11/22] Rootkit Scanner"
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would install rkhunter and enable daily scans"
        return 0
    fi

    install_package rkhunter || { log_warning "rkhunter unavailable — skipping"; return 0; }

    rkhunter --update  --nocolors >>"$LOG_FILE" 2>&1 || true
    rkhunter --propupd --nocolors >>"$LOG_FILE" 2>&1 || true

    if [[ -f /etc/default/rkhunter ]]; then
        set_config "CRON_DAILY_RUN" '"yes"'  /etc/default/rkhunter "="
        set_config "REPORT_EMAIL"   '"root"' /etc/default/rkhunter "="
    fi

    log_success "rkhunter installed, baseline set, daily scan enabled"
    count_fix
}

# --- 12. Disable unnecessary services ----------------------------------------
# Services this module stops. Module-level for the same reason as
# UH_SUID_SAFELIST above: the menu's state probe checks exactly this list.
UH_UNNEEDED_SERVICES=(
    avahi-daemon cups cups-browsed bluetooth
    telnet rsh rlogin rexec tftp xinetd
    nfs-server rpcbind ypserv ypbind
    talk ntalk finger lpd snmpd vsftpd
)

apply_disable_services() {
    log_message "${GEAR} [12/22] Disable Unnecessary Services"
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would disable up to ${#UH_UNNEEDED_SERVICES[@]} unnecessary network services"
        return 0
    fi

    local -a services=("${UH_UNNEEDED_SERVICES[@]}")

    # Recorded so a revert knows exactly which of these were actually
    # running and disabled BY THIS TOOL on THIS host — most of the 16 in
    # UH_UNNEEDED_SERVICES are inactive by default on a normal install, and
    # re-enabling all 16 blind on revert would turn on services this run
    # never touched. Same idea as SUID's own inventory (SUID_BACKUP_FILE):
    # a record of the change, not a guess at it.
    create_backup_dir
    local inventory="$BACKUP_DIR/disabled_services.txt"
    local disabled=0
    for svc in "${services[@]}"; do
        if is_service_active "$svc"; then
            stop_service "$svc"
            log_info "  disabled: $svc"
            [[ "$SKIP_BACKUP" == false ]] && printf '%s\n' "$svc" >> "$inventory"
            bump disabled
        fi
    done

    log_success "Disabled $disabled unnecessary services"
    count_fix
}

# --- 13. Mandatory access control --------------------------------------------
apply_apparmor() {
    log_message "${SHIELD} [13/22] Mandatory Access Control"

    if ! is_linux; then
        log_warning "AppArmor/SELinux are Linux-specific — skipping on ${DISTRO_TYPE}"
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would set AppArmor or SELinux to enforcing mode"
        return 0
    fi

    if command -v aa-status >/dev/null 2>&1; then
        install_package apparmor-utils || true
        enable_service apparmor
        command -v aa-enforce >/dev/null 2>&1 && \
            { aa-enforce /etc/apparmor.d/* >>"$LOG_FILE" 2>&1 || true; }
        # enable_service logs "enabled" unconditionally — verify apparmor is
        # actually running before claiming profiles are enforced, same as
        # apply_fail2ban.
        if is_service_active apparmor; then
            log_success "AppArmor enabled, profiles set to enforce"
            count_fix
        else
            log_warning "AppArmor profiles were set but the service is not running — check: systemctl status apparmor"
        fi
    elif command -v sestatus >/dev/null 2>&1; then
        backup_file /etc/selinux/config
        set_config "SELINUX" "enforcing" /etc/selinux/config "="
        log_success "SELinux set to enforcing (takes effect after reboot)"
        count_fix
    else
        log_warning "No MAC framework present — install apparmor or selinux manually"
        return 0
    fi
}

# --- 14. etckeeper -----------------------------------------------------------
apply_etckeeper() {
    log_message "${GEAR} [14/22] /etc Version Control"
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would initialise etckeeper git tracking for /etc"
        return 0
    fi

    install_package etckeeper || { log_warning "etckeeper unavailable — skipping"; return 0; }

    local prev; prev=$(pwd)
    cd /etc 2>/dev/null || { log_warning "Could not enter /etc"; return 0; }

    if [[ ! -d /etc/.git ]]; then
        etckeeper init >>"$LOG_FILE" 2>&1 || true
        etckeeper commit "Baseline before hardening v${UH_VERSION}" >>"$LOG_FILE" 2>&1 || true
        log_success "etckeeper initialised — /etc now tracked in git"
    else
        etckeeper commit "Hardening run v${UH_VERSION} $(date +%F)" >>"$LOG_FILE" 2>&1 || true
        log_success "etckeeper committed current /etc state"
    fi

    cd "$prev" >/dev/null 2>&1 || true
    count_fix
}

# --- 15. Boot security -------------------------------------------------------
apply_boot_secure() {
    log_message "${LOCK} [15/22] Boot Security"

    if ! is_linux; then
        log_warning "GRUB hardening is Linux-specific — skipping on ${DISTRO_TYPE}"
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would restrict GRUB config permissions and blacklist USB storage"
        return 0
    fi

    create_backup_dir
    local inventory="$BACKUP_DIR/boot_original_perms.txt"
    for cfg in /boot/grub/grub.cfg /boot/grub2/grub.cfg /boot/efi/EFI/*/grub.cfg; do
        [[ -f "$cfg" ]] || continue
        local orig; orig=$(stat -c '%a' "$cfg" 2>/dev/null || stat -f '%Lp' "$cfg" 2>/dev/null)
        [[ -n "$orig" && "$orig" != "600" && "$SKIP_BACKUP" == false ]] && printf '%s %s\n' "$cfg" "$orig" >> "$inventory"
        chmod 600 "$cfg" 2>/dev/null && log_info "  locked: $cfg" || true
    done

    if [[ -d /etc/modprobe.d ]]; then
        cat > /etc/modprobe.d/99-hardening-usb.conf << 'EOF'
install usb-storage /bin/true
blacklist usb-storage
EOF
        log_info "  USB storage module blacklisted"
    fi

    log_success "Boot configuration hardened"
    count_fix
}

# =============================================================================
#  Modules 16-22
#
#  These shipped in v2.2.0 and were dropped by the lib/ refactor without
#  being reimplemented anywhere. Ported back from 7e40b93, adapted to the
#  lib conventions: log_dry for previews, backup_file before every write,
#  confirm/confirm_risky instead of hand-rolled read prompts, restart_service
#  instead of bare systemctl, count_fix on success, and explicit `return 0`
#  so nothing dies under `set -euo pipefail`.
# =============================================================================

# --- 16. GRUB password -------------------------------------------------------
# Genuinely interactive: it needs a password typed twice and cannot be
# meaningfully automated, so it skips in auto-mode rather than pretending.
apply_grub_password() {
    log_message "${LOCK} [16/22] GRUB Password ${RED}(HIGH RISK)${NC}"

    if ! is_linux; then
        log_warning "GRUB is Linux-specific — skipping on ${DISTRO_TYPE}"
        return 0
    fi
    if ! command -v grub-mkpasswd-pbkdf2 >/dev/null 2>&1; then
        log_warning "grub-mkpasswd-pbkdf2 not found — no GRUB on this system, skipping"
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would generate a GRUB PBKDF2 hash and add a superuser to /etc/grub.d/40_custom"
        return 0
    fi
    if [[ "$AUTO_MODE" == true ]]; then
        log_warning "GRUB password needs an interactive password entry — skipping in auto-mode"
        return 0
    fi
    confirm_risky "Set a GRUB bootloader password?" || { log_info "Skipped GRUB password"; return 0; }

    local pass1 pass2
    read -r -s -p "$(echo -e "  ${YELLOW}Password for the GRUB administrator:${NC} ")" pass1; echo
    read -r -s -p "$(echo -e "  ${YELLOW}Re-enter password:${NC} ")" pass2; echo
    if [[ "$pass1" != "$pass2" ]]; then
        log_error "Passwords do not match — skipping"
        return 0
    fi
    if [[ -z "$pass1" ]]; then
        log_error "Empty password — skipping"
        return 0
    fi

    local hash
    hash=$(printf '%s\n%s\n' "$pass1" "$pass2" | grub-mkpasswd-pbkdf2 2>/dev/null \
           | grep -oE 'grub\.pbkdf2\.sha512\.[^[:space:]]+' || true)
    if [[ -z "$hash" ]]; then
        log_error "Could not generate a GRUB password hash"
        return 0
    fi

    create_backup_dir
    backup_file /etc/grub.d/40_custom
    {
        echo 'set superusers="root"'
        echo "password_pbkdf2 root $hash"
    } >> /etc/grub.d/40_custom

    update-grub >>"$LOG_FILE" 2>&1 \
        || grub2-mkconfig -o /boot/grub2/grub.cfg >>"$LOG_FILE" 2>&1 \
        || log_warning "GRUB config regeneration failed — run update-grub manually"

    log_success "GRUB password set"
    count_fix
    return 0
}

# --- 17. Docker security -----------------------------------------------------
# Only meaningful when Docker is actually installed. The v2.2.0 version said
# it "would install docker if not present" in its dry-run text but then bailed
# on a real run if Docker was missing — a hardening tool should not be
# installing a container runtime, so the dry-run text is corrected here.
apply_docker_security() {
    log_message "${GEAR} [17/22] Docker Security"

    if ! command -v docker >/dev/null 2>&1; then
        log_warning "Docker is not installed — skipping Docker hardening"
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would write a hardened /etc/docker/daemon.json (userns-remap, icc off, log rotation, live-restore) and restart docker"
        return 0
    fi
    confirm "Apply Docker daemon hardening?" || { log_info "Skipped Docker security"; return 0; }

    create_backup_dir
    backup_file /etc/docker/daemon.json
    mkdir -p /etc/docker 2>/dev/null || true
    cat > /etc/docker/daemon.json << 'EOF'
{
  "userns-remap": "default",
  "icc": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true
}
EOF

    restart_service docker || log_warning "Could not restart docker — the new daemon.json applies on next restart"
    log_success "Docker daemon hardened"
    count_fix
    return 0
}

# --- 18. ModSecurity WAF -----------------------------------------------------
# Web-application firewall. Only relevant on a host actually serving web
# traffic, so it stays opt-in and reports N/A-style skips rather than
# installing Apache onto a machine that has none.
apply_modsecurity() {
    log_message "${SHIELD} [18/22] ModSecurity WAF"

    if ! is_linux; then
        log_warning "ModSecurity packaging here is Linux-specific — skipping on ${DISTRO_TYPE}"
        return 0
    fi
    if ! command -v apache2 >/dev/null 2>&1 && ! command -v httpd >/dev/null 2>&1; then
        log_warning "No Apache/httpd found — skipping ModSecurity (it hardens a web server, not the host)"
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would install ModSecurity plus the core rule set and restart the web server"
        return 0
    fi
    confirm "Install and enable ModSecurity for the local web server?" || { log_info "Skipped ModSecurity"; return 0; }

    case "$DISTRO_TYPE" in
        debian)
            install_package libapache2-mod-security2 || { log_warning "ModSecurity package unavailable — skipping"; return 0; }
            install_package modsecurity-crs || true
            a2enmod security2 >>"$LOG_FILE" 2>&1 || true
            restart_service apache2 || log_warning "Could not restart apache2"
            ;;
        rhel)
            install_package mod_security || { log_warning "ModSecurity package unavailable — skipping"; return 0; }
            install_package mod_security_crs || true
            restart_service httpd || log_warning "Could not restart httpd"
            ;;
        *)
            log_warning "No ModSecurity package mapping for ${DISTRO_TYPE} — skipping"
            return 0
            ;;
    esac

    log_success "ModSecurity installed and enabled"
    count_fix
    return 0
}

# --- 19. Disable unused protocols --------------------------------------------
# The CIS benchmarks ask for two kinds of kernel module to be unloadable: the
# uncommon network protocols (1.2.x) and the uncommon filesystems (1.1.1.x).
# Both are the same mechanism — a modprobe.d entry — so they are one module
# here rather than two, which is also what keeps the free tier at 22.
#
# `install X /bin/false` stops an on-demand autoload; `blacklist X` stops a
# load by name. CIS asks for both, and either alone leaves a way in.
UH_BLACKLIST_PROTOCOLS=(dccp sctp rds tipc)
# Deliberately NOT here: overlay (containers), vfat (EFI system partition),
# iso9660 (installer and rescue media). Blacklisting those breaks hosts.
UH_BLACKLIST_FILESYSTEMS=(cramfs freevxfs hfs hfsplus jffs2 squashfs udf)

# Is this kernel module actually in use right now? Mounted, or held by
# something with a non-zero reference count.
_kmod_in_use() {
    local m="$1"
    awk -v m="$m" '$3 == m { found = 1 } END { exit !found }' /proc/mounts 2>/dev/null && return 0
    local refs
    refs=$(awk -v m="$m" '$1 == m { print $3 }' /proc/modules 2>/dev/null)
    [[ -n "$refs" && "$refs" != "0" ]]
}

# squashfs is the one entry on the CIS list that routinely breaks a working
# system: every snap package is a squashfs image, so blacklisting it on a host
# with snapd means no snap starts after the next boot. CIS notes the exception;
# this detects it rather than leaving the operator to find out.
_squashfs_required() {
    command -v snap >/dev/null 2>&1 && return 0
    [[ -d /snap || -d /var/lib/snapd ]] && return 0
    awk '$3 == "squashfs" { found = 1 } END { exit !found }' /proc/mounts 2>/dev/null
}

apply_unused_protocols() {
    log_message "${GEAR} [19/22] Disable Unused Kernel Modules"

    if ! is_linux; then
        log_warning "modprobe blacklisting is Linux-specific — skipping on ${DISTRO_TYPE}"
        return 0
    fi

    # Decide what is actually going to be blacklisted before announcing it, so
    # a dry run reports the same set a real run would write.
    local -a fs_wanted=() fs_skipped=()
    local fs
    for fs in "${UH_BLACKLIST_FILESYSTEMS[@]}"; do
        if [[ "$fs" == "squashfs" ]] && _squashfs_required; then
            fs_skipped+=("squashfs")
            continue
        fi
        fs_wanted+=("$fs")
    done

    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would blacklist ${#UH_BLACKLIST_PROTOCOLS[@]} unused protocols (${UH_BLACKLIST_PROTOCOLS[*]})"
        log_dry "Would blacklist ${#fs_wanted[@]} uncommon filesystems (${fs_wanted[*]})"
        [[ ${#fs_skipped[@]} -gt 0 ]] && \
            log_dry "Would leave ${fs_skipped[*]} alone (snapd present — blacklisting it would break every snap)"
        return 0
    fi

    create_backup_dir
    # UH_MODPROBE_DIR exists only so tests/cases/test_kmod_blacklist.sh can run
    # against a fake root; unset it is /etc/modprobe.d, as always.
    local md="${UH_MODPROBE_DIR:-/etc/modprobe.d}"
    mkdir -p "$md" 2>/dev/null || true

    backup_file "$md/disable-unused-protocols.conf"
    {
        echo "# Written by Ultimate Hardening — unused network protocols (CIS 3.2.x/1.2.x)."
        for fs in "${UH_BLACKLIST_PROTOCOLS[@]}"; do
            echo "install $fs /bin/false"
            echo "blacklist $fs"
        done
    } > "$md/disable-unused-protocols.conf"

    backup_file "$md/disable-unused-filesystems.conf"
    {
        echo "# Written by Ultimate Hardening — uncommon filesystems (CIS 1.1.1.x)."
        if [[ ${#fs_skipped[@]} -gt 0 ]]; then
            echo "# Deliberately absent: ${fs_skipped[*]} — snapd on this host needs squashfs;"
            echo "# blacklisting it would stop every snap mounting after the next boot."
        fi
        for fs in "${fs_wanted[@]}"; do
            echo "install $fs /bin/false"
            echo "blacklist $fs"
        done
    } > "$md/disable-unused-filesystems.conf"

    # Blacklisting stops the NEXT autoload; it does not unload what is already
    # resident. Unload the ones nothing is using so the running kernel matches
    # the file, and say so plainly about the ones still in use.
    local -a still_loaded=()
    for fs in "${UH_BLACKLIST_PROTOCOLS[@]}" "${fs_wanted[@]}"; do
        grep -qE "^${fs}[[:space:]]" /proc/modules 2>/dev/null || continue
        if _kmod_in_use "$fs"; then
            still_loaded+=("$fs")
        elif ! modprobe -r "$fs" >>"$LOG_FILE" 2>&1; then
            still_loaded+=("$fs")
        fi
    done

    log_success "Kernel modules blacklisted: ${#UH_BLACKLIST_PROTOCOLS[@]} protocols (${UH_BLACKLIST_PROTOCOLS[*]}), ${#fs_wanted[@]} filesystems (${fs_wanted[*]})"
    if [[ ${#fs_skipped[@]} -gt 0 ]]; then
        log_warning "Left alone: ${fs_skipped[*]} — snapd uses squashfs, and blacklisting it would stop every snap from mounting after the next boot"
    fi
    if [[ ${#still_loaded[@]} -gt 0 ]]; then
        log_warning "Already loaded and still in use: ${still_loaded[*]} — blacklisted for the next boot, but they stay loaded until whatever uses them is stopped"
    fi
    count_fix
    return 0
}

# --- 20. Compiler access restriction -----------------------------------------
# chmod 700 on installed compilers so an unprivileged foothold cannot build
# tooling in place. Records what it changed so --revert can put it back.
apply_compiler_restriction() {
    log_message "${GEAR} [20/22] Compiler Access Restriction"

    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would restrict gcc/g++/clang/clang++/cc/c++ to root only (chmod 700)"
        return 0
    fi
    confirm "Restrict compiler access to root only?" || { log_info "Skipped compiler restriction"; return 0; }

    create_backup_dir
    local inventory="$BACKUP_DIR/compiler_original_perms.txt"
    local restricted=0 path
    for compiler in gcc g++ clang clang++ cc c++; do
        path=$(command -v "$compiler" 2>/dev/null) || continue
        [[ -n "$path" ]] || continue
        if [[ "$SKIP_BACKUP" == false ]]; then
            printf '%s %s\n' "$path" "$(stat -c '%a' "$path" 2>/dev/null)" >> "$inventory"
        fi
        chmod 700 "$path" 2>/dev/null && { log_info "  restricted: $path"; bump restricted; } || true
    done

    if [[ "$restricted" -eq 0 ]]; then
        log_info "No compilers found to restrict"
        return 0
    fi
    log_success "Restricted $restricted compiler(s) to root"
    count_fix
    return 0
}

# --- 21. Remote syslog -------------------------------------------------------
# Needs a destination host, so like the GRUB password it skips in auto-mode
# rather than inventing one. UH_SYSLOG_SERVER lets a config file or CI supply
# it non-interactively.
# A remote-syslog destination is appended verbatim to /etc/rsyslog.conf as
# `*.* @host:514`, and it arrives from an environment variable, a terminal
# prompt, or (in the paid tiers) a config file. rsyslog's config language can
# run programs, so an unvalidated string — a newline followed by a directive —
# is arbitrary root code at the next rsyslog restart. A destination is a
# hostname or an IP address; nothing else is accepted.
#
# Split out of the module so it can be tested without the module's side
# effects: exercising it through apply_remote_syslog meant a real
# create_backup_dir and a real edit to /etc/rsyslog.conf, which then broke the
# NEXT test case. That is the test-pollution trap this project has hit three
# times; a pure predicate cannot cause it.
valid_syslog_destination() {
    [[ "${1:-}" =~ ^[A-Za-z0-9]([A-Za-z0-9._:-]*[A-Za-z0-9])?$ ]]
}

# udp | tcp | tls. Everything else is a typo, and a typo must not silently
# become plaintext UDP.
valid_syslog_protocol() {
    case "${1:-}" in udp|tcp|tls) return 0 ;; *) return 1 ;; esac
}

_syslog_default_port() {
    case "$1" in tls) echo 6514 ;; *) echo 514 ;; esac
}

# rsyslog needs a separate package for the GnuTLS network driver, and without
# it a TLS config loads but every forward fails. Package name differs per
# distro; a miss is reported, never assumed away.
_syslog_install_tls_driver() {
    [[ -n "$(find /usr/lib /usr/lib64 /lib -name 'lmnsd_gtls.so' -print -quit 2>/dev/null)" ]] && return 0
    local pkg
    case "${DISTRO_TYPE:-}" in
        debian|rhel) pkg="rsyslog-gnutls" ;;
        suse)        pkg="rsyslog-module-gtls" ;;
        alpine)      pkg="rsyslog-tls" ;;
        *)           pkg="rsyslog-gnutls" ;;
    esac
    install_package "$pkg" >/dev/null 2>&1 || true
    [[ -n "$(find /usr/lib /usr/lib64 /lib -name 'lmnsd_gtls.so' -print -quit 2>/dev/null)" ]]
}

apply_remote_syslog() {
    log_message "${NET_ICON} [21/22] Remote Syslog"

    local server="${UH_SYSLOG_SERVER:-}"
    local proto="${UH_SYSLOG_PROTO:-udp}"
    local ca="${UH_SYSLOG_TLS_CA:-}"
    # A CA on its own means TLS was intended; honour that rather than quietly
    # forwarding in clear text.
    [[ -n "$ca" && "$proto" == "udp" ]] && proto="tls"
    local port="${UH_SYSLOG_PORT:-$(_syslog_default_port "$proto")}"

    if ! valid_syslog_protocol "$proto"; then
        log_error "Refusing syslog protocol '${proto}' — expected udp, tcp or tls"
        return 0
    fi
    if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        log_error "Refusing syslog port '${port}' — expected 1-65535"
        return 0
    fi

    if [[ "$DRY_RUN" == true ]]; then
        if [[ "$proto" == tls ]]; then
            log_dry "Would forward all syslog facilities over TLS to ${server:-<server>}:${port}, verifying the collector against ${ca:-<CA file>}"
        else
            log_dry "Would forward all syslog facilities to ${server:-<server>}:${port} over ${proto}"
        fi
        return 0
    fi

    if [[ -z "$server" ]]; then
        if [[ "$AUTO_MODE" == true ]]; then
            log_warning "Remote syslog needs a destination — set UH_SYSLOG_SERVER to use it in auto-mode; skipping"
            return 0
        fi
        confirm "Configure remote syslog forwarding?" || { log_info "Skipped remote syslog"; return 0; }
        read -r -p "$(echo -e "  ${YELLOW}Remote syslog server (host or IP):${NC} ")" server
    fi
    if [[ -z "$server" ]]; then
        log_info "No server given — skipping remote syslog"
        return 0
    fi

    if ! valid_syslog_destination "$server"; then
        log_error "Refusing remote syslog destination '${server}' — not a hostname or IP address"
        log_warning "A destination goes into rsyslog.conf verbatim; only [A-Za-z0-9 . : _ -] are accepted."
        return 0
    fi

    # Both exist only for tests/cases/test_syslog_tls.sh; unset, they are the
    # real paths.
    local rsconf="${UH_RSYSLOG_CONF:-/etc/rsyslog.conf}"
    local ca_dir="${UH_SYSLOG_CA_DIR:-/etc/ultimate-hardening}"
    if [[ ! -f "$rsconf" ]]; then
        log_warning "$rsconf not found — rsyslog is not installed, skipping"
        return 0
    fi

    # TLS has prerequisites, and half a TLS setup forwards nothing at all. If
    # either the CA or the driver is missing, say so and change nothing —
    # falling back to plaintext would be the opposite of what was asked for.
    if [[ "$proto" == tls ]]; then
        if [[ -z "$ca" ]]; then
            log_error "TLS forwarding needs the collector's CA certificate — set UH_SYSLOG_TLS_CA; nothing changed"
            return 0
        fi
        if [[ ! -f "$ca" ]]; then
            log_error "CA certificate not found: ${ca} — nothing changed"
            return 0
        fi
        if ! _syslog_install_tls_driver; then
            log_error "rsyslog's GnuTLS driver (lmnsd_gtls) is not available and could not be installed — nothing changed, because a TLS config without it forwards nothing"
            return 0
        fi
        # The CA is read by rsyslog at startup; keep our own copy so a cert in
        # /tmp or a home directory cannot vanish and silently break forwarding.
        mkdir -p "$ca_dir" 2>/dev/null || true
        if [[ "$ca" != "$ca_dir/syslog-ca.pem" ]]; then
            if cp -- "$ca" "$ca_dir/syslog-ca.pem" 2>/dev/null; then
                chmod 644 "$ca_dir/syslog-ca.pem" 2>/dev/null || true
                ca="$ca_dir/syslog-ca.pem"
            else
                log_warning "Could not copy the CA to ${ca_dir} — using ${ca} in place"
            fi
        fi
    fi

    create_backup_dir
    backup_file "$rsconf"

    # Idempotent, and tolerant of what earlier versions wrote. The original
    # single-line form had no end marker, so a multi-line block could not be
    # replaced by the same `+1d` rule; both forms are removed here.
    sed -i '/# ultimate-hardening: remote syslog BEGIN/,/# ultimate-hardening: remote syslog END/d' "$rsconf" 2>/dev/null || true
    sed -i '/# ultimate-hardening: remote syslog$/,+1d' "$rsconf" 2>/dev/null || true

    {
        echo "# ultimate-hardening: remote syslog BEGIN"
        if [[ "$proto" == tls ]]; then
            echo "global(DefaultNetstreamDriver=\"gtls\")"
            echo "global(DefaultNetstreamDriverCAFile=\"${ca}\")"
            # x509/name: the collector must present a certificate signed by
            # that CA *and* matching the name we dialled. x509/certvalid would
            # accept any host the CA ever signed.
            echo "action(type=\"omfwd\" target=\"${server}\" port=\"${port}\" protocol=\"tcp\""
            echo "       StreamDriver=\"gtls\" StreamDriverMode=\"1\" StreamDriverAuthMode=\"x509/name\""
            echo "       StreamDriverPermittedPeers=\"${server}\""
            # A disk-assisted queue is what stops a collector outage becoming
            # lost audit evidence; UDP forwarding had nowhere to buffer.
            echo "       queue.type=\"LinkedList\" queue.filename=\"uh_fwd\" queue.maxdiskspace=\"256m\""
            echo "       queue.saveOnShutdown=\"on\" action.resumeRetryCount=\"-1\")"
        elif [[ "$proto" == tcp ]]; then
            echo "action(type=\"omfwd\" target=\"${server}\" port=\"${port}\" protocol=\"tcp\""
            echo "       queue.type=\"LinkedList\" queue.filename=\"uh_fwd\" queue.maxdiskspace=\"256m\""
            echo "       queue.saveOnShutdown=\"on\" action.resumeRetryCount=\"-1\")"
        else
            echo "*.* @${server}:${port}"
        fi
        echo "# ultimate-hardening: remote syslog END"
    } >> "$rsconf"

    # A bad directive makes rsyslog refuse to start, which takes local logging
    # down with it. Validate first and roll back rather than restart blind.
    if command -v rsyslogd >/dev/null 2>&1; then
        if ! rsyslogd -N1 >>"$LOG_FILE" 2>&1; then
            log_error "rsyslog rejected the new configuration — restoring the previous one, nothing forwarded"
            restore_file "$rsconf" || log_error "Restore failed. Check $rsconf by hand."
            return 0
        fi
    fi

    restart_service rsyslog || log_warning "Could not restart rsyslog — the change applies on next restart"
    case "$proto" in
        tls) log_success "Remote syslog forwarding to ${server}:${port} over TLS (collector verified against $(basename "$ca"), queued to disk if it is unreachable)" ;;
        tcp) log_success "Remote syslog forwarding to ${server}:${port} over TCP (queued to disk if it is unreachable)" ;;
        udp) log_success "Remote syslog forwarding configured to ${server}:${port} over UDP"
             log_warning "UDP syslog is unauthenticated, unencrypted and silently lossy — set UH_SYSLOG_PROTO=tls with UH_SYSLOG_TLS_CA for an auditable channel" ;;
    esac
    count_fix
    return 0
}

# --- 22. UMASK hardening -----------------------------------------------------
apply_umask_hardening() {
    log_message "${LOCK} [22/22] UMASK Hardening"

    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would set a restrictive default umask of 027 in login.defs, profile.d and bash.bashrc"
        return 0
    fi

    create_backup_dir

    if [[ -f /etc/login.defs ]]; then
        backup_file /etc/login.defs
        if grep -qE '^[[:space:]]*UMASK' /etc/login.defs 2>/dev/null; then
            sed -i 's/^[[:space:]]*UMASK.*/UMASK           027/' /etc/login.defs
        else
            echo "UMASK           027" >> /etc/login.defs
        fi
    fi

    if [[ -d /etc/profile.d ]]; then
        backup_file /etc/profile.d/hardening-umask.sh
        cat > /etc/profile.d/hardening-umask.sh << 'EOF'
# Restrictive default umask (ultimate-hardening)
umask 027
EOF
        chmod 644 /etc/profile.d/hardening-umask.sh 2>/dev/null || true
    fi

    if [[ -f /etc/bash.bashrc ]]; then
        backup_file /etc/bash.bashrc
        grep -qE '^umask 027' /etc/bash.bashrc 2>/dev/null || echo "umask 027" >> /etc/bash.bashrc
    fi

    log_success "UMASK hardening applied (027 — owner rwx, group rx, others none)"
    count_fix
    return 0
}

# --- module runner -----------------------------------------------------------
# One module returning non-zero must not truncate the run.
#
# Before this wrapper the aggregates below called each module bare, one per
# line, under the `set -euo pipefail` the tier scripts set. A single non-zero
# return therefore killed the script mid-sequence and every module after it was
# silently skipped -- no error, no summary, just a run that stopped. That is
# exactly what apply_firewall did on Rocky 9: it aborted at [3/22], modules
# 4-22 never ran, and the host was left hardened through SSH and untouched from
# the firewall onward with nothing in the output saying so.
#
# Failures are recorded and the run continues to the end, then reports what
# failed. Each module's own contract (top of this file) still stands: degrade
# and return 0 on a benign failure rather than leaning on this net.
#
# Trade-off worth knowing: calling the module as the left side of `||` disables
# errexit inside that call, so a failing command partway through a module no
# longer stops that module either -- it runs on to its next line. That is the
# price of not stopping the other 21, and it is why the set -e contract above
# is a contract rather than a convenience.
UH_MODULE_FAILED=()

run_module() {
    local key="$1" fn="$2" rc=0

    # MOD_LABEL lives in lib/menu.sh so the name printed here and the name in
    # the menu table cannot drift. menu.sh is not required to be sourced
    # (test_lib_loading sources less than a tier does), hence the fallback.
    local label="$key"
    if declare -p MOD_LABEL >/dev/null 2>&1; then
        label="${MOD_LABEL[$key]:-$key}"
    fi

    "$fn" || rc=$?
    if [[ $rc -eq 0 ]]; then
        return 0
    fi

    UH_MODULE_FAILED+=("$label")
    log_warning "Module '$label' failed (exit $rc) - continuing with the remaining modules"
    return 0
}

# Close out an aggregate run by saying plainly what did and did not complete.
# A run that stops early used to look identical to a run that finished.
report_module_results() {
    local scope="$1"
    local n=${#UH_MODULE_FAILED[@]}

    if [[ $n -eq 0 ]]; then
        log_success "$scope - $FIXES_APPLIED fixes applied, all modules completed"
        return 0
    fi

    log_warning "$scope - $FIXES_APPLIED fixes applied, $n module(s) did not complete: ${UH_MODULE_FAILED[*]}"
    log_warning "Run those modules individually from the menu to see the failure in full."
    return 0
}


# --- Aggregate ---------------------------------------------------------------
# Every module, including the High-risk one (module 9, SUID/SGID hardening).
apply_all_modules() {
    log_message "${ROCKET} Applying all 22 hardening modules (including High risk)"
    create_backup_dir
    UH_MODULE_FAILED=()

    # Resolve every module's packages before the first module changes anything,
    # so an unobtainable dependency is reported up front rather than discovered
    # partway through a half-hardened system.
    preflight_dependencies

    run_module updates   apply_system_updates
    run_module ssh       apply_ssh_hardening
    run_module firewall  apply_firewall
    run_module fail2ban  apply_fail2ban
    run_module perms     apply_permission_hardening
    run_module kernel    apply_kernel_hardening
    run_module audit     apply_audit_config
    run_module password  apply_password_policies
    run_module suid      apply_suid_hardening
    run_module aide      apply_aide
    run_module rkhunter  apply_rkhunter
    run_module services  apply_disable_services
    run_module apparmor  apply_apparmor
    run_module etckeeper apply_etckeeper
    run_module boot      apply_boot_secure
    run_module grubpw    apply_grub_password
    run_module docker    apply_docker_security
    run_module modsec    apply_modsecurity
    run_module protocols apply_unused_protocols
    run_module compiler  apply_compiler_restriction
    run_module syslog    apply_remote_syslog
    run_module umask     apply_umask_hardening

    report_module_results "All 22 modules processed"
}

# Safe + Medium risk only — skips module 9 (SUID/SGID hardening), the one
# High-risk module, for anyone who wants the rest applied without that
# module's binaries potentially breaking third-party setuid tooling. Run
# module 9 on its own (menu option 9) once you've reviewed what it strips.
#
# NOTE: this function used to be named apply_all_safe() but actually called
# apply_suid_hardening along with everything else — "safe" described none
# of what it did. apply_all_modules() above is the old behavior under an
# honest name; this is what apply_all_safe() should always have been.
apply_safe_modules() {
    log_message "${ROCKET} Applying Safe/Medium modules (skipping the High-risk SUID/SGID and GRUB password modules)"
    create_backup_dir
    UH_MODULE_FAILED=()

    # Resolve every module's packages before the first module changes anything,
    # so an unobtainable dependency is reported up front rather than discovered
    # partway through a half-hardened system.
    preflight_dependencies

    run_module updates   apply_system_updates
    run_module ssh       apply_ssh_hardening
    run_module firewall  apply_firewall
    run_module fail2ban  apply_fail2ban
    run_module perms     apply_permission_hardening
    run_module kernel    apply_kernel_hardening
    run_module audit     apply_audit_config
    run_module password  apply_password_policies
    run_module aide      apply_aide
    run_module rkhunter  apply_rkhunter
    run_module services  apply_disable_services
    run_module apparmor  apply_apparmor
    run_module etckeeper apply_etckeeper
    run_module boot      apply_boot_secure
    run_module docker    apply_docker_security
    run_module modsec    apply_modsecurity
    run_module protocols apply_unused_protocols
    run_module compiler  apply_compiler_restriction
    run_module syslog    apply_remote_syslog
    run_module umask     apply_umask_hardening

    report_module_results "Safe/Medium modules processed (High-risk 9 and 16 skipped, run them separately)"
}
