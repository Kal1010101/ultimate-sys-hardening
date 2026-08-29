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
    update_packages
    log_success "System packages updated"
    # The menu caches the pending-upgrade count; this run just changed it.
    declare -F invalidate_pending_updates_cache >/dev/null && invalidate_pending_updates_cache
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

    # Validate before restarting — a bad config must never lock the operator out.
    if sshd -t 2>/dev/null; then
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
apply_firewall() {
    log_message "${FIRE} [3/22] Firewall"
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would configure firewall: default-deny inbound, allow SSH/80/443"
        return 0
    fi

    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset          >>"$LOG_FILE" 2>&1 || true
        ufw default deny incoming  >>"$LOG_FILE" 2>&1 || true
        ufw default allow outgoing >>"$LOG_FILE" 2>&1 || true
        ufw allow ssh              >>"$LOG_FILE" 2>&1 || true
        ufw allow 80/tcp           >>"$LOG_FILE" 2>&1 || true
        ufw allow 443/tcp          >>"$LOG_FILE" 2>&1 || true
        ufw --force enable         >>"$LOG_FILE" 2>&1 || true
        log_success "UFW: deny inbound, allow outbound, SSH/80/443 open"
    elif command -v nft >/dev/null 2>&1; then
        nft flush ruleset 2>/dev/null || true
        nft add table ip filter 2>/dev/null || true
        nft add chain ip filter INPUT  '{ type filter hook input  priority 0; policy drop; }'   2>/dev/null || true
        nft add chain ip filter OUTPUT '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true
        nft add rule  ip filter INPUT ct state established,related accept 2>/dev/null || true
        nft add rule  ip filter INPUT iif lo accept                       2>/dev/null || true
        nft add rule  ip filter INPUT tcp dport '{ 22, 80, 443 }' accept  2>/dev/null || true
        log_success "nftables: default-drop inbound, SSH/80/443 accepted"
    elif command -v pfctl >/dev/null 2>&1; then
        log_warning "BSD pf detected — configure /etc/pf.conf manually (not automated)"
        return 0
    else
        log_warning "No firewall found — installing ufw"
        install_package ufw || { log_error "Could not install a firewall"; return 1; }
        ufw --force enable >>"$LOG_FILE" 2>&1 || true
        ufw allow ssh      >>"$LOG_FILE" 2>&1 || true
        log_success "UFW installed and enabled"
    fi
    count_fix
}

# --- 4. Fail2Ban -------------------------------------------------------------
apply_fail2ban() {
    log_message "${SHIELD} [4/22] Fail2Ban"
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would install fail2ban with an SSH jail (3 tries, 2h ban)"
        return 0
    fi

    install_package fail2ban || { log_warning "fail2ban unavailable — skipping"; return 0; }

    backup_file /etc/fail2ban/jail.local
    mkdir -p /etc/fail2ban 2>/dev/null || true
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled  = true
port     = ssh
maxretry = 3
bantime  = 7200
EOF

    enable_service fail2ban
    log_success "Fail2Ban active: SSH jail bans for 2h after 3 failures"
    count_fix
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
    for entry in "${targets[@]}"; do
        local file="${entry%:*}" mode="${entry##*:}"
        [[ -f "$file" ]] || continue
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
        log_dry "Would write 25 sysctl parameters to /etc/sysctl.d/99-hardening.conf"
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
    log_success "Auditd configured with 18 audit rules"
    count_fix
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
    [[ -f /var/lib/aide/aide.db.new ]] && \
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true

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

    local disabled=0
    for svc in "${services[@]}"; do
        if is_service_active "$svc"; then
            stop_service "$svc"
            log_info "  disabled: $svc"
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
        log_success "AppArmor enabled, profiles set to enforce"
    elif command -v sestatus >/dev/null 2>&1; then
        backup_file /etc/selinux/config
        set_config "SELINUX" "enforcing" /etc/selinux/config "="
        log_success "SELinux set to enforcing (takes effect after reboot)"
    else
        log_warning "No MAC framework present — install apparmor or selinux manually"
        return 0
    fi
    count_fix
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

    for cfg in /boot/grub/grub.cfg /boot/grub2/grub.cfg /boot/efi/EFI/*/grub.cfg; do
        [[ -f "$cfg" ]] || continue
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
apply_unused_protocols() {
    log_message "${GEAR} [19/22] Disable Unused Network Protocols"

    if ! is_linux; then
        log_warning "modprobe blacklisting is Linux-specific — skipping on ${DISTRO_TYPE}"
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would blacklist the DCCP, SCTP, RDS and TIPC kernel modules"
        return 0
    fi

    create_backup_dir
    backup_file /etc/modprobe.d/disable-unused-protocols.conf
    mkdir -p /etc/modprobe.d 2>/dev/null || true
    cat > /etc/modprobe.d/disable-unused-protocols.conf << 'EOF'
install dccp /bin/false
install sctp /bin/false
install rds  /bin/false
install tipc /bin/false
EOF

    log_success "Unused network protocols blacklisted (DCCP, SCTP, RDS, TIPC)"
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
apply_remote_syslog() {
    log_message "${NET_ICON} [21/22] Remote Syslog"

    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would forward all syslog facilities to a remote collector on port 514"
        return 0
    fi

    local server="${UH_SYSLOG_SERVER:-}"
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
    if [[ ! -f /etc/rsyslog.conf ]]; then
        log_warning "/etc/rsyslog.conf not found — rsyslog is not installed, skipping"
        return 0
    fi

    create_backup_dir
    backup_file /etc/rsyslog.conf
    # Idempotent: replace any forwarding line this module added before rather
    # than appending a second one on every run.
    sed -i '/# ultimate-hardening: remote syslog/,+1d' /etc/rsyslog.conf 2>/dev/null || true
    {
        echo "# ultimate-hardening: remote syslog"
        echo "*.* @${server}:514"
    } >> /etc/rsyslog.conf

    restart_service rsyslog || log_warning "Could not restart rsyslog — the change applies on next restart"
    log_success "Remote syslog forwarding configured to ${server}:514"
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

# --- Aggregate ---------------------------------------------------------------
# Every module, including the High-risk one (module 9, SUID/SGID hardening).
apply_all_modules() {
    log_message "${ROCKET} Applying all 22 hardening modules (including High risk)"
    create_backup_dir

    apply_system_updates
    apply_ssh_hardening
    apply_firewall
    apply_fail2ban
    apply_permission_hardening
    apply_kernel_hardening
    apply_audit_config
    apply_password_policies
    apply_suid_hardening
    apply_aide
    apply_rkhunter
    apply_disable_services
    apply_apparmor
    apply_etckeeper
    apply_boot_secure
    apply_grub_password
    apply_docker_security
    apply_modsecurity
    apply_unused_protocols
    apply_compiler_restriction
    apply_remote_syslog
    apply_umask_hardening

    log_success "All modules processed — $FIXES_APPLIED applied"
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

    apply_system_updates
    apply_ssh_hardening
    apply_firewall
    apply_fail2ban
    apply_permission_hardening
    apply_kernel_hardening
    apply_audit_config
    apply_password_policies
    apply_aide
    apply_rkhunter
    apply_disable_services
    apply_apparmor
    apply_etckeeper
    apply_boot_secure
    apply_docker_security
    apply_modsecurity
    apply_unused_protocols
    apply_compiler_restriction
    apply_remote_syslog
    apply_umask_hardening

    log_success "Safe/Medium modules processed — $FIXES_APPLIED applied (High-risk modules 9 and 16 skipped, run them separately)"
}
