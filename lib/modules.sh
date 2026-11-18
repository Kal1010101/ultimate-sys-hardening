#!/bin/bash
# =============================================================================
#  lib/modules.sh — the 23 core hardening modules
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
    log_message "${GEAR} [1/23] System Updates"

    local kernels_before="" had_modules=false
    if kernel_update_pending; then
        log_warning "A kernel update is pending. Installing it removes the running kernel's modules, so the firewall and Fail2Ban may not load until you reboot"
    fi
    if [[ "$DRY_RUN" != true ]]; then
        kernels_before=$(installed_kernel_versions)
        running_kernel_has_modules && had_modules=true
    fi

    update_packages
    # update_packages printed its "Would upgrade" line; nothing was upgraded,
    # so report no success and count no fix.
    [[ "$DRY_RUN" == true ]] && return 0
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
    if [[ "$had_modules" == true ]] && ! running_kernel_has_modules; then
        UH_REBOOT_REQUIRED=true
        log_warning "The upgrade removed the running kernel's modules — the firewall and Fail2Ban cannot load new kernel modules until you reboot"
    fi

    log_success "System packages updated"
    count_fix
}

# --- 2. SSH hardening --------------------------------------------------------
# The pre-login banner module 2 writes to /etc/issue.net. One copy, so revert
# can tell its own output from an admin's banner (see tool_written_content).
_ssh_issue_net_banner() {
    echo "Authorized access only. All activity is monitored and logged."
}

# Lockout guard. Turning off password login and root login on a host where no
# other account can log in with a key locks the operator out: the usual state
# of a fresh cloud VPS reached as root with a password. Module 2 writes those
# two settings only when a way in by key survives them.
UH_SSH_DEFAULT_KEY_FILES=".ssh/authorized_keys .ssh/authorized_keys2"

# Prints sshd's effective settings (sshd -T), or nothing when sshd cannot
# report them. Like sshd_config_valid, it uses a throwaway host key where sshd
# has never started and so has none.
_sshd_effective_settings() {
    command -v sshd >/dev/null 2>&1 || return 0
    if compgen -G '/etc/ssh/ssh_host_*_key' >/dev/null; then
        sshd -T 2>/dev/null || true
        return 0
    fi
    local keydir
    keydir=$(mktemp -d) || return 0
    ssh-keygen -q -t ed25519 -N '' -f "$keydir/k" >/dev/null 2>&1 \
        && sshd -T -h "$keydir/k" 2>/dev/null
    rm -rf "$keydir"
    return 0
}

# $1 = sshd -T output, $2 = lower-case keyword. Prints the keyword's value.
# OpenSSH 10.4 and later print keywords in mixed case, hence tolower.
_sshd_setting() {
    awk -v key="$2" 'tolower($1) == key { $1 = ""; sub(/^ /, ""); print; exit }' <<< "$1"
}

# $1 = file. True when it holds a public key line, not only comments. Option
# and cert-authority prefixes before the key type are allowed.
_file_has_ssh_key() {
    [[ -r "$1" ]] && grep -qE '^[^#]*(ssh-|ecdsa-|sk-)[^[:space:]]+[[:space:]]+AAAA' "$1"
}

# Can an account other than root still log in once password and root login
# are off? A TrustedUserCAKeys CA counts as yes: an admin sets one up only to
# log in with certificates. An AuthorizedKeysCommand does not count, because
# it says nothing about whether it serves anyone a key: stock Arch sets
# userdbctl as one on every host, keys or not. Hosts whose keys come from such
# a command set UH_SSH_LOCKOUT_CHECK=false.
ssh_key_login_possible() {
    local settings user_ca key_file_setting
    settings=$(_sshd_effective_settings)
    user_ca=$(_sshd_setting "$settings" trustedusercakeys)
    [[ -n "$user_ca" && "$user_ca" != none ]] && return 0
    key_file_setting=$(_sshd_setting "$settings" authorizedkeysfile)

    local -a key_file_patterns
    read -ra key_file_patterns <<< "${key_file_setting:-$UH_SSH_DEFAULT_KEY_FILES}"

    local user uid home shell pattern path
    while IFS=: read -r user _ uid _ _ home shell; do
        [[ "$uid" == 0 ]] && continue
        case "$shell" in */nologin|*/false) continue ;; esac
        for pattern in "${key_file_patterns[@]}"; do
            [[ "$pattern" == none ]] && continue
            path=${pattern//%h/$home}; path=${path//%u/$user}; path=${path//%U/$uid}
            [[ "$path" == /* ]] || path="$home/$path"
            _file_has_ssh_key "$path" && return 0
        done
    done < <(getent passwd 2>/dev/null || cat /etc/passwd)
    return 1
}

# True when module 2 may turn off password login and root login.
# UH_SSH_LOCKOUT_CHECK=false skips the check, for hosts where sshd finds keys in a
# way this cannot see (an AuthorizedKeysCommand, a per-user Match block).
ssh_login_lockdown_safe() {
    local check="${UH_SSH_LOCKOUT_CHECK:-true}"
    if [[ "$check" != true && "$check" != false ]]; then
        log_warning "UH_SSH_LOCKOUT_CHECK='$check' is not true/false — keeping the SSH key check"
        check=true
    fi
    [[ "$check" == false ]] && return 0
    ssh_key_login_possible
}

# Crypto allowlists, best first. Only names this host's OpenSSH build knows
# are written (see _ssh_supported_list), so an old release is never handed a
# name sshd -t would reject: the post-quantum kex (mlkem768x25519 from 9.9,
# sntrup761x25519 from 8.5) appears only where the build has it.
# Ciphers: CIS Ubuntu 22.04 5.1.6, CIS RHEL 9 5.1.4, STIG RHEL-09-255064/65.
# KexAlgorithms: CIS Ubuntu 22.04 5.1.12, CIS RHEL 9 5.1.5.
# MACs: CIS Ubuntu 22.04 5.1.15, CIS RHEL 9 5.1.6, STIG RHEL-09-255070/75.
# HostKeyAlgorithms has no CIS or STIG control; it is here because weak host
# key signatures (ssh-rsa SHA-1, DSA) are the same class of risk.
UH_SSH_CIPHERS=(chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com
                aes256-ctr aes192-ctr aes128-ctr)
UH_SSH_KEX=(mlkem768x25519-sha256 sntrup761x25519-sha512 sntrup761x25519-sha512@openssh.com
            curve25519-sha256 curve25519-sha256@libssh.org
            diffie-hellman-group16-sha512 diffie-hellman-group18-sha512)
UH_SSH_MACS=(hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com)
UH_SSH_HOSTKEY_ALGS=(ssh-ed25519 ssh-ed25519-cert-v01@openssh.com
                     rsa-sha2-512 rsa-sha2-512-cert-v01@openssh.com
                     rsa-sha2-256 rsa-sha2-256-cert-v01@openssh.com
                     ecdsa-sha2-nistp256 ecdsa-sha2-nistp256-cert-v01@openssh.com
                     ecdsa-sha2-nistp384 ecdsa-sha2-nistp384-cert-v01@openssh.com
                     ecdsa-sha2-nistp521 ecdsa-sha2-nistp521-cert-v01@openssh.com)
# RHEL, Fedora and their rebuilds set sshd's algorithms system-wide through
# crypto-policies; Red Hat asks admins to change the policy, not override it
# per daemon, so the allowlist is left out there.
UH_SSH_CRYPTO_POLICY_FILE=/etc/crypto-policies/back-ends/opensshserver.config

# $1 = ssh -Q query (cipher, kex, mac, key), then the allowlist. Prints the
# entries this OpenSSH build supports, comma-separated, in allowlist order.
_ssh_supported_list() {
    local query="$1" supported alg out=""
    shift
    supported=$(ssh -Q "$query" 2>/dev/null) || return 0
    for alg in "$@"; do
        grep -qxF -- "$alg" <<< "$supported" && out+="${out:+,}$alg"
    done
    printf '%s' "$out"
}

# "Keyword value" lines for the crypto allowlist, one per keyword this build
# supports at least one allowlisted algorithm for. Empty where the client
# that answers ssh -Q is missing or crypto-policies owns the setting.
_ssh_crypto_settings() {
    command -v ssh >/dev/null 2>&1 || return 0
    [[ -f "$UH_SSH_CRYPTO_POLICY_FILE" ]] && return 0
    local list
    list=$(_ssh_supported_list cipher "${UH_SSH_CIPHERS[@]}");        [[ -n "$list" ]] && echo "Ciphers $list"
    list=$(_ssh_supported_list kex "${UH_SSH_KEX[@]}");               [[ -n "$list" ]] && echo "KexAlgorithms $list"
    list=$(_ssh_supported_list mac "${UH_SSH_MACS[@]}");              [[ -n "$list" ]] && echo "MACs $list"
    list=$(_ssh_supported_list key "${UH_SSH_HOSTKEY_ALGS[@]}");      [[ -n "$list" ]] && echo "HostKeyAlgorithms $list"
    return 0
}

_ssh_crypto_policy_note() {
    [[ -f "$UH_SSH_CRYPTO_POLICY_FILE" ]] || return 0
    log_info "  SSH ciphers, kex, MACs and host key algorithms are left to the system crypto policy ($(update-crypto-policies --show 2>/dev/null || echo 'see update-crypto-policies')); change it there with update-crypto-policies"
}

_ssh_no_key_warning() {
    log_warning "SSH: no account other than root has a key sshd accepts — password login and root login are left as they are, so this run cannot lock you out"
    log_warning "  Add a key for a sudo user (ssh-copy-id user@host), check you can log in with it, then run module 2 again. If your keys come from an AuthorizedKeysCommand (LDAP, SSSD), UH_SSH_LOCKOUT_CHECK=false skips this check."
}

apply_ssh_hardening() {
    log_message "${LOCK} [2/23] SSH Hardening"
    local cfg="/etc/ssh/sshd_config"
    local dropin="/etc/ssh/sshd_config.d/00-ultimate-hardening.conf"

    if [[ ! -f "$cfg" ]]; then
        log_warning "sshd_config not found — SSH not installed, skipping"
        return 0
    fi

    local lockdown=true setting_count=13
    if ! ssh_login_lockdown_safe; then
        lockdown=false
        setting_count=11
    fi
    local crypto_settings crypto_keywords
    crypto_settings=$(_ssh_crypto_settings)
    crypto_keywords=$(awk '{print $1}' <<< "$crypto_settings")
    setting_count=$((setting_count + $(grep -c . <<< "$crypto_settings" || true)))

    if [[ "$DRY_RUN" == true ]]; then
        # The keywords set below, for the preview's count only.
        local keyword skipped=""
        # shellcheck disable=SC2086  # crypto_keywords is a word list on purpose
        for keyword in PermitRootLogin PasswordAuthentication ChallengeResponseAuthentication \
                       X11Forwarding AllowTcpForwarding PermitEmptyPasswords MaxAuthTries \
                       LoginGraceTime ClientAliveInterval ClientAliveCountMax UsePAM PrintLastLog Banner \
                       $crypto_keywords; do
            [[ "$lockdown" == false && ( "$keyword" == PermitRootLogin || "$keyword" == PasswordAuthentication ) ]] && continue
            setting_skipped "$keyword" && { skipped+="$keyword "; setting_count=$((setting_count - 1)); }
        done
        log_dry "Would apply $setting_count hardened settings to $cfg"
        [[ -n "$crypto_keywords" ]] && log_dry "  including an allowlist for: $(tr '\n' ' ' <<< "$crypto_keywords")"
        _ssh_crypto_policy_note
        [[ -n "$skipped" ]] && log_info "  Left as they are (UH_SKIP_SETTINGS): ${skipped% }"
        [[ "$lockdown" == true ]] || _ssh_no_key_warning
        return 0
    fi

    local was_running=false
    { is_service_active sshd || is_service_active ssh; } && was_running=true

    backup_file "$cfg"

    UH_SETTINGS_SKIPPED_COUNT=0
    if [[ "$lockdown" == true ]]; then
        set_config "PermitRootLogin"             "no"              "$cfg"
        set_config "PasswordAuthentication"      "no"              "$cfg"
    else
        _ssh_no_key_warning
    fi
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
    local crypto_keyword crypto_value
    while read -r crypto_keyword crypto_value; do
        [[ -n "$crypto_keyword" ]] && set_config "$crypto_keyword" "$crypto_value" "$cfg"
    done <<< "$crypto_settings"
    _ssh_crypto_policy_note
    setting_count=$((setting_count - UH_SETTINGS_SKIPPED_COUNT))

    backup_file_for_rewrite /etc/issue.net
    _ssh_issue_net_banner > /etc/issue.net 2>/dev/null || true
    relabel_path "$cfg" /etc/issue.net

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
        {
        cat << 'EOF'
# Written by Ultimate Hardening. Named to sort first among
# /etc/ssh/sshd_config.d/*.conf so it wins sshd's first-value-wins parsing
# over drop-ins (e.g. cloud-init's 50-cloud-init.conf) that would otherwise
# silently override the settings below.
EOF
        [[ "$lockdown" == true ]] && printf 'PermitRootLogin no\nPasswordAuthentication no\n'
        cat << 'EOF'
ChallengeResponseAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
EOF
        if [[ -n "$crypto_settings" ]]; then printf '%s\n' "$crypto_settings"; fi
        } | drop_skipped_settings > "$dropin"
        chmod 600 "$dropin" 2>/dev/null || true
        relabel_path "$dropin"
    fi

    # sshd -t itself needs /run/sshd (privilege separation) to exist, which a
    # normal boot creates but a host where sshd has never once started (a
    # freshly `apt install`'d package, a minimal container) has not — sshd -t
    # then fails on a missing directory, not the config, and this safety
    # check would wrongly restore the backup and skip hardening entirely on
    # an otherwise-fine host. Harmless and idempotent to ensure it exists.
    mkdir -p /run/sshd 2>/dev/null || true

    # Validate before restarting — a bad config must never lock the operator out.
    # sshd -t runs unconfined, so it passes configs the confined daemon is
    # not allowed to read. Only a running sshd proves the restart worked.
    if sshd_config_valid; then
        if restart_sshd && { is_service_active sshd || is_service_active ssh; }; then
            log_success "SSH hardened ($setting_count settings) and daemon restarted"
        elif [[ "$was_running" == true ]]; then
            log_error "sshd did not come back after the restart — restoring the previous config"
            restore_file "$cfg" || log_error "Restore failed. Inspect $cfg manually before disconnecting."
            rm -f "$dropin" 2>/dev/null || true
            restart_sshd || log_error "sshd is still down — check $(service_status_hint sshd) before disconnecting"
            return 1
        else
            log_success "SSH hardened ($setting_count settings); sshd is not running, so nothing was restarted"
        fi
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
#
# Inbound, only SSH is opened. Earlier releases also opened 80/443 on every
# host, desktops included, with no record of why; a hardening tool should not
# open ports nobody asked for, so a host that serves the web opens them itself.
apply_firewall() {
    log_message "${FIRE} [3/23] Firewall"
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would configure firewall: default-deny inbound, allow SSH only"
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

# ufw keeps all of its state in these files: the rules (IPv4 and IPv6), the
# default policies, and whether it is enabled. Backing them up before the first
# change is what lets revert put back the firewall the host already had.
UFW_CONF=/etc/ufw/ufw.conf
UFW_STATE_FILES=(/etc/ufw/user.rules /etc/ufw/user6.rules /etc/default/ufw "$UFW_CONF")

# Each backend counts its own fix, so a module that configured nothing does
# not inflate FIXES_APPLIED.
#
# Releases up to 2.4.9 reset ufw, opened 22, 80 and 443, and kept no backup of
# its files. On such a host, saving those files now would make revert put that
# hardening back instead of undoing it; with no backup, revert falls back to
# the old reset. Recognised by all three: this tool ran before (an earlier
# per-run backup exists), genesis has no copy of user.rules, and user.rules
# opens 22, 80 and 443.
_ufw_holds_earlier_release_rules() {
    local user_rules="${UFW_STATE_FILES[0]}" rules port
    [[ -f "$BACKUP_GENESIS_DIR/files$user_rules" ]] && return 1
    grep -q . <<<"$(find "$UH_BACKUP_ROOT" -maxdepth 1 -type d -name 'hardening_backup_*' 2>/dev/null | grep -vxF "$BACKUP_DIR")" || return 1
    rules=$(cat "$user_rules" 2>/dev/null) || return 1
    for port in 22 80 443; do
        grep -qE "^### tuple ### allow tcp $port 0\.0\.0\.0/0 any 0\.0\.0\.0/0 in" <<<"$rules" || return 1
    done
}

# No `ufw reset` first: it deleted every rule already there, including ones a
# distro's firewall GUI made (Aero Linux's aero-firewall-gui, for one). The
# policies and the SSH allow below are added on top of whatever exists.
_fw_ufw() {
    local state_file
    if _ufw_holds_earlier_release_rules; then
        log_info "ufw already holds an earlier release's rules (22, 80 and 443 open, no backup of ufw from before) — not saving them as the state before hardening"
    else
        for state_file in "${UFW_STATE_FILES[@]}"; do
            backup_file "$state_file"
        done
    fi
    ufw default deny incoming  >>"$LOG_FILE" 2>&1 || true
    ufw default allow outgoing >>"$LOG_FILE" 2>&1 || true
    ufw allow ssh              >>"$LOG_FILE" 2>&1 || true
    ufw --force enable         >>"$LOG_FILE" 2>&1 || true
    log_success "UFW: deny inbound, allow outbound, SSH open"
    count_fix
}

# firewall-cmd --reload drops every runtime rule, fail2ban's bans included,
# while fail2ban goes on listing those addresses as banned. Restarting its
# jails re-applies the active bans from its database.
_fw_firewalld_reload() {
    firewall-cmd --reload >>"$LOG_FILE" 2>&1 || true
    if command -v fail2ban-client >/dev/null 2>&1 && is_service_active fail2ban; then
        fail2ban-client reload --restart >>"$LOG_FILE" 2>&1 || true
    fi
}

# firewalld keeps its rules in the running daemon and in many zone files, so
# revert cannot restore one file the way ufw's does. Instead, the three things
# module 3 changes are recorded once, before its first run (genesis, first run
# wins): whether firewalld was running, the default zone, and whether the drop
# zone already allowed SSH.
FIREWALLD_STATE_NAME=firewalld_state.txt
# The zone an earlier release left ssh, http and https in. Written instead of
# the state record, it also stops later runs recording the hardened state.
FIREWALLD_EARLIER_RELEASE_NAME=firewalld_earlier_release_zone.txt

# Releases up to 2.4.9 added ssh, http and https to the default zone. Since
# --set-default-zone was fixed that is the drop zone; before, that call always
# failed and they landed in whatever zone was the default then, usually public.
# Prints the zone holding them. Outside drop, a web server's own zone can hold
# all three too, so that counts only when this tool ran here before (an
# earlier per-run backup exists).
_firewalld_earlier_release_zone() {
    if firewall-cmd --permanent --zone=drop --query-service=http >/dev/null 2>&1 \
       && firewall-cmd --permanent --zone=drop --query-service=https >/dev/null 2>&1; then
        echo drop
        return 0
    fi
    grep -q . <<<"$(find "$UH_BACKUP_ROOT" -maxdepth 1 -type d -name 'hardening_backup_*' 2>/dev/null | grep -vxF "$BACKUP_DIR")" || return 1
    local zone service
    zone=$(firewall-cmd --get-default-zone 2>/dev/null) || return 1
    [[ "$zone" =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
    for service in ssh http https; do
        firewall-cmd --permanent --zone="$zone" --query-service="$service" >/dev/null 2>&1 || return 1
    done
    echo "$zone"
}

# $1 = yes|no: firewalld was running before this run started it.
_record_firewalld_state() {
    local rec="$BACKUP_GENESIS_DIR/$FIREWALLD_STATE_NAME"
    local earlier_rec="$BACKUP_GENESIS_DIR/$FIREWALLD_EARLIER_RELEASE_NAME"
    [[ "$SKIP_BACKUP" == true || -f "$rec" || -f "$earlier_rec" ]] && return 0
    # An earlier release's rules mean the original state is already gone;
    # recording this one as "before hardening" would make revert keep the
    # hardening (and reopen 80/443 when it switched back to that zone).
    local earlier_zone
    if earlier_zone=$(_firewalld_earlier_release_zone); then
        log_info "firewalld already holds an earlier release's rules (ssh, http and https in the $earlier_zone zone) — not recording them as the state before hardening"
        ( umask 077; mkdir -p "$BACKUP_GENESIS_DIR" ) 2>/dev/null
        printf '%s\n' "$earlier_zone" > "$earlier_rec" 2>/dev/null \
            || log_warning "Could not write $earlier_rec — revert will not remove http and https from the $earlier_zone zone"
        return 0
    fi
    local zone ssh_in_drop=no
    zone=$(firewall-cmd --get-default-zone 2>/dev/null) || zone=""
    if [[ -z "$zone" ]]; then
        log_warning "Could not read firewalld's default zone — revert will not be able to put it back"
        return 0
    fi
    firewall-cmd --permanent --zone=drop --query-service=ssh >/dev/null 2>&1 && ssh_in_drop=yes
    ( umask 077; mkdir -p "$BACKUP_GENESIS_DIR" ) 2>/dev/null
    printf 'was_active=%s\ndefault_zone=%s\nssh_in_drop=%s\n' "$1" "$zone" "$ssh_in_drop" > "$rec" 2>/dev/null \
        || log_warning "Could not record firewalld's state in $rec — revert will not be able to put it back"
}

_zone_allows_ssh() {
    firewall-cmd --permanent --zone="$1" --query-service=ssh >/dev/null 2>&1 \
        || firewall-cmd --permanent --zone="$1" --query-port=22/tcp >/dev/null 2>&1
}

# Put firewalld back the way _record_firewalld_state found it. Returns 1 when
# there is no usable record, so the caller can fall back.
_restore_firewalld_state() {
    local rec="$BACKUP_GENESIS_DIR/$FIREWALLD_STATE_NAME"
    [[ -f "$rec" ]] || return 1
    local was_active zone ssh_in_drop
    was_active=$(sed -n 's/^was_active=//p' "$rec")
    zone=$(sed -n 's/^default_zone=//p' "$rec")
    ssh_in_drop=$(sed -n 's/^ssh_in_drop=//p' "$rec")
    if [[ ! "$was_active" =~ ^(yes|no)$ || ! "$zone" =~ ^[A-Za-z0-9_.-]+$ || ! "$ssh_in_drop" =~ ^(yes|no)$ ]]; then
        log_warning "firewalld state record $rec is not readable — falling back to the generic revert"
        return 1
    fi

    # Going back to a zone without SSH would lock out remote logins, and a
    # reload has cut a live session before (see the note in revert_firewall).
    # Judged by whether sshd runs, not only by $SSH_CONNECTION: sudo's default
    # env_reset drops that variable, so `sudo` over SSH looked like a console.
    if [[ "$was_active" == yes ]] && ! _zone_allows_ssh "$zone" \
       && { [[ -n "${SSH_CONNECTION:-}" ]] || is_service_active sshd || is_service_active ssh; }; then
        log_warning "firewalld: nothing changed. The default zone before hardening ($zone) does not allow SSH, and sshd is running, so switching back would lock SSH out. If that is intended, run from a local console: firewall-cmd --set-default-zone=$zone"
        return 0
    fi

    if [[ "$ssh_in_drop" == no ]]; then
        firewall-cmd --permanent --zone=drop --remove-service=ssh >>"$LOG_FILE" 2>&1 || true
    fi
    firewall-cmd --set-default-zone="$zone" >>"$LOG_FILE" 2>&1 || true

    if [[ "$was_active" == yes ]]; then
        _fw_firewalld_reload
        log_success "firewalld: default zone $zone is back, and firewalld keeps running as it did before hardening"
    else
        # No reload into a daemon that is about to stop: see revert_firewall.
        stop_service firewalld
        log_success "firewalld: default zone $zone is back; firewalld was not running before hardening, so it is stopped again"
    fi
    return 0
}

_fw_firewalld() {
    local was_active=no
    is_service_active firewalld && was_active=yes
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
    _record_firewalld_state "$was_active"

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
    _fw_firewalld_reload

    # Verify the zone change actually took rather than trusting firewall-
    # cmd's own exit code. One retry before giving an honest warning — the
    # readiness wait above still matters for this retry, since
    # --set-default-zone genuinely does need firewalld's D-Bus service up.
    local zone; zone=$(firewall-cmd --get-default-zone 2>/dev/null)
    if [[ "$zone" != "drop" ]]; then
        firewall-cmd --set-default-zone=drop >>"$LOG_FILE" 2>&1 || true
        _fw_firewalld_reload
        zone=$(firewall-cmd --get-default-zone 2>/dev/null)
    fi

    # enable_service logs "enabled" unconditionally (systemctl start's own
    # exit code is thrown away) — the same false-positive shape apply_fail2ban
    # already guards against. Same fix here: only claim success once the
    # service is actually confirmed running.
    if is_service_active firewalld; then
        if [[ "$zone" == "drop" ]]; then
            log_success "firewalld: default zone drop, SSH open"
            count_fix
        else
            log_warning "firewalld default zone is '$zone', not 'drop', after a retry — check: firewall-cmd --get-default-zone"
        fi
    else
        log_warning "firewalld was configured but is not running — check: $(service_status_hint firewalld)"
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
    record_service_state nftables
    nft delete table inet uh_filter 2>/dev/null || true
    # The table earlier releases created. A packet must be accepted by EVERY
    # base chain at a hook, so leaving its drop policy in place would keep
    # dropping whatever this table accepts. Removed only when it is recognisably
    # ours (the combined 22/80/443 accept), never a table that merely shares
    # the name.
    if grep -q 'dport { 22, 80, 443 } accept' <<<"$(nft list chain ip filter INPUT 2>/dev/null)"; then
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
    nft add rule  inet uh_filter input tcp dport 22 accept 2>/dev/null || true

    # Captured, not piped into grep -q: under pipefail nft can take SIGPIPE
    # when grep exits on the first match, and the check then fails at random.
    local loaded_chain; loaded_chain=$(nft list chain inet uh_filter input 2>/dev/null || true)
    if ! grep -q 'policy drop' <<<"$loaded_chain"; then
        log_warning "nftables could not load the firewall rules — nothing was applied. If a kernel update is waiting for a reboot, reboot and run module 3 again"
        return 0
    fi
    # Default-drop without the SSH accept locks out every new SSH login, and
    # saving it would bring the lockout back at every boot. Take the table out.
    if ! grep -qE '^[[:space:]]*tcp dport 22 accept$' <<<"$loaded_chain"; then
        nft delete table inet uh_filter 2>/dev/null || true
        log_warning "nftables: the SSH accept rule did not load, so the firewall rules were removed again and nothing was saved — SSH stays reachable. Check $UH_LOG_PATH and run module 3 again"
        return 0
    fi

    # The rules above are live in the kernel already. What the service gates
    # is persistence: loading the config at boot. It is enabled for boot but
    # never started here: starting it loads the host's config, which may begin
    # with `flush ruleset` and would wipe Docker's and fail2ban's tables.
    # Not persisted means not enabled either: enabling would load whatever
    # config is there, and Alpine's unused default drops SSH.
    count_fix
    if ! persist_uh_filter_table; then
        log_success "nftables: default-drop inbound (IPv4 and IPv6), SSH accepted (active now)"
        log_warning "nftables: this ruleset will NOT survive a reboot (see the warning above)"
    elif is_service_enabled nftables || enable_service_at_boot nftables; then
        log_success "nftables: default-drop inbound (IPv4 and IPv6), SSH accepted (persisted)"
    else
        log_success "nftables: default-drop inbound (IPv4 and IPv6), SSH accepted (active now)"
        log_warning "nftables could not be enabled at boot — this ruleset will NOT survive a reboot; check: $(service_status_hint nftables)"
    fi
}

# The host's own nftables config: the file its nftables service loads at boot.
# UH_NFT_CONF is a test hook that lets the suite write somewhere harmless.
nft_main_conf() {
    if [[ -n "${UH_NFT_CONF:-}" ]]; then echo "$UH_NFT_CONF"; return; fi
    if command -v rc-update >/dev/null 2>&1; then echo /etc/nftables.nft; else echo /etc/nftables.conf; fi
}

# This module's table lives in its own file, pulled in by one include line
# appended to the host's config. Earlier releases overwrote the host's config
# with this table alone, so whatever ruleset the host loaded at boot (a
# distro default, or a hand-written one) was gone after the next reboot.
UH_NFT_TABLE_FILE_DEFAULT=/etc/nftables-uh_filter.nft
uh_nft_table_file() { echo "${UH_NFT_TABLE_FILE:-$UH_NFT_TABLE_FILE_DEFAULT}"; }
uh_nft_include_line() { echo "include \"$(uh_nft_table_file)\""; }
# The note at the top of the boot file written in place of a dormant host
# config. Revert recognises that file by it.
UH_NFT_BOOT_FILE_NOTE_1='# Ultimate Hardening (module 3). The config that was here, never loaded at'
UH_NFT_BOOT_FILE_NOTE_2='# boot, is in the hardening backup and is restored when module 3 is reverted.'

# Write the live `inet uh_filter` table to its own file and make sure the
# host's config includes it. Also used by the paid SSH rate limit, which edits
# the same table. Persists OUR table only: `nft list ruleset` would freeze
# whatever else is loaded right now (Docker's rules, fail2ban's bans) into a
# boot file. `table X` then `delete table X` makes reloading the file
# idempotent whether or not the table already exists.
persist_uh_filter_table() {
    local table_file conf include
    table_file=$(uh_nft_table_file); conf=$(nft_main_conf); include=$(uh_nft_include_line)
    {
        echo '#!/usr/sbin/nft -f'
        echo '# Written by Ultimate Hardening (module 3). Included from the host config.'
        echo
        echo 'table inet uh_filter'
        echo 'delete table inet uh_filter'
        nft list table inet uh_filter 2>/dev/null
    } > "$table_file" 2>/dev/null || { log_warning "Could not write $table_file — the ruleset will not survive a reboot"; return 1; }
    grep -qxF "$include" "$conf" 2>/dev/null && return 0
    [[ -f "$conf" ]] && backup_file "$conf"
    if _nft_host_config_in_use; then
        # Loaded at boot already: the host's ruleset stays in force, and this
        # module's table is added to it.
        [[ -f "$conf" ]] || echo '#!/usr/sbin/nft -f' > "$conf" 2>/dev/null || true
        printf '\n%s\n' "$include" >> "$conf" 2>/dev/null \
            || { log_warning "Could not add the include line to $conf — the ruleset will not survive a reboot"; return 1; }
    elif [[ "$SKIP_BACKUP" == true && -s "$conf" ]]; then
        # Overwriting it below relies on the backup to bring it back on revert.
        log_warning "Not replacing $conf, which nftables does not load at boot: --skip-backup is set, so it could never be put back"
        return 1
    else
        # Never loaded at boot (nftables was not enabled): a distro default
        # sitting there unused. Enabling nftables would start loading it, and
        # Alpine's drops SSH: a lab guest came back from a reboot locked out.
        # So the boot file loads this module's table alone; the dormant config
        # is in the backup and comes back on revert.
        {
            echo '#!/usr/sbin/nft -f'
            echo "$UH_NFT_BOOT_FILE_NOTE_1"
            echo "$UH_NFT_BOOT_FILE_NOTE_2"
            echo "$include"
        } > "$conf" 2>/dev/null \
            || { log_warning "Could not write $conf — the ruleset will not survive a reboot"; return 1; }
    fi
}

# Was the host's nftables config loaded at boot before hardening? Judged by
# whether the nftables service was enabled then (recorded by module 3), or
# now when there is no record.
_nft_host_config_in_use() {
    local state enabled
    if state=$(recorded_service_state nftables); then
        read -r _ enabled <<<"$state"
        [[ "$enabled" == yes ]]
    else
        is_service_enabled nftables
    fi
}

# Undo persist_uh_filter_table: drop the table file, and take out of the
# host's config only what this module put there. Copying the backup over the
# config used to throw away every edit the admin made after hardening.
unpersist_uh_filter_table() {
    local table_file conf include
    table_file=$(uh_nft_table_file); conf=$(nft_main_conf); include=$(uh_nft_include_line)
    rm -f "$table_file" 2>/dev/null || true
    [[ -f "$conf" ]] || return 0
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would remove this module's lines from $conf"
        return 0
    fi
    if grep -qxF "$UH_NFT_BOOT_FILE_NOTE_1" "$conf" 2>/dev/null; then
        _unpersist_nft_boot_file "$conf" "$include"
    elif grep -q 'uh_filter' <<<"$(grep -v -xF "$include" "$conf" 2>/dev/null)"; then
        # A release before 2.5.0 wrote its table into the config itself, after
        # backing the config up: only the backup holds the host's own.
        revert_backed_up_file "$conf" >/dev/null 2>&1 || true
    else
        _remove_nft_include_line "$conf" "$include"
    fi
    # Genesis can hold our own earlier output when the config did not exist
    # before (see UH_TOOL_CREATED_PATHS in core.sh), so the include line is
    # removed whatever was restored.
    remove_line "$include" "$conf"
    # A config this module created holds nothing else; it goes too.
    if ! grep -qvE '^[[:space:]]*($|#)' "$conf" 2>/dev/null; then
        rm -f "$conf" 2>/dev/null || true
    fi
}

# Take out the include line persist_uh_filter_table appended to a config
# nftables loads at boot, with the blank line it put before it, so an
# unedited config is byte-identical to the original again.
_remove_nft_include_line() {
    local conf="$1" include="$2" line_count tmp
    if [[ "$(tail -n 2 "$conf" 2>/dev/null)" == $'\n'"$include" ]]; then
        line_count=$(wc -l < "$conf")
        tmp=$(mktemp) || return 1
        awk -v keep="$((line_count - 2))" 'NR <= keep' "$conf" > "$tmp" && cat "$tmp" > "$conf"
        rm -f "$tmp"
    else
        remove_line "$include" "$conf"
    fi
}

# The boot file written in place of a dormant config: the backup comes back,
# unless the admin has since added their own lines. Their file then stays (it
# is the newer intent, and nftables goes back to not loading it at boot), and
# the config from before hardening is put next to it instead.
_unpersist_nft_boot_file() {
    local conf="$1" include="$2" admin_lines before_copy saved
    admin_lines=$(grep -v -xF -e '#!/usr/sbin/nft -f' -e "$UH_NFT_BOOT_FILE_NOTE_1" \
                      -e "$UH_NFT_BOOT_FILE_NOTE_2" -e "$include" "$conf" \
                  | grep -vE '^[[:space:]]*$' || true)
    if [[ -z "$admin_lines" ]]; then
        revert_backed_up_file "$conf" >/dev/null 2>&1 || true
        return 0
    fi
    before_copy="$conf.before-hardening"
    saved=$(mktemp) || return 1
    cat "$conf" > "$saved"
    revert_backed_up_file "$conf" >/dev/null 2>&1 || true
    if [[ -f "$conf" ]] && ! cmp -s "$conf" "$saved"; then
        cp -a "$conf" "$before_copy"
        log_warning "nftables: $conf was edited after hardening, so it was kept. The config from before hardening is in $before_copy"
    fi
    # Written through the existing file, not copied over it: a temp file's
    # SELinux label would come with a copy.
    cat "$saved" > "$conf"
    rm -f "$saved"
    remove_line "$UH_NFT_BOOT_FILE_NOTE_1" "$conf"
    remove_line "$UH_NFT_BOOT_FILE_NOTE_2" "$conf"
}

# Revert module 3 on whichever backend is actually configured right now —
# detected the same way apply_firewall() picks one to apply to, not
# re-derived from DISTRO_TYPE, since what is live is the ground truth.
# ufw and firewalld have a captured "before". ufw's state is plain files
# (UFW_STATE_FILES), backed up by apply, so revert restores them and turns ufw
# back on or off as it was. For firewalld, apply records what it changes
# (_record_firewalld_state) and revert puts that back. nftables has no captured
# ruleset (SECURITY.md: "If you have a hand-built ruleset, back it up
# separately"), and neither do hosts hardened before these records existed, so
# for them "revert" means back to that backend's own clean, inactive default,
# not a guess at whatever was there before.
#
# nftables specifically: `nft delete table ip filter` rather than `nft
# flush ruleset` (what apply uses) — flush would wipe every table on the
# system, including anything unrelated to this tool; delete removes
# exactly the one table this module (and the paid rate-limit module, which
# only ever adds rules inside this same table) created, and nothing else.
# Make the running ufw match its config files after they were restored: back
# on with the restored rules if it was enabled before, off if it was not.
ufw_apply_restored_config() {
    if grep -qE '^ENABLED=yes' "$UFW_CONF" 2>/dev/null; then
        # `ufw enable` on an already running firewall does not re-read the
        # rule files; `ufw reload` does.
        if grep -qi '^Status: active' <<<"$(ufw status 2>/dev/null)"; then
            ufw reload         >>"$LOG_FILE" 2>&1 || true
        else
            ufw --force enable >>"$LOG_FILE" 2>&1 || true
        fi
        log_success "ufw: the rules from before hardening are back and active"
    else
        ufw disable >>"$LOG_FILE" 2>&1 || true
        log_success "ufw: the rules from before hardening are back; ufw was off then, so it is off again"
    fi
}

# Never stops nftables: its unit flushes the whole ruleset on stop, other
# tools' tables included. Only its start-at-boot setting goes back to what it
# was before module 3 (nothing happens without a record).
restore_nftables_boot_state() {
    local nft_state nft_active nft_enabled
    nft_state=$(recorded_service_state nftables) || return 0
    read -r nft_active nft_enabled <<<"$nft_state"
    [[ "$nft_enabled" == no ]] && disable_service_at_boot nftables
    # OpenRC can mark a service stopped without running its stop (which would
    # flush). systemd cannot; there it reads active until the next boot,
    # holding only the host's own rules.
    if [[ "$nft_active" == no ]] && _has_openrc && command -v rc-service >/dev/null 2>&1; then
        rc-service nftables zap >>"$LOG_FILE" 2>&1 || true
    fi
    return 0
}

revert_firewall() {
    local acted=false host_nft_ruleset_kept=false firewalld_state_restored=false

    if command -v ufw >/dev/null 2>&1 && grep -qi '^Status: active' <<<"$(ufw status 2>/dev/null)"; then
        local state_file restored=0
        for state_file in "${UFW_STATE_FILES[@]}"; do
            [[ -f "$state_file" ]] && revert_backed_up_file "$state_file" && bump restored
        done
        if (( restored > 0 )); then
            ufw_apply_restored_config
        else
            # Hardened by a release that took no backup of these files: there
            # is nothing to go back to, so only the old reset is possible.
            ufw --force reset  >>"$LOG_FILE" 2>&1 || true
            ufw disable        >>"$LOG_FILE" 2>&1 || true
            log_success "ufw: no backup of its earlier rules was found, so it was reset to defaults and disabled"
        fi
        acted=true
    fi

    if command -v firewall-cmd >/dev/null 2>&1 && is_service_active firewalld \
       && _restore_firewalld_state; then
        acted=true
        firewalld_state_restored=true
    elif command -v firewall-cmd >/dev/null 2>&1 && is_service_active firewalld; then
        # No record: hardened by a release up to 2.4.9, or with --skip-backup.
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
        # Releases from before the --set-default-zone fix left http and https
        # in the zone that was default then (usually public), and switching
        # back to it would open 80/443 again whenever firewalld next starts.
        # ssh stays: public allows it out of the box.
        local earlier_zone
        earlier_zone=$(cat "$BACKUP_GENESIS_DIR/$FIREWALLD_EARLIER_RELEASE_NAME" 2>/dev/null || true)
        if [[ "$earlier_zone" =~ ^[A-Za-z0-9_.-]+$ && "$earlier_zone" != "$zone" ]]; then
            firewall-cmd --permanent --zone="$earlier_zone" --remove-service=http  >>"$LOG_FILE" 2>&1 || true
            firewall-cmd --permanent --zone="$earlier_zone" --remove-service=https >>"$LOG_FILE" 2>&1 || true
            log_info "firewalld: removed http and https, which an earlier release added, from the $earlier_zone zone"
        fi
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

    if command -v nft >/dev/null 2>&1 && nft list table inet uh_filter >/dev/null 2>&1; then
        nft delete table inet uh_filter 2>>"$LOG_FILE" || true
        unpersist_uh_filter_table
        restore_nftables_boot_state
        log_success "nftables: removed this module's table and its include line; the host's own nftables config is as it was before hardening"
        acted=true
        host_nft_ruleset_kept=true
    elif command -v nft >/dev/null 2>&1 \
         && grep -q 'dport { 22, 80, 443 } accept' <<<"$(nft list chain ip filter INPUT 2>/dev/null)"; then
        # The IPv4-only table of releases before the inet one, recognised by
        # its combined 22/80/443 accept as apply does. Not any `ip filter`:
        # iptables-nft makes one for ufw and Docker, and deleting it wiped
        # their live rules. Those releases overwrote the host's config, after
        # backing it up: put that back.
        nft delete table ip filter 2>>"$LOG_FILE" || true
        local legacy_conf; legacy_conf=$(nft_main_conf)
        if ! revert_backed_up_file "$legacy_conf" >/dev/null 2>&1 || grep -q 'dport { 22, 80, 443 } accept' "$legacy_conf" 2>/dev/null; then
            rm -f "$legacy_conf"
        fi
        stop_service nftables
        log_success "nftables: removed the legacy filter table, restored or removed its persisted ruleset file, and stopped the service"
        acted=true
    fi

    if [[ "$acted" != true ]]; then
        log_info "Firewall: nothing reverted — no active ufw/firewalld configuration or nftables filter table from this tool was found"
        return 1
    fi

    # The host's own earlier ufw or firewalld firewall is back in force.
    if command -v ufw >/dev/null 2>&1 && grep -qi '^Status: active' <<<"$(ufw status 2>/dev/null)"; then
        return 0
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && is_service_active firewalld; then
        return 0
    fi
    # Only this module's table was removed; whatever ruleset the host loads
    # itself is still in force, as it was before hardening.
    if [[ "$host_nft_ruleset_kept" == true ]]; then
        return 0
    fi

    if [[ "$firewalld_state_restored" == true ]]; then
        log_info "The host has no active firewall now, as before module 3 ran: firewalld was not running then."
        return 0
    fi
    log_warning "The host now has no active firewall, as before module 3 ran. On firewalld and nftables, rules from before hardening are not restored (see SECURITY.md: only config files are backed up, not live kernel firewall state)."
    return 0
}

# --- 4. Fail2Ban -------------------------------------------------------------
_fail2ban_jail_local() {
    # The sshd jail's default backend reads /var/log/auth.log, which does not
    # exist on a journald-only host (no rsyslog installed) — increasingly the
    # default on modern Debian/Ubuntu cloud images. Without a log source the
    # whole fail2ban daemon fails to start at all (not just the sshd jail),
    # so apply_fail2ban's enable_service would report "enabled" for a service
    # that is actually dead. On a systemd host, reading the journal directly
    # sidesteps the missing-file problem entirely; on a non-systemd host (e.g.
    # Alpine's OpenRC) the traditional file-based backend is left as-is.
    local backend="auto"
    _has_systemd && backend="systemd"
    cat << EOF
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
}

# The SSH jail this module runs, in a file of its own. jail.d/*.local is read
# after jail.local, so it applies whatever an admin's jail.local says, and the
# admin's own jails and [DEFAULT] stay as they are. Earlier releases wrote
# jail.local itself (_fail2ban_jail_local, kept so revert still recognises
# that output), which switched off every jail an admin had there.
UH_FAIL2BAN_JAIL=/etc/fail2ban/jail.d/99-ultimate-hardening.local

_fail2ban_sshd_jail() {
    # Same journald reasoning as _fail2ban_jail_local above.
    local backend="auto"
    _has_systemd && backend="systemd"
    cat << EOF
[sshd]
enabled  = true
port     = ssh
findtime = 600
maxretry = 3
bantime  = 7200
backend  = ${backend}
EOF
    _fail2ban_increment_lines
}

# Fail2Ban 0.11 added bantime.increment: each repeat ban of the same address
# lasts longer (2h, 4h, 8h ... capped at a week here). Older releases reject
# the keys, so they are written only where the installed version has them.
# No CIS or STIG control covers Fail2Ban; this follows its own documentation.
UH_FAIL2BAN_MAXTIME=1w

# $1 = version string like "1.0.2" or "0.11.2". True for 0.11 and later.
_fail2ban_version_has_increment() {
    local major minor
    IFS=. read -r major minor _ <<< "$1"
    [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
    (( major > 0 || minor >= 11 ))
}

_fail2ban_installed_version() {
    local out; out=$(fail2ban-client --version 2>/dev/null || true)
    grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' <<< "$out" | head -1 || true
}

_fail2ban_increment_lines() {
    _fail2ban_version_has_increment "$(_fail2ban_installed_version)" || return 0
    printf 'bantime.increment = true\nbantime.maxtime   = %s\n' "$UH_FAIL2BAN_MAXTIME"
}

# Where fail2ban logs, as fail2ban.conf and its .local/.d overrides say (the
# last setting read wins, as in fail2ban). Empty when nothing sets it.
_fail2ban_logtarget() {
    local dir="${UH_FAIL2BAN_DIR:-/etc/fail2ban}" f target=""
    for f in "$dir/fail2ban.conf" "$dir"/fail2ban.d/*.conf "$dir/fail2ban.local" "$dir"/fail2ban.d/*.local; do
        [[ -f "$f" ]] || continue
        local v
        v=$(sed -nE 's/^[[:space:]]*logtarget[[:space:]]*=[[:space:]]*([^[:space:]]+).*/\1/p' "$f" | tail -1)
        [[ -n "$v" ]] && target="$v"
    done
    printf '%s' "$target"
}

# The recidive jail bans for a week any address banned five times in a day,
# reading fail2ban's own log. Printed only where that log is a file or the
# journal; logging to syslog or stdout leaves it nothing to read.
_fail2ban_recidive_jail() {
    local target; target=$(_fail2ban_logtarget)
    case "$target" in
        /*)
            printf '\n[recidive]\nenabled  = true\nlogpath  = %s\nbackend  = auto\n' "$target" ;;
        SYSTEMD-JOURNAL)
            printf '\n[recidive]\nenabled  = true\nbackend  = systemd\njournalmatch = _SYSTEMD_UNIT=fail2ban.service\n' ;;
        *) return 0 ;;
    esac
    printf 'findtime = 1d\nmaxretry = 5\nbantime  = 1w\n'
}

# Jails for services this host runs, each only where the service is installed
# and its log is there to read: a jail whose log is missing stops the whole
# daemon from starting, not just that jail.
_fail2ban_service_jails() {
    local log
    if command -v nginx >/dev/null 2>&1 && [[ -f /var/log/nginx/error.log ]]; then
        printf '\n[nginx-http-auth]\nenabled  = true\n'
        _fail2ban_increment_lines
    fi
    if command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
        for log in /var/log/apache2/error.log /var/log/httpd/error_log; do
            [[ -f "$log" ]] || continue
            printf '\n[apache-auth]\nenabled  = true\nlogpath  = %s\n' "$log"
            _fail2ban_increment_lines
            break
        done
    fi
    if command -v postfix >/dev/null 2>&1; then
        if _has_systemd; then
            printf '\n[postfix]\nenabled  = true\nbackend  = systemd\n'
            _fail2ban_increment_lines
        else
            for log in /var/log/mail.log /var/log/maillog; do
                [[ -f "$log" ]] || continue
                printf '\n[postfix]\nenabled  = true\nlogpath  = %s\n' "$log"
                _fail2ban_increment_lines
                break
            done
        fi
    fi
    return 0
}

# Names of the jails in the file module 4 writes, for the log.
_fail2ban_jail_names() {
    sed -nE 's/^\[([a-z0-9-]+)\]$/\1/p' "$UH_FAIL2BAN_JAIL" 2>/dev/null | paste -sd' ' -
}

# True when fail2ban accepts its whole configuration. Releases without -t
# fail this too, which drops back to the SSH jail alone: the safe side.
_fail2ban_config_valid() {
    fail2ban-client -t >>"$LOG_FILE" 2>&1
}

apply_fail2ban() {
    log_message "${SHIELD} [4/23] Fail2Ban"
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would install fail2ban with an SSH jail (3 tries, 2h ban, longer on each repeat where fail2ban 0.11+ allows), a recidive jail, and jails for the web and mail servers installed here"
        return 0
    fi

    # Before the install: Debian's package starts the service on its own.
    record_service_state fail2ban
    install_package fail2ban || { log_warning "fail2ban unavailable — skipping"; return 0; }

    mkdir -p "$(dirname "$UH_FAIL2BAN_JAIL")" 2>/dev/null || true
    { _fail2ban_sshd_jail; _fail2ban_recidive_jail; _fail2ban_service_jails; } > "$UH_FAIL2BAN_JAIL"
    if ! _fail2ban_config_valid; then
        local rejected; rejected=$(_fail2ban_jail_names)
        _fail2ban_sshd_jail > "$UH_FAIL2BAN_JAIL"
        if _fail2ban_config_valid; then
            log_warning "fail2ban rejected the extra jails (${rejected}) — keeping the SSH jail alone; details in $LOG_FILE"
        else
            log_warning "fail2ban rejects its configuration even with the SSH jail alone (often: no log for sshd to read) — keeping only the SSH jail; details in $LOG_FILE"
        fi
    fi

    if [[ -f /etc/fail2ban/filter.d/alpine-sshd.conf ]]; then
        cat > /etc/fail2ban/filter.d/alpine-sshd.local << 'EOF'
[Definition]
failregex = Failed [-/\w]+ for .* from <HOST> port \d* ssh2
            sshd(?:-session)?(?:\.pam)?\[.*\]: Invalid user .* from <HOST> port \d*
            sshd(?:-session)?(?:\.pam)?\[.*\]: Received disconnect from <HOST> port \d*:[0-9]+:  \[preauth\]
            sshd(?:-session)?(?:\.pam)?\[.*\]: Disconnected from invalid user .* <HOST> port \d* \[preauth\]
EOF
    fi

    local was_active=false
    is_service_active fail2ban && was_active=true
    enable_service fail2ban
    # A daemon already running reads the new jail file only on reload.
    if [[ "$was_active" == true ]]; then
        fail2ban-client reload >>"$LOG_FILE" 2>&1 || log_warning "fail2ban did not reload; the new jails apply at its next restart"
    fi
    if is_service_active fail2ban; then
        log_success "Fail2Ban active: SSH jail bans for 2h after 3 failures; jails: $(_fail2ban_jail_names)"
        grep -q '^bantime.increment' "$UH_FAIL2BAN_JAIL" 2>/dev/null \
            && log_info "  Repeat offenders are banned for longer each time, up to $UH_FAIL2BAN_MAXTIME"
        count_fix
    else
        log_warning "fail2ban was configured but is not running — check: $(service_status_hint fail2ban)"
    fi
}

# --- 5. File permissions -----------------------------------------------------
apply_permission_hardening() {
    log_message "${LOCK} [5/23] File Permissions"
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
# Each parameter carries its source. CIS = CIS Ubuntu 22.04 v2 / RHEL 9
# (same numbers for these), STIG = DISA RHEL 9 STIG. Where this sets a value
# stricter than the source asks, the comment says so. The two with neither
# source (sysrq, tcp_syn*_retries) date from earlier releases and stay.
_kernel_sysctl_conf() {
    cat << 'EOF'
# Ultimate Hardening — kernel and network parameters
# CIS 1.5.1, STIG RHEL-09-213070
kernel.randomize_va_space = 2
# STIG RHEL-09-213010
kernel.dmesg_restrict = 1
# STIG RHEL-09-213025 (asks for 1; 2 also hides pointers from root)
kernel.kptr_restrict = 2
# No CIS/STIG control; kept from earlier releases
kernel.sysrq = 0
# STIG RHEL-09-213075
kernel.unprivileged_bpf_disabled = 1
# STIG (sysctl_net_core_bpf_jit_harden)
net.core.bpf_jit_harden = 2
# STIG RHEL-09-213015 (asks for 2; 3 is stricter where the kernel has it)
kernel.perf_event_paranoid = 3
# CIS 1.5.2, STIG RHEL-09-213080
kernel.yama.ptrace_scope = 1
# CIS 1.5.3
fs.suid_dumpable = 0
# STIG RHEL-09-213030, RHEL-09-213035
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
# CIS 3.3.1, STIG RHEL-09-254025 (IPv6)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
# CIS 3.3.10
net.ipv4.tcp_syncookies = 1
# No CIS/STIG control; kept from earlier releases
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
# CIS 3.3.4
net.ipv4.icmp_echo_ignore_broadcasts = 1
# CIS 3.3.3
net.ipv4.icmp_ignore_bogus_error_responses = 1
# CIS 3.3.7
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# CIS 3.3.9
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
# CIS 3.3.8, STIG RHEL-09-254040 (IPv6 default)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# CIS 3.3.5, STIG RHEL-09-254035 (IPv6 default)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# CIS 3.3.6
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
# CIS 3.3.2, STIG RHEL-09-253070
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# CIS 3.3.11, STIG RHEL-09-254010, RHEL-09-254030
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF
}

# Router adverts give a host its IPv6 address and route under SLAAC, as on
# most cloud networks; accept_ra = 0 there takes IPv6 away at the next
# renewal. True when an interface holds a global IPv6 address the kernel
# learned dynamically.
_ipv6_uses_router_adverts() {
    command -v ip >/dev/null 2>&1 || return 1
    [[ -n "$(ip -6 -o addr show scope global dynamic 2>/dev/null)" ]]
}

# Filters sysctl lines on stdin: drops accept_ra where the host needs it.
_drop_accept_ra_if_needed() {
    if _ipv6_uses_router_adverts; then
        grep -v '^net\.ipv6\.conf\.[a-z]*\.accept_ra ' || true
    else
        cat
    fi
}

# The live value of every setting this module changes, recorded once before
# its first run (genesis, first run wins per key). Removing the drop-in on
# revert does not change live values; they stayed hardened until a reboot.
UH_SYSCTL_RECORD_NAME=sysctl_before.txt

# The sysctl settings this run writes: the module's set minus UH_SKIP_SETTINGS.
_kernel_sysctl_settings() {
    _kernel_sysctl_conf | drop_skipped_settings | _drop_accept_ra_if_needed
}

# $1 = this module's drop-in. Hosts hardened by a release that kept no record
# already run the hardened values, so nothing is recorded for them.
_record_sysctl_before() {
    local rec="$BACKUP_GENESIS_DIR/$UH_SYSCTL_RECORD_NAME" key val
    [[ "$SKIP_BACKUP" == true ]] && return 0
    [[ ! -f "$rec" && -f "$1" ]] && return 0
    ( umask 077; mkdir -p "$BACKUP_GENESIS_DIR" ) 2>/dev/null
    while read -r key; do
        grep -q "^${key}=" "$rec" 2>/dev/null && continue
        val=$(sysctl -n "$key" 2>/dev/null) || continue
        printf '%s=%s\n' "$key" "$val" >> "$rec" 2>/dev/null || true
    done < <(_kernel_sysctl_settings | awk -F'[[:space:]]*=[[:space:]]*' '/^[a-z]/ {print $1}')
}

# Put the recorded live values back, then re-read every sysctl config so the
# distro's own files win over them, as they would at boot.
restore_sysctl_before() {
    local rec="$BACKUP_GENESIS_DIR/$UH_SYSCTL_RECORD_NAME" key val
    if [[ -f "$rec" ]]; then
        while IFS='=' read -r key val; do
            [[ "$key" =~ ^[a-z0-9_.]+$ && "$val" =~ ^-?[0-9]+$ ]] || continue
            sysctl -w "${key}=${val}" >>"$LOG_FILE" 2>&1 || true
        done < "$rec"
    fi
    sysctl --system >>"$LOG_FILE" 2>&1 || true
}

apply_kernel_hardening() {
    log_message "${GEAR} [6/23] Kernel & Network Hardening"

    if ! is_linux; then
        log_warning "sysctl hardening is Linux-specific — skipping on ${DISTRO_TYPE}"
        return 0
    fi
    local skipped; skipped=$(_kernel_sysctl_conf | skipped_settings_in)
    [[ -n "$skipped" ]] && log_info "  Left as they are (UH_SKIP_SETTINGS): $skipped"
    if _ipv6_uses_router_adverts; then
        log_info "  IPv6 router adverts left on (accept_ra): this host has an address from them, and turning them off would drop its IPv6"
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would write $(_kernel_sysctl_settings | grep -c '^[a-z]') sysctl parameters to /etc/sysctl.d/99-hardening.conf"
        return 0
    fi

    local sysctl_file="/etc/sysctl.d/99-hardening.conf"
    backup_file "$sysctl_file"
    mkdir -p /etc/sysctl.d 2>/dev/null || true

    _record_sysctl_before "$sysctl_file"
    _kernel_sysctl_settings > "$sysctl_file"

    sysctl -p "$sysctl_file" >>"$LOG_FILE" 2>&1 || true
    local n; n=$(grep -c '^[a-z]' "$sysctl_file" 2>/dev/null || echo 0)
    log_success "Kernel hardening applied ($n parameters)"
    count_fix
}

# --- 7. Auditd ---------------------------------------------------------------
# The merged rules file auditd loads. augenrules rebuilds it from rules.d;
# Alpine's auditd loads it at start and never runs augenrules itself.
UH_AUDIT_RULES_FILE=/etc/audit/audit.rules
# Recorded in genesis when that file did not exist before the first run, so
# revert removes it rather than leaving our rules to load at every boot.
UH_AUDIT_RULES_ABSENT_NAME=audit_rules_absent_before

_audit_rules_dir() { echo "${UH_AUDIT_DIR:-/etc/audit}"; }   # test hook

# Back up the merged rules file once, or record that it did not exist. Once
# the marker is there the file is ours, and backing it up would make genesis
# hold our own output as "the original".
_backup_audit_rules_file() {
    local f marker; f="$(_audit_rules_dir)/audit.rules"; marker="$BACKUP_GENESIS_DIR/$UH_AUDIT_RULES_ABSENT_NAME"
    [[ -f "$marker" ]] && return 0
    if [[ -f "$f" ]]; then
        backup_file "$f"
    elif [[ "$SKIP_BACKUP" != true && ! -f "$BACKUP_GENESIS_DIR/files$f" ]]; then
        ( umask 077; mkdir -p "$BACKUP_GENESIS_DIR" ) 2>/dev/null
        : > "$marker" 2>/dev/null || true
    fi
}

# Load the rules now. augenrules only builds the merged file here: its own
# --load calls /sbin/auditctl by that exact path, and Alpine has it in
# /usr/sbin, so the rules were written but never loaded there. auditctl,
# found on PATH, then loads the merged file (whose first line is -D).
load_audit_rules() {
    local dir merged; dir=$(_audit_rules_dir); merged="$dir/audit.rules"
    command -v auditctl >/dev/null 2>&1 || return 1
    if command -v augenrules >/dev/null 2>&1; then
        augenrules >>"$LOG_FILE" 2>&1 || true
        [[ -f "$merged" ]] && { auditctl -R "$merged" >>"$LOG_FILE" 2>&1; return; }
    fi
    auditctl -R "$dir/rules.d/99-hardening.rules" >>"$LOG_FILE" 2>&1
}

# Are this module's rules loaded in the kernel right now?
audit_rules_loaded() {
    grep -q -- '-k identity' <<<"$(auditctl -l 2>/dev/null)"
}

# Revert of the merged file: back to what it was, or gone if hardening made
# it; then the kernel gets what is left (or nothing).
restore_audit_rules() {
    local f marker; f="$(_audit_rules_dir)/audit.rules"; marker="$BACKUP_GENESIS_DIR/$UH_AUDIT_RULES_ABSENT_NAME"
    if [[ -f "$marker" ]]; then
        rm -f "$f" "$f.prev" 2>/dev/null || true
        log_success "Removed (created by hardening, no earlier version existed): $f"
    else
        revert_backed_up_file "$f" >/dev/null 2>&1 || true
    fi
    command -v auditctl >/dev/null 2>&1 && is_service_active auditd || return 0
    if audit_rules_locked; then
        log_warning "The loaded audit rules are locked (-e 2, UH_AUDIT_IMMUTABLE): the files are reverted, and the kernel drops the hardened rules at the next reboot"
        return 0
    fi
    if [[ -f "$f" ]]; then
        auditctl -R "$f" >>"$LOG_FILE" 2>&1 || true
    else
        auditctl -D >>"$LOG_FILE" 2>&1 || true
    fi
}

# Syscall rules by group: "<key>|<filters>|<syscalls>". Each line becomes one
# rule per audited arch, holding only the syscalls that arch has. Keys are the
# CIS ones, except the three this module has used since before (modules,
# mounts, privesc), kept so searches written against them still work.
# CIS Ubuntu 22.04 v2 6.3.3.1-6.3.3.21 (RHEL 9: 6.3.3.x, same groups); -e 2 is
# CIS 6.3.3.20 and STIG RHEL-09-654275, opt-in here because it blocks revert
# until reboot.
_audit_syscall_groups() {
    local user="-F auid>=$1 -F auid!=unset"
    cat << EOF
time-change||adjtimex settimeofday stime
time-change|-F a0=0x0|clock_settime
system-locale||sethostname setdomainname
user_emulation|-C euid!=uid -F auid!=unset|execve
access|-F exit=-EACCES $user|creat open openat truncate ftruncate
access|-F exit=-EPERM $user|creat open openat truncate ftruncate
perm_mod|$user|chmod fchmod fchmodat
perm_mod|$user|chown fchown lchown fchownat
perm_mod|$user|setxattr lsetxattr fsetxattr removexattr lremovexattr fremovexattr
mounts||mount
delete|$user|unlink unlinkat rename renameat
modules||init_module finit_module delete_module create_module query_module
privesc|-F exit=0|setuid setgid
EOF
}

# Watched paths: "<key>|<perms>|<path>". A path is watched only where it or
# its parent directory exists, since auditctl rejects a watch under a missing
# directory and stops loading the rest of the file there.
_audit_watch_list() {
    cat << EOF
identity|wa|/etc/passwd
identity|wa|/etc/group
identity|wa|/etc/shadow
identity|wa|/etc/gshadow
identity|wa|/etc/security/opasswd
identity|wa|/etc/nsswitch.conf
sudoers|wa|/etc/sudoers
sudoers|wa|/etc/sudoers.d
sudo_log_file|wa|$(_audit_sudo_logfile)
sshd|wa|/etc/ssh/sshd_config
cron|wa|/etc/crontab
cron|wa|/etc/cron.d
cron|wa|/var/spool/cron
logins|wa|/var/log/lastlog
logins|wa|/var/run/faillock
session|wa|/var/run/utmp
session|wa|/var/log/wtmp
session|wa|/var/log/btmp
time-change|wa|/etc/localtime
system-locale|wa|/etc/issue
system-locale|wa|/etc/issue.net
system-locale|wa|/etc/hosts
system-locale|wa|/etc/hostname
system-locale|wa|/etc/networks
system-locale|wa|/etc/network
system-locale|wa|/etc/sysconfig/network
system-locale|wa|/etc/netplan
system-locale|wa|/etc/NetworkManager
MAC-policy|wa|/etc/apparmor
MAC-policy|wa|/etc/apparmor.d
MAC-policy|wa|/etc/selinux
MAC-policy|wa|/usr/share/selinux
modules|x|/sbin/insmod
modules|x|/sbin/rmmod
modules|x|/sbin/modprobe
modules|x|/usr/bin/kmod
EOF
}

# The file sudo logs to, from a Defaults logfile= line; module 23's default
# otherwise, which the rule then covers once that module runs.
_audit_sudo_logfile() {
    local f
    f=$(grep -hsE '^[[:space:]]*Defaults.*logfile[[:space:]]*=' /etc/sudoers /etc/sudoers.d/* 2>/dev/null \
        | sed -nE 's/.*logfile[[:space:]]*=[[:space:]]*"?([^",[:space:]]+).*/\1/p' | tail -1)
    printf '%s' "${f:-/var/log/sudo.log}"
}

# The arches whose syscalls are audited: b64 on 64-bit kernels, plus b32 for
# the 32-bit ABI they can also run (CIS writes both).
_audit_arches() {
    case "$(uname -m)" in
        x86_64|aarch64|ppc64*|s390x|riscv64|loongarch64) echo "b64 b32" ;;
        *) echo "b32" ;;
    esac
}

# Syscalls the newer 64-bit ABIs (aarch64, riscv64, loongarch64) never had;
# used only where ausyscall is not installed to ask.
UH_AUDIT_LEGACY_SYSCALLS="open creat chmod chown lchown rename unlink stime create_module query_module"

# $1 = arch, $2 = syscall. True when this kernel's arch has it.
_audit_syscall_known() {
    if command -v ausyscall >/dev/null 2>&1; then
        ausyscall "$1" "$2" --exact >/dev/null 2>&1
        return
    fi
    case "$1:$(uname -m)" in
        b64:aarch64|b64:riscv64|b64:loongarch64)
            [[ " $UH_AUDIT_LEGACY_SYSCALLS " != *" $2 "* ]] ;;
        *) return 0 ;;
    esac
}

# Setuid and setgid programs on the local root and /usr filesystems, one
# exec rule each (CIS: privileged commands).
#
# Root-owned only, and only names of plain printable characters. Any user can
# set the setuid bit on a file of their own, and auditctl splits a rule on
# whitespace: a file named "x -F bogus=1" in a home directory broke its rule,
# auditctl -R stopped there, and every rule after it (sudo, su, passwd, and
# the -e 2 lock) never loaded, at every boot. A setuid file a user owns
# grants nothing, so it needs no rule.
_audit_privileged_programs() {
    local path
    while IFS= read -r -d '' path; do
        [[ "$path" =~ ^/[[:graph:]]+$ ]] && printf '%s\n' "$path"
    done < <(find / /usr -xdev -type f -uid 0 \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null) | sort -u
}

_audit_uid_min() {
    local v; v=$(awk '/^UID_MIN/ {print $2}' /etc/login.defs 2>/dev/null)
    [[ "$v" =~ ^[0-9]+$ ]] && printf '%s' "$v" || printf '1000'
}

# The rules file module 7 writes.
_audit_rules_content() {
    local uid_min arch key filters syscalls perms path s kept
    uid_min=$(_audit_uid_min)
    echo "-D"
    echo "-b 8192"
    echo "-f 1"
    while IFS='|' read -r key perms path; do
        [[ -n "$path" ]] || continue
        [[ -e "$path" || -d "$(dirname "$path")" ]] || continue
        echo "-w $path -p $perms -k $key"
    done < <(_audit_watch_list)
    for arch in $(_audit_arches); do
        while IFS='|' read -r key filters syscalls; do
            kept=""
            for s in $syscalls; do
                _audit_syscall_known "$arch" "$s" && kept+=" -S $s"
            done
            [[ -n "$kept" ]] && echo "-a always,exit -F arch=$arch${kept}${filters:+ $filters} -k $key"
        done < <(_audit_syscall_groups "$uid_min")
    done
    for path in /usr/bin/chcon /usr/bin/setfacl /usr/bin/chacl; do
        [[ -x "$path" ]] && echo "-a always,exit -F path=$path -F perm=x -F auid>=$uid_min -F auid!=unset -k perm_chng"
    done
    for path in /usr/sbin/usermod /usr/bin/usermod; do
        [[ -x "$path" && ! -L "$path" ]] && echo "-a always,exit -F path=$path -F perm=x -F auid>=$uid_min -F auid!=unset -k usermod"
    done
    while IFS= read -r path; do
        [[ -n "$path" ]] && echo "-a always,exit -F path=$path -F perm=x -F auid>=$uid_min -F auid!=unset -k privileged"
    done < <(_audit_privileged_programs)
    if [[ "$(_audit_immutable)" == true ]]; then
        echo "-e 2"
    fi
    return 0
}

# UH_AUDIT_IMMUTABLE=true locks the loaded rules until the next reboot.
_audit_immutable() {
    local v="${UH_AUDIT_IMMUTABLE:-false}"
    if [[ "$v" != true && "$v" != false ]]; then
        log_warning "UH_AUDIT_IMMUTABLE='$v' is not true/false — leaving the rules changeable" >&2
        v=false
    fi
    printf '%s' "$v"
}

# True when the kernel holds locked (-e 2) rules: nothing loads until reboot.
audit_rules_locked() {
    grep -qE '^enabled[[:space:]]+2' <<<"$(auditctl -s 2>/dev/null)"
}

apply_audit_config() {
    log_message "${SHIELD} [7/23] Audit Daemon"

    if ! is_linux; then
        log_warning "auditd is Linux-specific — skipping on ${DISTRO_TYPE}"
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would install auditd and write $(_audit_rules_content | grep -c '^-[aw] ' || true) audit rules (CIS 6.3.3 groups, privileged programs, module loading)"
        [[ "$(_audit_immutable)" == true ]] && log_dry "  and lock them until reboot (-e 2, UH_AUDIT_IMMUTABLE=true)"
        return 0
    fi

    # Before the install: some packages start the service on their own.
    record_service_state auditd
    install_package auditd || install_package audit || {
        log_warning "auditd unavailable — skipping"; return 0; }

    mkdir -p /etc/audit/rules.d 2>/dev/null || true
    backup_file /etc/audit/rules.d/99-hardening.rules
    _backup_audit_rules_file

    _audit_rules_content > /etc/audit/rules.d/99-hardening.rules
    local rule_count
    rule_count=$(grep -c '^-[aw] ' /etc/audit/rules.d/99-hardening.rules || true)

    enable_service auditd
    if audit_rules_locked; then
        log_warning "Audit rules written, but the rules loaded now are locked (-e 2) — the new ones load at the next reboot"
        count_fix
        return 0
    fi
    load_audit_rules || true
    # enable_service logs "enabled" unconditionally, and the rules were once
    # reported as configured on Alpine where none had loaded: check both.
    if ! is_service_active auditd; then
        log_warning "Audit rules written but auditd is not running — check: $(service_status_hint auditd)"
    elif ! audit_rules_loaded; then
        log_warning "Audit rules written but not loaded in the kernel (auditctl -l does not list them) — they apply at the next auditd start; check: auditctl -R $UH_AUDIT_RULES_FILE"
    else
        log_success "Auditd configured with $rule_count audit rules (loaded)$( [[ "$(_audit_immutable)" == true ]] && echo ', locked until reboot')"
        count_fix
    fi
}

# --- 8. Password policy (login.defs only — PAM is never touched) --------------
apply_password_policies() {
    log_message "${LOCK} [8/23] Password Policy"

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
# First line of a v2 SUID inventory (one record per whole path). Older
# inventories are restored only after confirmation (see undo_suid_hardening).
UH_SUID_INVENTORY_HEADER='# uh-suid-inventory v2'

# Module 9 and its revert chmod only a path that no one but root can redirect:
# no symlink anywhere in it, the file owned by root, and every directory above
# it owned by root and not group- or world-writable.
suid_path_is_root_controlled() {
    local path="$1" dir owner perms
    [[ ! -L "$path" && "$(readlink -f "$path" 2>/dev/null)" == "$path" ]] || return 1
    [[ "$(stat -c %u "$path" 2>/dev/null)" == 0 ]] || return 1
    dir=${path%/*}
    while [[ -n "$dir" ]]; do
        read -r owner perms < <(stat -c '%u %a' "$dir" 2>/dev/null) || return 1
        [[ "$owner" == 0 ]] && (( (8#$perms & 8#022) == 0 )) || return 1
        dir=${dir%/*}
    done
}

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
    log_message "${FIRE} [9/23] SUID/SGID Hardening ${RED}(HIGH RISK)${NC}"

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
        # One "path mode" record per line, so a name containing a newline
        # can't be recorded as one record; skip it.
        local suid_path suid_mode
        printf '%s\n' "$UH_SUID_INVENTORY_HEADER" > "$SUID_BACKUP_FILE"
        # -print0 rather than -printf, which BusyBox find (Alpine) lacks.
        while IFS= read -r -d '' suid_path; do
            if [[ "$suid_path" == *$'\n'* ]]; then
                log_warning "  SUID/SGID file with a newline in its name, not recorded: ${suid_path//$'\n'/\\n}"
                continue
            fi
            suid_mode=$(stat -c %a "$suid_path" 2>/dev/null) || continue
            printf '%s %s\n' "$suid_path" "$suid_mode" >&3
        done < <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print0 2>/dev/null) \
            3>> "$SUID_BACKUP_FILE"
        log_info "SUID inventory recorded: $SUID_BACKUP_FILE"
    fi

    local -a safe=("${UH_SUID_SAFELIST[@]}")

    local removed=0
    # NUL-separated so each name is one whole path.
    while IFS= read -r -d '' bin; do
        local keep=false
        for s in "${safe[@]}"; do
            [[ "$bin" == "$s" ]] && { keep=true; break; }
        done
        if [[ "$keep" == false ]]; then
            suid_path_is_root_controlled "$bin" || {
                log_warning "  not stripped, path is not under root's sole control (review by hand): $bin"; continue; }
            chmod u-s "$bin" 2>/dev/null && { log_info "  stripped SUID: $bin"; bump removed; } || true
        fi
    done < <(find / -xdev -perm -4000 -type f -print0 2>/dev/null)

    log_success "SUID removed from $removed binaries (restore: --revert-suid)"
    count_fix
}

# --- 10. AIDE ----------------------------------------------------------------
# A stopped init leaves an empty database, and AIDE cannot compare against a
# truncated one. A database may be gzipped under either name, so test the content.
aide_database_is_valid() {
    local db="$1"
    [[ -s "$db" ]] || return 1
    command -v gzip >/dev/null 2>&1 || return 0
    gzip -t < "$db" >/dev/null 2>&1 && return 0
    grep -aq '^@@begin_db' "$db" || return 1
    # AIDE 0.16 (RHEL 8, openSUSE Leap 15) writes no end marker in a plain database.
    grep -aq '^@@end_db' "$db" || grep -aqi '^# This file was generated by Aide, version 0\.1[0-6]\b' "$db"
}

apply_aide() {
    log_message "${SHIELD} [10/23] AIDE File Integrity"
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would install AIDE and initialise its baseline database"
        return 0
    fi

    # Arch has no repo package, so pacman fails even when an AUR build is
    # already installed. Only ask the package manager when aide is absent.
    if ! command -v aide >/dev/null 2>&1 && ! install_package aide; then
        if [[ "${DISTRO_TYPE:-}" == arch ]]; then
            log_warning "AIDE is not packaged in the Arch repositories — install it from the AUR, then run this module again. Skipping"
        else
            log_warning "AIDE unavailable — skipping"
        fi
        return 0
    fi

    # A rebuild would accept every change since the last one, unread. Replacing a
    # good baseline is left to --aide-refresh, which shows the changes first.
    local existing_db
    for existing_db in /var/lib/aide/aide.db /var/lib/aide/aide.db.gz; do
        if aide_database_is_valid "$existing_db"; then
            log_info "AIDE baseline already present, kept: $existing_db (review and replace it with --aide-refresh)"
            install_aide_daily_check
            return 0
        fi
        if [[ -f "$existing_db" ]]; then
            cp -a "$existing_db" "${existing_db}.bak-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
            log_warning "AIDE database $existing_db is empty or corrupt, rebuilding it (a copy was kept)"
        fi
    done

    log_info "Building AIDE baseline (this can take several minutes)..."
    local init_status=0 new_db="" live_db=""
    if command -v aideinit >/dev/null 2>&1; then
        aideinit >>"$LOG_FILE" 2>&1 || init_status=$?
    else
        aide --init >>"$LOG_FILE" 2>&1 || init_status=$?
    fi
    if (( init_status != 0 )); then
        log_warning "AIDE baseline failed (exit $init_status), any existing database left in place — see $UH_LOG_PATH"
        return 0
    fi
    # aideinit (Debian) writes the uncompressed .new; RHEL-family hosts have
    # no aideinit and aide.conf's own default is a compressed .new.gz — miss
    # that variant and aide.db.gz never exists, so both this module's own
    # compliance tag and the daily cron check above (which reads aide.db.gz)
    # stay broken forever. Found by testing this module for real on Rocky.
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        new_db=/var/lib/aide/aide.db.new; live_db=/var/lib/aide/aide.db
    elif [[ -f /var/lib/aide/aide.db.new.gz ]]; then
        new_db=/var/lib/aide/aide.db.new.gz; live_db=/var/lib/aide/aide.db.gz
    fi
    if [[ -n "$new_db" ]]; then
        if ! aide_database_is_valid "$new_db"; then
            log_warning "AIDE baseline $new_db is empty or corrupt, any existing database left in place — see $UH_LOG_PATH"
            return 0
        fi
        if ! mv "$new_db" "$live_db" 2>/dev/null; then
            log_warning "AIDE baseline could not be moved to $live_db"
            return 0
        fi
    # aideinit may already have put the database in place itself
    elif ! aide_database_is_valid /var/lib/aide/aide.db && ! aide_database_is_valid /var/lib/aide/aide.db.gz; then
        log_warning "AIDE init wrote no usable database in /var/lib/aide — see $UH_LOG_PATH"
        return 0
    fi

    install_aide_daily_check

    log_success "AIDE baseline created, daily integrity check scheduled"
    # aideinit may have put the database in place itself, under either name
    if [[ -z "$live_db" ]]; then
        live_db=/var/lib/aide/aide.db.gz
        aide_database_is_valid /var/lib/aide/aide.db && live_db=/var/lib/aide/aide.db
    fi
    aide_record_fingerprint "$live_db"
    count_fix
}

install_aide_daily_check() {
    if [[ -d /etc/cron.daily ]]; then
        cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/sh
/usr/bin/aide --check 2>&1 | logger -t aide-check
EOF
        chmod +x /etc/cron.daily/aide-check 2>/dev/null || true
    fi
}

# Prints the path AIDE's config gives for database_in or database_out.
aide_config_db_path() {
    local conf="$1" key="$2" dbdir path
    dbdir=$(sed -n 's/^@@define[[:space:]]\+DBDIR[[:space:]]\+\([^[:space:]]*\).*/\1/p' "$conf" | head -n 1 || true)
    path=$(sed -n "s/^${key}=file:\([^[:space:]]*\).*/\1/p" "$conf" | head -n 1 || true)
    path="${path//@@\{DBDIR\}/$dbdir}"
    [[ -n "$path" && "$path" != *'@@'* ]] && printf '%s\n' "$path"
}

# AIDE lists a database's hashes under its path, wrapped over two lines.
aide_report_sha256() {
    local report="$1" db="$2"
    awk -v db="$db" '
        $0 == db { found = 1; next }
        found && /SHA256[[:space:]]*:/ {
            sub(/.*:[[:space:]]*/, ""); hash = $0
            if ((getline) > 0 && $0 !~ /:/) { gsub(/[[:space:]]/, ""); hash = hash $0 }
            print hash; exit
        }' "$report"
}

# AIDE hashes the uncompressed database, so a hash of the file on disk never matches.
aide_database_sha256() {
    zcat -f "$1" 2>/dev/null | openssl dgst -sha256 -binary | base64
}

# --- --aide-refresh: replace the AIDE baseline, only after the changes are read.
# Stopping aide --update leaves an empty database, and moving that over the
# baseline silently ends monitoring, so every step here is checked before the move.
aide_refresh() {
    local conf="" candidate tool live_db new_db stamp report status=0 expected actual answer
    for tool in aide gzip openssl pgrep; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_error "AIDE refresh needs $tool, which is not installed"
            return 1
        fi
    done
    for candidate in /etc/aide/aide.conf /etc/aide.conf /usr/local/etc/aide.conf; do
        [[ -r "$candidate" ]] && { conf="$candidate"; break; }
    done
    if [[ -z "$conf" ]]; then
        log_error "AIDE refresh found no readable aide.conf"
        return 1
    fi
    # AIDE 0.16 (RHEL 8, openSUSE Leap 15) calls database_in just "database".
    live_db=$(aide_config_db_path "$conf" database_in) \
        || live_db=$(aide_config_db_path "$conf" database) || live_db=""
    new_db=$(aide_config_db_path "$conf" database_out) || new_db=""
    if [[ -z "$live_db" || -z "$new_db" ]]; then
        log_error "AIDE refresh could not read database_in and database_out from $conf"
        return 1
    fi
    if pgrep -x aide >/dev/null 2>&1; then
        log_error "AIDE is already running, and a second run would overwrite its database. Try again when it finishes"
        return 1
    fi
    if ! aide_database_is_valid "$live_db"; then
        log_error "No valid AIDE baseline at $live_db to compare against. Restore a backup, or run module 10 to build one"
        return 1
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would run aide --update, show the changes, and replace $live_db only after they are accepted"
        return 0
    fi

    stamp=$(date +%Y%m%d-%H%M%S)
    # aide --update truncates this file on start, even one holding a finished run.
    if [[ -f "$new_db" ]] && ! mv "$new_db" "${new_db}.bak-${stamp}"; then
        log_error "Could not set aside the existing $new_db"
        return 1
    fi
    [[ -f "${new_db}.bak-${stamp}" ]] && log_info "Kept the earlier new database as ${new_db}.bak-${stamp}"

    report=$(mktemp "${TMPDIR:-/tmp}/aide-refresh.XXXXXX") || { log_error "Could not create a report file"; return 1; }
    log_info "Running aide --update. This can take a long time; let it finish..."
    aide --config="$conf" --update > "$report" 2>&1 || status=$?
    # AIDE's exit status is 0-7 when it ran: bits for added, removed and changed.
    if (( status > 7 )); then
        log_error "aide --update failed (exit $status), baseline not changed. Output: $report"
        return 1
    fi
    if ! aide_database_is_valid "$new_db"; then
        log_error "aide --update left $new_db empty or corrupt, baseline not changed. Output: $report"
        return 1
    fi
    expected=$(aide_report_sha256 "$report" "$new_db")
    actual=$(aide_database_sha256 "$new_db") || actual=""
    if [[ -z "$expected" || "$expected" != "$actual" ]]; then
        log_error "$new_db does not match the hash AIDE reported (reported '${expected:-none}', file '$actual'), baseline not changed"
        return 1
    fi

    echo
    grep -E '^[[:space:]]*(Number of entries|Total number of entries|Added entries|Removed entries|Changed entries):[[:space:]]*[0-9]' "$report" || true
    log_info "Full report: $report"
    log_warning "Accepting makes every change in that report the new normal. Read it first."
    answer=""
    read -r -p "Type ACCEPT to replace the baseline: " answer || true
    if [[ "$answer" != ACCEPT ]]; then
        log_info "Baseline not changed. The new database stays at $new_db"
        return 1
    fi

    if ! cp -a "$live_db" "${live_db}.bak-${stamp}"; then
        log_error "Could not back up $live_db, baseline not changed"
        return 1
    fi
    # stat, not --reference, which BusyBox does not have: a new baseline must not end up more open.
    if ! chown "$(stat -c %u:%g "$live_db")" "$new_db" || ! chmod "$(stat -c %a "$live_db")" "$new_db"; then
        log_error "Could not copy the owner and mode of $live_db to $new_db, baseline not changed"
        return 1
    fi
    if ! mv "$new_db" "$live_db"; then
        log_error "Could not move $new_db to $live_db, baseline not changed"
        return 1
    fi
    actual=$(aide_database_sha256 "$live_db") || actual=""
    if [[ "$actual" != "$expected" ]]; then
        log_error "$live_db does not match after the move. Restore ${live_db}.bak-${stamp}"
        return 1
    fi
    log_success "AIDE baseline replaced: $live_db (previous: ${live_db}.bak-${stamp})"
    aide_record_fingerprint "$live_db"
}

# --- AIDE baseline fingerprint ------------------------------------------------
# The hash AIDE reports for its database, recorded each time a baseline is
# accepted. The copy kept here only catches mistakes and changes made without
# root: root can rewrite it together with the database. The copies that count
# leave the machine: syslog (sent on when remote logging is set up), a drive,
# or the owner's own notes, checked later with --aide-verify. It is not secret,
# so it is world-readable, which lets another machine fetch it with plain scp.
: "${UH_STATE_DIR:=/var/lib/ultimate-hardening}"
UH_AIDE_FINGERPRINT_FILE="$UH_STATE_DIR/aide-fingerprint"
UH_AIDE_DESTINATION_FILE="$UH_STATE_DIR/aide-fingerprint-destination"
UH_AIDE_SYSLOG_TAG="uh-aide-fingerprint"
UH_AIDE_HASH_RE='^[A-Za-z0-9+/]{43}=$'

# Tests replace this to drive the prompt without a terminal.
_uh_stdin_is_terminal() { [[ -t 0 ]]; }

# Prints the database AIDE compares against, from the first readable aide.conf.
aide_live_database() {
    local candidate db=""
    for candidate in /etc/aide/aide.conf /etc/aide.conf /usr/local/etc/aide.conf; do
        [[ -r "$candidate" ]] || continue
        # AIDE 0.16 (RHEL 8, openSUSE Leap 15) calls database_in just "database".
        db=$(aide_config_db_path "$candidate" database_in) \
            || db=$(aide_config_db_path "$candidate" database) || db=""
        [[ -n "$db" ]] || return 1
        printf '%s\n' "$db"
        return 0
    done
    return 1
}

# Records the fingerprint of a baseline that was just accepted, then offers to
# copy it off the machine. The baseline is already in place, so a problem here
# is a warning and never fails the run.
aide_record_fingerprint() {
    local db="$1" hash host recorded_at tmp
    hash=$(aide_database_sha256 "$db") || hash=""
    if [[ ! "$hash" =~ $UH_AIDE_HASH_RE ]]; then
        log_warning "Could not hash $db, so no AIDE fingerprint was recorded"
        return 0
    fi
    host=$(uname -n)
    recorded_at=$(date '+%Y-%m-%dT%H:%M:%S%z')
    if [[ -L "$UH_STATE_DIR" ]] || ! mkdir -p "$UH_STATE_DIR" 2>/dev/null; then
        log_warning "Could not use $UH_STATE_DIR, so the AIDE fingerprint was not saved on this machine"
    elif ! tmp=$(mktemp "$UH_STATE_DIR/.aide-fingerprint.XXXXXX"); then
        log_warning "Could not write in $UH_STATE_DIR, so the AIDE fingerprint was not saved on this machine"
    elif ! {
            echo "# AIDE baseline fingerprint, recorded by Ultimate Hardening when the baseline was accepted."
            echo "# Keep a copy off this machine and check it with: --aide-verify <this file>"
            echo "host=$host"
            echo "date=$recorded_at"
            echo "database=$db"
            echo "sha256=$hash"
        } > "$tmp" || ! chmod 644 "$tmp" || ! mv -f "$tmp" "$UH_AIDE_FINGERPRINT_FILE"; then
        rm -f "$tmp"
        log_warning "Could not save the AIDE fingerprint to $UH_AIDE_FINGERPRINT_FILE"
    fi
    # A umask such as 027 creates the folder closed to other accounts, and the
    # scp below logs in as one. Search only, so its contents still can't be listed.
    if [[ -d "$UH_STATE_DIR" && ! -L "$UH_STATE_DIR" ]]; then
        chmod a+x "$UH_STATE_DIR" 2>/dev/null || true
    fi
    if command -v logger >/dev/null 2>&1; then
        logger -t "$UH_AIDE_SYSLOG_TAG" -- "host=$host database=$db sha256=$hash" 2>/dev/null || true
    fi

    echo
    log_success "AIDE baseline fingerprint: $hash"
    log_info "Keep a copy somewhere other than this machine. Check the baseline against it with:"
    log_info "  --aide-verify $hash"
    if [[ -f "$UH_AIDE_FINGERPRINT_FILE" ]]; then
        log_info "To fetch it from another machine, run this there:"
        log_info "  scp $(aide_scp_source):$UH_AIDE_FINGERPRINT_FILE ./aide-fingerprint-$host-$(date +%Y%m%d-%H%M).txt"
        aide_save_fingerprint_offbox "$db"
    fi
    return 0
}

# Prints user@address for the scp hint. The hostname alone may not resolve from
# another machine, and root usually can't log in over ssh, so it names the
# account that ran sudo and this machine's first address.
aide_scp_source() {
    local address
    address=$(hostname -I 2>/dev/null | awk '{print $1}') || address=""
    # Arch's inetutils and busybox hostname have no -I; iproute2/busybox ip do.
    [[ -n "$address" ]] || address=$(ip -o addr show scope global 2>/dev/null \
        | awk '$3 == "inet" || $3 == "inet6" { sub(/\/.*/, "", $4); print $4; exit }') || address=""
    [[ -n "$address" ]] || address=$(uname -n)
    [[ "$address" == *:* ]] && address="[$address]"   # scp needs IPv6 in brackets
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
        printf '%s@%s\n' "$SUDO_USER" "$address"
    else
        printf '%s\n' "$address"
    fi
}

# Prints the saved drive folder, only if it still passes the checks a typed one would.
aide_saved_destination() {
    local saved
    [[ -f "$UH_AIDE_DESTINATION_FILE" && ! -L "$UH_AIDE_DESTINATION_FILE" ]] || return 1
    saved=$(head -n 1 "$UH_AIDE_DESTINATION_FILE" 2>/dev/null) || return 1
    [[ "$saved" == /* && "$saved" != *[[:cntrl:]]* ]] || return 1
    printf '%s\n' "$saved"
}

aide_remember_destination() {
    local dir="$1" tmp
    tmp=$(mktemp "$UH_STATE_DIR/.aide-destination.XXXXXX") || return 1
    printf '%s\n' "$dir" > "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$UH_AIDE_DESTINATION_FILE" || return 1
    if command -v logger >/dev/null 2>&1; then
        logger -t "$UH_AIDE_SYSLOG_TAG" -- "fingerprint destination set to $dir" 2>/dev/null || true
    fi
    log_info "Saved $dir as the fingerprint folder for later runs"
}

# True when DIR is on the filesystem holding / or the AIDE database: an
# unmounted drive leaves its empty mount folder there, and a copy kept on this
# machine gives no protection if the machine is compromised.
aide_on_system_disk() {
    local dir="$1" db="$2" dev
    dev=$(stat -c %d "$dir" 2>/dev/null) || return 0
    [[ "$dev" == "$(stat -c %d / 2>/dev/null)" ]] && return 0
    [[ "$dev" == "$(stat -c %d "$(dirname "$db")" 2>/dev/null)" ]]
}

# Copies the fingerprint into DIR as a new file. Never writes over an existing
# one: on a drive a non-root account owns, a planted link could otherwise make
# root write over a system file. noclobber opens a new name with O_EXCL, which
# also refuses a link.
aide_copy_fingerprint_to() {   # <dir> <database> <interactive: true|false>
    local dir="${1%/}" db="$2" interactive="$3" host target attempt reply
    if [[ "$dir" != /* || "$dir" == *[[:cntrl:]]* ]]; then
        log_warning "Fingerprint folder must be an absolute path: $dir"
        return 1
    fi
    if [[ ! -d "$dir" || ! -w "$dir" ]]; then
        log_warning "Fingerprint folder is missing or not writable (is the drive plugged in and mounted?): $dir"
        return 1
    fi
    if aide_on_system_disk "$dir" "$db"; then
        if [[ "$interactive" != true ]]; then
            log_warning "Fingerprint not copied: $dir is on this machine's own disk (is the drive mounted?)"
            return 1
        fi
        log_warning "$dir is on this machine's own disk, so a copy there gives no protection if this machine is compromised"
        reply=""
        read -r -p "Save here anyway? (y/N): " reply || true
        [[ "$reply" =~ ^[Yy] ]] || return 1
    fi
    host=$(uname -n)
    for attempt in 1 2 3 4 5; do
        target="$dir/aide-fingerprint-$host-$(date +%Y%m%d-%H%M%S)-$RANDOM.txt"
        if ( set -C; cat "$UH_AIDE_FINGERPRINT_FILE" > "$target" ) 2>/dev/null; then
            sync "$target" 2>/dev/null || sync
            # compared in bash: cmp is in diffutils, which minimal RHEL-family images lack
            if [[ "$(< "$target")" == "$(< "$UH_AIDE_FINGERPRINT_FILE")" ]]; then
                log_success "Fingerprint saved to $target"
                log_info "Unmount the drive before unplugging it"
                return 0
            fi
            log_warning "The copy at $target does not read back the same; the drive may be failing"
            return 1
        fi
    done
    log_warning "Could not create a new file in $dir"
    return 1
}

# Asks for a drive folder, or reuses the one saved last time. Unattended runs
# use the saved folder without asking, and skip when there is none.
aide_save_fingerprint_offbox() {
    local db="$1" saved="" answer dir
    saved=$(aide_saved_destination) || saved=""
    if [[ "$AUTO_MODE" == true ]] || ! _uh_stdin_is_terminal; then
        if [[ -n "$saved" ]]; then
            aide_copy_fingerprint_to "$saved" "$db" false || true
        fi
        return 0
    fi
    while :; do
        answer=""
        if [[ -n "$saved" ]]; then
            echo "Fingerprint folder: $saved"
            read -r -p "Press Enter to save a copy there, type a new folder to replace it, or type skip: " answer || return 0
        else
            read -r -p "Save a copy of the fingerprint to another drive? Enter a folder, or press Enter to skip: " answer || return 0
        fi
        [[ "$answer" == skip || ( -z "$answer" && -z "$saved" ) ]] && return 0
        dir="${answer:-$saved}"
        if aide_copy_fingerprint_to "$dir" "$db" true; then
            if [[ "${dir%/}" != "$saved" ]] && ! aide_remember_destination "${dir%/}"; then
                log_warning "Could not save $dir for later runs"
            fi
            return 0
        fi
    done
}

# --aide-fingerprint: records the current baseline, for one accepted without
# --aide-refresh (by hand, or before this version).
aide_fingerprint_current() {
    local db
    db=$(aide_live_database) || { log_error "Could not find AIDE's database in its config"; return 1; }
    if ! aide_database_is_valid "$db"; then
        log_error "No valid AIDE baseline at $db"
        return 1
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would record the fingerprint of $db and offer to copy it to a drive"
        return 0
    fi
    log_warning "This records $db as the trusted baseline. Do it only after reading the AIDE report it came from."
    confirm "Record the fingerprint of $db?" || { log_info "Nothing recorded"; return 1; }
    aide_record_fingerprint "$db"
}

# --aide-verify: compares the live database with a fingerprint kept elsewhere,
# given as the hash or as a saved fingerprint file. Exit 0 = matches,
# 1 = does not match, 2 = could not check.
aide_verify() {
    local given="$1" expected="" file_host="" db actual
    if [[ -f "$given" ]]; then
        expected=$(sed -n 's/^sha256=//p' "$given" | head -n 1 || true)
        file_host=$(sed -n 's/^host=//p' "$given" | head -n 1 || true)
        if [[ -n "$file_host" && "$file_host" != "$(uname -n)" ]]; then
            log_error "That fingerprint is for $file_host, not $(uname -n)"
            return 2
        fi
    else
        expected="$given"
    fi
    if [[ ! "$expected" =~ $UH_AIDE_HASH_RE ]]; then
        log_error "Not a fingerprint: give the sha256 value printed when the baseline was accepted, or a saved fingerprint file"
        return 2
    fi
    db=$(aide_live_database) || { log_error "Could not find AIDE's database in its config"; return 2; }
    if ! aide_database_is_valid "$db"; then
        log_error "No valid AIDE baseline at $db"
        return 2
    fi
    actual=$(aide_database_sha256 "$db") || actual=""
    if [[ "$actual" == "$expected" ]]; then
        log_success "AIDE baseline $db matches the fingerprint"
        return 0
    fi
    log_error "AIDE baseline $db does NOT match the fingerprint (now $actual). It changed after that fingerprint was recorded: find out why before trusting AIDE's reports, or restore a backup"
    return 1
}

# --- 11. rkhunter ------------------------------------------------------------
apply_rkhunter() {
    log_message "${SHIELD} [11/23] Rootkit Scanner"
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
    log_message "${GEAR} [12/23] Disable Unnecessary Services"
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
# AppArmor profiles that were in complain mode before this module, recorded
# once in genesis so revert can put exactly those back. Lines are
# "file|<profile>" (complain set in the profile's flags; the file itself is
# backed up) or "link|<force-complain link>|<profile>". Earlier releases ran
# aa-enforce on everything in /etc/apparmor.d with no record, and the only
# advice for undoing it, aa-complain on everything, would also have weakened
# profiles that were enforcing before.
UH_APPARMOR_RECORD_NAME=apparmor_complain_before.txt

_apparmor_dir() { echo "${UH_APPARMOR_DIR:-/etc/apparmor.d}"; }   # test hook

# Prints the record lines for the profiles in complain mode right now.
_apparmor_complain_entries() {
    local dir f l; dir=$(_apparmor_dir)
    for f in "$dir"/*; do
        [[ -f "$f" && ! -L "$f" ]] || continue
        grep -qE 'flags=\([^)]*complain' "$f" 2>/dev/null && echo "file|$f"
    done
    for l in "$dir"/force-complain/*; do
        [[ -L "$l" ]] && echo "link|$l|$(readlink "$l")"
    done
    return 0
}

# Switch the profiles in complain mode to enforce, recording each first.
_apparmor_enforce_complain_profiles() {
    local rec="$BACKUP_GENESIS_DIR/$UH_APPARMOR_RECORD_NAME" entry kind path target
    local -a profiles=()
    while IFS= read -r entry; do
        IFS='|' read -r kind path target <<<"$entry"
        if [[ "$SKIP_BACKUP" != true ]] && ! grep -qxF "$entry" "$rec" 2>/dev/null; then
            ( umask 077; mkdir -p "$BACKUP_GENESIS_DIR" ) 2>/dev/null
            printf '%s\n' "$entry" >> "$rec" 2>/dev/null \
                || log_warning "Could not record that $path was in complain mode — revert will not put it back"
        fi
        if [[ "$kind" == file ]]; then
            backup_file "$path"
            profiles+=("$path")
        else
            # A relative link target is relative to force-complain/.
            [[ "$target" == /* ]] || target="$(dirname "$path")/$target"
            profiles+=("$target")
        fi
    done < <(_apparmor_complain_entries)
    if (( ${#profiles[@]} == 0 )); then
        log_info "  no AppArmor profile was in complain mode"
        return 0
    fi
    aa-enforce "${profiles[@]}" >>"$LOG_FILE" 2>&1 || true
    log_info "  ${#profiles[@]} profile(s) moved from complain to enforce"
}

# Put back complain mode on exactly the profiles that had it before hardening.
undo_apparmor_enforce() {
    local rec="$BACKUP_GENESIS_DIR/$UH_APPARMOR_RECORD_NAME" kind path target restored=0
    if [[ -f "$rec" ]]; then
        while IFS='|' read -r kind path target; do
            if [[ "$kind" == file ]]; then
                revert_backed_up_file "$path" >/dev/null 2>&1 || continue
                apparmor_parser -r "$path" >>"$LOG_FILE" 2>&1 || true
            elif [[ "$kind" == link && -n "$target" ]]; then
                [[ -e "$path" || -L "$path" ]] || ln -s "$target" "$path" 2>/dev/null || continue
                local profile="$target"
                [[ "$profile" == /* ]] || profile="$(dirname "$path")/$profile"
                apparmor_parser -r -C "$profile" >>"$LOG_FILE" 2>&1 || true
            else
                continue
            fi
            bump restored
        done < "$rec"
        log_success "AppArmor: $restored profile(s) back in complain mode, as before hardening"
    else
        log_info "AppArmor: no record of profiles in complain mode — either none were, or they were changed by a release that kept no record. Nothing changed."
    fi
    restore_service_state apparmor
}

apply_apparmor() {
    log_message "${SHIELD} [13/23] Mandatory Access Control"

    if ! is_linux; then
        log_warning "AppArmor/SELinux are Linux-specific — skipping on ${DISTRO_TYPE}"
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would set AppArmor profiles in complain mode to enforce (recorded for revert), or SELinux to enforcing"
        return 0
    fi

    if command -v aa-status >/dev/null 2>&1; then
        record_service_state apparmor
        install_package apparmor-utils || true
        enable_service apparmor
        command -v aa-enforce >/dev/null 2>&1 && _apparmor_enforce_complain_profiles
        # enable_service logs "enabled" unconditionally — verify apparmor is
        # actually running before claiming profiles are enforced, same as
        # apply_fail2ban.
        if is_service_active apparmor; then
            log_success "AppArmor enabled, profiles set to enforce"
            count_fix
        else
            log_warning "AppArmor profiles were set but the service is not running — check: $(service_status_hint apparmor)"
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
    log_message "${GEAR} [14/23] /etc Version Control"
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
    log_message "${LOCK} [15/23] Boot Security"

    if ! is_linux; then
        log_warning "GRUB hardening is Linux-specific — skipping on ${DISTRO_TYPE}"
        return 0
    fi
    # UH_USB_STORAGE_BLACKLIST=false leaves USB storage usable (for hosts that
    # need USB disks). Anything other than true/false keeps the blacklist.
    local usb_bl="${UH_USB_STORAGE_BLACKLIST:-true}"
    if [[ "$usb_bl" != true && "$usb_bl" != false ]]; then
        log_warning "UH_USB_STORAGE_BLACKLIST='$usb_bl' is not true/false — keeping the USB storage blacklist"
        usb_bl=true
    fi
    if [[ "$DRY_RUN" == true ]]; then
        if [[ "$usb_bl" == true ]]; then
            log_dry "Would restrict GRUB config permissions and blacklist USB storage"
        else
            log_dry "Would restrict GRUB config permissions (USB storage blacklist off: UH_USB_STORAGE_BLACKLIST=false)"
        fi
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

    # UH_MODPROBE_DIR is a test hook (see test_kmod_blacklist.sh); unset it is
    # /etc/modprobe.d.
    local md="${UH_MODPROBE_DIR:-/etc/modprobe.d}"
    if [[ "$usb_bl" == false ]]; then
        log_info "  USB storage blacklist skipped (UH_USB_STORAGE_BLACKLIST=false)"
        [[ -f "$md/99-hardening-usb.conf" ]] && \
            log_warning "  An earlier run's USB storage blacklist is still in place — revert this module to remove it"
    elif [[ -d "$md" ]]; then
        cat > "$md/99-hardening-usb.conf" << 'EOF'
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
    log_message "${LOCK} [16/23] GRUB Password ${RED}(HIGH RISK)${NC}"

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
    log_message "${GEAR} [17/23] Docker Security"

    if ! command -v docker >/dev/null 2>&1; then
        log_warning "Docker is not installed — skipping Docker hardening"
        return 0
    fi
    local conf="${UH_DOCKER_CONF:-/etc/docker/daemon.json}"   # UH_DOCKER_CONF: test hook
    if [[ "$DRY_RUN" == true ]]; then
        _docker_preview "$conf"
        return 0
    fi
    confirm "Apply Docker daemon hardening?" || { log_info "Skipped Docker security"; return 0; }

    local with_userns=yes
    if ! _docker_userns_allowed "$conf"; then
        with_userns=no
        log_warning "Docker: userns-remap left off — this host already has containers, images or volumes (or Docker is not running, so that cannot be checked), and turning it on would hide them. Turn it on by hand once they are moved, if you want it."
    fi
    _docker_warn_default_bridge

    create_backup_dir
    backup_file "$conf"
    mkdir -p "$(dirname "$conf")" 2>/dev/null || true
    # Merged into the existing file rather than replacing it: an admin's own
    # settings (storage location, registry mirrors, DNS) were lost otherwise.
    if [[ -s "$conf" ]] && grep -q '[^[:space:]]' "$conf"; then
        local merged
        if ! merged=$(_docker_merge_json "$conf" "$with_userns"); then
            log_warning "Docker: $conf could not be merged (not valid JSON, or python3 is missing) — left unchanged. Add by hand: \"icc\": false, \"live-restore\": true, log rotation"
            return 0
        fi
        printf '%s\n' "$merged" > "$conf"
    else
        _docker_daemon_json "$with_userns" > "$conf"
    fi

    # Restarting stops running containers unless live-restore is already on
    # in the daemon that is running now.
    local stopped; stopped=$(_docker_containers_a_restart_stops)
    if (( stopped > 0 )); then
        log_warning "Docker: not restarted — $stopped running container(s) would be stopped. The new daemon.json applies at the next Docker restart, when it suits you."
    else
        restart_service docker || log_warning "Could not restart docker — the new daemon.json applies on next restart"
    fi
    log_success "Docker daemon hardened"
    count_fix
    return 0
}

# userns-remap makes Docker keep everything in a separate folder, so the
# containers, images and volumes a host already has disappear from view until
# it is turned off again. $1 = daemon.json. True where it is already set (the
# merge keeps it) or Docker holds nothing yet.
_docker_userns_allowed() {
    grep -q '"userns-remap"' "$1" 2>/dev/null || ! _docker_has_data
}

# Prints how many running containers a Docker restart would stop: none when
# live-restore is already on in the daemon running now.
_docker_containers_a_restart_stops() {
    local running; running=$(docker ps -q 2>/dev/null | wc -l)
    if (( running > 0 )) && [[ "$(docker info --format '{{.LiveRestoreEnabled}}' 2>/dev/null)" != true ]]; then
        echo "$running"
    else
        echo 0
    fi
}

# "icc": false stops containers on Docker's default bridge network reaching
# each other; user-defined networks are not affected. Warns when two or more
# running containers share that network, since they may rely on it.
_docker_warn_default_bridge() {
    local on_bridge
    on_bridge=$(docker network inspect bridge --format '{{len .Containers}}' 2>/dev/null) || return 0
    [[ "$on_bridge" =~ ^[0-9]+$ ]] && (( on_bridge >= 2 )) || return 0
    log_warning "Docker: $on_bridge running containers share the default bridge network. With inter-container traffic off they can no longer reach each other there once Docker restarts. Move any that talk to each other to a user-defined network (docker network create) first."
}

# --dry-run: what a real run would do on THIS host, from the same read-only
# checks it makes. $1 = daemon.json.
_docker_preview() {
    local conf="$1" stopped
    log_dry "Would merge hardening into $conf (inter-container traffic off on the default bridge, log rotation, live-restore)"
    if _docker_userns_allowed "$conf"; then
        log_dry "  userns-remap: would be turned on (Docker holds no containers, images or volumes yet)"
    else
        log_dry "  userns-remap: would be left off — Docker already holds data it would hide, or is not running"
    fi
    stopped=$(_docker_containers_a_restart_stops)
    if (( stopped > 0 )); then
        log_dry "  Docker would not be restarted: $stopped running container(s) would stop. The change would wait for the next Docker restart."
    else
        log_dry "  Docker would be restarted (no running container would stop)"
    fi
    _docker_warn_default_bridge
}

# Does Docker already hold containers, images or volumes? When Docker is not
# running this cannot be told, so it answers yes, the safe side.
_docker_has_data() {
    docker info >/dev/null 2>&1 || return 0
    [[ -n "$(docker ps -aq 2>/dev/null)$(docker images -q 2>/dev/null)$(docker volume ls -q 2>/dev/null)" ]]
}

# $1 = existing daemon.json, $2 = yes|no: add userns-remap. Prints the merged
# JSON: the admin's keys are kept, this module's are added, and a log driver
# the admin chose is left alone.
_docker_merge_json() {
    command -v python3 >/dev/null 2>&1 || return 1
    python3 -I - "$1" "$2" << 'PY'
import json, sys
path, userns = sys.argv[1], sys.argv[2]
with open(path) as f:
    cfg = json.load(f)
if not isinstance(cfg, dict):
    sys.exit(1)
cfg["icc"] = False
cfg["live-restore"] = True
if userns == "yes":
    cfg.setdefault("userns-remap", "default")
if "log-driver" not in cfg:
    cfg["log-driver"] = "json-file"
    cfg.setdefault("log-opts", {"max-size": "10m", "max-file": "3"})
print(json.dumps(cfg, indent=2))
PY
}

# $1 = yes|no: include userns-remap (default yes).
_docker_daemon_json() {
    echo '{'
    [[ "${1:-yes}" == yes ]] && echo '  "userns-remap": "default",'
    cat << 'EOF'
  "icc": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true
}
EOF
}

# What a module writes to a file whose name it shares with the admin's own
# configuration (see UH_SHARED_WRITTEN_PATHS in lib/core.sh).
tool_written_content() {
    case "$1" in
        /etc/fail2ban/jail.local) _fail2ban_jail_local ;;
        /etc/issue.net) _ssh_issue_net_banner ;;
        /etc/docker/daemon.json)
            # Written with or without userns-remap (see apply_docker_security).
            if grep -q '"userns-remap"' "$1" 2>/dev/null; then _docker_daemon_json yes; else _docker_daemon_json no; fi ;;
        *) return 1 ;;
    esac
}

# --- 18. ModSecurity WAF -----------------------------------------------------
# Web-application firewall. Only relevant on a host actually serving web
# traffic, so it stays opt-in and reports N/A-style skips rather than
# installing Apache onto a machine that has none.
apply_modsecurity() {
    log_message "${SHIELD} [18/23] ModSecurity WAF"

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
# here rather than two.
#
# `install X /bin/false` stops an on-demand autoload; `blacklist X` stops a
# load by name. CIS asks for both, and either alone leaves a way in.
# dccp, sctp, rds, tipc: CIS 3.2.1-3.2.4 (sctp and tipc also STIG
# RHEL-09-213060/213065). atm, can: STIG RHEL-09-213045/213050.
UH_BLACKLIST_PROTOCOLS=(dccp sctp rds tipc atm can)
# Hardware buses an attacker with physical access reaches the kernel through.
# firewire-core: STIG RHEL-09-213055. bluetooth: STIG RHEL-09-291035, opt-in
# (UH_BLACKLIST_BLUETOOTH=true) because laptops and desktops use it.
UH_BLACKLIST_HARDWARE=(firewire-core)
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

# The hardware modules this run blacklists: the default set, plus bluetooth
# when UH_BLACKLIST_BLUETOOTH=true.
_kmod_hardware_wanted() {
    local bt="${UH_BLACKLIST_BLUETOOTH:-false}"
    if [[ "$bt" != true && "$bt" != false ]]; then
        log_warning "UH_BLACKLIST_BLUETOOTH='$bt' is not true/false — leaving bluetooth loadable" >&2
        bt=false
    fi
    printf '%s\n' "${UH_BLACKLIST_HARDWARE[@]}"
    [[ "$bt" == true ]] && echo bluetooth
    return 0
}

apply_unused_protocols() {
    log_message "${GEAR} [19/23] Disable Unused Kernel Modules"

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
    local -a hw_wanted=()
    mapfile -t hw_wanted < <(_kmod_hardware_wanted)

    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would blacklist ${#UH_BLACKLIST_PROTOCOLS[@]} unused protocols (${UH_BLACKLIST_PROTOCOLS[*]})"
        log_dry "Would blacklist ${#fs_wanted[@]} uncommon filesystems (${fs_wanted[*]})"
        [[ ${#fs_skipped[@]} -gt 0 ]] && \
            log_dry "Would leave ${fs_skipped[*]} alone (snapd present — blacklisting it would break every snap)"
        log_dry "Would blacklist ${#hw_wanted[@]} hardware bus module(s) (${hw_wanted[*]})"
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

    backup_file "$md/disable-unused-hardware.conf"
    {
        echo "# Written by Ultimate Hardening — hardware buses (STIG RHEL-09-213055, RHEL-09-291035)."
        for fs in "${hw_wanted[@]}"; do
            echo "install $fs /bin/false"
            echo "blacklist $fs"
        done
    } > "$md/disable-unused-hardware.conf"

    # Blacklisting stops the NEXT autoload; it does not unload what is already
    # resident. Unload the ones nothing is using so the running kernel matches
    # the file, and say so plainly about the ones still in use.
    local -a still_loaded=()
    for fs in "${UH_BLACKLIST_PROTOCOLS[@]}" "${fs_wanted[@]}" "${hw_wanted[@]}"; do
        # /proc/modules spells modules with underscores (firewire_core).
        grep -qE "^${fs//-/_}[[:space:]]" /proc/modules 2>/dev/null || continue
        if _kmod_in_use "${fs//-/_}"; then
            still_loaded+=("$fs")
        elif ! modprobe -r "$fs" >>"$LOG_FILE" 2>&1; then
            still_loaded+=("$fs")
        fi
    done

    log_success "Kernel modules blacklisted: ${#UH_BLACKLIST_PROTOCOLS[@]} protocols (${UH_BLACKLIST_PROTOCOLS[*]}), ${#fs_wanted[@]} filesystems (${fs_wanted[*]}), ${#hw_wanted[@]} hardware (${hw_wanted[*]})"
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
    log_message "${GEAR} [20/23] Compiler Access Restriction"

    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would restrict gcc/g++/clang/clang++/cc/c++ to root only (chmod 700)"
        return 0
    fi
    confirm "Restrict compiler access to root only?" || { log_info "Skipped compiler restriction"; return 0; }

    create_backup_dir
    local inventory="$BACKUP_DIR/compiler_original_perms.txt"
    local restricted=0 path seen=" "
    for compiler in gcc g++ clang clang++ cc c++; do
        path=$(command -v "$compiler" 2>/dev/null) || continue
        [[ -n "$path" ]] || continue
        # cc, c++ and on Debian gcc itself are symlinks. A symlink's own mode
        # is always 777, and recording that let the revert chmod 777 the real
        # compiler, so record and restrict the binary the link points at.
        path=$(readlink -f "$path" 2>/dev/null) || continue
        [[ "$seen" == *" $path "* ]] && continue
        seen+="$path "
        suid_path_is_root_controlled "$path" || {
            log_warning "  not restricted, path is not under root's sole control: $path"; continue; }
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
    log_message "${NET_ICON} [21/23] Remote Syslog"

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
        local bad_path='[[:cntrl:]"\\]'
        if [[ "$ca" =~ $bad_path || "$ca_dir" =~ $bad_path ]]; then
            log_error "Refusing CA path with quotes, backslashes or control characters — it is written into rsyslog.conf; nothing changed"
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
    log_message "${LOCK} [22/23] UMASK Hardening"

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

# --- 23. Base system: /dev/shm, time sync, sudo -----------------------------
# Three small CIS items with no module of their own. Each part can be left
# out with UH_SKIP_SETTINGS: dev_shm, time_sync, use_pty, logfile.

# /dev/shm mount options. CIS Ubuntu 22.04 / RHEL 9 1.1.2.2.2-1.1.2.2.4,
# STIG RHEL-09-231110/231115/231120. noexec breaks the few programs that run
# code from shared memory; skip it with UH_SKIP_SETTINGS=dev_shm.
UH_SHM_OPTIONS="nodev,nosuid,noexec"
UH_SHM_RECORD_NAME=shm_options_before.txt
UH_FSTAB="${UH_FSTAB:-/etc/fstab}"   # test hook

# The live mount options of /dev/shm, or nothing when it is not mounted.
_shm_live_options() {
    local out; out=$(findmnt -no OPTIONS /dev/shm 2>/dev/null || true)
    printf '%s' "${out%%$'\n'*}"
}

# True when $1 (comma list) holds nodev, nosuid and noexec.
_shm_options_hardened() {
    local opt
    for opt in ${UH_SHM_OPTIONS//,/ }; do
        [[ ",$1," == *",$opt,"* ]] || return 1
    done
}

# Prints fstab with the /dev/shm line carrying the hardened options: an
# existing line gets the missing ones added, otherwise one is appended.
_shm_fstab_rewritten() {
    awk -v want="$UH_SHM_OPTIONS" '
        !/^[[:space:]]*#/ && $2 == "/dev/shm" {
            n = split(want, w, ",")
            for (i = 1; i <= n; i++) if (("," $4 ",") !~ ("," w[i] ",")) $4 = $4 "," w[i]
            found = 1
        }
        { print }
        END {
            if (!found) {
                print "# Ultimate Hardening: /dev/shm without devices, setuid or executables (CIS 1.1.2.2)"
                print "tmpfs /dev/shm tmpfs defaults," want " 0 0"
            }
        }' "$UH_FSTAB"
}

# Errors findmnt --verify reports for the fstab given, or nothing where
# findmnt has no --verify (util-linux before 2.29, busybox).
_fstab_error_count() {
    findmnt --verify --tab-file "$1" >/dev/null 2>&1 && { echo 0; return 0; }
    findmnt --verify --tab-file "$1" 2>&1 | grep -c '^[[:space:]]*\[E\]' || true
}

_harden_dev_shm() {
    if setting_skipped dev_shm; then
        log_info "  Left /dev/shm as it is (UH_SKIP_SETTINGS)"
        return 1
    fi
    local live; live=$(_shm_live_options)
    if [[ -z "$live" ]]; then
        log_info "  /dev/shm is not mounted here — nothing to do"
        return 1
    fi
    if _shm_options_hardened "$live" && grep -qE '^[^#]*[[:space:]]/dev/shm[[:space:]].*noexec' "$UH_FSTAB" 2>/dev/null; then
        log_info "  /dev/shm already mounted nodev,nosuid,noexec"
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would mount /dev/shm $UH_SHM_OPTIONS (fstab line, then remount)"
        return 0
    fi

    # The options before the first run, for revert's remount.
    local rec="$BACKUP_GENESIS_DIR/$UH_SHM_RECORD_NAME"
    if [[ "$SKIP_BACKUP" != true && ! -f "$rec" ]]; then
        ( umask 077; mkdir -p "$BACKUP_GENESIS_DIR" ) 2>/dev/null
        printf '%s\n' "$live" > "$rec" 2>/dev/null || true
    fi

    backup_file "$UH_FSTAB"
    local tmp before after
    tmp=$(mktemp) || return 1
    _shm_fstab_rewritten > "$tmp"
    before=$(_fstab_error_count "$UH_FSTAB"); after=$(_fstab_error_count "$tmp")
    if (( after > before )); then
        log_warning "  /dev/shm: the new fstab line fails findmnt --verify — fstab left as it was"
        rm -f "$tmp"
        return 1
    fi
    cat "$tmp" > "$UH_FSTAB"; rm -f "$tmp"
    relabel_path "$UH_FSTAB"

    if mount -o "remount,$UH_SHM_OPTIONS" /dev/shm >>"$LOG_FILE" 2>&1; then
        log_success "  /dev/shm mounted $UH_SHM_OPTIONS"
    else
        log_warning "  /dev/shm: fstab updated, but the remount failed — the options apply at the next boot"
    fi
    return 0
}

# Revert's remount: back to the options recorded before the first run.
restore_shm_options() {
    local rec="$BACKUP_GENESIS_DIR/$UH_SHM_RECORD_NAME" before opts="" opt
    [[ -f "$rec" ]] || return 0
    before=$(head -1 "$rec")
    for opt in nodev:dev nosuid:suid noexec:exec; do
        if [[ ",$before," == *",${opt%%:*},"* ]]; then opts+="${opt%%:*},"; else opts+="${opt##*:},"; fi
    done
    mount -o "remount,${opts%,}" /dev/shm >>"$LOG_FILE" 2>&1 \
        && log_success "Remounted /dev/shm with its earlier options (${opts%,})" \
        || log_warning "Could not remount /dev/shm; its earlier options return at the next boot"
}

# Time sync. CIS Ubuntu 22.04 2.3.1.1 (one time sync daemon), STIG
# RHEL-09-252010-252025 (chrony). A daemon already running is kept; with none,
# systemd-timesyncd is enabled where it exists, chrony installed otherwise.
UH_TIME_DAEMONS="chronyd chrony systemd-timesyncd ntpd ntp ntpsec openntpd"

_time_sync_running() {
    local svc
    for svc in $UH_TIME_DAEMONS; do
        is_service_active "$svc" && { echo "$svc"; return 0; }
    done
    return 1
}

_has_timesyncd() {
    _has_systemd && [[ -n "$(systemctl list-unit-files systemd-timesyncd.service --no-legend 2>/dev/null)" ]]
}

_enable_time_sync() {
    if setting_skipped time_sync; then
        log_info "  Left time sync as it is (UH_SKIP_SETTINGS)"
        return 1
    fi
    local running
    if running=$(_time_sync_running); then
        log_info "  Time sync already running: $running"
        return 0
    fi
    local svc=systemd-timesyncd
    if ! _has_timesyncd; then
        svc=chronyd
        [[ "$(get_package_manager)" == apt ]] && svc=chrony
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would enable time sync ($svc)"
        return 0
    fi
    record_service_state "$svc"
    if [[ "$svc" != systemd-timesyncd ]]; then
        install_package chrony || { log_warning "  chrony unavailable — no time sync enabled"; return 1; }
    fi
    enable_service "$svc"
    if is_service_active "$svc"; then
        log_success "  Time sync running: $svc"
    else
        log_warning "  $svc enabled but not running (containers and some VMs leave time to the host) — check: $(service_status_hint "$svc")"
    fi
    return 0
}

# sudo. CIS Ubuntu 22.04 / RHEL 9 5.2.2 (use_pty) and 5.2.3 (logfile).
# Written as a drop-in only after visudo accepts it, and only where sudoers
# reads /etc/sudoers.d: /etc/sudoers itself is never edited.
UH_SUDOERS_DIR="${UH_SUDOERS_DIR:-/etc/sudoers.d}"   # test hook
UH_SUDOERS_DROPIN_NAME=50-ultimate-hardening
UH_SUDO_LOGFILE=/var/log/sudo.log

_sudoers_reads_dropins() {
    grep -qE '^[[:space:]]*[#@]includedir[[:space:]]+/etc/sudoers\.d[[:space:]]*$' "${UH_SUDOERS_FILE:-/etc/sudoers}" 2>/dev/null
}

# The Defaults lines this run writes: those not already set somewhere else
# and not skipped.
_sudo_defaults_wanted() {
    local existing
    existing=$(grep -hsE '^[[:space:]]*Defaults' "${UH_SUDOERS_FILE:-/etc/sudoers}" "$UH_SUDOERS_DIR"/* 2>/dev/null \
               | grep -v "$UH_SUDOERS_DROPIN_NAME" || true)
    if ! setting_skipped use_pty && ! grep -qE '(^|[[:space:],])use_pty' <<< "$existing"; then
        echo "Defaults use_pty"
    fi
    if ! setting_skipped logfile && ! grep -qE 'logfile[[:space:]]*=' <<< "$existing"; then
        echo "Defaults logfile=\"$UH_SUDO_LOGFILE\""
    fi
    return 0
}

_harden_sudo() {
    if ! command -v visudo >/dev/null 2>&1; then
        log_info "  sudo is not installed — nothing to do"
        return 1
    fi
    if ! _sudoers_reads_dropins; then
        log_warning "  sudoers has no includedir for /etc/sudoers.d — sudo left as it is (this tool never edits /etc/sudoers)"
        return 1
    fi
    local dropin="$UH_SUDOERS_DIR/$UH_SUDOERS_DROPIN_NAME" wanted
    wanted=$(_sudo_defaults_wanted)
    if [[ -z "$wanted" ]]; then
        log_info "  sudo already uses a pty and a log file"
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would add to $dropin: $(tr '\n' ';' <<< "$wanted")"
        return 0
    fi
    local tmp; tmp=$(mktemp) || return 1
    { echo "# Written by Ultimate Hardening (CIS 5.2.2, 5.2.3). Revert removes this file."; echo "$wanted"; } > "$tmp"
    if ! visudo -cf "$tmp" >>"$LOG_FILE" 2>&1; then
        log_warning "  visudo rejected the sudo settings — nothing written"
        rm -f "$tmp"
        return 1
    fi
    install -m 0440 -o root -g root "$tmp" "$dropin" 2>>"$LOG_FILE" || cp "$tmp" "$dropin"
    chmod 0440 "$dropin" 2>/dev/null || true
    rm -f "$tmp"
    relabel_path "$dropin"
    # The whole configuration, with the drop-in in place, must still parse.
    if ! visudo -c >>"$LOG_FILE" 2>&1; then
        rm -f "$dropin"
        log_warning "  sudo's configuration failed visudo -c with the drop-in — removed it again"
        return 1
    fi
    log_success "  sudo: $(tr '\n' ' ' <<< "$wanted" | sed 's/Defaults //g; s/ $//')"
    return 0
}

apply_base_system() {
    log_message "${GEAR} [23/23] Base System (/dev/shm, time sync, sudo)"
    if ! is_linux; then
        log_warning "Base system settings are Linux-specific — skipping on ${DISTRO_TYPE}"
        return 0
    fi
    local done_any=false
    _harden_dev_shm && done_any=true
    _enable_time_sync && done_any=true
    _harden_sudo && done_any=true
    [[ "$DRY_RUN" == true ]] && return 0
    if [[ "$done_any" == true ]]; then
        log_success "Base system hardened"
        count_fix
    fi
    return 0
}

# Revert of module 23: fstab back and /dev/shm remounted, the time daemon
# back to how it was (the package stays), the sudo drop-in removed.
undo_base_system() {
    local acted=false
    if revert_backed_up_file "$UH_FSTAB" >/dev/null 2>&1 && [[ -f "$BACKUP_GENESIS_DIR/$UH_SHM_RECORD_NAME" ]]; then
        restore_shm_options
        acted=true
    fi
    local svc
    for svc in systemd-timesyncd chronyd chrony; do
        recorded_service_state "$svc" >/dev/null && { restore_service_state "$svc"; acted=true; }
    done
    if [[ -f "$UH_SUDOERS_DIR/$UH_SUDOERS_DROPIN_NAME" ]]; then
        rm -f "$UH_SUDOERS_DIR/$UH_SUDOERS_DROPIN_NAME" && { log_success "Removed $UH_SUDOERS_DIR/$UH_SUDOERS_DROPIN_NAME"; acted=true; }
    fi
    [[ "$acted" == true ]] && log_success "Base system reverted" \
        || log_info "Base system: nothing reverted — this module does not appear to have changed anything here"
    return 0
}

# --- module runner -----------------------------------------------------------
# One module returning non-zero must not truncate the run.
#
# Before this wrapper the aggregates below called each module bare, one per
# line, under the `set -euo pipefail` the tier scripts set. A single non-zero
# return therefore killed the script mid-sequence and every module after it was
# silently skipped -- no error, no summary, just a run that stopped. That is
# exactly what apply_firewall did on Rocky 9: it aborted at module 3 of 22, modules
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
UH_REBOOT_REQUIRED=false
UH_EXIT_REBOOT_REQUIRED=10

offer_reboot_if_required() {
    [[ "${UH_REBOOT_REQUIRED:-false}" == true ]] || return 0
    [[ "${UH_DEFER_REBOOT_OFFER:-false}" == true ]] && return 0
    if [[ "${DRY_RUN:-false}" == true ]]; then
        return 0
    fi
    if [[ "${AUTO_MODE:-false}" == true ]] || [[ ! -t 0 ]]; then
        log_warning "REBOOT REQUIRED: the kernel was upgraded during this run. Reboot, then run the Firewall (3) and Fail2Ban (4) modules again. Unattended runs never reboot."
        return 0
    fi
    if confirm "The kernel was upgraded. Reboot now? Afterwards run the Firewall (3) and Fail2Ban (4) modules again"; then
        log_info "Rebooting"
        reboot
    else
        log_warning "Reboot later, then run the Firewall (3) and Fail2Ban (4) modules again"
    fi
}

uh_exit_status() {
    if [[ "${UH_REBOOT_REQUIRED:-false}" == true ]]; then
        printf '%s' "$UH_EXIT_REBOOT_REQUIRED"
    else
        printf '0'
    fi
}

run_module() {
    local key="$1" fn="$2" rc=0

    # MOD_LABEL lives in lib/menu.sh so the name printed here and the name in
    # the menu table cannot drift. menu.sh is not required to be sourced
    # (test_lib_loading sources less than a tier does), hence the fallback.
    local label="$key"
    if declare -p MOD_LABEL >/dev/null 2>&1; then
        label="${MOD_LABEL[$key]:-$key}"
    fi

    UH_MODULES_RUN+=("$key")
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
        offer_reboot_if_required
        return 0
    fi

    log_warning "$scope - $FIXES_APPLIED fixes applied, $n module(s) did not complete: ${UH_MODULE_FAILED[*]}"
    log_warning "Run those modules individually from the menu to see the failure in full."
    offer_reboot_if_required
    return 0
}


# --- Post-hardening health check (--verify) ----------------------------------
# A run can finish "successfully" and still leave a host worse off: sshd not
# back, a unit that now fails to start, the firewall gone. Each aggregate run
# records what was healthy before it changed anything; --verify then checks
# that the same things are still healthy, and exits UH_EXIT_VERIFY_FAILED
# with the reasons when they are not. It changes nothing.
UH_EXIT_VERIFY_FAILED=20
UH_HEALTH_SNAPSHOT_NAME=health-snapshot
UH_MODULES_RUN=()

_health_snapshot_file() { echo "$UH_STATE_DIR/$UH_HEALTH_SNAPSHOT_NAME"; }

# Is systemd the running init? systemctl alone also exists in containers
# and on hosts booted with another init.
_systemd_running() { _has_systemd && [[ -d /run/systemd/system ]]; }

# systemd units in the failed state, sorted, one per line. Empty elsewhere.
# Never fails: the callers run under set -e and pipefail.
_failed_units() {
    _systemd_running || return 0
    systemctl --failed --plain --no-legend --no-pager 2>/dev/null | awk '{print $1}' | sort -u || true
}

# Is a firewall enforcing right now? The same backends the compliance check
# counts (ufw's own status, since its unit is a oneshot; module 3's nftables
# table; firewalld; pf).
firewall_loaded() {
    if command -v ufw >/dev/null 2>&1 && grep -q '^Status: active' <<<"$(ufw status 2>/dev/null)"; then
        return 0
    fi
    { command -v nft >/dev/null 2>&1 && nft list chain inet uh_filter input >/dev/null 2>&1; } && return 0
    is_service_active nftables || is_service_active firewalld || is_service_active pf
}

_sshd_running() { is_service_active sshd || is_service_active ssh; }

# Ports sshd is configured to listen on, one per line (22 when it cannot say).
_sshd_ports() {
    local ports
    ports=$(_sshd_effective_settings | awk 'tolower($1) == "port" {print $2}' | sort -u)
    printf '%s\n' "${ports:-22}"
}

# True when something listens on TCP port $1. Unknown (no ss) counts as yes.
_tcp_port_listening() {
    command -v ss >/dev/null 2>&1 || return 0
    [[ -n "$(ss -Htln "sport = :$1" 2>/dev/null)" ]]
}

# Record the health baseline, in memory and (outside a dry run) in the state
# dir for a later standalone --verify.
record_health_snapshot() {
    UH_HEALTH_FAILED_BEFORE=$(_failed_units)
    UH_HEALTH_FIREWALL_BEFORE=no; firewall_loaded && UH_HEALTH_FIREWALL_BEFORE=yes
    UH_HEALTH_SSHD_BEFORE=no; _sshd_running && UH_HEALTH_SSHD_BEFORE=yes
    UH_HEALTH_SNAPSHOT_TAKEN=true
    [[ "${DRY_RUN:-false}" == true ]] && return 0
    if [[ -L "$UH_STATE_DIR" ]] || ! ( umask 077; mkdir -p "$UH_STATE_DIR" ) 2>/dev/null; then
        return 0
    fi
    {
        echo "taken=$(date '+%Y-%m-%d %H:%M:%S')"
        echo "firewall_before=$UH_HEALTH_FIREWALL_BEFORE"
        echo "sshd_before=$UH_HEALTH_SSHD_BEFORE"
        echo "failed_units=$(tr '\n' ' ' <<< "$UH_HEALTH_FAILED_BEFORE")"
    } > "$(_health_snapshot_file)" 2>/dev/null || true
}

# After an aggregate run: note whether module 3 ran, so a later --verify
# expects a firewall even if there was none before.
record_health_after_run() {
    [[ "${DRY_RUN:-false}" == true ]] && return 0
    local f; f=$(_health_snapshot_file)
    [[ -f "$f" ]] || return 0
    local key ran=no
    for key in "${UH_MODULES_RUN[@]}"; do [[ "$key" == firewall ]] && ran=yes; done
    echo "firewall_applied=$ran" >> "$f" 2>/dev/null || true
}

# $1 = key. The value from the snapshot file.
_health_snapshot_value() {
    sed -n "s/^$1=//p" "$(_health_snapshot_file)" 2>/dev/null | tail -1
}

# Load the baseline from the file when this process did not take one.
_load_health_snapshot() {
    [[ "${UH_HEALTH_SNAPSHOT_TAKEN:-false}" == true ]] && return 0
    if [[ ! -f "$(_health_snapshot_file)" ]]; then
        log_warning "No health baseline from an earlier run ($(_health_snapshot_file)) — checking against nothing, so every failed unit counts"
        UH_HEALTH_FAILED_BEFORE=""; UH_HEALTH_FIREWALL_BEFORE=no; UH_HEALTH_SSHD_BEFORE=no
        return 0
    fi
    UH_HEALTH_FAILED_BEFORE=$(tr ' ' '\n' <<< "$(_health_snapshot_value failed_units)" | sed '/^$/d')
    UH_HEALTH_FIREWALL_BEFORE=$(_health_snapshot_value firewall_before)
    UH_HEALTH_SSHD_BEFORE=$(_health_snapshot_value sshd_before)
    log_info "Comparing with the health baseline taken $(_health_snapshot_value taken)"
}

# Checks the host after hardening. Prints one line per check; returns 1 and
# names every problem when anything broke.
verify_health() {
    log_message "${SHIELD} Post-hardening health check"
    _load_health_snapshot
    local -a problems=()

    # sshd: only demanded where it was running before.
    if [[ "$UH_HEALTH_SSHD_BEFORE" == yes ]]; then
        if ! _sshd_running; then
            problems+=("sshd was running before hardening and is not running now — check: $(service_status_hint sshd)")
        else
            local port
            while read -r port; do
                if _tcp_port_listening "$port"; then
                    log_success "  sshd is running and listening on port $port"
                else
                    problems+=("sshd is running but nothing listens on its port $port")
                fi
            done < <(_sshd_ports)
        fi
    else
        log_info "  sshd was not running before this run — not checked"
    fi

    # Units that failed only after the run.
    local unit new_failed=""
    while read -r unit; do
        [[ -z "$unit" ]] && continue
        grep -qxF -- "$unit" <<< "$UH_HEALTH_FAILED_BEFORE" || new_failed+="$unit "
    done < <(_failed_units)
    if [[ -n "$new_failed" ]]; then
        problems+=("systemd units failed since the run: ${new_failed% } — see: systemctl status ${new_failed%% *}")
    elif _systemd_running; then
        log_success "  No systemd unit has failed since the run"
    else
        log_info "  systemd is not running here — unit failures not checked"
    fi

    # Firewall: expected where one was enforcing before, or module 3 ran.
    local firewall_expected=false key
    [[ "$UH_HEALTH_FIREWALL_BEFORE" == yes ]] && firewall_expected=true
    for key in "${UH_MODULES_RUN[@]}"; do [[ "$key" == firewall ]] && firewall_expected=true; done
    [[ "$(_health_snapshot_value firewall_applied)" == yes ]] && firewall_expected=true
    if [[ "$firewall_expected" == true ]]; then
        if firewall_loaded; then
            log_success "  A firewall is loaded"
        else
            problems+=("no firewall is loaded, although one was before or module 3 ran")
        fi
    else
        log_info "  No firewall was loaded before and module 3 did not run — not checked"
    fi

    if (( ${#problems[@]} == 0 )); then
        log_success "Health check passed"
        return 0
    fi
    local p
    for p in "${problems[@]}"; do log_error "  $p"; done
    log_error "Health check FAILED (${#problems[@]} problem(s)); exit status $UH_EXIT_VERIFY_FAILED"
    return 1
}

# --- Aggregate ---------------------------------------------------------------
# Ban and unban a documentation address (RFC 5737 / RFC 3849) once, so the
# kernel modules Fail2Ban's ban action needs are loaded before a kernel
# upgrade removes the running kernel's modules from disk.
_fail2ban_preload_ban_action() {
    [[ "$DRY_RUN" == true ]] && return 0
    command -v fail2ban-client >/dev/null 2>&1 && is_service_active fail2ban || return 0
    local i ip
    for i in 1 2 3 4 5 6 7 8 9 10; do
        fail2ban-client status sshd >/dev/null 2>&1 && break
        sleep 0.5
    done
    for ip in 192.0.2.1 2001:db8::1; do
        fail2ban-client set sshd banip "$ip"   >>"$LOG_FILE" 2>&1 || true
        fail2ban-client set sshd unbanip "$ip" >>"$LOG_FILE" 2>&1 || true
    done
    log_info "Fail2Ban's ban action was run once against a documentation address, so bans keep working after the kernel upgrade"
}

# A pending kernel upgrade removes the running kernel's modules, and what is
# not loaded by then cannot load until the reboot. The firewall and Fail2Ban
# go first in that case.
_run_first_four_modules() {
    if kernel_update_pending; then
        log_info "A kernel update is pending — applying the firewall and Fail2Ban before system updates, so both keep working until you reboot"
        run_module firewall  apply_firewall
        run_module fail2ban  apply_fail2ban
        _fail2ban_preload_ban_action
        run_module updates   apply_system_updates
        run_module ssh       apply_ssh_hardening
    else
        run_module updates   apply_system_updates
        run_module ssh       apply_ssh_hardening
        run_module firewall  apply_firewall
        run_module fail2ban  apply_fail2ban
    fi
}

# Every module, including the High-risk one (module 9, SUID/SGID hardening).
apply_all_modules() {
    log_message "${ROCKET} Applying all 23 hardening modules (including High risk)"
    create_backup_dir
    UH_MODULE_FAILED=()
    record_health_snapshot

    # Resolve every module's packages before the first module changes anything,
    # so an unobtainable dependency is reported up front rather than discovered
    # partway through a half-hardened system.
    preflight_dependencies

    _run_first_four_modules
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
    run_module basesys   apply_base_system
    record_health_after_run

    report_module_results "All 23 modules processed"
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
    record_health_snapshot

    # Resolve every module's packages before the first module changes anything,
    # so an unobtainable dependency is reported up front rather than discovered
    # partway through a half-hardened system.
    preflight_dependencies

    _run_first_four_modules
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
    run_module basesys   apply_base_system
    record_health_after_run

    report_module_results "Safe/Medium modules processed (High-risk 9 and 16 skipped, run them separately)"
}
