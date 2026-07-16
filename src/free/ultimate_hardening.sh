#!/bin/bash
# =============================================================================
#  ULTIMATE SYSTEM HARDENING SCRIPT (PAM-SAFE VERSION)
#  Version: 2.1.0  |  Multi-distribution support with interactive distro selection
#  28 Security Features - CIS Benchmark Aligned
# =============================================================================
#  CHANGES FROM v2.0.1:
#    - RE-ADDED: Password Policies as option 24 ("Password Policies (Safe)").
#      Only writes /etc/security/pwquality.conf — never touches any
#      /etc/pam.d/* file, so it can't repeat the ecryptfs/KDE-Plasma login
#      breakage that got the original version pulled. See the comment above
#      the old option-8 slot for the root-cause writeup.
#    - apply_all_safe() now also applies the new option 24.
#    - Total options increased from 28 to 29.
# =============================================================================
# Usage: sudo ./ultimate_hardening.sh [--skip-backup] [--auto-mode] [--dry-run] [--revert] [--revert-suid] [--help]
# =============================================================================
# shellcheck disable=SC2059
# SC2059 fires throughout the menu printf calls below because they embed
# ${COLOR}/${ICON} variables directly in the format string. Every one of
# those variables is a fixed literal defined in this file (never user input,
# args, or file content), so there's no format-string injection risk here —
# rewriting ~30 hand-aligned menu lines to printf '%s' form would only risk
# breaking their spacing for no real safety gain.

set -euo pipefail

# ----------------------------- Configuration ---------------------------------
VERSION="2.1.0"
LOG_FILE="/var/log/ultimate_hardening_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="/root/hardening_backup_$(date +%Y%m%d_%H%M%S)"
SUID_BACKUP_FILE="$BACKUP_DIR/suid_sgid_original_perms.txt"
AUTO_MODE=false
SKIP_BACKUP=false
DRY_RUN=false
REVERT_MODE=false
REVERT_SUID_ONLY=false
DISTRO_TYPE=""

# Parse command line arguments
for arg in "$@"; do
    case $arg in
        --auto-mode) AUTO_MODE=true ;;
        --skip-backup) SKIP_BACKUP=true ;;
        --dry-run) DRY_RUN=true ;;
        --revert) REVERT_MODE=true ;;
        --revert-suid) REVERT_SUID_ONLY=true ;;
        --help|-h)
            cat << EOF
Usage: sudo ./ultimate_hardening.sh [OPTIONS]

Options:
  --auto-mode      Run without interactive prompts (use defaults)
  --skip-backup    Skip creating backup directory
  --dry-run        Show what would be changed without applying
  --revert         Revert ALL hardening changes (restores from backup)
  --revert-suid    Revert only SUID/SGID permissions
  --help, -h       Show this help message

Examples:
  sudo ./ultimate_hardening.sh                              # Interactive mode
  sudo ./ultimate_hardening.sh --auto-mode                  # Non-interactive
  sudo ./ultimate_hardening.sh --dry-run                    # Preview changes
  sudo ./ultimate_hardening.sh --revert                     # Full system revert
  sudo ./ultimate_hardening.sh --revert-suid                # Revert only SUID bits
EOF
            exit 0
            ;;
    esac
done

# Color codes and emojis
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

CHECK_MARK="✅"
CROSS_MARK="❌"
WARNING="⚠️"
INFO="ℹ️"
LOCK="🔒"
SHIELD="🛡️"
GEAR="⚙️"
FIRE="🔥"
ROCKET="🚀"
UNDO="↩️"
DOCKER_ICON="🐳"
CIS_ICON="📊"

# ----------------------------- Logging Functions -----------------------------
log_message() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}${CHECK_MARK}${NC} $1" | tee -a "$LOG_FILE"; }
log_warning() { echo -e "${YELLOW}${WARNING}${NC} $1" | tee -a "$LOG_FILE"; }
log_error()   { echo -e "${RED}${CROSS_MARK}${NC} $1" | tee -a "$LOG_FILE"; }
log_info()    { echo -e "${CYAN}${INFO}${NC} $1" | tee -a "$LOG_FILE"; }
log_cis()     { echo -e "${MAGENTA}${CIS_ICON}${NC} $1" | tee -a "$LOG_FILE"; }

# ----------------------------- Helper Functions ------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}${CROSS_MARK} This script must be run as root.${NC}"
        exit 1
    fi
}

create_backup_dir() {
    if [[ "$SKIP_BACKUP" == true ]]; then
        log_info "Backup skipped (--skip-backup flag)"
        return
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would create backup directory at $BACKUP_DIR"
        return
    fi
    mkdir -p "$BACKUP_DIR"
    log_info "Backup directory: $BACKUP_DIR"
}

backup_file() {
    if [[ "$SKIP_BACKUP" == true ]] || [[ "$DRY_RUN" == true ]]; then
        return
    fi
    local file="$1"
    if [[ -f "$file" ]]; then
        local safe_name="${file#/}"
        safe_name="${safe_name//'/'/_}"
        local backup_name="$BACKUP_DIR/${safe_name}.backup"
        cp -p "$file" "$backup_name"
        log_info "Backed up $file"
    fi
}

restore_file() {
    local file="$1"
    local safe_name="${file#/}"
    safe_name="${safe_name//'/'/_}"
    local backup_name="$BACKUP_DIR/${safe_name}.backup"

    if [[ -f "$backup_name" ]]; then
        cp -p "$backup_name" "$file"
        log_success "Restored $file"
        return 0
    else
        log_warning "No backup found for $file"
        return 1
    fi
}

press_enter() {
    echo ""
    read -r -p "Press Enter to return to menu..."
}

# Package manager helpers
get_package_manager() {
    case "$DISTRO_TYPE" in
        debian) echo "apt-get" ;;
        rhel) echo "yum" ;;
        arch) echo "pacman" ;;
        suse) echo "zypper" ;;
        *) echo "apt-get" ;;
    esac
}

install_package() {
    local pkg="$1"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would install package: $pkg"
        return 0
    fi

    local pm
pm=$(get_package_manager)
    case "$pm" in
        apt-get)
            apt-get update -qq >> "$LOG_FILE" 2>&1
            apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1
            ;;
        yum)
            yum install -y "$pkg" >> "$LOG_FILE" 2>&1
            ;;
        pacman)
            pacman -S --noconfirm "$pkg" >> "$LOG_FILE" 2>&1
            ;;
        zypper)
            zypper install -y "$pkg" >> "$LOG_FILE" 2>&1
            ;;
    esac
    log_success "Installed: $pkg"
}

enable_service() {
    local svc="$1"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would enable and start service: $svc"
        return 0
    fi
    systemctl enable "$svc" >> "$LOG_FILE" 2>&1
    systemctl start "$svc" >> "$LOG_FILE" 2>&1
    log_success "Service enabled: $svc"
}

# ----------------------------- Distro Selection ------------------------------
detect_or_select_distro() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        case "$ID" in
            ubuntu|debian) echo "debian" ;;
            rhel|centos|fedora|rocky|almalinux) echo "rhel" ;;
            arch|manjaro) echo "arch" ;;
            opensuse*|suse) echo "suse" ;;
            *) echo "debian" ;;
        esac
    else
        echo "debian"
    fi
}

show_distro_menu() {
    if [[ "$AUTO_MODE" == true ]]; then
        DISTRO_TYPE=$(detect_or_select_distro)
        log_success "Auto-detected: $DISTRO_TYPE"
        return
    fi

    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    SELECT YOUR DISTRIBUTION                      ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${WHITE}Select your Linux distribution:${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} Ubuntu / Debian"
    echo -e "  ${GREEN}2)${NC} RHEL / CentOS / Fedora / Rocky / AlmaLinux"
    echo -e "  ${GREEN}3)${NC} Arch Linux / Manjaro"
    echo -e "  ${GREEN}4)${NC} openSUSE / SUSE Linux Enterprise"
    echo -e "  ${GREEN}5)${NC} Auto-detect"
    echo ""
    read -r -p "Enter choice (1-5): " distro_choice

    case "$distro_choice" in
        1) DISTRO_TYPE="debian" ;;
        2) DISTRO_TYPE="rhel" ;;
        3) DISTRO_TYPE="arch" ;;
        4) DISTRO_TYPE="suse" ;;
        5) DISTRO_TYPE=$(detect_or_select_distro) ;;
        *) DISTRO_TYPE="debian" ;;
    esac

    log_success "Selected: $DISTRO_TYPE"
}

# ============================ REVERT FUNCTIONS ================================

# Full system revert
full_system_revert() {
    log_message "${UNDO} FULL SYSTEM REVERT - Restoring from backup"
    echo -e "\n${RED}${WARNING} DANGER: This will restore ALL backed up configurations${NC}"
    echo -e "${RED}This may break your system if not done carefully.${NC}\n"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Are you absolutely sure you want to revert ALL changes? (yes/NO): " choice
        [[ ! "$choice" =~ ^[Yy]es$ ]] && { log_info "Revert cancelled."; return; }
    fi

    if [[ ! -d "$BACKUP_DIR" ]]; then
        # This invocation's backup dir is timestamped fresh at script start,
        # so it won't exist yet if hardening was applied in an earlier run.
        # Fall back to the most recent backup on disk before giving up.
        local found_dir
        found_dir=$(find /root -maxdepth 1 -type d -name "hardening_backup_*" 2>/dev/null | sort | tail -1)
        if [[ -n "$found_dir" ]]; then
            BACKUP_DIR="$found_dir"
            SUID_BACKUP_FILE="$BACKUP_DIR/suid_sgid_original_perms.txt"
            log_info "Using most recent backup found: $BACKUP_DIR"
        else
            log_error "No backup directory found at $BACKUP_DIR"
            log_info "Cannot perform revert without backups."
            return
        fi
    fi

    # Restore SSH config
    if restore_file "/etc/ssh/sshd_config"; then
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
    fi

    # Restore sysctl config
    if restore_file "/etc/sysctl.d/99-hardening.conf"; then
        sysctl -p /etc/sysctl.d/99-hardening.conf 2>/dev/null || true
    fi

    # Restore audit rules
    restore_file "/etc/audit/rules.d/99-hardening.rules"

    # Restore SUID permissions
    undo_suid_hardening

    # Restore firewall: if a pre-hardening nftables.conf was backed up, restore it;
    # otherwise nftables was introduced by hardening, so disable it.
    if [[ -f "$BACKUP_DIR/etc_nftables.conf.backup" ]]; then
        restore_file "/etc/nftables.conf"
        systemctl restart nftables 2>/dev/null || true
        log_info "Firewall configuration restored from backup"
    else
        systemctl stop nftables 2>/dev/null || true
        systemctl disable nftables 2>/dev/null || true
        log_info "Firewall reverted to disabled state"
    fi

    # Re-enable services that were disabled
    for svc in avahi-daemon cups nfs-server rpcbind slapd named postfix; do
        systemctl enable "$svc" 2>/dev/null || true
        systemctl start "$svc" 2>/dev/null || true
    done

    # Restore USB storage
    if [[ -f /etc/modprobe.d/usb-storage-blacklist.conf ]]; then
        rm -f /etc/modprobe.d/usb-storage-blacklist.conf
        modprobe usb-storage 2>/dev/null || true
        log_info "USB storage re-enabled"
    fi

    # Restore protocols
    if [[ -f /etc/modprobe.d/disable-unused-protocols.conf ]]; then
        rm -f /etc/modprobe.d/disable-unused-protocols.conf
        log_info "Unused protocols re-enabled"
    fi

    # Restore compiler permissions
    for compiler in gcc g++ clang clang++ cc c++ ; do
        if command -v "$compiler" &> /dev/null; then
            chmod 755 "$(command -v "$compiler")" 2>/dev/null || true
        fi
    done

    log_success "Full system revert completed! System has been restored from backup."
    log_warning "Some changes may require a reboot to take full effect."
}

# Revert SUID hardening (standalone function)
undo_suid_hardening() {
    log_message "${UNDO} Restoring SUID permissions"

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would restore SUID permissions from backup"
        log_success "DRY RUN: SUID permissions restored"
        return
    fi

    if [[ ! -f "$SUID_BACKUP_FILE" ]]; then
        # This invocation's backup dir is timestamped fresh at script start,
        # so it won't exist yet if hardening was applied in an earlier run.
        # Fall back to the most recent backup on disk before giving up.
        local found_backup
        found_backup=$(find /root -maxdepth 2 -name "suid_sgid_original_perms.txt" -type f 2>/dev/null | sort | tail -1)
        if [[ -n "$found_backup" ]]; then
            SUID_BACKUP_FILE="$found_backup"
            log_info "Using most recent backup found: $SUID_BACKUP_FILE"
        else
            log_error "No backup file found at $SUID_BACKUP_FILE"
            return
        fi
    fi

    if [[ "$AUTO_MODE" == false ]] && [[ "$REVERT_SUID_ONLY" == false ]]; then
        read -r -p "Restore SUID permissions? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Cancelled."; return; }
    fi

    while IFS=' ' read -r mode binary; do
        if [[ -n "$mode" ]] && [[ -f "$binary" ]]; then
            chmod "$mode" "$binary" 2>/dev/null || true
            log_info "Restored permissions ($mode) to $binary"
        fi
    done < "$SUID_BACKUP_FILE"

    log_success "SUID permissions restored"
}

# ============================ CORE HARDENING FUNCTIONS ========================

# --- 1. System Updates -------------------------------------------------------
apply_system_updates() {
    create_backup_dir
    log_message "${GEAR} [1/24] System Updates"
    echo -e "\n${GREEN}${INFO} This will update all system packages${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Apply system updates? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would update package lists and upgrade all packages"
        log_success "DRY RUN: System updates completed"
        return
    fi

    local pm
pm=$(get_package_manager)
    case "$pm" in
        apt-get)
            apt-get update -qq >> "$LOG_FILE" 2>&1
            apt-get upgrade -y >> "$LOG_FILE" 2>&1
            ;;
        yum)
            yum update -y >> "$LOG_FILE" 2>&1
            ;;
        pacman)
            pacman -Syu --noconfirm >> "$LOG_FILE" 2>&1
            ;;
        zypper)
            zypper update -y >> "$LOG_FILE" 2>&1
            ;;
    esac
    log_success "System updates completed"
}

# --- 2. SSH Hardening --------------------------------------------------------
apply_ssh_hardening() {
    create_backup_dir
    log_message "${LOCK} [2/24] SSH Hardening"
    echo -e "\n${YELLOW}${WARNING} This will harden SSH configuration${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Apply SSH hardening? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    local SSH_CONFIG="/etc/ssh/sshd_config"
    if [[ ! -f "$SSH_CONFIG" ]]; then
        log_error "SSH config not found at $SSH_CONFIG. Skipping."
        return
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would backup $SSH_CONFIG"
        log_info "DRY RUN: Would set PermitRootLogin no"
        log_info "DRY RUN: Would set PasswordAuthentication no"
        log_info "DRY RUN: Would set ChallengeResponseAuthentication no"
        log_info "DRY RUN: Would set PermitEmptyPasswords no"
        log_info "DRY RUN: Would set MaxAuthTries 3"
        log_info "DRY RUN: Would restart sshd service"
        log_success "DRY RUN: SSH hardening completed"
        return
    fi

    backup_file "$SSH_CONFIG"

    # Apply SSH hardening
    sed -i 's/^#PermitRootLogin .*/PermitRootLogin no/' "$SSH_CONFIG"
    sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' "$SSH_CONFIG"
    sed -i 's/^#PasswordAuthentication .*/PasswordAuthentication no/' "$SSH_CONFIG"
    sed -i 's/^PasswordAuthentication .*/PasswordAuthentication no/' "$SSH_CONFIG"
    sed -i 's/^#ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' "$SSH_CONFIG"
    sed -i 's/^ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' "$SSH_CONFIG"
    sed -i 's/^#PermitEmptyPasswords .*/PermitEmptyPasswords no/' "$SSH_CONFIG"
    sed -i 's/^PermitEmptyPasswords .*/PermitEmptyPasswords no/' "$SSH_CONFIG"
    sed -i 's/^#MaxAuthTries .*/MaxAuthTries 3/' "$SSH_CONFIG"
    sed -i 's/^MaxAuthTries .*/MaxAuthTries 3/' "$SSH_CONFIG"

    # Ensure lines exist if they weren't there
    grep -q "^PermitRootLogin" "$SSH_CONFIG" || echo "PermitRootLogin no" >> "$SSH_CONFIG"
    grep -q "^PasswordAuthentication" "$SSH_CONFIG" || echo "PasswordAuthentication no" >> "$SSH_CONFIG"
    grep -q "^ChallengeResponseAuthentication" "$SSH_CONFIG" || echo "ChallengeResponseAuthentication no" >> "$SSH_CONFIG"
    grep -q "^PermitEmptyPasswords" "$SSH_CONFIG" || echo "PermitEmptyPasswords no" >> "$SSH_CONFIG"
    grep -q "^MaxAuthTries" "$SSH_CONFIG" || echo "MaxAuthTries 3" >> "$SSH_CONFIG"

    systemctl restart sshd >> "$LOG_FILE" 2>&1 || systemctl restart ssh >> "$LOG_FILE" 2>&1
    log_success "SSH hardening completed"
}

# --- 3. Firewall Configuration (nftables) -------------------------------------
apply_firewall() {
    create_backup_dir
    log_message "${SHIELD} [3/24] Firewall Configuration"
    echo -e "\n${YELLOW}${WARNING} This will configure nftables firewall${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Configure firewall? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would install nftables"
        log_info "DRY RUN: Would create basic nftables ruleset"
        log_info "DRY RUN: Would enable and start nftables service"
        log_success "DRY RUN: Firewall configuration completed"
        return
    fi

    backup_file "/etc/nftables.conf"
    install_package "nftables"

    # Create basic nftables ruleset
    cat > /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow established/related connections
        ct state established,related accept

        # Allow loopback
        iif lo accept

        # Allow ICMP (ping)
        ip protocol icmp icmp type echo-request accept
        ip6 nexthdr icmpv6 icmpv6 type echo-request accept

        # Allow SSH (port 22)
        tcp dport 22 accept

        # Allow HTTP/HTTPS (optional)
        tcp dport { 80, 443 } accept
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF

    {
        systemctl enable nftables
        systemctl start nftables
        nft -f /etc/nftables.conf
    } >> "$LOG_FILE" 2>&1

    log_success "Firewall configured"
}

# --- 4. Fail2Ban -------------------------------------------------------------
apply_fail2ban() {
    create_backup_dir
    log_message "${SHIELD} [4/24] Fail2Ban Installation"
    echo -e "\n${GREEN}${INFO} This will install and configure Fail2Ban${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Install Fail2Ban? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would install fail2ban"
        log_info "DRY RUN: Would create basic jail configuration"
        log_info "DRY RUN: Would enable fail2ban service"
        log_success "DRY RUN: Fail2Ban installation completed"
        return
    fi

    install_package "fail2ban"

    # Create basic jail configuration
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF

    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    systemctl start fail2ban >> "$LOG_FILE" 2>&1

    log_success "Fail2Ban installed"
}

# --- 5. File Permissions -----------------------------------------------------
apply_permission_hardening() {
    create_backup_dir
    log_message "${LOCK} [5/24] File Permission Hardening"
    echo -e "\n${GREEN}${INFO} This will secure critical file permissions${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Harden file permissions? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would set permissions on critical system files"
        log_success "DRY RUN: File permissions hardened"
        return
    fi

    backup_file "/etc/shadow"
    backup_file "/etc/gshadow"
    backup_file "/etc/passwd"
    backup_file "/etc/group"
    backup_file "/etc/sudoers"

    # Secure critical files
    chmod 600 /etc/shadow 2>/dev/null || true
    chmod 600 /etc/gshadow 2>/dev/null || true
    chmod 644 /etc/passwd 2>/dev/null || true
    chmod 644 /etc/group 2>/dev/null || true
    chmod 440 /etc/sudoers 2>/dev/null || true

    log_success "File permissions hardened"
}

# --- 6. Kernel Hardening -----------------------------------------------------
apply_kernel_hardening() {
    create_backup_dir
    log_message "${GEAR} [6/24] Kernel Hardening"
    echo -e "\n${GREEN}${INFO} This will apply kernel sysctl hardening${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Apply kernel hardening? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    local SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would create $SYSCTL_CONF with security parameters"
        log_info "DRY RUN: Would apply sysctl settings"
        log_success "DRY RUN: Kernel hardening applied"
        return
    fi

    backup_file "$SYSCTL_CONF"

    cat > "$SYSCTL_CONF" << 'EOF'
# Kernel hardening parameters
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

    sysctl -p "$SYSCTL_CONF" >> "$LOG_FILE" 2>&1
    log_success "Kernel hardening applied"
}

# --- 7. Auditd Configuration -------------------------------------------------
apply_audit_config() {
    create_backup_dir
    log_message "${SHIELD} [7/24] Auditd Configuration"
    echo -e "\n${GREEN}${INFO} This will configure system auditing${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Configure auditd? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would install auditd"
        log_info "DRY RUN: Would configure audit rules"
        log_success "DRY RUN: Auditd configured"
        return
    fi

    install_package "auditd"
    backup_file "/etc/audit/rules.d/99-hardening.rules"

    # Configure audit rules
    cat > /etc/audit/rules.d/99-hardening.rules << 'EOF'
# Critical file monitoring
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd

# System call monitoring
-a always,exit -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -S sethostname -S setdomainname -k system-locale
EOF

    {
        systemctl enable auditd
        systemctl start auditd
        auditctl -R /etc/audit/rules.d/99-hardening.rules
    } >> "$LOG_FILE" 2>&1

    log_success "Auditd configured"
}

# --- 8. Password Policies (REMOVED from its original slot - see option 24) --
# The original version of this module hand-edited /etc/pam.d/common-password
# with sed. On Debian/Ubuntu/Mint that file is machine-managed by
# pam-auth-update from /usr/share/pam-configs/* profiles (including
# ecryptfs's own profile, which inserts pam_ecryptfs.so to re-wrap the
# encrypted-home mount passphrase on password change). The sed edit sat
# outside pam-auth-update's tracking markers, so installing a second desktop
# environment (e.g. KDE Plasma/SDDM) later re-triggered pam-auth-update and
# desynced the login password from the ecryptfs-wrapped mount passphrase,
# breaking login under SDDM specifically.
#
# A safe replacement is available as option 24 ("Password Policies (Safe)"):
# it only writes /etc/security/pwquality.conf and never touches any
# /etc/pam.d/* file, so it can't repeat this failure mode.

# --- 9. SUID Hardening (renumbered to 8) -------------------------------------
apply_suid_hardening() {
    create_backup_dir
    log_message "${FIRE} [8/24] SUID/SGID Hardening"
    echo -e "\n${RED}${WARNING} HIGH RISK: This removes SUID bits from non-essential binaries${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Proceed with SUID hardening? (yes/NO): " choice
        [[ ! "$choice" =~ ^[Yy]es$ ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would scan for SUID/SGID binaries"
        log_info "DRY RUN: Would backup SUID permissions"
        log_info "DRY RUN: Would remove SUID from non-essential binaries"
        log_success "DRY RUN: SUID hardening completed"
        return
    fi

    if [[ "$SKIP_BACKUP" == false ]]; then
        mkdir -p "$BACKUP_DIR"
        : > "$SUID_BACKUP_FILE"
        for binary in /usr/bin/at /usr/bin/chage /usr/bin/crontab /usr/bin/expiry /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/ssh-agent /usr/bin/fusermount /usr/bin/fusermount3; do
            if [[ -f "$binary" ]]; then
                stat -c '%a %n' "$binary" >> "$SUID_BACKUP_FILE"
            fi
        done
        log_success "SUID permissions backed up to $SUID_BACKUP_FILE"
    fi

    # Common non-essential SUID binaries to remove
    for binary in /usr/bin/at /usr/bin/chage /usr/bin/crontab /usr/bin/expiry /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/ssh-agent /usr/bin/fusermount /usr/bin/fusermount3; do
        if [[ -f "$binary" ]]; then
            chmod u-s "$binary" 2>/dev/null || true
            log_info "Removed SUID from $binary"
        fi
    done

    log_success "SUID hardening completed"
}

# --- 10. SUID Revert (legacy function - kept for menu) -----------------------
undo_suid_hardening_menu() {
    undo_suid_hardening
}

# --- 11. AIDE (renumbered to 10) --------------------------------------------
apply_aide() {
    create_backup_dir
    log_message "${SHIELD} [10/24] AIDE Installation"
    echo -e "\n${GREEN}${INFO} This installs file integrity monitoring${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Install AIDE? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would install aide"
        log_info "DRY RUN: Would initialize AIDE database"
        log_success "DRY RUN: AIDE installed"
        return
    fi

    install_package "aide"
    aideinit 2>/dev/null || true
    mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null || true

    log_success "AIDE installed"
}

# --- 12. rkhunter (renumbered to 11) -----------------------------------------
apply_rkhunter() {
    create_backup_dir
    log_message "${SHIELD} [11/24] rkhunter Installation"
    echo -e "\n${GREEN}${INFO} This installs rootkit hunter${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Install rkhunter? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would install rkhunter"
        log_info "DRY RUN: Would run initial system check"
        log_success "DRY RUN: rkhunter installed"
        return
    fi

    install_package "rkhunter"
    rkhunter --update 2>/dev/null || true
    rkhunter --propupd 2>/dev/null || true

    log_success "rkhunter installed"
}

# --- 13. Disable Services (renumbered to 12) ---------------------------------
apply_disable_services() {
    create_backup_dir
    log_message "${GEAR} [12/24] Disabling Unnecessary Services"
    echo -e "\n${YELLOW}${WARNING} This disables unnecessary services${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Disable unnecessary services? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would disable common unnecessary services"
        log_success "DRY RUN: Unnecessary services disabled"
        return
    fi

    # Common services to disable
    for svc in avahi-daemon cups nfs-server rpcbind slapd named postfix; do
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
    done

    log_success "Unnecessary services disabled"
}

# --- 14. AppArmor/SELinux (renumbered to 13) --------------------------------
apply_apparmor() {
    create_backup_dir
    log_message "${SHIELD} [13/24] AppArmor/SELinux Configuration"
    echo -e "\n${GREEN}${INFO} This configures mandatory access control${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Configure AppArmor/SELinux? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would install and configure MAC system"
        log_success "DRY RUN: MAC system configured"
        return
    fi

    case "$DISTRO_TYPE" in
        debian)
            install_package "apparmor"
            install_package "apparmor-utils"
            systemctl enable apparmor >> "$LOG_FILE" 2>&1
            systemctl start apparmor >> "$LOG_FILE" 2>&1
            aa-enforce /etc/apparmor.d/* 2>/dev/null || true
            ;;
        rhel)
            backup_file "/etc/selinux/config"
            # SELinux should be enabled by default on RHEL
            sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config 2>/dev/null || true
            setenforce 1 2>/dev/null || true
            ;;
    esac

    log_success "MAC system configured"
}

# --- 15. etckeeper (renumbered to 14) ----------------------------------------
apply_etckeeper() {
    create_backup_dir
    log_message "${GEAR} [14/24] etckeeper Setup"
    echo -e "\n${GREEN}${INFO} This sets up version control for /etc${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Install etckeeper? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would install etckeeper"
        log_info "DRY RUN: Would initialize git repository for /etc"
        log_success "DRY RUN: etckeeper configured"
        return
    fi

    install_package "etckeeper"
    etckeeper init 2>/dev/null || true
    etckeeper commit "Initial commit before hardening" 2>/dev/null || true

    log_success "etckeeper configured"
}

# --- 16. Boot Security (renumbered to 15) ------------------------------------
apply_boot_secure() {
    create_backup_dir
    log_message "${LOCK} [15/24] Boot Security"
    echo -e "\n${GREEN}${INFO} This secures boot loader permissions${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Secure boot permissions? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would secure GRUB configuration permissions"
        log_success "DRY RUN: Boot permissions secured"
        return
    fi

    backup_file "/boot/grub/grub.cfg"
    chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
    chmod 600 /etc/grub.d/* 2>/dev/null || true

    log_success "Boot permissions secured"
}

# --- 17. GRUB Password (renumbered to 16) ------------------------------------
apply_grub_password() {
    create_backup_dir
    log_message "${LOCK} [16/24] GRUB Password"
    echo -e "\n${RED}${WARNING} HIGH RISK: This sets a GRUB password${NC}"

    if [[ "$AUTO_MODE" == true ]]; then
        log_warning "GRUB password requires interactive input; skipping in auto-mode."
        return
    fi

    read -r -p "Set GRUB password? (yes/NO): " choice
    [[ ! "$choice" =~ ^[Yy]es$ ]] && { log_info "Skipped."; return; }

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would generate GRUB password hash"
        log_info "DRY RUN: Would add superusers to GRUB config"
        log_success "DRY RUN: GRUB password set"
        return
    fi

    echo -e "\n${YELLOW}Enter password for GRUB administrator:${NC}"
    read -s -r grub_pass
    echo
    echo -e "${YELLOW}Re-enter password:${NC}"
    read -s -r grub_pass2

    if [[ "$grub_pass" != "$grub_pass2" ]]; then
        log_error "Passwords do not match. Skipping."
        return
    fi

    local grub_hash
grub_hash=$(printf '%s\n%s\n' "$grub_pass" "$grub_pass" | grub-mkpasswd-pbkdf2 2>/dev/null | grep -oP 'grub\.pbkdf2\.sha512\.\S+' || true)

    if [[ -n "$grub_hash" ]]; then
        backup_file "/etc/grub.d/40_custom"
        echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
        echo "password_pbkdf2 root $grub_hash" >> /etc/grub.d/40_custom
        update-grub 2>/dev/null || grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || true
        log_success "GRUB password set"
    else
        log_error "Failed to generate GRUB password hash"
    fi
}

# --- 18. Docker Security (renumbered to 17) ----------------------------------
apply_docker_security() {
    create_backup_dir
    log_message "${DOCKER_ICON} [17/24] Docker Security"
    echo -e "\n${YELLOW}${WARNING} This hardens Docker configuration${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Apply Docker security? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would install docker if not present"
        log_info "DRY RUN: Would configure Docker daemon security options"
        log_success "DRY RUN: Docker security applied"
        return
    fi

    if ! command -v docker &> /dev/null; then
        log_warning "Docker not installed. Skipping Docker security."
        return
    fi

    backup_file "/etc/docker/daemon.json"

    # Create Docker daemon security configuration
    mkdir -p /etc/docker
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

    systemctl restart docker >> "$LOG_FILE" 2>&1

    log_success "Docker security applied"
}

# --- 19. ModSecurity (renumbered to 18) --------------------------------------
apply_modsecurity() {
    create_backup_dir
    log_message "${SHIELD} [18/24] ModSecurity WAF"
    echo -e "\n${YELLOW}${WARNING} This installs ModSecurity for Apache${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Install ModSecurity? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would install libapache2-mod-security2"
        log_info "DRY RUN: Would enable ModSecurity rules"
        log_success "DRY RUN: ModSecurity installed"
        return
    fi

    case "$DISTRO_TYPE" in
        debian)
            install_package "libapache2-mod-security2"
            install_package "modsecurity-crs"
            a2enmod security2 >> "$LOG_FILE" 2>&1
            systemctl restart apache2 >> "$LOG_FILE" 2>&1
            ;;
        rhel)
            install_package "mod_security"
            install_package "mod_security_crs"
            systemctl restart httpd >> "$LOG_FILE" 2>&1
            ;;
    esac

    log_success "ModSecurity installed"
}

# --- 20. Google Authenticator (renumbered to 19) -----------------------------
apply_google_auth() {
    create_backup_dir
    log_message "${LOCK} [19/24] Google Authenticator MFA"
    echo -e "\n${YELLOW}${WARNING} This enables MFA for SSH${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Setup Google Authenticator? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would install google-authenticator"
        log_info "DRY RUN: Would provide Google Authenticator setup guidance"
        log_success "DRY RUN: Google Authenticator configured"
        return
    fi

    log_warning "Google Authenticator requires manual PAM configuration."
    echo -e "\n${YELLOW}Install libpam-google-authenticator manually, then run 'google-authenticator'${NC}"
    echo -e "${YELLOW}Do NOT modify /etc/pam.d files — this can cause login lockouts on ecryptfs systems${NC}"

    log_success "Google Authenticator guidance provided (no PAM files modified)"
}

# --- 21. USB Blocking (renumbered to 20) -------------------------------------
apply_usb_blocking() {
    create_backup_dir
    log_message "${FIRE} [20/24] USB Storage Blocking"
    echo -e "\n${YELLOW}${WARNING} This disables USB storage${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Block USB storage? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would blacklist usb-storage module"
        log_success "DRY RUN: USB storage blocked"
        return
    fi

    echo "blacklist usb-storage" > /etc/modprobe.d/usb-storage-blacklist.conf
    modprobe -r usb-storage 2>/dev/null || true

    log_success "USB storage blocked"
}

# --- 22. Disable Unused Protocols (renumbered to 21) -------------------------
disable_unused_protocols() {
    create_backup_dir
    log_message "${GEAR} [21/24] Disabling Unused Protocols"
    echo -e "\n${YELLOW}${WARNING} This disables DCCP, SCTP, RDS, TIPC${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Disable unused protocols? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would blacklist DCCP, SCTP, RDS, TIPC modules"
        log_success "DRY RUN: Unused protocols disabled"
        return
    fi

    cat > /etc/modprobe.d/disable-unused-protocols.conf << 'EOF'
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
EOF

    log_success "Unused protocols disabled"
}

# --- 23. Compiler Restriction (renumbered to 22) -----------------------------
apply_compiler_restriction() {
    create_backup_dir
    log_message "${GEAR} [22/24] Compiler Restriction"
    echo -e "\n${YELLOW}${WARNING} This restricts compilers to root only${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Restrict compiler access? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would remove execute permissions from compilers for non-root"
        log_success "DRY RUN: Compiler access restricted"
        return
    fi

    for compiler in gcc g++ clang clang++ cc c++ ; do
        if command -v "$compiler" &> /dev/null; then
            chmod 700 "$(command -v "$compiler")" 2>/dev/null || true
            log_info "Restricted $compiler"
        fi
    done

    log_success "Compiler access restricted"
}

# --- 24. Remote Syslog (renumbered to 23) ------------------------------------
configure_remote_syslog() {
    create_backup_dir
    log_message "${INFO} [23/24] Remote Syslog"
    echo -e "\n${YELLOW}${WARNING} This configures remote logging${NC}"

    if [[ "$AUTO_MODE" == true ]]; then
        log_warning "Remote syslog requires interactive input; skipping in auto-mode."
        return
    fi

    read -r -p "Configure remote syslog? (y/N): " choice
    [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would configure rsyslog for remote logging"
        log_success "DRY RUN: Remote syslog configured"
        return
    fi

    echo -e "\n${YELLOW}Enter remote syslog server IP:${NC}"
    read -r syslog_server

    if [[ -n "$syslog_server" ]]; then
        backup_file "/etc/rsyslog.conf"
        echo "*.* @$syslog_server:514" >> /etc/rsyslog.conf
        systemctl restart rsyslog >> "$LOG_FILE" 2>&1
        log_success "Remote syslog configured for $syslog_server"
    else
        log_info "No server provided. Skipping."
    fi
}

# --- 24. Password Policies (Safe) --------------------------------------------
apply_password_policies() {
    create_backup_dir
    log_message "${LOCK} [24/24] Password Policies (Safe)"
    echo -e "\n${GREEN}${INFO} This sets password complexity requirements via pwquality.conf${NC}"
    echo -e "${CYAN}${INFO} No PAM stack files (common-password/common-auth/etc.) are touched.${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Apply password policies? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would install pwquality and set complexity rules in /etc/security/pwquality.conf"
        log_success "DRY RUN: Password policies applied"
        return
    fi

    # Skip if more than one display manager's PAM profile is present — a sign
    # of a layered desktop environment (e.g. KDE Plasma/SDDM added on top of a
    # different base DE). See the comment above the old option-8 slot for why.
    local dm_count=0
    for dm_pam in /etc/pam.d/sddm /etc/pam.d/gdm /etc/pam.d/gdm3 /etc/pam.d/lightdm /etc/pam.d/lxdm; do
        [[ -f "$dm_pam" ]] && dm_count=$((dm_count + 1))
    done
    if [[ $dm_count -gt 1 ]]; then
        log_warning "Multiple display manager PAM profiles detected (possible layered desktop environment). Skipping to avoid login issues."
        return
    fi

    case "$DISTRO_TYPE" in
        debian) install_package "libpam-pwquality" ;;
        rhel)   install_package "pam" ;;
        arch)   install_package "libpwquality" ;;
        suse)   install_package "pam" ;;
    esac

    local PWQUALITY_CONF="/etc/security/pwquality.conf"
    backup_file "$PWQUALITY_CONF"
    [[ -f "$PWQUALITY_CONF" ]] || touch "$PWQUALITY_CONF"

    # Idempotent: strip any prior values for these keys before appending fresh ones
    sed -i '/^\s*minlen\s*=/d;/^\s*dcredit\s*=/d;/^\s*ucredit\s*=/d;/^\s*ocredit\s*=/d;/^\s*lcredit\s*=/d' "$PWQUALITY_CONF"

    cat >> "$PWQUALITY_CONF" << 'EOF'
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF

    log_success "Password complexity policy applied (minlen=12, requires upper/lower/digit/special)"
    log_info "Note: on Arch, pam_pwquality isn't wired into the default PAM stack — this config takes effect only if pam_pwquality.so is already referenced in your PAM profile."
}

# --- 25. CIS Checks ----------------------------------------------------------
run_cis_checks() {
    log_cis "Running CIS benchmark compliance checks..."
    echo -e "\n${MAGENTA}${CIS_ICON} CIS BENCHMARK COMPLIANCE CHECK${NC}"
    echo -e "${YELLOW}These checks are non-intrusive (read-only).${NC}\n"

    local issues=0

    # Check 1: Filesystem partitions
    for partition in /home /tmp /var; do
        if mount | grep -q "$partition"; then
            log_success "  $partition is a separate partition"
        else
            log_warning "  $partition is NOT a separate partition"
            issues=$((issues + 1))
        fi
    done

    # Check 2: SSH settings
    if [[ -f /etc/ssh/sshd_config ]]; then
        if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
            log_success "  SSH root login disabled"
        else
            log_warning "  SSH root login not disabled"
            issues=$((issues + 1))
        fi

        if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
            log_success "  SSH password auth disabled"
        else
            log_warning "  SSH password auth not disabled"
            issues=$((issues + 1))
        fi
    fi

    # Check 3: Auditd
    if systemctl is-active auditd &>/dev/null; then
        log_success "  auditd is running"
    else
        log_warning "  auditd is not running"
        issues=$((issues + 1))
    fi

    # Check 4: Fail2ban
    if systemctl is-active fail2ban &>/dev/null; then
        log_success "  fail2ban is running"
    else
        log_warning "  fail2ban is not running"
        issues=$((issues + 1))
    fi

    # Check 5: Firewall
    if systemctl is-active nftables &>/dev/null || systemctl is-active ufw &>/dev/null; then
        log_success "  Firewall is active"
    else
        log_warning "  No active firewall detected"
        issues=$((issues + 1))
    fi

    echo ""
    if [[ $issues -eq 0 ]]; then
        echo -e "${GREEN}${CHECK_MARK} CIS Compliance: PERFECT SCORE! (0 issues)${NC}"
    else
        echo -e "${YELLOW}${WARNING} CIS Compliance: $issues issue(s) found${NC}"
    fi
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
    return 0
}

# --- 26. All Safe Fixes (renumbered to 24) -----------------------------------
apply_all_safe() {
    create_backup_dir
    log_message "${ROCKET} Applying all safe fixes (1-7, 9-16, 24)..."
    echo -e "\n${CYAN}This will apply options 1-7, 9-16, and 24 (Password Policies - Safe)${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Continue? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Cancelled."; return; }
    fi

    apply_system_updates
    apply_ssh_hardening
    apply_firewall
    apply_fail2ban
    apply_permission_hardening
    apply_kernel_hardening
    apply_audit_config
    apply_suid_hardening
    apply_aide
    apply_rkhunter
    apply_disable_services
    apply_apparmor
    apply_etckeeper
    apply_boot_secure
    apply_password_policies

    log_success "All safe fixes processed"
}

# --- 29. Check for Updates ----------------------------------------------------
check_for_updates() {
    log_message "${INFO} Checking for updates from GitHub..."
    echo ""
    echo -e "${CYAN}Installed version:${NC} $VERSION"
    echo ""

    if ! command -v curl &>/dev/null; then
        log_warning "curl is required to check for updates. Install curl and try again."
        return
    fi

    local repo="Kal1010101/ultimate-sys-hardening"
    local api_url="https://api.github.com/repos/${repo}/commits?path=src/free/ultimate_hardening.sh&per_page=1"

    local response
    response=$(curl -fsSL --max-time 10 "$api_url" 2>/dev/null) || true

    if [[ -z "$response" ]]; then
        log_warning "Could not reach GitHub. Check your network connection."
        return
    fi

    local sha message date
    if command -v jq &>/dev/null; then
        sha=$(echo "$response" | jq -r '.[0].sha // empty') || true
        message=$(echo "$response" | jq -r '.[0].commit.message // empty' | head -1) || true
        date=$(echo "$response" | jq -r '.[0].commit.committer.date // empty') || true
    else
        sha=$(echo "$response" | grep -m1 '"sha"' | sed -E 's/.*"sha": *"([^"]+)".*/\1/') || true
        message=$(echo "$response" | grep -m1 '"message"' | sed -E 's/.*"message": *"([^"]*)".*/\1/') || true
        date=$(echo "$response" | grep -m1 '"date"' | sed -E 's/.*"date": *"([^"]+)".*/\1/') || true
    fi

    if [[ -z "$sha" ]]; then
        log_warning "Could not parse update information from GitHub (rate-limited or unexpected response)."
        return
    fi

    echo -e "${CYAN}Latest commit on GitHub (this file):${NC}"
    echo -e "  ${WHITE}${sha:0:7}${NC} - $message"
    echo -e "  ${WHITE}Date:${NC} $date"
    echo ""
    echo -e "${YELLOW}Compare the date/message above with your local copy to see if an update is available.${NC}"
    echo -e "${YELLOW}To update: git -C <repo-dir> pull   (or re-download the script)${NC}"
}

# ----------------------------- Live Status Checks ----------------------------
# Fast, read-only checks used to show whether each module already appears to
# be applied on this system. "N/A" means the option is an action rather than
# a persistent on/off state (e.g. System Updates, Undo SUID, Exit).
get_status() {
    case "$1" in
        1) # System Updates: ON = system is up to date, OFF = updates pending
            local pending=0
            case "$DISTRO_TYPE" in
                debian) pending=$(apt list --upgradable 2>/dev/null | tail -n +2 | wc -l) || pending=0 ;;
                rhel)   pending=$( { yum check-update 2>/dev/null || true; } | grep -cE '^[a-zA-Z0-9]') || pending=0 ;;
                arch)   pending=$(pacman -Qu 2>/dev/null | wc -l) || pending=0 ;;
                suse)   pending=$(zypper lu 2>/dev/null | grep -cE '^v \|') || pending=0 ;;
            esac
            pending="${pending:-0}"
            [[ "$pending" -eq 0 ]] && echo "ON" || echo "OFF" ;;
        2) # SSH Hardening
            if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null && \
               grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
                echo "ON"
            else
                echo "OFF"
            fi ;;
        3) # Firewall
            systemctl is-active --quiet nftables 2>/dev/null && echo "ON" || echo "OFF" ;;
        4) # Fail2Ban
            systemctl is-active --quiet fail2ban 2>/dev/null && echo "ON" || echo "OFF" ;;
        5) # File Permission Hardening
            [[ "$(stat -c '%a' /etc/shadow 2>/dev/null)" == "600" ]] && echo "ON" || echo "OFF" ;;
        6) # Kernel/Network Hardening
            [[ -f /etc/sysctl.d/99-hardening.conf ]] && echo "ON" || echo "OFF" ;;
        7) # Auditd
            systemctl is-active --quiet auditd 2>/dev/null && echo "ON" || echo "OFF" ;;
        8) # SUID/SGID Hardening (checks every binary apply_suid_hardening touches)
            local suid_bins=(/usr/bin/at /usr/bin/chage /usr/bin/crontab /usr/bin/expiry /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/ssh-agent)
            local suid_found=false suid_any_set=false
            for b in "${suid_bins[@]}"; do
                if [[ -f "$b" ]]; then
                    suid_found=true
                    [[ -u "$b" ]] && suid_any_set=true
                fi
            done
            if [[ "$suid_found" == false ]]; then
                echo "N/A"
            elif [[ "$suid_any_set" == true ]]; then
                echo "OFF"
            else
                echo "ON"
            fi ;;
        10) # AIDE
            command -v aide &>/dev/null && [[ -f /var/lib/aide/aide.db.gz ]] && echo "ON" || echo "OFF" ;;
        11) # rkhunter
            command -v rkhunter &>/dev/null && echo "ON" || echo "OFF" ;;
        12) # Disable Unnecessary Services (checks every service apply_disable_services touches)
            local svcs=(avahi-daemon cups nfs-server rpcbind slapd named postfix)
            local svc_found=false svc_any_enabled=false
            for s in "${svcs[@]}"; do
                local svc_state
                svc_state=$(systemctl is-enabled "$s" 2>/dev/null || true)
                case "$svc_state" in
                    enabled|enabled-runtime|static)
                        svc_found=true
                        svc_any_enabled=true
                        ;;
                    disabled|masked)
                        svc_found=true
                        ;;
                esac
            done
            if [[ "$svc_found" == false ]]; then
                echo "N/A"
            elif [[ "$svc_any_enabled" == true ]]; then
                echo "OFF"
            else
                echo "ON"
            fi ;;
        13) # AppArmor/SELinux
            if systemctl is-active --quiet apparmor 2>/dev/null; then
                echo "ON"
            elif [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
                echo "ON"
            else
                echo "OFF"
            fi ;;
        14) # etckeeper
            [[ -d /etc/.git ]] && echo "ON" || echo "OFF" ;;
        15) # Secure Boot Permissions
            [[ "$(stat -c '%a' /boot/grub/grub.cfg 2>/dev/null)" == "600" ]] && echo "ON" || echo "OFF" ;;
        16) # GRUB Password
            grep -q "password_pbkdf2" /etc/grub.d/40_custom 2>/dev/null && echo "ON" || echo "OFF" ;;
        17) # Docker Security
            grep -q "userns-remap" /etc/docker/daemon.json 2>/dev/null && echo "ON" || echo "OFF" ;;
        18) # ModSecurity
            [[ -e /etc/apache2/mods-enabled/security2.load ]] && echo "ON" || echo "OFF" ;;
        19) # Google Authenticator MFA
            grep -q "pam_google_authenticator" /etc/pam.d/sshd 2>/dev/null && echo "ON" || echo "OFF" ;;
        20) # Block USB Storage
            [[ -f /etc/modprobe.d/usb-storage-blacklist.conf ]] && echo "ON" || echo "OFF" ;;
        21) # Disable Unused Protocols
            [[ -f /etc/modprobe.d/disable-unused-protocols.conf ]] && echo "ON" || echo "OFF" ;;
        22) # Restrict Compiler Access
            local gcc_path; gcc_path=$(command -v gcc 2>/dev/null)
            if [[ -n "$gcc_path" ]]; then
                [[ "$(stat -c '%a' "$gcc_path" 2>/dev/null)" == "700" ]] && echo "ON" || echo "OFF"
            else
                echo "N/A"
            fi ;;
        23) # Remote Syslog
            grep -qE '^\*\.\* @' /etc/rsyslog.conf 2>/dev/null && echo "ON" || echo "OFF" ;;
        24) # Password Policies (Safe)
            grep -q "^minlen = 12" /etc/security/pwquality.conf 2>/dev/null && echo "ON" || echo "OFF" ;;
        *) echo "N/A" ;;
    esac
}

# Fixed-width colored badge so menu alignment stays consistent regardless of value
status_tag() {
    case "$1" in
        ON)  printf '%s' "${GREEN}[ON] ${NC}" ;;
        OFF) printf '%s' "${YELLOW}[OFF]${NC}" ;;
        *)   printf '%s' "${CYAN}[N/A]${NC}" ;;
    esac
}

# ----------------------------- Main Menu -------------------------------------
show_menu() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                         ${SHIELD}  ULTIMATE SYSTEM HARDENING v${VERSION}  ${SHIELD}                                          ║${NC}"
    echo -e "${CYAN}║                    Multi-Distribution Security Configuration (${WHITE}${DISTRO_TYPE^^}${CYAN})                                   ║${NC}"
    echo -e "${CYAN}║                   ${GREEN}ecryptfs-Compatible: PAM modules not modified${CYAN}                                   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [[ "$DRY_RUN" == true ]]; then
        echo -e "${YELLOW}⚠️  DRY RUN MODE ENABLED - No changes will be made${NC}"
        echo ""
    fi

    echo -e "${WHITE}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${WHITE}│                         ${GREEN}CORE SECURITY (1-7)${WHITE}                                   │${NC}"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${WHITE}│${NC}  ${ROCKET} 1) System Updates                   ${GREEN}(Safe)${NC} $(status_tag "$(get_status 1)")               ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${LOCK}  2) Harden SSH Configuration       ${YELLOW}(Medium)${NC} $(status_tag "$(get_status 2)")              ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${FIRE}  3) Configure Firewall             ${YELLOW}(Medium)${NC} $(status_tag "$(get_status 3)")              ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD} 4) Install Fail2Ban               ${GREEN}(Safe)${NC} $(status_tag "$(get_status 4)")               ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${LOCK}  5) File Permission Hardening      ${GREEN}(Safe)${NC} $(status_tag "$(get_status 5)")               ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${GEAR}  6) Kernel/Network Hardening       ${GREEN}(Safe)${NC} $(status_tag "$(get_status 6)")               ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD} 7) Configure Auditd               ${GREEN}(Safe)${NC} $(status_tag "$(get_status 7)")               ${WHITE}│${NC}\n"
    echo -e "${WHITE}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${WHITE}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${WHITE}│                         ${YELLOW}MONITORING & HARDENING (8-15)${WHITE}                        │${NC}"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${WHITE}│${NC}  ${FIRE}  8) Harden SUID/SGID Binaries      ${RED}(HIGH RISK)${NC} $(status_tag "$(get_status 8)")            ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${UNDO}  9) Undo SUID Hardening            ${GREEN}(Restore)${NC} $(status_tag "$(get_status 9)")            ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD}10) Install AIDE                  ${GREEN}(Safe)${NC} $(status_tag "$(get_status 10)")               ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD}11) Install rkhunter              ${GREEN}(Safe)${NC} $(status_tag "$(get_status 11)")               ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${GEAR} 12) Disable Unnecessary Services   ${GREEN}(Safe)${NC} $(status_tag "$(get_status 12)")               ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD}13) Configure AppArmor/SELinux    ${GREEN}(Safe)${NC} $(status_tag "$(get_status 13)")               ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${GEAR} 14) Setup etckeeper                ${GREEN}(Safe)${NC} $(status_tag "$(get_status 14)")               ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${LOCK} 15) Secure Boot Permissions        ${GREEN}(Safe)${NC} $(status_tag "$(get_status 15)")               ${WHITE}│${NC}\n"
    echo -e "${WHITE}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${WHITE}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${WHITE}│                         ${MAGENTA}ADVANCED FEATURES (16-24)${WHITE}                           │${NC}"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${WHITE}│${NC}  ${LOCK} 16) Set GRUB Password              ${RED}(HIGH RISK)${NC} $(status_tag "$(get_status 16)")            ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${DOCKER_ICON}17) Docker Security           ${YELLOW}(Medium)${NC} $(status_tag "$(get_status 17)")              ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD}18) Install ModSecurity           ${YELLOW}(Medium)${NC} $(status_tag "$(get_status 18)")              ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${LOCK} 19) Google Authenticator MFA       ${YELLOW}(Medium)${NC} $(status_tag "$(get_status 19)")              ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${FIRE} 20) Block USB Storage              ${YELLOW}(Medium)${NC} $(status_tag "$(get_status 20)")              ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${GEAR} 21) Disable Unused Protocols       ${GREEN}(Safe)${NC} $(status_tag "$(get_status 21)")               ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${GEAR} 22) Restrict Compiler Access       ${GREEN}(Safe)${NC} $(status_tag "$(get_status 22)")               ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${INFO} 23) Configure Remote Syslog        ${YELLOW}(Medium)${NC} $(status_tag "$(get_status 23)")              ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${LOCK} 24) Password Policies (Safe)       ${GREEN}(Safe)${NC} $(status_tag "$(get_status 24)")               ${WHITE}│${NC}\n"
    echo -e "${WHITE}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${WHITE}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${WHITE}│                         ${CYAN}META OPERATIONS${WHITE}                                      │${NC}"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${WHITE}│${NC}  ${CIS_ICON} 25) Run CIS Benchmark Checks     ${GREEN}(Read-only)${NC}                   ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${ROCKET}26) Apply All Safe Fixes (1-7,9-16,24) ${GREEN}(Recommended)${NC}           ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${ROCKET}27) Apply All (Full Hardening)    ${YELLOW}(Complete)${NC}                   ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${UNDO} 28) Full System Revert (from backup) ${RED}(DANGER)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${INFO} 29) Check for Updates              ${GREEN}(Read-only)${NC}                   ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${CROSS_MARK}30) Exit                                       ${WHITE}                  │${NC}\n"
    echo -e "${WHITE}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
    read -r -p "$(echo -e "${WHITE}Enter your choice (1-30):${NC} ")" choice

    case "$choice" in
        1) apply_system_updates ;;
        2) apply_ssh_hardening ;;
        3) apply_firewall ;;
        4) apply_fail2ban ;;
        5) apply_permission_hardening ;;
        6) apply_kernel_hardening ;;
        7) apply_audit_config ;;
        8) apply_suid_hardening ;;
        9) undo_suid_hardening ;;
        10) apply_aide ;;
        11) apply_rkhunter ;;
        12) apply_disable_services ;;
        13) apply_apparmor ;;
        14) apply_etckeeper ;;
        15) apply_boot_secure ;;
        16) apply_grub_password ;;
        17) apply_docker_security ;;
        18) apply_modsecurity ;;
        19) apply_google_auth ;;
        20) apply_usb_blocking ;;
        21) disable_unused_protocols ;;
        22) apply_compiler_restriction ;;
        23) configure_remote_syslog ;;
        24) apply_password_policies ;;
        25) run_cis_checks ;;
        26) apply_all_safe ;;
        27)
            apply_all_safe
            apply_grub_password
            apply_docker_security
            apply_modsecurity
            apply_google_auth
            apply_usb_blocking
            disable_unused_protocols
            apply_compiler_restriction
            configure_remote_syslog
            ;;
        28) full_system_revert ;;
        29) check_for_updates ;;
        30)
            log_info "Exiting. Log file: $LOG_FILE"
            echo -e "${CYAN}Backup directory: $BACKUP_DIR${NC}"
            exit 0
            ;;
        *)
            log_error "Invalid choice"
            ;;
    esac

    press_enter
    show_menu
}

# ----------------------------- Main Execution --------------------------------
main() {
    # Check for revert modes first (don't need distro selection for revert)
    if [[ "$REVERT_MODE" == true ]]; then
        check_root
        full_system_revert
        exit 0
    fi

    if [[ "$REVERT_SUID_ONLY" == true ]]; then
        check_root
        undo_suid_hardening
        exit 0
    fi

    check_root
    show_distro_menu
    # create_backup_dir   # <-- REMOVED: Backup now created only when needed

    trap 'echo -e "\n${RED}Script interrupted. Exiting.${NC}"; exit 1' INT TERM

    show_menu
}

main "$@"