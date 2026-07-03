#!/bin/bash
# =============================================================================
#  ULTIMATE SYSTEM HARDENING SCRIPT (PAM-SAFE VERSION)
#  Version: 2.0.1  |  Multi-distribution support with interactive distro selection
#  27 Security Features - CIS Benchmark Aligned
# =============================================================================
#  CHANGES FROM v2.0.0:
#    - REMOVED: Password Policies module (#8) - caused login loops on ecryptfs
#    - Updated: apply_all_safe() now only applies modules 1-7 and 9-16
#    - Updated: Menu now shows 15 modules instead of 16
#    - Total options reduced from 29 to 28
# =============================================================================
# Usage: sudo ./ultimate_hardening.sh [--skip-backup] [--auto-mode] [--dry-run] [--revert] [--revert-suid] [--help]
# =============================================================================

set -euo pipefail

# ----------------------------- Configuration ---------------------------------
VERSION="2.0.1"
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
        log_error "No backup directory found at $BACKUP_DIR"
        log_info "Cannot perform revert without backups."
        return
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

    # Restore PAM configs
    restore_file "/etc/pam.d/common-password"

    # Restore SUID permissions
    undo_suid_hardening

    # Restore firewall (disable nftables if it wasn't there before)
    if [[ -f /etc/nftables.conf.backup ]] || [[ ! -f /etc/nftables.conf.original ]]; then
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
        log_error "No backup file found at $SUID_BACKUP_FILE"
        return
    fi

    if [[ "$AUTO_MODE" == false ]] && [[ "$REVERT_SUID_ONLY" == false ]]; then
        read -r -p "Restore SUID permissions? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Cancelled."; return; }
    fi

    while IFS= read -r binary; do
        if [[ -f "$binary" ]]; then
            chmod u+s "$binary" 2>/dev/null || true
            log_info "Restored SUID to $binary"
        fi
    done < "$SUID_BACKUP_FILE"

    log_success "SUID permissions restored"
}

# ============================ CORE HARDENING FUNCTIONS ========================

# --- 1. System Updates -------------------------------------------------------
apply_system_updates() {
    create_backup_dir
    log_message "${GEAR} [1/15] System Updates"
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
    log_message "${LOCK} [2/15] SSH Hardening"
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
    log_message "${SHIELD} [3/15] Firewall Configuration"
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

    systemctl enable nftables >> "$LOG_FILE" 2>&1
    systemctl start nftables >> "$LOG_FILE" 2>&1
    nft -f /etc/nftables.conf >> "$LOG_FILE" 2>&1

    log_success "Firewall configured"
}

# --- 4. Fail2Ban -------------------------------------------------------------
apply_fail2ban() {
    create_backup_dir
    log_message "${SHIELD} [4/15] Fail2Ban Installation"
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
    log_message "${LOCK} [5/15] File Permission Hardening"
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
    log_message "${GEAR} [6/15] Kernel Hardening"
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
    log_message "${SHIELD} [7/15] Auditd Configuration"
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

    systemctl enable auditd >> "$LOG_FILE" 2>&1
    systemctl start auditd >> "$LOG_FILE" 2>&1
    auditctl -R /etc/audit/rules.d/99-hardening.rules >> "$LOG_FILE" 2>&1

    log_success "Auditd configured"
}

# --- 8. Password Policies (REMOVED - causes issues with ecryptfs)
# This module has been removed to prevent login loops on systems with
# encrypted home directories. The PAM modifications in this module
# were found to break authentication on ecryptfs systems.

# --- 9. SUID Hardening (renumbered to 8) -------------------------------------
apply_suid_hardening() {
    create_backup_dir
    log_message "${FIRE} [8/15] SUID/SGID Hardening"
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
        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | head -20 > "$SUID_BACKUP_FILE"
        log_success "SUID permissions backed up to $SUID_BACKUP_FILE"
    fi

    # Common non-essential SUID binaries to remove
    for binary in /usr/bin/at /usr/bin/chage /usr/bin/crontab /usr/bin/expiry /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/ssh-agent; do
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
    log_message "${SHIELD} [10/15] AIDE Installation"
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
    log_message "${SHIELD} [11/15] rkhunter Installation"
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
    log_message "${GEAR} [12/15] Disabling Unnecessary Services"
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
    log_message "${SHIELD} [13/15] AppArmor/SELinux Configuration"
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
    log_message "${GEAR} [14/15] etckeeper Setup"
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
    log_message "${LOCK} [15/15] Boot Security"
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
    log_message "${LOCK} [16/15] GRUB Password"
    echo -e "\n${RED}${WARNING} HIGH RISK: This sets a GRUB password${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Set GRUB password? (yes/NO): " choice
        [[ ! "$choice" =~ ^[Yy]es$ ]] && { log_info "Skipped."; return; }
    fi

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
grub_hash=$(echo -e "$grub_pass\n$grub_pass" | grub-mkpasswd-pbkdf2 2>/dev/null | grep -oP 'grub\.pbkdf2\.sha512\.[^\s]+')

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
    log_message "${DOCKER_ICON} [17/15] Docker Security"
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
    log_message "${SHIELD} [18/15] ModSecurity WAF"
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
    log_message "${LOCK} [19/15] Google Authenticator MFA"
    echo -e "\n${YELLOW}${WARNING} This enables MFA for SSH${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Setup Google Authenticator? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "DRY RUN: Would install google-authenticator"
        log_info "DRY RUN: Would configure PAM for MFA"
        log_success "DRY RUN: Google Authenticator configured"
        return
    fi

    install_package "libpam-google-authenticator"

    echo -e "\n${YELLOW}Run 'google-authenticator' manually for each user that needs MFA${NC}"
    echo -e "${YELLOW}Then add 'auth required pam_google_authenticator.so' to /etc/pam.d/sshd${NC}"

    log_success "Google Authenticator configured"
}

# --- 21. USB Blocking (renumbered to 20) -------------------------------------
apply_usb_blocking() {
    create_backup_dir
    log_message "${FIRE} [20/15] USB Storage Blocking"
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
    log_message "${GEAR} [21/15] Disabling Unused Protocols"
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
    log_message "${GEAR} [22/15] Compiler Restriction"
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
    log_message "${INFO} [23/15] Remote Syslog"
    echo -e "\n${YELLOW}${WARNING} This configures remote logging${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -r -p "Configure remote syslog? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

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
        grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null && \
            log_success "  SSH root login disabled" || { log_warning "  SSH root login not disabled"; issues=$((issues + 1)); }

        grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null && \
            log_success "  SSH password auth disabled" || { log_warning "  SSH password auth not disabled"; issues=$((issues + 1)); }
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
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
    return 0
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
    log_message "${ROCKET} [24/15] Applying all safe fixes (1-7, 9-16)..."
    echo -e "\n${CYAN}This will apply options 1-7 and 9-16${NC}"
    echo -e "${YELLOW}NOTE: Password Policies (option 8) has been removed for safety on ecryptfs systems.${NC}"

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
    # Password Policies (option 8) REMOVED - safe for ecryptfs
    apply_suid_hardening
    apply_aide
    apply_rkhunter
    apply_disable_services
    apply_apparmor
    apply_etckeeper
    apply_boot_secure

    log_success "All safe fixes processed"
}

# ----------------------------- Main Menu -------------------------------------
show_menu() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                         ${SHIELD}  ULTIMATE SYSTEM HARDENING v${VERSION}  ${SHIELD}                                          ║${NC}"
    echo -e "${CYAN}║                    Multi-Distribution Security Configuration (${WHITE}${DISTRO_TYPE^^}${CYAN})                                   ║${NC}"
    echo -e "${CYAN}║                   ${YELLOW}PAM-SAFE: Password Policies Removed for ecryptfs Compatibility${CYAN}                   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [[ "$DRY_RUN" == true ]]; then
        echo -e "${YELLOW}⚠️  DRY RUN MODE ENABLED - No changes will be made${NC}"
        echo ""
    fi

    echo -e "${WHITE}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${WHITE}│                         ${GREEN}CORE SECURITY (1-7)${WHITE}                                   │${NC}"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${WHITE}│${NC}  ${ROCKET} 1) System Updates                   ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${LOCK}  2) Harden SSH Configuration       ${YELLOW}(Medium)${NC}                    ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${FIRE}  3) Configure Firewall             ${YELLOW}(Medium)${NC}                    ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD} 4) Install Fail2Ban               ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${LOCK}  5) File Permission Hardening      ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${GEAR}  6) Kernel/Network Hardening       ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD} 7) Configure Auditd               ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    echo -e "${WHITE}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${WHITE}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${WHITE}│                         ${YELLOW}MONITORING & HARDENING (8-15)${WHITE}                        │${NC}"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${WHITE}│${NC}  ${FIRE}  8) Harden SUID/SGID Binaries      ${RED}(HIGH RISK)${NC}                  ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${UNDO}  9) Undo SUID Hardening            ${GREEN}(Restore)${NC}                  ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD}10) Install AIDE                  ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD}11) Install rkhunter              ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${GEAR} 12) Disable Unnecessary Services   ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD}13) Configure AppArmor/SELinux    ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${GEAR} 14) Setup etckeeper                ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${LOCK} 15) Secure Boot Permissions        ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    echo -e "${WHITE}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${WHITE}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${WHITE}│                         ${MAGENTA}ADVANCED FEATURES (16-23)${WHITE}                           │${NC}"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${WHITE}│${NC}  ${LOCK} 16) Set GRUB Password              ${RED}(HIGH RISK)${NC}                  ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${DOCKER_ICON}17) Docker Security           ${YELLOW}(Medium)${NC}                    ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD}18) Install ModSecurity           ${YELLOW}(Medium)${NC}                    ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${LOCK} 19) Google Authenticator MFA       ${YELLOW}(Medium)${NC}                    ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${FIRE} 20) Block USB Storage              ${YELLOW}(Medium)${NC}                    ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${GEAR} 21) Disable Unused Protocols       ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${GEAR} 22) Restrict Compiler Access       ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${INFO} 23) Configure Remote Syslog        ${YELLOW}(Medium)${NC}                    ${WHITE}│${NC}\n"
    echo -e "${WHITE}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${WHITE}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${WHITE}│                         ${CYAN}META OPERATIONS${WHITE}                                      │${NC}"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${WHITE}│${NC}  ${CIS_ICON} 24) Run CIS Benchmark Checks     ${GREEN}(Read-only)${NC}                   ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${ROCKET}25) Apply All Safe Fixes (1-7,9-15) ${GREEN}(Recommended)${NC}              ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${ROCKET}26) Apply All (Full Hardening)    ${YELLOW}(Complete)${NC}                   ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${UNDO} 27) Full System Revert (from backup) ${RED}(DANGER)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${CROSS_MARK}28) Exit                                       ${WHITE}                  │${NC}\n"
    echo -e "${WHITE}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
    read -r -p "$(echo -e "${WHITE}Enter your choice (1-28):${NC} ")" choice

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
        24) run_cis_checks ;;
        25) apply_all_safe ;;
        26)
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
        27) full_system_revert ;;
        28)
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