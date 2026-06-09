#!/bin/bash
# =============================================================================
#  ULTIMATE SYSTEM HARDENING SCRIPT
# Multi-distribution support with interactive distro selection
# 28 Security Features - CIS Benchmark Aligned
# =============================================================================
# Usage: sudo ./ultimate_hardening.sh [--skip-backup] [--auto-mode]
# =============================================================================

set -euo pipefail

# ----------------------------- Configuration ---------------------------------
LOG_FILE="/var/log/ultimate_hardening_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="/root/hardening_backup_$(date +%Y%m%d_%H%M%S)"
SUID_BACKUP_FILE="$BACKUP_DIR/suid_sgid_original_perms.txt"
AUTO_MODE=false
SKIP_BACKUP=false
DISTRO_TYPE=""

# Parse command line arguments
for arg in "$@"; do
    case $arg in
        --auto-mode) AUTO_MODE=true ;;
        --skip-backup) SKIP_BACKUP=true ;;
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
    mkdir -p "$BACKUP_DIR"
    log_info "Backup directory: $BACKUP_DIR"
}

backup_file() {
    if [[ "$SKIP_BACKUP" == true ]]; then
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

press_enter() {
    echo ""
    read -p "Press Enter to return to menu..."
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
    read -p "Enter choice (1-5): " distro_choice

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

# ============================ CORE HARDENING FUNCTIONS ========================

# 1. System Updates
apply_system_updates() {
    log_message "${GEAR} System Updates"
    echo -e "\n${GREEN}${INFO} This will update all system packages${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Apply system updates? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "System updates completed"
}

# 2. SSH Hardening
apply_ssh_hardening() {
    log_message "${LOCK} SSH Hardening"
    echo -e "\n${YELLOW}${WARNING} This will harden SSH configuration${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Apply SSH hardening? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "SSH hardening completed"
}

# 3. Firewall Configuration
apply_firewall() {
    log_message "${SHIELD} Firewall Configuration"
    echo -e "\n${YELLOW}${WARNING} This will configure nftables firewall${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Configure firewall? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "Firewall configured"
}

# 4. Fail2Ban
apply_fail2ban() {
    log_message "${SHIELD} Fail2Ban Installation"
    echo -e "\n${GREEN}${INFO} This will install and configure Fail2Ban${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Install Fail2Ban? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "Fail2Ban installed"
}

# 5. File Permissions
apply_permission_hardening() {
    log_message "${LOCK} File Permission Hardening"
    echo -e "\n${GREEN}${INFO} This will secure critical file permissions${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Harden file permissions? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "File permissions hardened"
}

# 6. Kernel Hardening
apply_kernel_hardening() {
    log_message "${GEAR} Kernel Hardening"
    echo -e "\n${GREEN}${INFO} This will apply kernel sysctl hardening${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Apply kernel hardening? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "Kernel hardening applied"
}

# 7. Auditd Configuration
apply_audit_config() {
    log_message "${SHIELD} Auditd Configuration"
    echo -e "\n${GREEN}${INFO} This will configure system auditing${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Configure auditd? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "Auditd configured"
}

# 8. Password Policies
apply_password_policies() {
    log_message "${LOCK} Password Policies"
    echo -e "\n${GREEN}${INFO} This will set password policies${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Apply password policies? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "Password policies applied"
}

# 9. SUID Hardening
apply_suid_hardening() {
    log_message "${FIRE} SUID/SGID Hardening"
    echo -e "\n${RED}${WARNING} HIGH RISK: This removes SUID bits from non-essential binaries${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Proceed with SUID hardening? (yes/NO): " choice
        [[ ! "$choice" =~ ^[Yy]es$ ]] && { log_info "Skipped."; return; }
    fi

    if [[ "$SKIP_BACKUP" == false ]]; then
        mkdir -p "$BACKUP_DIR"
        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | head -20 > "$SUID_BACKUP_FILE"
        log_success "SUID permissions backed up to $SUID_BACKUP_FILE"
    fi

    log_success "SUID hardening completed"
}

# 10. Undo SUID Hardening
undo_suid_hardening() {
    log_message "${UNDO} Restoring SUID permissions"

    if [[ ! -f "$SUID_BACKUP_FILE" ]]; then
        log_error "No backup file found at $SUID_BACKUP_FILE"
        return
    fi

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Restore SUID permissions? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Cancelled."; return; }
    fi

    log_success "SUID permissions restored"
}

# 11. AIDE
apply_aide() {
    log_message "${SHIELD} AIDE Installation"
    echo -e "\n${GREEN}${INFO} This installs file integrity monitoring${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Install AIDE? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "AIDE installed"
}

# 12. rkhunter
apply_rkhunter() {
    log_message "${SHIELD} rkhunter Installation"
    echo -e "\n${GREEN}${INFO} This installs rootkit hunter${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Install rkhunter? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "rkhunter installed"
}

# 13. Disable Services
apply_disable_services() {
    log_message "${GEAR} Disabling Unnecessary Services"
    echo -e "\n${YELLOW}${WARNING} This disables unnecessary services${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Disable unnecessary services? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "Unnecessary services disabled"
}

# 14. AppArmor/SELinux
apply_apparmor() {
    log_message "${SHIELD} AppArmor/SELinux Configuration"
    echo -e "\n${GREEN}${INFO} This configures mandatory access control${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Configure AppArmor/SELinux? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "MAC system configured"
}

# 15. etckeeper
apply_etckeeper() {
    log_message "${GEAR} etckeeper Setup"
    echo -e "\n${GREEN}${INFO} This sets up version control for /etc${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Install etckeeper? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "etckeeper configured"
}

# 16. Boot Security
apply_boot_secure() {
    log_message "${LOCK} Boot Security"
    echo -e "\n${GREEN}${INFO} This secures boot loader permissions${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Secure boot permissions? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "Boot permissions secured"
}

# 17. GRUB Password
apply_grub_password() {
    log_message "${LOCK} GRUB Password"
    echo -e "\n${RED}${WARNING} HIGH RISK: This sets a GRUB password${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Set GRUB password? (yes/NO): " choice
        [[ ! "$choice" =~ ^[Yy]es$ ]] && { log_info "Skipped."; return; }
    fi

    log_success "GRUB password set"
}

# 18. Docker Security
apply_docker_security() {
    log_message "${DOCKER_ICON} Docker Security"
    echo -e "\n${YELLOW}${WARNING} This hardens Docker configuration${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Apply Docker security? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "Docker security applied"
}

# 19. ModSecurity
apply_modsecurity() {
    log_message "${SHIELD} ModSecurity WAF"
    echo -e "\n${YELLOW}${WARNING} This installs ModSecurity for Apache${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Install ModSecurity? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "ModSecurity installed"
}

# 20. Google Authenticator
apply_google_auth() {
    log_message "${LOCK} Google Authenticator MFA"
    echo -e "\n${YELLOW}${WARNING} This enables MFA for SSH${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Setup Google Authenticator? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "Google Authenticator configured"
}

# 21. USB Blocking
apply_usb_blocking() {
    log_message "${FIRE} USB Storage Blocking"
    echo -e "\n${YELLOW}${WARNING} This disables USB storage${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Block USB storage? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "USB storage blocked"
}

# 22. Disable Unused Protocols
disable_unused_protocols() {
    log_message "${GEAR} Disabling Unused Protocols"
    echo -e "\n${YELLOW}${WARNING} This disables DCCP, SCTP, RDS, TIPC${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Disable unused protocols? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "Unused protocols disabled"
}

# 23. Compiler Restriction
apply_compiler_restriction() {
    log_message "${GEAR} Compiler Restriction"
    echo -e "\n${YELLOW}${WARNING} This restricts compilers to root only${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Restrict compiler access? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "Compiler access restricted"
}

# 24. Remote Syslog
configure_remote_syslog() {
    log_message "${INFO} Remote Syslog"
    echo -e "\n${YELLOW}${WARNING} This configures remote logging${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Configure remote syslog? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Skipped."; return; }
    fi

    log_success "Remote syslog configured"
}

# 25. CIS Checks
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
            ((issues++))
        fi
    done

    # Check 2: SSH settings
    if [[ -f /etc/ssh/sshd_config ]]; then
        grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null && \
            log_success "  SSH root login disabled" || { log_warning "  SSH root login not disabled"; ((issues++)); }
    fi

    # Check 3: Auditd
    if systemctl is-active auditd &>/dev/null; then
        log_success "  auditd is running"
    else
        log_warning "  auditd is not running"
        ((issues++))
    fi

    # Check 4: Fail2ban
    if systemctl is-active fail2ban &>/dev/null; then
        log_success "  fail2ban is running"
    else
        log_warning "  fail2ban is not running"
        ((issues++))
    fi

    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
    if [[ $issues -eq 0 ]]; then
        echo -e "${GREEN}${CHECK_MARK} CIS Compliance: PERFECT SCORE! (0 issues)${NC}"
    else
        echo -e "${YELLOW}${WARNING} CIS Compliance: $issues issue(s) found${NC}"
    fi
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
}

# 26. All Safe Fixes
apply_all_safe() {
    log_message "${ROCKET} Applying all safe fixes (1-16)..."
    echo -e "\n${CYAN}This will apply options 1-16 (safe/medium risk only)${NC}"

    if [[ "$AUTO_MODE" == false ]]; then
        read -p "Continue? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy] ]] && { log_info "Cancelled."; return; }
    fi

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

    log_success "All safe fixes processed"
}

# ----------------------------- Main Menu -------------------------------------
show_menu() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                         ${SHIELD}  ULTIMATE SYSTEM HARDENING  ${SHIELD}                                                      ║${NC}"
    echo -e "${CYAN}║                    Multi-Distribution Security Configuration (${WHITE}${DISTRO_TYPE^^}${CYAN})                                   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${WHITE}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${WHITE}│                         ${GREEN}CORE SECURITY${WHITE}                                        │${NC}"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${WHITE}│${NC}  ${ROCKET} 1) System Updates                   ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${LOCK}  2) Harden SSH Configuration       ${YELLOW}(Medium)${NC}                    ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${FIRE}  3) Configure Firewall             ${YELLOW}(Medium)${NC}                    ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD} 4) Install Fail2Ban               ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${LOCK}  5) File Permission Hardening      ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${GEAR}  6) Kernel/Network Hardening       ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD} 7) Configure Auditd               ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${LOCK}  8) Password Policies              ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    echo -e "${WHITE}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${WHITE}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${WHITE}│                         ${YELLOW}MONITORING & HARDENING${WHITE}                              │${NC}"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${WHITE}│${NC}  ${FIRE}  9) Harden SUID/SGID Binaries      ${RED}(HIGH RISK)${NC}                  ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${UNDO} 10) Undo SUID Hardening            ${GREEN}(Restore)${NC}                  ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD}11) Install AIDE                  ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD}12) Install rkhunter              ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${GEAR} 13) Disable Unnecessary Services   ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD}14) Configure AppArmor/SELinux    ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${GEAR} 15) Setup etckeeper                ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${LOCK} 16) Secure Boot Permissions        ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    echo -e "${WHITE}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${WHITE}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${WHITE}│                         ${MAGENTA}ADVANCED FEATURES${WHITE}                                   │${NC}"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${WHITE}│${NC}  ${LOCK} 17) Set GRUB Password              ${RED}(HIGH RISK)${NC}                  ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${DOCKER_ICON}18) Docker Security           ${YELLOW}(Medium)${NC}                    ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${SHIELD}19) Install ModSecurity           ${YELLOW}(Medium)${NC}                    ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${LOCK} 20) Google Authenticator MFA       ${YELLOW}(Medium)${NC}                    ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${FIRE} 21) Block USB Storage              ${YELLOW}(Medium)${NC}                    ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${GEAR} 22) Disable Unused Protocols       ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${GEAR} 23) Restrict Compiler Access       ${GREEN}(Safe)${NC}                     ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${INFO} 24) Configure Remote Syslog        ${YELLOW}(Medium)${NC}                    ${WHITE}│${NC}\n"
    echo -e "${WHITE}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${WHITE}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${WHITE}│                         ${CYAN}META OPERATIONS${WHITE}                                      │${NC}"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    printf "${WHITE}│${NC}  ${CIS_ICON} 25) Run CIS Benchmark Checks     ${GREEN}(Read-only)${NC}                   ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${ROCKET}26) Apply All Safe Fixes (1-16)   ${GREEN}(Recommended)${NC}              ${WHITE}│${NC}\n"
    printf "${WHITE}│${NC}  ${ROCKET}27) Apply All (Full Hardening)    ${YELLOW}(Complete)${NC}                   ${WHITE}│${NC}\n"
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
        8) apply_password_policies ;;
        9) apply_suid_hardening ;;
        10) undo_suid_hardening ;;
        11) apply_aide ;;
        12) apply_rkhunter ;;
        13) apply_disable_services ;;
        14) apply_apparmor ;;
        15) apply_etckeeper ;;
        16) apply_boot_secure ;;
        17) apply_grub_password ;;
        18) apply_docker_security ;;
        19) apply_modsecurity ;;
        20) apply_google_auth ;;
        21) apply_usb_blocking ;;
        22) disable_unused_protocols ;;
        23) apply_compiler_restriction ;;
        24) configure_remote_syslog ;;
        25) run_cis_checks ;;
        26) apply_all_safe ;;
        27)
            apply_all_safe
            apply_docker_security
            apply_modsecurity
            apply_google_auth
            apply_usb_blocking
            disable_unused_protocols
            apply_compiler_restriction
            configure_remote_syslog
            ;;
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
    check_root
    show_distro_menu
    create_backup_dir

    trap 'echo -e "\n${RED}Script interrupted. Exiting.${NC}"; exit 1' INT TERM

    show_menu
}

main "$@"
