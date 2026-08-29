#!/bin/bash
# =============================================================================
#  lib/platform.sh — OS abstraction layer
#
#  Provides a uniform interface over 11 package managers and 4 init systems so
#  hardening modules never branch on distro themselves.
#
#  Exports:
#    detect_platform          -> sets DISTRO_TYPE, OS_FAMILY
#    show_distro_menu         -> interactive selection (respects AUTO_MODE)
#    get_package_manager      -> echoes pm name
#    install_package <pkg>    -> best-effort install, never fatal
#    update_packages          -> full system upgrade, never fatal
#    enable_service <svc>     -> enable + start via detected init
#    stop_service <svc>       -> stop + disable via detected init
#    is_service_active <svc>  -> exit 0 if running
#    is_linux                 -> exit 0 on Linux
#
#  Requires: lib/core.sh sourced first (for log_* and DRY_RUN).
# =============================================================================

# ---------------------------------------------------------------- detection --
detect_platform() {
    local os_name; os_name=$(uname -s)

    case "$os_name" in
        Darwin)  OS_FAMILY="unix"; echo "macos";   return ;;
        FreeBSD) OS_FAMILY="bsd";  echo "freebsd"; return ;;
        OpenBSD) OS_FAMILY="bsd";  echo "openbsd"; return ;;
        NetBSD)  OS_FAMILY="bsd";  echo "netbsd";  return ;;
        SunOS)   OS_FAMILY="unix"; echo "solaris"; return ;;
    esac

    OS_FAMILY="linux"

    if [[ ! -f /etc/os-release ]]; then
        echo "debian"; return
    fi

    local id id_like
    # ID_LIKE (and, on some minimal images, ID itself) may be absent from
    # /etc/os-release — grep exits 1 on no match, which pipefail propagates
    # even though cut/tr/head downstream exit 0; `|| true` prevents that from
    # killing the script under set -e.
    id=$(grep -E '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | head -1 || true)
    id_like=$(grep -E '^ID_LIKE=' /etc/os-release | cut -d= -f2 | tr -d '"' | head -1 || true)

    case "$id" in
        ubuntu|debian|linuxmint|pop|kali|raspbian|elementary|zorin|devuan)
            echo "debian" ;;
        rhel|centos|fedora|rocky|almalinux|amzn|ol|scientific|navylinux)
            echo "rhel" ;;
        arch|manjaro|endeavouros|garuda|artix|cachyos)
            echo "arch" ;;
        opensuse*|sles|suse)
            echo "suse" ;;
        alpine) echo "alpine" ;;
        void)   echo "void" ;;
        gentoo) echo "gentoo" ;;
        nixos)  echo "nixos" ;;
        *)
            case "$id_like" in
                *debian*|*ubuntu*) echo "debian" ;;
                *rhel*|*fedora*|*centos*) echo "rhel" ;;
                *arch*)  echo "arch" ;;
                *suse*)  echo "suse" ;;
                *alpine*) echo "alpine" ;;
                *)       echo "debian" ;;
            esac
            ;;
    esac
}

is_linux() { [[ "${OS_FAMILY:-linux}" == "linux" ]]; }

show_distro_menu() {
    if [[ "${AUTO_MODE:-false}" == true ]]; then
        DISTRO_TYPE=$(detect_platform)
        log_success "Auto-detected platform: $DISTRO_TYPE"
        return
    fi

    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              SELECT YOUR OPERATING SYSTEM / DISTRO               ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${WHITE}Linux${NC}"
    echo -e "  ${GREEN} 1)${NC} Debian / Ubuntu / Mint / Kali / Raspbian"
    echo -e "  ${GREEN} 2)${NC} RHEL / CentOS / Fedora / Rocky / Alma / Amazon"
    echo -e "  ${GREEN} 3)${NC} Arch / Manjaro / EndeavourOS / Artix"
    echo -e "  ${GREEN} 4)${NC} openSUSE / SLES"
    echo -e "  ${GREEN} 5)${NC} Alpine"
    echo -e "  ${GREEN} 6)${NC} Void"
    echo -e "  ${GREEN} 7)${NC} Gentoo"
    echo -e "  ${GREEN} 8)${NC} NixOS"
    echo ""
    echo -e "  ${WHITE}Unix / BSD${NC}  ${YELLOW}(partial coverage)${NC}"
    echo -e "  ${GREEN} 9)${NC} macOS      ${GREEN}10)${NC} FreeBSD    ${GREEN}11)${NC} OpenBSD"
    echo -e "  ${GREEN}12)${NC} NetBSD     ${GREEN}13)${NC} Solaris"
    echo ""
    echo -e "  ${GREEN} 0)${NC} Auto-detect ${CYAN}(recommended)${NC}"
    echo ""
    read -r -p "Enter choice (0-13): " distro_choice

    case "$distro_choice" in
        1)  DISTRO_TYPE="debian";  OS_FAMILY="linux" ;;
        2)  DISTRO_TYPE="rhel";    OS_FAMILY="linux" ;;
        3)  DISTRO_TYPE="arch";    OS_FAMILY="linux" ;;
        4)  DISTRO_TYPE="suse";    OS_FAMILY="linux" ;;
        5)  DISTRO_TYPE="alpine";  OS_FAMILY="linux" ;;
        6)  DISTRO_TYPE="void";    OS_FAMILY="linux" ;;
        7)  DISTRO_TYPE="gentoo";  OS_FAMILY="linux" ;;
        8)  DISTRO_TYPE="nixos";   OS_FAMILY="linux" ;;
        9)  DISTRO_TYPE="macos";   OS_FAMILY="unix"  ;;
        10) DISTRO_TYPE="freebsd"; OS_FAMILY="bsd"   ;;
        11) DISTRO_TYPE="openbsd"; OS_FAMILY="bsd"   ;;
        12) DISTRO_TYPE="netbsd";  OS_FAMILY="bsd"   ;;
        13) DISTRO_TYPE="solaris"; OS_FAMILY="unix"  ;;
        *)  DISTRO_TYPE=$(detect_platform) ;;
    esac

    log_success "Platform: $DISTRO_TYPE"
}

# ---------------------------------------------------------- package manager --
get_package_manager() {
    case "${DISTRO_TYPE:-debian}" in
        debian)  echo "apt" ;;
        rhel)    if command -v dnf >/dev/null 2>&1; then echo "dnf"; else echo "yum"; fi ;;
        arch)    echo "pacman" ;;
        suse)    echo "zypper" ;;
        alpine)  echo "apk" ;;
        void)    echo "xbps" ;;
        gentoo)  echo "emerge" ;;
        nixos)   echo "nix" ;;
        macos)   if command -v brew >/dev/null 2>&1; then echo "brew"; else echo "none"; fi ;;
        freebsd|openbsd|netbsd|solaris) echo "pkg" ;;
        *)       echo "apt" ;;
    esac
}

# Never fatal: a missing package degrades one module, it doesn't end the run.
install_package() {
    local pkg="$1"
    if [[ "${DRY_RUN:-false}" == true ]]; then
        log_info "DRY RUN: Would install package: $pkg"
        return 0
    fi

    local pm; pm=$(get_package_manager)
    case "$pm" in
        apt)    DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >>"$LOG_FILE" 2>&1 || return 1 ;;
        dnf)    dnf install -y "$pkg" >>"$LOG_FILE" 2>&1 || return 1 ;;
        yum)    yum install -y "$pkg" >>"$LOG_FILE" 2>&1 || return 1 ;;
        pacman) pacman -S --noconfirm --needed "$pkg" >>"$LOG_FILE" 2>&1 || return 1 ;;
        zypper) zypper --non-interactive install "$pkg" >>"$LOG_FILE" 2>&1 || return 1 ;;
        apk)    apk add --no-cache "$pkg" >>"$LOG_FILE" 2>&1 || return 1 ;;
        xbps)   xbps-install -y "$pkg" >>"$LOG_FILE" 2>&1 || return 1 ;;
        emerge) emerge --quiet "$pkg" >>"$LOG_FILE" 2>&1 || return 1 ;;
        pkg)    pkg install -y "$pkg" >>"$LOG_FILE" 2>&1 || return 1 ;;
        nix)    nix-env -iA "nixpkgs.$pkg" >>"$LOG_FILE" 2>&1 || return 1 ;;
        brew)   sudo -u "${SUDO_USER:-root}" brew install "$pkg" 2>&1 | tee -a "$LOG_FILE" >/dev/null || return 1 ;;
        none)   log_warning "No package manager available — install $pkg manually"; return 1 ;;
    esac
    log_success "Installed: $pkg"
    return 0
}

# How many upgrades are pending against the package index AS IT CURRENTLY
# STANDS on disk. Deliberately does NOT refresh the index first — that needs
# the network, and this is called on every menu redraw. Echoes an integer;
# echoes "unknown" when the package manager has no cheap offline query.
#
# Every branch is wrapped so a package manager that errors (broken index,
# unusual state) reports 0 rather than killing the caller under `set -e`.
count_pending_updates() {
    local pm; pm=$(get_package_manager)
    local n=0
    case "$pm" in
        apt)    n=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst ' || true) ;;
        dnf)    n=$(dnf -q --cacheonly check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9]' || true) ;;
        yum)    n=$(yum -q -C check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9]' || true) ;;
        pacman) n=$(pacman -Qu 2>/dev/null | wc -l || true) ;;
        zypper) n=$(zypper --non-interactive list-updates 2>/dev/null | grep -c '^v ' || true) ;;
        apk)    n=$(apk version -l '<' 2>/dev/null | tail -n +2 | grep -c . || true) ;;
        xbps)   n=$(xbps-install -Mun 2>/dev/null | grep -c . || true) ;;
        *)      printf 'unknown'; return 0 ;;
    esac
    printf '%s' "${n:-0}"
    return 0
}

update_packages() {
    if [[ "${DRY_RUN:-false}" == true ]]; then
        log_info "DRY RUN: Would upgrade all system packages"
        return 0
    fi
    local pm; pm=$(get_package_manager)
    case "$pm" in
        apt)    DEBIAN_FRONTEND=noninteractive apt-get update -qq >>"$LOG_FILE" 2>&1 || true
                DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >>"$LOG_FILE" 2>&1 || true ;;
        dnf)    dnf upgrade -y >>"$LOG_FILE" 2>&1 || true ;;
        yum)    yum update -y  >>"$LOG_FILE" 2>&1 || true ;;
        pacman) pacman -Syu --noconfirm >>"$LOG_FILE" 2>&1 || true ;;
        zypper) zypper --non-interactive update >>"$LOG_FILE" 2>&1 || true ;;
        apk)    apk update >>"$LOG_FILE" 2>&1 || true; apk upgrade >>"$LOG_FILE" 2>&1 || true ;;
        xbps)   xbps-install -Suy >>"$LOG_FILE" 2>&1 || true ;;
        emerge) emerge --sync >>"$LOG_FILE" 2>&1 || true
                emerge -uDN @world >>"$LOG_FILE" 2>&1 || true ;;
        pkg)    pkg upgrade -y >>"$LOG_FILE" 2>&1 || true ;;
        nix)    nix-channel --update >>"$LOG_FILE" 2>&1 || true ;;
        brew)   sudo -u "${SUDO_USER:-root}" brew update  2>&1 | tee -a "$LOG_FILE" >/dev/null || true
                sudo -u "${SUDO_USER:-root}" brew upgrade 2>&1 | tee -a "$LOG_FILE" >/dev/null || true ;;
    esac
    return 0
}

# ------------------------------------------------------------- init systems --
_has_systemd() { command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; }
_has_openrc()  { command -v rc-update >/dev/null 2>&1; }

enable_service() {
    local svc="$1"
    if [[ "${DRY_RUN:-false}" == true ]]; then
        log_info "DRY RUN: Would enable and start service: $svc"
        return 0
    fi
    if _has_systemd; then
        systemctl enable "$svc" >>"$LOG_FILE" 2>&1 || true
        systemctl start  "$svc" >>"$LOG_FILE" 2>&1 || true
    elif _has_openrc; then
        rc-update add "$svc" default >>"$LOG_FILE" 2>&1 || true
        rc-service "$svc" start      >>"$LOG_FILE" 2>&1 || true
    elif [[ -f /etc/rc.conf ]] && command -v sysrc >/dev/null 2>&1; then
        sysrc "${svc}_enable=YES" >>"$LOG_FILE" 2>&1 || true
        service "$svc" start      >>"$LOG_FILE" 2>&1 || true
    elif command -v service >/dev/null 2>&1; then
        service "$svc" start >>"$LOG_FILE" 2>&1 || true
    else
        log_warning "No supported init system — enable $svc manually"
        return 1
    fi
    log_success "Service enabled: $svc"
    return 0
}

stop_service() {
    local svc="$1"
    if [[ "${DRY_RUN:-false}" == true ]]; then
        log_info "DRY RUN: Would stop and disable service: $svc"
        return 0
    fi
    if _has_systemd; then
        systemctl stop    "$svc" >>"$LOG_FILE" 2>&1 || true
        systemctl disable "$svc" >>"$LOG_FILE" 2>&1 || true
    elif _has_openrc; then
        rc-service "$svc" stop  >>"$LOG_FILE" 2>&1 || true
        rc-update  del   "$svc" >>"$LOG_FILE" 2>&1 || true
    elif command -v service >/dev/null 2>&1; then
        service "$svc" stop >>"$LOG_FILE" 2>&1 || true
    fi
    return 0
}

restart_service() {
    local svc="$1"
    [[ "${DRY_RUN:-false}" == true ]] && { log_info "DRY RUN: Would restart $svc"; return 0; }
    if _has_systemd; then
        systemctl restart "$svc" >>"$LOG_FILE" 2>&1 || return 1
    elif _has_openrc; then
        rc-service "$svc" restart >>"$LOG_FILE" 2>&1 || return 1
    elif command -v service >/dev/null 2>&1; then
        service "$svc" restart >>"$LOG_FILE" 2>&1 || return 1
    else
        return 1
    fi
    return 0
}

is_service_active() {
    local svc="$1"
    if _has_systemd; then
        systemctl is-active "$svc" >/dev/null 2>&1
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service "$svc" status >/dev/null 2>&1
    elif command -v service >/dev/null 2>&1; then
        service "$svc" status >/dev/null 2>&1
    else
        return 1
    fi
}

# SSH daemon is named differently across distros; try both.
restart_sshd() {
    restart_service sshd || restart_service ssh || {
        log_warning "Could not restart SSH daemon — restart it manually"
        return 1
    }
    return 0
}
