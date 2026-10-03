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
    # UH_AUTODETECT_PLATFORM is set by the paid tiers for flags that run to
    # completion without a menu (--policy, --openscap, --report, --auto-fix…).
    # It is deliberately NOT AUTO_MODE: that one also auto-answers every
    # confirm() prompt, which an unattended flag has no business doing.
    if [[ "${AUTO_MODE:-false}" == true || "${UH_AUTODETECT_PLATFORM:-false}" == true ]]; then
        DISTRO_TYPE=$(detect_platform)
        log_success "Auto-detected platform: $DISTRO_TYPE"
        return
    fi

    clear
    # This box was the only hand-padded one that happened to be correct — it
    # holds no emoji and nothing variable. It still goes through box_line, so
    # there is one way to draw a box rather than one way plus an exception.
    box_top
    box_line "${CYAN}              SELECT YOUR OPERATING SYSTEM / DISTRO${NC}"
    box_bottom
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

# ------------------------------------------------- dependency resolution ------
#  Preflight: resolve every module's packages BEFORE the first module writes
#  anything, so an unobtainable dependency is reported up front instead of
#  discovered partway through a half-hardened system.
#
#    module_dependencies         -> "module_key:package" lines for THIS platform
#    package_installed <pkg>     -> 0 installed, 1 not, 2 cannot tell
#    package_available <pkg>     -> 0 available, 1 not, 2 cannot tell
#    refresh_package_index       -> sync the index (skipped under --dry-run)
#    preflight_dependencies      -> resolve + install; ALWAYS returns 0
#
#  Package managers covered: apt dnf yum zypper pacman apk xbps. Elsewhere
#  (emerge, nix, brew, BSD pkg) there is no clean offline query, so preflight
#  says so and leaves each module to install what it needs as it runs.
UH_PREFLIGHT_MISSING=()

_preflight_supported() {
    is_linux || return 1
    case "$(get_package_manager)" in
        apt|dnf|yum|zypper|pacman|apk|xbps) return 0 ;;
        *) return 1 ;;
    esac
}

# Only modules that actually install something appear. Conditional ones are
# left out when their precondition is absent, exactly as the module itself
# would return early: no Apache means no ModSecurity line.
module_dependencies() {
    _preflight_supported || return 0
    local pm distro
    pm=$(get_package_manager)
    distro="${DISTRO_TYPE:-$(detect_platform)}"

    # apply_firewall configures whatever is already present and installs one
    # only when nothing is. Mirror that, using the module's own picker.
    if ! command -v ufw >/dev/null 2>&1 && ! command -v nft >/dev/null 2>&1 \
       && ! command -v firewall-cmd >/dev/null 2>&1; then
        echo "firewall:$(firewall_package_for "$distro")"
    fi
    echo "fail2ban:fail2ban"
    if [[ "$pm" == "apt" ]]; then echo "audit:auditd"; else echo "audit:audit"; fi
    echo "aide:aide"
    echo "rkhunter:rkhunter"
    # apply_apparmor only acts when aa-status already exists, so on Debian the
    # package has to be present BEFORE that module runs or it is a no-op.
    if [[ "$distro" == "debian" ]] && ! command -v aa-status >/dev/null 2>&1; then
        echo "apparmor:apparmor-utils"
    fi
    echo "etckeeper:etckeeper"
    if command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
        case "$distro" in
            debian) echo "modsec:libapache2-mod-security2" ;;
            rhel)   echo "modsec:mod_security" ;;
        esac
    fi
}

package_installed() {
    local pkg="$1" rc=1
    case "$(get_package_manager)" in
        apt)    [[ "$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null)" == *"install ok installed"* ]] && rc=0 ;;
        dnf|yum|zypper) rpm -q "$pkg" >/dev/null 2>&1 && rc=0 ;;
        pacman) pacman -Q "$pkg" >/dev/null 2>&1 && rc=0 ;;
        apk)    apk info -e "$pkg" >/dev/null 2>&1 && rc=0 ;;
        xbps)   xbps-query "$pkg" >/dev/null 2>&1 && rc=0 ;;
        *)      rc=2 ;;
    esac
    return "$rc"
}

# 2 means "cannot tell" and is treated by the caller as "let the install try",
# never as "missing".
package_available() {
    local pkg="$1" rc=1 cand
    case "$(get_package_manager)" in
        apt)
            # `apt-cache search`/`show` exit 0 for unknown names; only the
            # policy Candidate line is reliable.
            cand=$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ && !d {print $2; d=1}')
            [[ -n "$cand" && "$cand" != "(none)" ]] && rc=0 ;;
        dnf)    dnf -q list --available "$pkg" >/dev/null 2>&1 && rc=0 ;;
        yum)    yum -q list available "$pkg" >/dev/null 2>&1 && rc=0 ;;
        zypper) zypper --non-interactive -q info "$pkg" >/dev/null 2>&1 && rc=0 ;;
        pacman) pacman -Si "$pkg" >/dev/null 2>&1 && rc=0 ;;
        apk)    [[ -n "$(apk search -e "$pkg" 2>/dev/null)" ]] && rc=0 ;;
        xbps)   xbps-query -R "$pkg" >/dev/null 2>&1 && rc=0 ;;
        *)      rc=2 ;;
    esac
    return "$rc"
}

# Without this, apt and apk answer "unavailable" for everything on a fresh
# cloud image (empty index) — a confident, uniform and wrong verdict. dnf ships
# a populated cache, which is why this bug only shows on the other managers.
# pacman is deliberately NOT synced: a database sync without a full upgrade is
# the unsupported partial-upgrade state, and module 1 does the real -Syu.
refresh_package_index() {
    [[ "${DRY_RUN:-false}" == true ]] && return 0
    case "$(get_package_manager)" in
        apt)    DEBIAN_FRONTEND=noninteractive apt-get update -qq >>"$LOG_FILE" 2>&1 || return 1 ;;
        dnf)    dnf -q makecache >>"$LOG_FILE" 2>&1 || return 1 ;;
        yum)    yum -q makecache >>"$LOG_FILE" 2>&1 || return 1 ;;
        zypper) zypper --non-interactive -q refresh >>"$LOG_FILE" 2>&1 || return 1 ;;
        apk)    apk update >>"$LOG_FILE" 2>&1 || return 1 ;;
        xbps)   xbps-install -Sy >>"$LOG_FILE" 2>&1 || return 1 ;;
        *)      return 0 ;;
    esac
    log_info "  package index refreshed"
    return 0
}

# Always returns 0. Every module that needs a package already degrades to a
# skip; abandoning a hardening pass over a missing rkhunter is the operator's
# call, not ours. What this changes is that the outcome is visible before the
# first byte is written.
preflight_dependencies() {
    UH_PREFLIGHT_MISSING=()
    if ! _preflight_supported; then
        log_info "Preflight: dependency resolution is not available on this platform — each module installs what it needs as it runs"
        return 0
    fi

    log_message "${GEAR} Preflight: resolving package dependencies"
    if ! refresh_package_index; then
        log_warning "Preflight: could not refresh the package index — the answers below come from the index already on disk"
    fi

    local key pkg avail checked=0
    while IFS=: read -r key pkg; do
        [[ -n "$key" && -n "$pkg" ]] || continue
        checked=$((checked + 1))
        if package_installed "$pkg"; then
            log_info "  ok       $key: $pkg already installed"
            continue
        fi
        avail=0; package_available "$pkg" || avail=$?
        if [[ $avail -eq 1 ]]; then
            log_warning "  missing  $key: $pkg is not available from the configured repositories"
            UH_PREFLIGHT_MISSING+=("$key:$pkg")
            continue
        fi
        # ModSecurity changes a live web server; module 18 asks first, so
        # preflight only reports on it and never installs it unprompted.
        if [[ "$key" == "modsec" ]]; then
            log_info "  ok       $key: $pkg is available (installed only if you confirm module 18)"
            continue
        fi
        if [[ "${DRY_RUN:-false}" == true ]]; then
            log_info "  Would install $pkg (for $key)"
        elif install_package "$pkg"; then
            :
        else
            log_warning "  missing  $key: $pkg could not be installed"
            UH_PREFLIGHT_MISSING+=("$key:$pkg")
        fi
    done < <(module_dependencies)

    if [[ ${#UH_PREFLIGHT_MISSING[@]} -gt 0 ]]; then
        log_warning "Preflight: ${#UH_PREFLIGHT_MISSING[@]} package(s) cannot be obtained — these modules will skip: ${UH_PREFLIGHT_MISSING[*]}"
        case "${DISTRO_TYPE:-}" in
            rhel)   log_info "  Hint: fail2ban, rkhunter and etckeeper live in EPEL, not the base repositories" ;;
            alpine) log_info "  Hint: aide and rkhunter are outside main/community — enable the testing repository" ;;
        esac
    else
        log_success "Preflight: all $checked dependencies resolved"
    fi
    return 0
}

# --------------------------------------------------------------- boot chain --
#  An upgrade that leaves the next boot broken is not a successful upgrade.
#  On 2026-09-05 an unattended `apk upgrade` moved Alpine to a new kernel and
#  never rebuilt the initramfs; the module printed "System packages updated"
#  and the machine failed its next reboot.
#
#  Alpine is the trap: it keeps ONE image per flavour (/boot/initramfs-virt),
#  shared by every version, so the file always exists and existence proves
#  nothing — the image has to contain THIS version's modules. Debian, RHEL and
#  SUSE name the image after the kernel, so existence is enough there.
#
#  UH_BOOTCHECK_ROOT prefixes every path read here and UH_BOOTCHECK_RUNNING
#  overrides `uname -r`; both exist only so tests/cases/test_boot_images.sh can
#  run against a fake root. Unset, they change nothing.

# One installed kernel version per line (uname -r style), oldest first. Taken
# from /lib/modules, which is what a boot image is built from. Distros that
# name their kernel files by version must also have that file, so the leftover
# directory of a removed kernel is not mistaken for an installed one.
installed_kernel_versions() {
    is_linux || return 0
    local root="${UH_BOOTCHECK_ROOT:-}" distro="${DISTRO_TYPE:-$(detect_platform)}" d v
    for d in "$root"/lib/modules/*/; do
        [[ -d "$d" ]] || continue
        v="${d%/}"; v="${v##*/}"
        [[ "$v" =~ ^[0-9] ]] || continue
        case "$distro" in
            debian|rhel|suse) [[ -e "$root/boot/vmlinuz-$v" ]] || continue ;;
        esac
        printf '%s\n' "$v"
    done | sort -V
}

# boot_image_has_modules <image> <version>
# 0 the image contains lib/modules/<version>/, 1 it does not or is missing.
# grep -ac, not grep -q: an initramfs is tens of MB with module paths near the
# start, so an early-exiting grep would SIGPIPE gzip and pipefail would read a
# found module as missing — then every image would be "rebuilt", every run.
boot_image_has_modules() {
    local img="$1" ver="$2" n
    [[ -f "$img" ]] || return 1
    n=$(gzip -dc "$img" 2>/dev/null | grep -ac "lib/modules/${ver}/" || true)
    [[ "${n:-0}" -gt 0 ]]
}

_boot_image_path() {
    local ver="$1" root="${UH_BOOTCHECK_ROOT:-}"
    case "${DISTRO_TYPE:-$(detect_platform)}" in
        alpine) printf '%s' "$root/boot/initramfs-${ver##*-}" ;;
        debian) printf '%s' "$root/boot/initrd.img-$ver" ;;
        rhel)   printf '%s' "$root/boot/initramfs-$ver.img" ;;
        suse)   printf '%s' "$root/boot/initrd-$ver" ;;
    esac
}

# 0 the boot image for <version> is good, 1 missing or stale, 2 not checked here.
_boot_image_ok() {
    local ver="$1" img
    img=$(_boot_image_path "$ver")
    [[ -n "$img" ]] || return 2
    if [[ "${DISTRO_TYPE:-$(detect_platform)}" == "alpine" ]]; then
        boot_image_has_modules "$img" "$ver"
    else
        [[ -f "$img" ]]
    fi
}

_rebuild_boot_image() {
    local ver="$1" img
    img=$(_boot_image_path "$ver")
    case "${DISTRO_TYPE:-$(detect_platform)}" in
        alpine) mkinitfs "$ver" >>"$LOG_FILE" 2>&1 ;;
        debian)
            if [[ -f "$img" ]]; then
                update-initramfs -u -k "$ver" >>"$LOG_FILE" 2>&1
            else
                update-initramfs -c -k "$ver" >>"$LOG_FILE" 2>&1
            fi ;;
        rhel|suse) dracut --force "$img" "$ver" >>"$LOG_FILE" 2>&1 ;;
        *) return 1 ;;
    esac
}

# $1 = the kernel list captured BEFORE the upgrade. Checks every kernel that
# appeared since, plus the kernel that boots next — so a breakage left by an
# earlier run is caught too, which is the state that sat unnoticed for nine
# days. Rebuilds a stale image and re-checks. Returns 1, deliberately breaking
# the "never exit non-zero" module contract, only when an image is still wrong
# after the rebuild.
verify_boot_chain() {
    local before="${1:-}"
    is_linux || return 0
    local root="${UH_BOOTCHECK_ROOT:-}" distro="${DISTRO_TYPE:-$(detect_platform)}"
    local now running k f rel rc failed=0 unknown=0 nextmax
    now=$(installed_kernel_versions)
    running="${UH_BOOTCHECK_RUNNING:-$(uname -r)}"

    # The kernel(s) that boot next. Alpine records it per flavour; elsewhere it
    # is the newest installed.
    local -a nexts=() check=()
    if [[ "$distro" == "alpine" ]]; then
        for f in "$root"/usr/share/kernel/*/kernel.release; do
            [[ -f "$f" ]] || continue
            rel=$(tr -d '[:space:]' <"$f")
            [[ -n "$rel" ]] && nexts+=("$rel")
        done
    fi
    if [[ ${#nexts[@]} -eq 0 && -n "$now" ]]; then
        nexts=("$(printf '%s\n' "$now" | tail -n 1)")
    fi
    if [[ ${#nexts[@]} -eq 0 ]]; then
        log_info "Boot chain: no installed kernel found — nothing to verify"
        return 0
    fi

    if [[ "$distro" == "alpine" ]]; then
        # One shared image per flavour holds only the newest kernel's modules;
        # checking two versions of a flavour would have each rebuild undo the
        # other. The kernel that boots next wins; a flavour with no recorded
        # next gets its newest new version.
        local seen=""
        for k in "${nexts[@]}"; do
            check+=("$k"); seen+=" ${k##*-}"
        done
        local -a fresh=()
        while IFS= read -r k; do
            [[ -n "$k" ]] && ! grep -qxF -- "$k" <<<"$before" && fresh+=("$k")
        done <<<"$now"
        local i
        for ((i=${#fresh[@]}-1; i>=0; i--)); do
            k="${fresh[i]}"
            [[ " $seen " == *" ${k##*-} "* ]] && continue
            seen+=" ${k##*-}"; check+=("$k")
        done
    else
        check=("${nexts[@]}")
        while IFS= read -r k; do
            [[ -n "$k" ]] || continue
            grep -qxF -- "$k" <<<"$before" && continue
            [[ " ${check[*]} " == *" $k "* ]] || check+=("$k")
        done <<<"$now"
    fi

    for k in "${check[@]}"; do
        rc=0; _boot_image_ok "$k" || rc=$?
        case $rc in
            0) log_info "Boot chain: boot image for $k is present" ;;
            2) unknown=1 ;;
            *)
                log_warning "Boot chain: boot image for $k is missing or stale — rebuilding"
                _rebuild_boot_image "$k" || true
                rc=0; _boot_image_ok "$k" || rc=$?
                if [[ $rc -eq 0 ]]; then
                    log_success "Boot chain: rebuilt the boot image for $k"
                else
                    log_error "Boot chain: boot image for $k is still wrong after rebuilding"
                    failed=1
                fi ;;
        esac
    done

    if [[ $unknown -eq 1 ]]; then
        log_warning "Boot chain: boot images are not checked on '$distro' — verify the next boot yourself"
    fi
    nextmax=$(printf '%s\n' "${nexts[@]}" | sort -V | tail -n 1)
    if [[ $failed -eq 0 && "$nextmax" != "$running" ]]; then
        log_info "Kernel $nextmax is installed but $running is running — reboot to use it"
    fi
    return "$failed"
}
