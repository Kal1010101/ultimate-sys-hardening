#!/bin/bash
# =============================================================================
#  lib/core.sh — shared primitives for all tiers
#
#  Colors, logging, root check, backup directory management, and the guard
#  helpers that keep `set -euo pipefail` from killing a run on a benign
#  non-zero exit.
#
#  Source this first; everything else depends on it.
# =============================================================================

# ------------------------------------------------------------------ version --
UH_VERSION="2.4.0"

# ------------------------------------------------------------------- colors --
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

# Strip colors when not writing to a terminal (log files, CI, pipes)
if [[ ! -t 1 ]]; then
    RED=''; GREEN=''; YELLOW=''; BLUE=''
    CYAN=''; MAGENTA=''; WHITE=''; NC=''
fi

CHECK_MARK="✅"; CROSS_MARK="❌"; WARNING="⚠️"; INFO="ℹ️"
LOCK="🔒";      SHIELD="🛡️";    GEAR="⚙️";     FIRE="🔥"
ROCKET="🚀";    UNDO="↩️";      CIS_ICON="📊"; DB_ICON="🗄️"; NET_ICON="🌐"

# ------------------------------------------------------------------ globals --
: "${DRY_RUN:=false}"
: "${AUTO_MODE:=false}"
: "${SKIP_BACKUP:=false}"
: "${DISTRO_TYPE:=}"
: "${OS_FAMILY:=linux}"
# Which tier is running. Pro and Enterprise override this immediately after
# sourcing; Free leaves the default. It is stamped into the backup directory
# name and manifest so a later revert can say which tier's run produced the
# backup it is restoring from.
: "${UH_TIER:=free}"

: "${LOG_FILE:=/var/log/ultimate_hardening_$(date +%Y%m%d_%H%M%S).log}"

# The run log records every file touched, every service stopped and the full
# SUID inventory. tee creates it with the ambient umask — 0644 on a default
# root shell, i.e. readable by every local account. Created here, restricted
# here, before anything writes to it.
#
# ONLY ever a regular file we created. Callers legitimately point LOG_FILE at
# /dev/null to silence logging — docs/build-terminals.sh does exactly that —
# and an unguarded chmod turned /dev/null into 0600 root:root on a real guest,
# which breaks every program on the host that redirects to it. Found by the VM
# lab, in a test run that then could not copy its own report back.
#
# The symlink guard is the cheaper half of the same lesson: LOG_FILE is a
# predictable path under /var/log, and `: >` through a symlink would truncate
# whatever it points at.
_uh_init_log() {
    case "$LOG_FILE" in
        /dev/*) return 0 ;;
    esac
    if [[ -L "$LOG_FILE" ]]; then
        return 0
    fi
    if [[ ! -e "$LOG_FILE" ]]; then
        ( umask 077; : > "$LOG_FILE" ) 2>/dev/null || return 0
    fi
    if [[ -f "$LOG_FILE" ]]; then
        chmod 600 "$LOG_FILE" 2>/dev/null || true
    fi
    return 0
}
_uh_init_log

# Backup directory name is <timestamp>_<tier>, deliberately timestamp-FIRST:
# find_latest_backup() picks the newest by lexical sort, so putting the tier
# in front would sort "enterprise" before "free" and break "latest".
: "${BACKUP_DIR:=/root/hardening_backup_$(date +%Y%m%d_%H%M%S)_${UH_TIER}}"
: "${SUID_BACKUP_FILE:=$BACKUP_DIR/suid_sgid_original_perms.txt}"

# Persistent, non-timestamped directory holding the FIRST-ever captured copy
# of every file any tier's hardening run has touched on this host. Per-run
# BACKUP_DIR only ever captures "state right before THIS run," which after a
# Free -> Pro -> Enterprise upgrade path is already hardened state, not the
# system's true original. Genesis fixes that: backup_file() seeds it once,
# first write wins, and full_system_revert() restores from it.
: "${BACKUP_GENESIS_DIR:=/root/.ultimate_hardening_genesis}"

FIXES_APPLIED=0
BACKUP_CREATED=false

# ------------------------------------------------------- running as root --
# Everything below runs as root and calls tools by bare name (sed, grep,
# systemctl, apt-get, ufw, …). A PATH with a writable directory ahead of the
# system ones therefore chooses which binaries root executes. sudo's secure_path
# normally prevents that, but this script is also run from cron, from CI, from
# systemd units and by `bash script.sh` where nothing resets PATH.
#
# The system directories are PREPENDED rather than PATH being replaced: a
# replacement would break hosts whose tooling genuinely lives in /opt or
# /usr/local/opt, while prepending is enough — a planted `sed` further down the
# PATH is shadowed by /usr/bin/sed either way.
_uh_harden_path() {
    local d std="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    local new="$std"
    local IFS=':'
    for d in ${PATH:-}; do
        [[ -z "$d" ]] && continue
        case ":$std:" in
            *":$d:"*) continue ;;
        esac
        new="$new:$d"
    done
    PATH="$new"
    export PATH
}
_uh_harden_path

# Is the library this run just sourced writable by anyone who is not root and
# not the person who invoked it? If so, that party chooses what runs as root
# here. This does NOT refuse to run: `sudo ./src/free/ultimate_hardening.sh`
# from your own checkout is the documented way to use this, and your own files
# are yours to trust. It refuses nothing and warns precisely — group- or
# world-writable, or owned by some third party.
#
# Set UH_TRUST_LIB=1 to silence it (a deliberate "I know, this is a shared
# build host" switch, not a default).
# EUID is readonly in bash, so the effective uid is read through this rather
# than the variable directly — it is the only way the check above can be
# exercised by a test that is not running as root.
_uh_euid() { printf '%s' "${EUID:-$(id -u)}"; }

check_lib_trust() {
    if [[ "${UH_TRUST_LIB:-0}" == "1" ]]; then
        return 0
    fi
    [[ "$(_uh_euid)" -eq 0 ]] || return 0
    local dir="${1:-${LIB_DIR:-}}"
    [[ -n "$dir" && -d "$dir" ]] || return 0

    local invoker="${SUDO_UID:-0}"
    local f owner mode
    local -a risky=()
    for f in "$dir" "$dir"/*.sh; do
        [[ -e "$f" ]] || continue
        owner=$(stat -c '%u' "$f" 2>/dev/null) || continue
        mode=$(stat -c '%A' "$f" 2>/dev/null) || continue
        # group- or world-writable, whoever owns it
        if [[ "$mode" == ?????w???? || "$mode" == ????????w? ]]; then
            risky+=("$f (mode $mode)")
        elif [[ "$owner" != "0" && "$owner" != "$invoker" ]]; then
            risky+=("$f (owned by uid $owner)")
        fi
    done

    if (( ${#risky[@]} )); then
        log_warning "The library this run loaded is writable by someone other than root or you:"
        for f in "${risky[@]}"; do log_warning "    $f"; done
        log_warning "Whoever can write there chooses what runs as root in this session."
        log_warning "Move the checkout somewhere only you can write, or set UH_TRUST_LIB=1 to silence this."
    fi
    return 0
}

# ------------------------------------------------------------------ logging --
log_message() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}${CHECK_MARK}${NC} $1"        | tee -a "$LOG_FILE"; }
log_warning() { echo -e "${YELLOW}${WARNING}${NC} $1"          | tee -a "$LOG_FILE"; }
log_error()   { echo -e "${RED}${CROSS_MARK}${NC} $1"          | tee -a "$LOG_FILE"; }
log_info()    { echo -e "${CYAN}${INFO}${NC} $1"               | tee -a "$LOG_FILE"; }
log_cis()     { echo -e "${MAGENTA}${CIS_ICON}${NC} $1"        | tee -a "$LOG_FILE"; }
log_dry()     { echo -e "${YELLOW}[DRY-RUN]${NC} $1"           | tee -a "$LOG_FILE"; }

# -------------------------------------------------------- set -e safe guards --
# Bare (( x++ )) returns the PRE-increment value, so incrementing from 0 exits
# non-zero and kills the script under `set -e`. Always use these.
bump()  { local __n="$1"; eval "$__n=\$(( \${$__n:-0} + 1 ))"; return 0; }
count_fix() { bump FIXES_APPLIED; }

# --------------------------------------------------------------------- root --
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}${CROSS_MARK} This script must be run as root.${NC}" >&2
        echo -e "${CYAN}Try: sudo $0 $*${NC}" >&2
        exit 1
    fi
}

# Modules and revert call these with 2>/dev/null, so a missing one reads as
# "nothing found" (e.g. no restore points) rather than an error. Refuse to
# start instead. Seen on the rockylinux:8 image, which ships without find.
check_base_tools() {
    local c missing=()
    for c in find awk sed grep sort; do
        command -v "$c" >/dev/null 2>&1 || missing+=("$c")
    done
    (( ${#missing[@]} == 0 )) && return 0
    echo -e "${RED}${CROSS_MARK} Missing required command(s): ${missing[*]}${NC}" >&2
    echo -e "${CYAN}Install them (find is in the findutils package) and re-run.${NC}" >&2
    exit 1
}

# ------------------------------------------------------------------- backup --
create_backup_dir() {
    [[ "$BACKUP_CREATED" == true ]] && return 0

    if [[ "$SKIP_BACKUP" == true ]]; then
        log_warning "Backup skipped (--skip-backup) — revert will not be available"
        return 0
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would create backup directory at $BACKUP_DIR"
        return 0
    fi

    mkdir -p "$BACKUP_DIR" || {
        log_error "Could not create backup directory: $BACKUP_DIR"
        return 1
    }
    chmod 700 "$BACKUP_DIR" 2>/dev/null || true

    # Stamp which tier produced this backup, so a revert months later can say
    # what it is restoring from instead of just printing a bare path.
    {
        echo "tier=${UH_TIER}"
        echo "version=${UH_VERSION}"
        echo "created=$(date '+%Y-%m-%d %H:%M:%S')"
        echo "host=$(hostname 2>/dev/null || echo unknown)"
        echo "platform=${DISTRO_TYPE:-unknown}"
    } > "$BACKUP_DIR/backup_info.txt" 2>/dev/null || true

    BACKUP_CREATED=true
    log_info "Backup directory: $BACKUP_DIR  (${UH_TIER} tier, v${UH_VERSION})"
    prune_old_backups
    return 0
}

# Per-run backup directories had no retention at all — every run left a new
# one behind forever, the same "grows unbounded" shape as the Enterprise
# state DB's runs/intrusion_snapshots tables (fixed separately in the
# commercial repo with db_prune()). Called from create_backup_dir() itself,
# so every real run prunes automatically with no separate cron entry.
#
# Genesis (BACKUP_GENESIS_DIR) is NEVER touched here and never will be: it
# holds the one true pre-hardening original of every file, and full_system_
# revert()/restore_file() both prefer it over any per-run copy. Deleting it
# would permanently remove the "revert to original" guarantee, which is a
# different failure mode entirely from an old per-run directory just taking
# up disk space.
prune_old_backups() {
    local days="${UH_BACKUP_RETENTION_DAYS:-90}"
    [[ "$days" =~ ^[0-9]+$ ]] || { log_warning "UH_BACKUP_RETENTION_DAYS='$days' is not a number — skipping backup prune, using the default next time is safer than guessing"; return 0; }
    local dir pruned=0
    while IFS= read -r dir; do
        [[ "$dir" == "$BACKUP_DIR" ]] && continue   # never prune the one just created
        rm -rf "$dir" 2>/dev/null && bump pruned
    done < <(find "$UH_BACKUP_ROOT" -maxdepth 1 -type d -name 'hardening_backup_*' -mtime "+${days}" 2>/dev/null)
    (( pruned > 0 )) && log_info "Pruned ${pruned} backup director$( [[ $pruned -eq 1 ]] && echo y || echo ies ) older than ${days} days"
    return 0
}

# Read one field out of a backup directory's manifest. Returns "" when the
# backup predates manifests (anything written before v2.3.0).
backup_info_field() {
    local dir="$1" field="$2"
    [[ -f "$dir/backup_info.txt" ]] || return 0
    local val; val=$(grep -m1 "^${field}=" "$dir/backup_info.txt" 2>/dev/null | cut -d= -f2-)
    printf '%s' "$val"
}

# "Pro tier, v2.3.0, 2026-08-26 20:23:24" — or a best-effort description when
# there is no manifest. Used in revert messages.
describe_backup() {
    local dir="$1"
    local tier; tier=$(backup_info_field "$dir" tier)
    local ver;  ver=$(backup_info_field  "$dir" version)
    local when; when=$(backup_info_field "$dir" created)

    if [[ -z "$tier" ]]; then
        # Fall back to the directory name, which carries the tier from v2.3.0
        # onward even if the manifest is missing.
        case "$dir" in
            *_free)       tier="free" ;;
            *_pro)        tier="pro" ;;
            *_enterprise) tier="enterprise" ;;
            *) printf 'unknown tier — backup predates tier tagging'; return 0 ;;
        esac
    fi

    local out="${tier} tier"
    [[ -n "$ver"  ]] && out+=", v${ver}"
    [[ -n "$when" ]] && out+=", ${when}"
    printf '%s' "$out"
}

# Seed the genesis dir with the CURRENT content of $1, but only if genesis
# doesn't already hold a copy of that path. First capture across the life
# of the host wins, regardless of which tier or which run captured it —
# that's what makes genesis the true "before any hardening ever touched
# this file" snapshot instead of just "before this run."
_seed_genesis() {
    local src="$1"
    local dest="$BACKUP_GENESIS_DIR/files$src"
    [[ -f "$dest" ]] && return 0
    mkdir -p "$(dirname "$dest")" 2>/dev/null || return 1
    # create_backup_dir chmods the per-run directory to 700; genesis holds the
    # same class of content and was inheriting the ambient umask instead —
    # observed as 755 on a real host. Same content, same mode.
    chmod 700 "$BACKUP_GENESIS_DIR" 2>/dev/null || true
    cp -a "$src" "$dest" 2>/dev/null || return 1

    # Genesis is shared across every tier and every run, so record which tier
    # captured each original. Without this, a genesis restore can tell you the
    # file came back to its true pre-hardening state but not which tier's run
    # first touched it.
    printf '%s|%s|v%s|%s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "${UH_TIER}" "${UH_VERSION}" "$src" \
        >> "$BACKUP_GENESIS_DIR/genesis_manifest.txt" 2>/dev/null || true
    return 0
}

# Most recently captured copy of $1, across genesis and every EXISTING
# per-run backup (never the one create_backup_dir just made for this run —
# that one is still empty for this path, so it would never match anyway).
# Per-run directories sort correctly by name (timestamp-first, see the
# BACKUP_DIR comment above), so the lexically-last one is the most recent.
_latest_backup_copy() {
    local src="$1" prior
    prior=$(find "$UH_BACKUP_ROOT" -maxdepth 1 -type d -name 'hardening_backup_*' 2>/dev/null \
             | grep -vF "$BACKUP_DIR" | sort | tail -1)
    if [[ -n "$prior" && -f "$prior/files$src" ]]; then
        printf '%s' "$prior/files$src"
        return 0
    fi
    [[ -f "$BACKUP_GENESIS_DIR/files$src" ]] && printf '%s' "$BACKUP_GENESIS_DIR/files$src"
    return 0
}

# Copy a file into the backup tree, preserving its absolute path structure.
backup_file() {
    local src="$1"
    [[ -f "$src" ]] || return 0
    [[ "$SKIP_BACKUP" == true ]] && return 0
    [[ "$DRY_RUN" == true ]] && { log_dry "Would back up $src"; return 0; }

    create_backup_dir || return 1

    # Skip a redundant per-run copy when the file is byte-identical to
    # whatever was captured last — genesis on the very first run ever, the
    # most recent prior per-run backup on every run after that. Restoring
    # from that earlier copy would produce exactly the same bytes a fresh
    # copy would, so making another physical copy is pure duplication. Found:
    # re-running hardening against an already-hardened, unchanged host (a
    # cron'd --auto-mode, or simply running the tool more than once, which
    # this session did heavily) left one full duplicate of every untouched
    # file behind per run — "too many copies of the same file with different
    # dates," reported directly by the user.
    #
    # This check MUST run before _seed_genesis(), not after: seeding first
    # means a file's very first-ever backup finds the genesis copy this same
    # call just created, correctly matches it byte-for-byte, and skips the
    # per-run copy — meaning no per-run copy is EVER created for any file's
    # first capture, on any host. Found via a real "no backup found" test
    # failure against a completely fresh container, where every file was
    # necessarily a first-ever capture.
    local prior skip_copy=false
    prior=$(_latest_backup_copy "$src")
    [[ -n "$prior" ]] && cmp -s "$src" "$prior" && skip_copy=true

    _seed_genesis "$src" || log_warning "Could not seed genesis backup for $src (revert-to-original may be incomplete for this file)"

    [[ "$skip_copy" == true ]] && return 0

    local dest="$BACKUP_DIR/files$src"
    mkdir -p "$(dirname "$dest")" 2>/dev/null || return 1
    cp -a "$src" "$dest" 2>/dev/null || {
        log_warning "Could not back up $src"
        return 1
    }
    return 0
}

# Restore a file previously captured by backup_file. Prefers the genesis
# copy (the true original) and falls back to the current-run BACKUP_DIR
# copy only if genesis has nothing for this path (e.g. a host that ran
# hardening before this fix existed).
restore_file() {
    local target="$1"
    local gsrc="$BACKUP_GENESIS_DIR/files$target"
    local src="$BACKUP_DIR/files$target"
    [[ -f "$gsrc" ]] && src="$gsrc"
    [[ -f "$src" ]] || return 1
    [[ "$DRY_RUN" == true ]] && { log_dry "Would restore $target"; return 0; }
    cp -a "$src" "$target" 2>/dev/null || return 1
    log_success "Restored: $target"
    return 0
}

# Revert one file to its TRUE ORIGINAL, without needing a specific
# BACKUP_DIR context the way restore_file() does — built for reverting a
# single module from the menu, standalone, not mid-run or as part of a full
# system revert.
#
# Deliberately NOT _latest_backup_copy() (the dedup helper above): that one
# exists to answer "what's the most recent thing captured," which is right
# for skipping a redundant copy but wrong here — on a host with a long
# history, the most recent per-run capture is often itself an
# ALREADY-hardened snapshot (caught by testing this for real: reverting SSH
# hardening on a heavily-tested guest silently restored an already-hardened
# sshd_config, because the "most recent" backup had been made moments
# earlier, mid-testing, from an already-hardened live file — PermitRootLogin
# stayed "no" instead of going back to "yes"). Genesis is the one place
# guaranteed to hold the true pre-hardening state (first capture ever,
# first write wins — see _seed_genesis() above), so prefer it unconditionally,
# same as restore_file() and full_system_revert() both already do. Only
# without a genesis copy at all (a host hardened before genesis tracking
# existed) does this fall back to the OLDEST per-run capture, not the
# newest, for the same reason.
#
# Files a module WROTE rather than modified never had a genuine "before"
# to go back to. The obvious signal — no backup exists anywhere — turned
# out NOT to be reliable for these on a host with real run history: the
# module's own apply function calls backup_file() on the path right before
# regenerating it wholesale (`backup_file "$f"; cat > "$f"`), so on the
# SECOND run ever (after the first run's own `cat >` already created the
# file), backup_file() sees the file exists and seeds genesis with THAT —
# already-hardened — content, permanently. There is never a run where
# genesis captures a genuine "doesn't exist yet" state for these paths,
# because backup_file() only ever fires once the file is already there.
# Caught by testing for real: reverting module 6 (kernel) restored
# `/etc/sysctl.d/99-hardening.conf` from genesis, and `kernel.dmesg_restrict`
# stayed hardened — genesis held this session's OWN earlier output, not a
# true original, because this guest has been kernel-hardened many times
# before genesis ever got a chance to see it absent.
#
# full_system_revert() already knew about this shape of problem — its own
# revert doesn't trust backup/genesis lookups for these paths at all, it
# just unconditionally `rm -f`s a hand-maintained list. Same fix here,
# generalized: a path known to be entirely module-output, not a modified
# pre-existing file, is always deleted, and genesis/per-run backups are
# never even consulted for it — no lookup to get poisoned by.
UH_TOOL_CREATED_PATHS=(
    "/etc/sysctl.d/99-hardening.conf"
    "/etc/audit/rules.d/99-hardening.rules"
    "/etc/modprobe.d/99-hardening-usb.conf"
    "/etc/modprobe.d/disable-unused-protocols.conf"
    "/etc/profile.d/hardening-umask.sh"
    "/etc/fail2ban/jail.local"
    "/etc/ssh/sshd_config.d/00-ultimate-hardening.conf"
    "/etc/docker/daemon.json"
)

_is_tool_created_path() {
    local target="$1" p
    for p in "${UH_TOOL_CREATED_PATHS[@]}"; do
        [[ "$target" == "$p" ]] && return 0
    done
    return 1
}

revert_backed_up_file() {
    local target="$1"
    [[ -f "$target" ]] || return 0   # nothing to revert
    [[ "$DRY_RUN" == true ]] && { log_dry "Would revert $target"; return 0; }

    if _is_tool_created_path "$target"; then
        rm -f "$target" 2>/dev/null && { log_success "Removed (created by hardening, no earlier version existed): $target"; return 0; }
        log_warning "Could not remove $target"
        return 1
    fi

    local src="$BACKUP_GENESIS_DIR/files$target"
    if [[ ! -f "$src" ]]; then
        src=""
        local d
        while IFS= read -r d; do
            if [[ -f "$d/files$target" ]]; then src="$d/files$target"; break; fi
        done < <(find "$UH_BACKUP_ROOT" -maxdepth 1 -type d -name 'hardening_backup_*' 2>/dev/null | sort)
    fi

    if [[ -n "$src" ]]; then
        cp -a "$src" "$target" 2>/dev/null && { log_success "Restored: $target"; return 0; }
        log_warning "Could not restore $target"
        return 1
    fi

    # No known-tool-created match AND no backup anywhere either. Found the
    # hard way this is NOT safe to treat as "must be tool-created, delete
    # it": on a host where the module was never actually applied — the
    # compliance check simply read the system as already matching (Rocky
    # ships SELinux enforcing by default, so module 13's SELinux branch
    # never ran, never called backup_file, and genesis was never seeded) —
    # this path deleted a real, in-use `/etc/selinux/config` outright.
    # backup_file() being silent tells you nothing changed; it does not
    # tell you the file was tool-created. Only UH_TOOL_CREATED_PATHS
    # (checked above) is an actual claim about provenance — anything else
    # with no backup is left alone, not guessed at.
    log_info "Nothing to revert for $target — no backup was ever taken, most likely because this module never actually changed it on this host (already compliant by default). Left untouched."
    return 2
}

# Locate the most recent backup when reverting in a fresh session.
# Where per-run backup directories live. A variable so tests can point it at a
# fixture instead of /root.
: "${UH_BACKUP_ROOT:=/root}"

find_latest_backup() {
    local latest
    latest=$(find "$UH_BACKUP_ROOT" -maxdepth 1 -type d -name 'hardening_backup_*' 2>/dev/null | sort | tail -1)
    [[ -n "$latest" ]] || return 1
    echo "$latest"
}

# Every restore point, NEWEST FIRST, one per line as "<path>\t<label>".
# Genesis (the true pre-hardening original) is listed last, as the oldest state.
list_backup_points() {
    local d
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        printf '%s\t%s\n' "$d" "$(describe_backup "$d")"
    done < <(find "$UH_BACKUP_ROOT" -maxdepth 1 -type d -name 'hardening_backup_*' 2>/dev/null | sort -r)
    [[ -d "$BACKUP_GENESIS_DIR/files" ]] && \
        printf '%s\t%s\n' "$BACKUP_GENESIS_DIR" "original pre-hardening state (genesis)"
    return 0
}

# Resolve a --revert-to value to a backup directory path.
#   ""|latest   -> most recent per-run backup
#   genesis|original -> the genesis directory
#   /abs/path   -> that directory if it exists
#   <text>      -> newest per-run backup whose name contains <text>
#                  (so a date like 20260921 or a full timestamp both work)
# Prints the path, or nothing (return 1) if no match.
resolve_revert_target() {
    local t="$1" hit
    case "$t" in
        ""|latest)         find_latest_backup ;;
        genesis|original)  [[ -d "$BACKUP_GENESIS_DIR/files" ]] && echo "$BACKUP_GENESIS_DIR" || return 1 ;;
        /*)                [[ -d "$t" ]] && echo "$t" || return 1 ;;
        *)  hit=$(find "$UH_BACKUP_ROOT" -maxdepth 1 -type d -name "hardening_backup_*${t}*" 2>/dev/null | sort | tail -1)
            [[ -n "$hit" ]] && echo "$hit" || return 1 ;;
    esac
}

# Interactive restore-point chooser. Draws the menu to STDERR and echoes only
# the chosen target token to STDOUT, so it is safe inside $(...). Returns 1 if
# the user cancels.
choose_backup_point() {
    local -a paths=() labels=()
    local p l
    while IFS=$'\t' read -r p l; do paths+=("$p"); labels+=("$l"); done < <(list_backup_points)
    (( ${#paths[@]} )) || { echo "genesis"; return 0; }
    {
        echo ""
        echo "Restore points, newest first:"
        local i
        for i in "${!paths[@]}"; do printf '  %2d) %s\n' "$((i+1))" "${labels[$i]}"; done
        echo "   0) original pre-hardening state (default)"
        echo "   q) cancel"
    } >&2
    local ans=""
    read -r -p "  Revert to which? [0]: " ans </dev/tty 2>/dev/null || ans=""
    case "$ans" in
        ""|0)      echo "genesis" ;;
        q|Q)       return 1 ;;
        *[!0-9]*)  echo "genesis" ;;
        *)         if (( ans >= 1 && ans <= ${#paths[@]} )); then echo "${paths[$((ans-1))]}"; else echo "genesis"; fi ;;
    esac
    return 0
}

# Print the restore points for --list-backups, then return.
list_backups_cli() {
    local any=false p l n=0
    log_info "Available restore points (newest first):"
    while IFS=$'\t' read -r p l; do
        any=true; n=$((n+1))
        printf '  %2d) %s\n      %s\n' "$n" "$l" "$p"
    done < <(list_backup_points)
    [[ "$any" == true ]] || log_warning "No backups found under $UH_BACKUP_ROOT and no genesis directory."
    return 0
}

# --------------------------------------------------------------- confirmation --
# Returns 0 to proceed. Auto-mode always proceeds; interactive asks.
confirm() {
    local prompt="$1"
    local default="${2:-N}"
    [[ "$AUTO_MODE" == true ]] && return 0

    local hint="(y/N)"
    [[ "$default" == "Y" ]] && hint="(Y/n)"

    local reply
    read -r -p "$(echo -e "${YELLOW}${prompt} ${hint}: ${NC}")" reply
    reply="${reply:-$default}"
    [[ "$reply" =~ ^[Yy] ]]
}

# High-risk modules require typing "yes" in full, even in interactive mode.
confirm_risky() {
    local prompt="$1"
    [[ "$AUTO_MODE" == true ]] && return 0
    local reply
    read -r -p "$(echo -e "${RED}${prompt} (type 'yes'): ${NC}")" reply
    [[ "$reply" == "yes" ]]
}

# ------------------------------------------------------------------- idempotent --
# Append a line to a file only if it isn't already present.
append_once() {
    local line="$1" file="$2"
    [[ "$DRY_RUN" == true ]] && { log_dry "Would append to $file: $line"; return 0; }
    [[ -f "$file" ]] || touch "$file" 2>/dev/null || return 1
    grep -qxF "$line" "$file" 2>/dev/null && return 0
    echo "$line" >> "$file" 2>/dev/null || return 1
    return 0
}

# Inverse of append_once() — remove an exact line if present, no-op otherwise.
remove_line() {
    local line="$1" file="$2" tmp
    [[ -f "$file" ]] || return 0
    [[ "$DRY_RUN" == true ]] && { log_dry "Would remove from $file: $line"; return 0; }
    grep -qxF "$line" "$file" 2>/dev/null || return 0
    tmp=$(mktemp) || return 1
    grep -vxF "$line" "$file" > "$tmp" && cat "$tmp" > "$file"
    rm -f "$tmp"
}

# Set key/value in a config file, replacing an existing line or appending.
set_config() {
    local key="$1" value="$2" file="$3" sep="${4:- }"
    [[ "$DRY_RUN" == true ]] && { log_dry "Would set $key${sep}$value in $file"; return 0; }
    [[ -f "$file" ]] || touch "$file" 2>/dev/null || return 1
    if grep -qE "^[[:space:]]*#?[[:space:]]*${key}([[:space:]]|=)" "$file" 2>/dev/null; then
        # NOTE: sed's delimiter is `|`, so the pattern below must not contain a
        # literal `|` — `([[:space:]]|=)` would prematurely end the s/// command
        # ("unknown option to `s'"). Use a bracket expression instead; it's the
        # same single-character alternation without the delimiter collision.
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]=].*|${key}${sep}${value}|" "$file" 2>/dev/null || return 1
    else
        echo "${key}${sep}${value}" >> "$file" 2>/dev/null || return 1
    fi
    return 0
}
