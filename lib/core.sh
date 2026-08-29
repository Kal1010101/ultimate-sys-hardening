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
UH_VERSION="2.3.0"

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

# Copy a file into the backup tree, preserving its absolute path structure.
backup_file() {
    local src="$1"
    [[ -f "$src" ]] || return 0
    [[ "$SKIP_BACKUP" == true ]] && return 0
    [[ "$DRY_RUN" == true ]] && { log_dry "Would back up $src"; return 0; }

    create_backup_dir || return 1
    local dest="$BACKUP_DIR/files$src"
    mkdir -p "$(dirname "$dest")" 2>/dev/null || return 1
    cp -a "$src" "$dest" 2>/dev/null || {
        log_warning "Could not back up $src"
        return 1
    }
    _seed_genesis "$src" || log_warning "Could not seed genesis backup for $src (revert-to-original may be incomplete for this file)"
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

# Locate the most recent backup when reverting in a fresh session.
find_latest_backup() {
    local latest
    latest=$(find /root -maxdepth 1 -type d -name 'hardening_backup_*' 2>/dev/null | sort | tail -1)
    [[ -n "$latest" ]] || return 1
    echo "$latest"
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
