#!/bin/bash
# A backup must record which tier produced it, and a revert must be able to
# say so. Guards the tier tagging in core.sh (BACKUP_DIR naming, the
# backup_info.txt manifest, genesis provenance) and describe_backup()'s
# fallback for backups written before tagging existed.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root

# shellcheck source=/dev/null
source "$REPO_ROOT/lib/core.sh"
# shellcheck source=/dev/null
source "$REPO_ROOT/lib/platform.sh"
# shellcheck source=/dev/null
source "$REPO_ROOT/lib/cis.sh"

WORK=$(mktemp -d)
TESTF="$WORK/tracked.conf"
echo "ORIGINAL" > "$TESTF"

LOG_FILE="$WORK/test.log"
BACKUP_GENESIS_DIR="$WORK/genesis"
DRY_RUN=false
SKIP_BACKUP=false
DISTRO_TYPE=testdistro

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# --- a Free-tier run captures the original -----------------------------------
UH_TIER=free
BACKUP_DIR="$WORK/hardening_backup_20260101_010101_free"
BACKUP_CREATED=false
backup_file "$TESTF"
echo "FREE-CHANGE" > "$TESTF"

assert_file_exists "$BACKUP_DIR/backup_info.txt" "free run wrote a backup manifest"
assert_file_contains "$BACKUP_DIR/backup_info.txt" '^tier=free' "manifest records the free tier"

# --- a Pro-tier run then captures the already-hardened state -----------------
UH_TIER=pro
BACKUP_DIR="$WORK/hardening_backup_20260202_020202_pro"
BACKUP_CREATED=false
backup_file "$TESTF"
echo "PRO-CHANGE" > "$TESTF"

assert_file_contains "$BACKUP_DIR/backup_info.txt" '^tier=pro' "manifest records the pro tier"

# Genesis must credit the tier that captured the ORIGINAL (free), not the
# most recent one to touch the file (pro).
assert_file_contains "$BACKUP_GENESIS_DIR/genesis_manifest.txt" '\|free\|' \
    "genesis provenance credits the tier that captured the original"
assert_file_not_contains "$BACKUP_GENESIS_DIR/genesis_manifest.txt" '\|pro\|' \
    "genesis is not re-credited to a later tier"

# --- describe_backup ---------------------------------------------------------
desc=$(describe_backup "$WORK/hardening_backup_20260202_020202_pro")
assert_output_contains "$desc" 'pro tier' "describe_backup names the tier"
assert_output_contains "$desc" 'v[0-9]' "describe_backup names the version"

# A backup written before tier tagging existed has no manifest and no tier
# suffix — it must degrade to a clear statement, not a crash or a false claim.
mkdir -p "$WORK/hardening_backup_20250101_000000"
legacy=$(describe_backup "$WORK/hardening_backup_20250101_000000")
assert_output_contains "$legacy" 'predates tier tagging' \
    "describe_backup degrades honestly on an untagged legacy backup"

# The tier suffix alone is enough even if the manifest is missing.
mkdir -p "$WORK/hardening_backup_20250202_000000_enterprise"
nomanifest=$(describe_backup "$WORK/hardening_backup_20250202_000000_enterprise")
assert_output_contains "$nomanifest" 'enterprise tier' \
    "describe_backup falls back to the directory name's tier suffix"

# --- naming must keep newest-by-sort working ---------------------------------
# find_latest_backup picks the newest by lexical sort, so the timestamp has to
# come before the tier. Tier-first would sort enterprise < free < pro and
# return the wrong directory.
newest=$(printf '%s\n' \
    "hardening_backup_20260101_010101_pro" \
    "hardening_backup_20260202_020202_enterprise" \
    "hardening_backup_20260103_010101_free" | sort | tail -1)
if [[ "$newest" == "hardening_backup_20260202_020202_enterprise" ]]; then
    pass_msg "timestamp-first naming keeps newest-by-sort correct across tiers"
else
    fail "newest-by-sort returned '$newest' — tier tagging broke backup ordering"
fi

finish
