#!/bin/bash
# The pre-commit hook must refuse commercial source, and must not get in the
# way of ordinary commits.
#
# Both halves matter equally. A hook that blocks legitimate work trains people
# to type --no-verify, and a hook everyone bypasses protects nothing — so the
# false-positive assertions here are not padding, they are the point.
#
# Context: this repo is public and MIT. The commercial checkout symlinks its
# lib/ and tests/ into this one, a commercial test file was once written through
# that symlink into tests/ — which is tracked, not ignored — and it reached the
# public repo. .gitignore did not stop it and cannot: it is path-based, and it
# is bypassed by `git add -f`.
#
# Runs anywhere git exists; skips visibly where it does not.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"
require_cmd git

HOOK="$REPO/scripts/hooks/pre-commit"
[[ -f "$HOOK" ]] || skip "scripts/hooks/pre-commit not in this checkout"

WORK="${TMPDIR:-/tmp}/uh_pubguard_$$"
rm -rf "$WORK"; mkdir -p "$WORK"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

cd "$WORK" || { fail "could not enter $WORK"; finish; }
git init -q . 2>/dev/null
git config user.email uh-test@example.invalid
git config user.name  "UH Test"
git config commit.gpgsign false
mkdir -p scripts/hooks
cp "$HOOK" scripts/hooks/pre-commit
chmod +x scripts/hooks/pre-commit
git config core.hooksPath scripts/hooks

# Something has to already be committed for later commits to be ordinary.
echo "readme" > README.md
git add README.md
git commit -qm "initial" 2>/dev/null || true

# try_commit <file> <content> -> prints "BLOCKED" or "ALLOWED"
try_commit() {
    local path="$1" body="$2"
    mkdir -p "$(dirname "$path")" 2>/dev/null
    printf '%s\n' "$body" > "$path"
    git add -f "$path" 2>/dev/null
    if git commit -qm "test" >/dev/null 2>&1; then
        echo ALLOWED
    else
        echo BLOCKED
    fi
    git reset -q HEAD -- "$path" 2>/dev/null
    rm -f "$path"
}

# --- must BLOCK: commercial by path ------------------------------------------
leaked=0
for p in src/pro/ultimate-hardening-pro.sh \
         src/enterprise/ultimate-hardening-enterprise.sh \
         src/shared/pro.sh \
         LICENSE-PRO.md \
         PRICING.md; do
    r=$(try_commit "$p" "# nothing incriminating in the body at all")
    if [[ "$r" != BLOCKED ]]; then
        fail "commercial path was allowed through: $p"
        leaked=$((leaked + 1))
    fi
done
# Only claim the pass if nothing above failed. An unconditional pass_msg after
# a loop of fails reports OK next to its own ASSERT lines — the "guard that
# always passes" problem, in the guard's own test.
[[ $leaked -eq 0 ]] && pass_msg "commercial paths are refused even with innocuous content"

# --- must BLOCK: commercial by content, at an innocent path ------------------
# This is the case .gitignore cannot cover — the leak that actually happened
# came through the symlinked tests/ directory, which is tracked.
leaked=0
check_blocked() {
    local what="$1" path="$2" body="$3"
    if [[ "$(try_commit "$path" "$body")" != BLOCKED ]]; then
        fail "$what was allowed through"
        leaked=$((leaked + 1))
    fi
}
check_blocked "a commercial file at a normal path" \
    "tests/cases/test_no_duplicate_functions.sh" \
    '#!/bin/bash
# a commercial test that arrived through the symlinked tests/
check() { tier_config_defaults; run_openscap_scan; }'
check_blocked "a tier constant in lib/" "lib/extra.sh" 'UH_TIER="enterprise"'
check_blocked "a commercial identifier in docs/" "docs/notes.md" \
    'the dashboard is opened by show_dashboard'
# Commercial TOOLING names no tier function. The real ci/ test that leaked once
# would have sailed through on the identifier list alone.
check_blocked "a commercial ci/ helper naming no tier function" \
    "tests/cases/test_no_duplicates.sh" \
    'REPO="${COMMERCIAL_ROOT:-$(pwd)}"
echo checking "$REPO"'
[[ $leaked -eq 0 ]] && pass_msg "commercial content is refused wherever it sits"

# --- must BLOCK the STAGED blob, not the working copy ------------------------
# Staging a bad version and then cleaning the worktree must not sneak past:
# the index is what gets committed.
printf 'run_openscap_scan\n' > sneaky.sh
git add -f sneaky.sh
printf 'harmless\n' > sneaky.sh          # worktree now clean, index still bad
if git commit -qm "test" >/dev/null 2>&1; then
    fail "the hook read the working copy, not the staged blob"
else
    pass_msg "the staged blob is what gets checked, not the worktree"
fi
git reset -q HEAD -- sneaky.sh 2>/dev/null; rm -f sneaky.sh

# --- must ALLOW: ordinary work ------------------------------------------------
# Real files from this repo, which must stay committable. test_module_count.sh
# and test_module_isolation.sh both name the tier script PATHS as they iterate
# tiers — an early draft of this hook used those paths as content markers and
# would have blocked them.
allowed=0
# The guard's own two files are in this list deliberately. They quote every
# marker, so without an explicit exemption the hook blocks itself — verified,
# and it did: this change could not have been committed at all.
for src in tests/cases/test_module_count.sh \
           tests/cases/test_module_isolation.sh \
           scripts/hooks/pre-commit \
           tests/cases/test_publication_guard.sh \
           lib/core.sh lib/modules.sh README.md LICENSE; do
    [[ -f "$REPO/$src" ]] || continue
    mkdir -p "$(dirname "$src")" 2>/dev/null
    cp "$REPO/$src" "$src"
    git add -f "$src" 2>/dev/null
    if git commit -qm "ordinary" >/dev/null 2>&1; then
        allowed=$((allowed + 1))
    else
        fail "the hook blocked an ordinary file from this repo: $src"
    fi
done
[[ "$allowed" -gt 0 ]] && pass_msg "ordinary repo files commit normally ($allowed checked)"

# --- exact-content match against the real commercial repo --------------------
# The identifier list is a heuristic that only ever caught bash tier source.
# Measured: 21 of the commercial repo's 27 files got through it once renamed —
# the Python dashboard, the HTML/CSS/JS, the examples, ci.yml, PRICING.md. The
# blob-hash check is what closes that, so it is asserted against the real repo
# rather than a fixture.
COMMERCIAL="${UH_COMMERCIAL_REPO:-$REPO/../ultimate-hardening-commercial}"
if [[ -d "$COMMERCIAL" ]]; then
    export UH_COMMERCIAL_REPO="$(cd "$COMMERCIAL" && pwd)"
    leaked=0; checked=0
    while IFS= read -r cf; do
        checked=$((checked + 1))
        dest="tests/$(printf '%s' "${cf#$UH_COMMERCIAL_REPO/}" | tr '/' '_')"
        mkdir -p tests 2>/dev/null
        cp "$cf" "$dest" 2>/dev/null || continue
        git add -f "$dest" 2>/dev/null
        if git commit -qm t >/dev/null 2>&1; then
            fail "commercial file published under an innocent name: ${cf#$UH_COMMERCIAL_REPO/}"
            leaked=$((leaked + 1))
        fi
        git reset -q HEAD -- "$dest" 2>/dev/null; rm -f "$dest"
    done < <(find "$UH_COMMERCIAL_REPO" -type f \
                -not -path '*/.git/*' -not -path '*/_gitjunk/*' \
                -not -path "$UH_COMMERCIAL_REPO/lib/*" \
                -not -path "$UH_COMMERCIAL_REPO/tests/*" 2>/dev/null)
    if [[ $checked -eq 0 ]]; then
        fail "the commercial repo was found but produced no files to check"
    elif [[ $leaked -eq 0 ]]; then
        pass_msg "all $checked real commercial files are refused, whatever they are renamed to"
    fi
    unset UH_COMMERCIAL_REPO
else
    echo "  ⏭️  SKIP: commercial repo not on this machine — the exact-content check"
    echo "           cannot be exercised here, only the identifier heuristic"
fi

# --- the guard must survive a vendored commercial repo ------------------------
# If the commercial repo is ever restructured from "paid tiers only, sharing
# lib/ by symlink" into "a whole self-contained copy of free + paid", then every
# free-tier file exists verbatim in both repos. Without subtracting this repo's
# own blobs, the hash check refuses ordinary free-tier work — measured, and it
# refused src/free/ultimate_hardening.sh and README.md. The guard must not be
# the reason that restructure cannot happen.
VEND="$WORK/vendored"
export UH_COMMERCIAL_REPO="$WORK/vendored"
mkdir -p "$VEND/lib" "$VEND/src/free" "$VEND/src/pro"
if [[ -f "$REPO/lib/core.sh" && -f "$REPO/src/free/ultimate_hardening.sh" ]]; then
    cp "$REPO/lib/core.sh"                  "$VEND/lib/core.sh"
    cp "$REPO/src/free/ultimate_hardening.sh" "$VEND/src/free/ultimate_hardening.sh"
    printf 'tier_config_defaults() { :; }
' > "$VEND/src/pro/paid.sh"

    # the free copy has to be in HEAD for the subtraction to see it
    mkdir -p src/free lib
    cp "$REPO/lib/core.sh" lib/core.sh
    cp "$REPO/src/free/ultimate_hardening.sh" src/free/ultimate_hardening.sh
    git add -f lib/core.sh src/free/ultimate_hardening.sh >/dev/null 2>&1
    git commit -qm "free tier" >/dev/null 2>&1

    vend_fail=0
    printf '
# an ordinary change
' >> src/free/ultimate_hardening.sh
    git add -f src/free/ultimate_hardening.sh >/dev/null 2>&1
    if ! git commit -qm "ordinary" >/dev/null 2>&1; then
        fail "a vendored commercial repo makes ordinary free-tier work unpublishable"
        vend_fail=1
        git reset -q HEAD -- src/free/ultimate_hardening.sh 2>/dev/null
    fi

    cp "$VEND/src/pro/paid.sh" tests/sneaky.sh
    git add -f tests/sneaky.sh >/dev/null 2>&1
    if git commit -qm "paid" >/dev/null 2>&1; then
        fail "a paid file leaked once the commercial repo vendored the free tier"
        vend_fail=1
    fi
    git reset -q HEAD -- tests/sneaky.sh 2>/dev/null; rm -f tests/sneaky.sh

    [[ $vend_fail -eq 0 ]] && \
        pass_msg "a vendored commercial layout blocks paid files and passes free ones"
fi

# --- binaries are skipped, and skipping them does not break the hook ---------
# Binary blobs are identified from git's own numstat, not by inspecting bytes.
# An earlier version tested the content for a NUL with `case ... in *$'\0'*)`,
# which bash expands to `**` — it matched everything and silently disabled the
# whole content check while the path rules kept working, so the hook looked fine.
# images/ is the only binary content this repo tracks.
mkdir -p images
printf 'PNG\x00\x00binary run_openscap_scan\x00blob\n' > images/logo.png
git add -f images/logo.png 2>/dev/null
if git commit -qm "binary" >/dev/null 2>&1; then
    pass_msg "a binary blob is skipped rather than grepped"
else
    fail "the hook blocked a binary file — it is grepping bytes instead of asking git"
fi
rm -f images/logo.png

# --- and the documented escape hatch has to work ------------------------------
printf 'run_openscap_scan\n' > override.sh
git add -f override.sh
if git commit -q --no-verify -m "deliberate" >/dev/null 2>&1; then
    pass_msg "--no-verify still works, so the hook is a guard and not a lock"
else
    fail "--no-verify did not bypass the hook"
fi

finish
