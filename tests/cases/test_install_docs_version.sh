#!/bin/bash
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

ver=$(sed -n 's/^UH_VERSION="\([^"]*\)"/\1/p' "$REPO/lib/core.sh")
[[ -n "$ver" ]] || { fail "UH_VERSION not found in lib/core.sh"; finish; }

for f in README.md SECURITY.md docs/index.html; do
    [[ -f "$REPO/$f" ]] || { echo "  ⏭️  SKIP: $f not present"; continue; }
    lines=$(grep -o 'git clone[^<]*ultimate-sys-hardening\.git' "$REPO/$f")
    if [[ -z "$lines" ]]; then
        fail "$f has no install command"
        continue
    fi
    bad=$(grep -v -- "--branch v$ver " <<<"$lines" || true)
    [[ -z "$bad" ]] && pass_msg "$f installs v$ver" \
                    || fail "$f has an install command not pinned to v$ver: $(head -1 <<<"$bad")"
done

grep -q 'cd ultimate-sys-hardening/src/free' "$REPO/docs/index.html" 2>/dev/null \
    && fail "docs/index.html changes into src/free, then runs ./src/free/…" \
    || pass_msg "the site's install commands run from the repository root"

finish
