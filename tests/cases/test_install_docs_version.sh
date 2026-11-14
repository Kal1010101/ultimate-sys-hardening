#!/bin/bash
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

ver=$(sed -n 's/^UH_VERSION="\([^"]*\)"/\1/p' "$REPO/lib/core.sh")
[[ -n "$ver" ]] || { fail "UH_VERSION not found in lib/core.sh"; finish; }

for f in README.md SECURITY.md docs/index.html docs/installation.md; do
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

# The README's package install pins the version in a V= line.
pkg_versions=$(grep -oE '^V=[0-9][0-9.]*$' "$REPO/README.md" | sort -u)
[[ "$pkg_versions" == "V=$ver" ]] && pass_msg "the README's package install fetches v$ver" \
    || fail "the README's package install has '${pkg_versions:-no V= line}', not V=$ver"

# The Ansible role installs the release it shipped with.
role_version=$(sed -n 's/^uh_version: "\([^"]*\)"$/\1/p' "$REPO/ansible/roles/ultimate_hardening/defaults/main.yml" 2>/dev/null)
[[ "$role_version" == "$ver" ]] && pass_msg "the Ansible role installs v$ver" \
    || fail "the Ansible role's uh_version is '${role_version:-missing}', not $ver"

badge=$(grep -o '<span class="badge ok">v[0-9][0-9.]*</span>' "$REPO/docs/index.html" 2>/dev/null | head -1)
[[ "$badge" == "<span class=\"badge ok\">v$ver</span>" ]] && pass_msg "the site's version badge says v$ver" \
    || fail "the site's version badge is '$badge', not v$ver"

grep -q 'cd ultimate-sys-hardening/src/free' "$REPO/docs/index.html" 2>/dev/null \
    && fail "docs/index.html changes into src/free, then runs ./src/free/…" \
    || pass_msg "the site's install commands run from the repository root"

finish
