#!/bin/bash
# Installs the built package in a throwaway container and checks the result.
# Usage, as root inside the container: test-package.sh <dir with .deb/.rpm> <version>
#
# Uses the repo's own assertions, so a failure names what broke.
set -uo pipefail

PACKAGE_DIR="$1"
VERSION="$2"
SHARE_DIR=/usr/share/ultimate-hardening
BACKUP_MARKER=/root/hardening_backup_package_test/keep

# shellcheck source=../tests/lib/assert.sh
source "$(dirname "${BASH_SOURCE[0]}")/../tests/lib/assert.sh"

# Slim images leave these out; a real host has them.
command -v find >/dev/null 2>&1 || dnf install -y -q findutils >/dev/null 2>&1

# /etc/apk/world is apk's own record of what is installed.
etc_snapshot() { find /etc -type f ! -path '/etc/apk/*' -exec sha256sum {} + 2>/dev/null | sort; }

if command -v dpkg >/dev/null 2>&1; then
    package_file=$(echo "$PACKAGE_DIR"/*.deb)
    package_scriptlets() { dpkg-deb -I "$package_file" | grep -E ' (pre|post)(inst|rm)$' || true; }
    install_package_file() { dpkg -i "$package_file" >/dev/null; }
    remove_package() { dpkg -r ultimate-hardening >/dev/null; }
elif command -v rpm >/dev/null 2>&1; then
    package_file=$(echo "$PACKAGE_DIR"/*.rpm)
    package_scriptlets() { rpm -qp --scripts --nosignature "$package_file" 2>/dev/null; }
    # Unsigned builds are the norm before release; signing is checked apart.
    install_package_file() { rpm -i --nosignature "$package_file" >/dev/null; }
    remove_package() { rpm -e ultimate-hardening >/dev/null; }
elif command -v pacman >/dev/null 2>&1; then
    package_file=$(echo "$PACKAGE_DIR"/*.pkg.tar.*)
    package_scriptlets() { bsdtar -tf "$package_file" | grep -x '.INSTALL' || true; }
    install_package_file() { pacman -U --noconfirm "$package_file" >/dev/null 2>&1; }
    remove_package() { pacman -R --noconfirm ultimate-hardening >/dev/null 2>&1; }
elif command -v apk >/dev/null 2>&1; then
    package_file=$(echo "$PACKAGE_DIR"/*.apk)
    # An .apk is several gzip streams, so ask apk's own database once installed.
    package_scriptlets() { tar -tf /lib/apk/db/scripts.tar 2>/dev/null | grep ultimate-hardening || true; }
    install_package_file() { apk add --no-network --allow-untrusted "$package_file" >/dev/null; }
    remove_package() { apk del ultimate-hardening >/dev/null; }
else
    skip "no dpkg, rpm, pacman or apk on this image"
fi

mkdir -p "$(dirname "$BACKUP_MARKER")"; touch "$BACKUP_MARKER"
etc_before=$(etc_snapshot)

install_package_file && pass_msg "the package installs" || { fail "the package did not install"; finish; }

scriptlets=$(package_scriptlets)
if [[ -z "$scriptlets" ]]; then
    pass_msg "the package has no install scriptlets"
else
    fail "the package carries scriptlets: $scriptlets"
fi

got=$(ultimate-harden --version 2>&1) || fail "ultimate-harden --version failed: $got"
assert_output_contains "$got" "$VERSION" "the installed command reports $VERSION"

writable=$(find "$SHARE_DIR" /usr/share/doc/ultimate-hardening \( ! -user root -o -perm /022 \) ! -type l 2>/dev/null)
if [[ -z "$writable" ]]; then
    pass_msg "installed files are root-owned and writable only by root"
else
    fail "unsafe ownership or mode: $writable"
fi
if [[ "$(etc_snapshot)" == "$etc_before" ]]; then
    pass_msg "installing changed nothing under /etc"
else
    fail "installing changed files under /etc"
fi

dry=$(printf 'Q\n' | UH_TEST=1 timeout 300 ultimate-harden --dry-run --auto-mode 2>&1); rc=$?
assert_exit_code 0 "$rc" "a dry run works from the installed location"
assert_output_contains "$dry" 'Preflight' "the dry run reached the tool"
if ! grep -qE 'UH_TRUST_LIB|owned by uid|writable' <<< "$dry"; then
    pass_msg "the library trust check stays quiet"
else
    fail "the library trust check warned about the installed files"
fi

remove_package && pass_msg "the package removes" || fail "the package did not remove"
assert_file_absent /usr/bin/ultimate-harden
assert_file_exists "$BACKUP_MARKER"

finish
