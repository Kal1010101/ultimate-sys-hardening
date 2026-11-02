#!/bin/bash
# Builds the .deb, .rpm, .apk and Arch package from this checkout into the given
# directory (default dist/). The version comes from lib/core.sh, so it cannot drift from the code.
#
# Signing is optional here so a pull request can build: set PACKAGE_SIGNING_KEY
# to an armored GPG private key file, and NFPM_PASSPHRASE if it has one. That
# signs the .deb and .rpm only: apk signing needs an RSA key and Arch packages
# are signed apart, so those two ship unsigned.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$REPO/dist}"

command -v nfpm >/dev/null 2>&1 || {
    echo "ERROR: nfpm not found. See https://nfpm.goreleaser.com/install/" >&2
    exit 1
}

VERSION=$(sed -n 's/^UH_VERSION="\([^"]*\)"/\1/p' "$REPO/lib/core.sh")
[[ -n "$VERSION" ]] || { echo "ERROR: UH_VERSION not found in lib/core.sh" >&2; exit 1; }
export VERSION
export PACKAGE_SIGNING_KEY="${PACKAGE_SIGNING_KEY:-}"

mkdir -p "$OUT_DIR"
cd "$REPO"
for format in deb rpm apk archlinux; do
    nfpm package --config packaging/nfpm.yaml --packager "$format" --target "$OUT_DIR/"
done
