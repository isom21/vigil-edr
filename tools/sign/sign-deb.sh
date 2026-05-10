#!/usr/bin/env bash
# sign-deb.sh - sign the cargo-deb output with the operator's GPG key.
#
# Usage:
#   GPG_KEY_ID=release@edr.example tools/sign/sign-deb.sh
#
# When EDR_DRY_RUN=1 is set, prints the command that would be run
# without actually signing. Useful for verifying the release flow
# pre-M19 (when the operator may not yet have a GPG key).

set -euo pipefail

DEB_DIR="${DEB_DIR:-target/debian}"
GPG_KEY_ID="${GPG_KEY_ID:-}"

if [ -z "$GPG_KEY_ID" ]; then
    echo "GPG_KEY_ID not set. Generate via: gpg --gen-key" >&2
    exit 2
fi

if ! command -v dpkg-sig >/dev/null 2>&1; then
    echo "dpkg-sig not installed. apt install dpkg-sig" >&2
    exit 2
fi

shopt -s nullglob
debs=( "$DEB_DIR"/*.deb )
if [ "${#debs[@]}" -eq 0 ]; then
    echo "no .deb files in $DEB_DIR" >&2
    exit 2
fi

for deb in "${debs[@]}"; do
    if [ "${EDR_DRY_RUN:-0}" = "1" ]; then
        echo "DRY-RUN: dpkg-sig --sign builder -k $GPG_KEY_ID $deb"
    else
        dpkg-sig --sign builder -k "$GPG_KEY_ID" "$deb"
        echo "  signed: $deb"
    fi
done
