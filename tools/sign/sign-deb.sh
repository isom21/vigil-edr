#!/usr/bin/env bash
# sign-deb.sh — sign .deb packages with the operator's GPG key.
#
# Usage:
#   GPG_KEY_ID=release@example.com tools/sign/sign-deb.sh [pkg.deb ...]
#
# With no positional arguments, signs every .deb under $DEB_DIR
# (default: target/debian). With VIGIL_DRY_RUN=1, prints the command
# that would be run without actually signing.

set -euo pipefail

DEB_DIR="${DEB_DIR:-target/debian}"
GPG_KEY_ID="${GPG_KEY_ID:-}"

if [ -z "$GPG_KEY_ID" ]; then
    echo "GPG_KEY_ID not set. Generate via: gpg --gen-key" >&2
    exit 2
fi

if [ "${VIGIL_DRY_RUN:-0}" != "1" ] && ! command -v dpkg-sig >/dev/null 2>&1; then
    echo "dpkg-sig not installed. apt install dpkg-sig" >&2
    exit 2
fi

if [ "$#" -gt 0 ]; then
    debs=( "$@" )
else
    shopt -s nullglob
    debs=( "$DEB_DIR"/*.deb )
fi

if [ "${#debs[@]}" -eq 0 ]; then
    echo "no .deb files to sign (looked in: $DEB_DIR)" >&2
    exit 2
fi

for deb in "${debs[@]}"; do
    if [ ! -f "$deb" ]; then
        echo "missing: $deb" >&2
        exit 2
    fi
    if [ "${VIGIL_DRY_RUN:-0}" = "1" ]; then
        echo "DRY-RUN: dpkg-sig --sign builder -k $GPG_KEY_ID $deb"
    else
        dpkg-sig --sign builder -k "$GPG_KEY_ID" "$deb"
        echo "  signed: $deb"
    fi
done
