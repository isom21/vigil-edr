#!/usr/bin/env bash
# sign-rpm.sh — sign .rpm packages with the operator's GPG key.
#
# Usage:
#   GPG_KEY_ID=release@example.com tools/sign/sign-rpm.sh [pkg.rpm ...]
#
# Requires the GPG key to be imported in the local keyring and either
# `%_gpg_name` already configured in ~/.rpmmacros or GPG_KEY_ID set
# (this script writes ~/.rpmmacros for that run if missing).
#
# With no positional arguments, signs every .rpm under $RPM_DIR
# (default: target/generate-rpm). With VIGIL_DRY_RUN=1, prints the
# command that would be run without actually signing.

set -euo pipefail

RPM_DIR="${RPM_DIR:-target/generate-rpm}"
GPG_KEY_ID="${GPG_KEY_ID:-}"

if [ -z "$GPG_KEY_ID" ]; then
    echo "GPG_KEY_ID not set. Generate via: gpg --gen-key" >&2
    exit 2
fi

if [ "${VIGIL_DRY_RUN:-0}" != "1" ] && ! command -v rpm >/dev/null 2>&1; then
    echo "rpm not installed. apt install rpm (or dnf install rpm-sign)" >&2
    exit 2
fi

# rpm --addsign reads %_gpg_name from ~/.rpmmacros. Set it if missing
# rather than mutate the operator's existing config. Skip in dry-run.
if [ "${VIGIL_DRY_RUN:-0}" != "1" ]; then
    RPMMACROS="$HOME/.rpmmacros"
    if [ ! -f "$RPMMACROS" ] || ! grep -q '^%_gpg_name' "$RPMMACROS" 2>/dev/null; then
        echo "%_gpg_name $GPG_KEY_ID" >> "$RPMMACROS"
        echo "[sign-rpm] wrote %_gpg_name to $RPMMACROS"
    fi
fi

if [ "$#" -gt 0 ]; then
    rpms=( "$@" )
else
    shopt -s nullglob
    rpms=( "$RPM_DIR"/*.rpm )
fi

if [ "${#rpms[@]}" -eq 0 ]; then
    echo "no .rpm files to sign (looked in: $RPM_DIR)" >&2
    exit 2
fi

for rpm in "${rpms[@]}"; do
    if [ ! -f "$rpm" ]; then
        echo "missing: $rpm" >&2
        exit 2
    fi
    if [ "${VIGIL_DRY_RUN:-0}" = "1" ]; then
        echo "DRY-RUN: rpm --addsign $rpm"
    else
        rpm --addsign "$rpm"
        echo "  signed: $rpm"
    fi
done
