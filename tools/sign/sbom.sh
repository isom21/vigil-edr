#!/usr/bin/env bash
# sbom.sh - generate CycloneDX SBOMs for every release artefact.
# M18.a scaffold; tools may be optional, missing-tool branches are
# silent so the script doesn't fail in environments where only some
# of the artefact types are produced.
set -uo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
OUT="$REPO/target/sbom"
mkdir -p "$OUT"

run_if_present() {
    local tool=$1
    shift
    if command -v "$tool" >/dev/null 2>&1; then
        echo "[sbom] $*"
        "$tool" "$@" || echo "[sbom] $tool failed (continuing)"
    else
        echo "[sbom] skip ($tool not installed)"
    fi
}

# Linux agent binary + .deb / .rpm artefacts.
if [ -f "$REPO/target/release/edr-agent" ]; then
    run_if_present syft "$REPO/target/release/edr-agent" -o cyclonedx-json --file "$OUT/agent-linux.cdx.json"
fi
for deb in "$REPO"/target/debian/*.deb; do
    [ -f "$deb" ] && run_if_present syft "$deb" -o cyclonedx-json --file "$OUT/$(basename "$deb").cdx.json"
done
for rpm in "$REPO"/target/generate-rpm/*.rpm; do
    [ -f "$rpm" ] && run_if_present syft "$rpm" -o cyclonedx-json --file "$OUT/$(basename "$rpm").cdx.json"
done

# Windows driver (only present if cross-built).
if [ -f "$REPO/kernel-windows/edr.sys" ]; then
    run_if_present syft "$REPO/kernel-windows/edr.sys" -o cyclonedx-json --file "$OUT/edr-driver.cdx.json"
fi

# Backend Python deps.
if [ -d "$HOME/edr-venvs/backend" ]; then
    run_if_present cyclonedx-py environment "$HOME/edr-venvs/backend" -o "$OUT/manager.cdx.json"
fi

# Frontend npm deps.
if [ -f "$REPO/frontend/package-lock.json" ]; then
    (cd "$REPO/frontend" && run_if_present cyclonedx-npm --output-file "$OUT/frontend.cdx.json")
fi

ls -la "$OUT"
