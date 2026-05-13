#!/usr/bin/env bash
# sbom.sh — generate a merged CycloneDX 1.5 SBOM for the release.
#
# Combines:
#   - Python deps in backend/  via cyclonedx-py (pip install cyclonedx-bom)
#   - Rust workspace deps      via cargo-cyclonedx (cargo install cargo-cyclonedx)
#
# Merges the two into one CycloneDX JSON. Uses `cyclonedx-cli merge` if
# present, otherwise a minimal Python fallback that concatenates the
# `components` arrays and rewrites top-level metadata.
#
# Usage:
#   tools/sign/sbom.sh [output.json]
#
# Default output: target/sbom/vigil-sbom.cdx.json
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
OUT_FILE="${1:-$REPO/target/sbom/vigil-sbom.cdx.json}"
OUT_DIR=$(dirname "$OUT_FILE")
mkdir -p "$OUT_DIR"

PY_SBOM="$OUT_DIR/backend-python.cdx.json"
RUST_SBOM="$OUT_DIR/agent-rust.cdx.json"

VERSION=$(grep -E '^version' "$REPO/Cargo.toml" | head -1 | sed -E 's/.*"([^"]+)".*/\1/' || echo "0.0.0")

echo "[sbom] repo=$REPO output=$OUT_FILE version=$VERSION"

write_empty_sbom() {
    printf '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}\n' > "$1"
}

# --- Python (backend/) -----------------------------------------------------
# `cyclonedx-py requirements -` reads requirements from stdin. We feed
# it `pip freeze` from a Python env that has backend deps installed.
# Prefers (in order): backend/.venv (dev box), the ambient python
# (release CI installs backend deps into the runner's site-packages
# before invoking this script).
PY_BIN=""
CYCLONEDX_PY=""
PY_FREEZE_FLAGS="--all"
if [ -x "$REPO/backend/.venv/bin/python" ]; then
    PY_BIN="$REPO/backend/.venv/bin/python"
    PY_FREEZE_FLAGS="--all --local --require-virtualenv"
    [ -x "$REPO/backend/.venv/bin/cyclonedx-py" ] && CYCLONEDX_PY="$REPO/backend/.venv/bin/cyclonedx-py"
elif command -v python3 >/dev/null 2>&1; then
    PY_BIN=python3
fi
if [ -z "$CYCLONEDX_PY" ] && command -v cyclonedx-py >/dev/null 2>&1; then
    CYCLONEDX_PY=cyclonedx-py
fi

if [ -n "$CYCLONEDX_PY" ] && [ -n "$PY_BIN" ]; then
    echo "[sbom] python: $CYCLONEDX_PY via $PY_BIN -m pip freeze"
    # shellcheck disable=SC2086
    "$PY_BIN" -m pip freeze $PY_FREEZE_FLAGS 2>/dev/null \
        | "$CYCLONEDX_PY" requirements --sv 1.5 --of JSON --no-validate -o "$PY_SBOM" - \
        || { echo "[sbom] cyclonedx-py failed; writing empty"; write_empty_sbom "$PY_SBOM"; }
else
    echo "[sbom] cyclonedx-py not installed or no python available — writing empty Python SBOM"
    write_empty_sbom "$PY_SBOM"
fi

# --- Rust workspace --------------------------------------------------------
# `cargo cyclonedx` writes one bom.json next to each Cargo.toml in the
# workspace. Run from the repo root, then merge the per-crate boms
# into one Rust-scoped SBOM. The per-crate files are removed after.
if cargo cyclonedx --version >/dev/null 2>&1; then
    echo "[sbom] rust: cargo cyclonedx -f json --spec-version 1.5"
    (cd "$REPO" && cargo cyclonedx -f json --spec-version 1.5 2>&1) \
        | sed 's/^/[sbom rust] /' \
        || echo "[sbom] cargo cyclonedx returned non-zero (continuing)"
    shopt -s nullglob
    rust_boms=( "$REPO"/bom.json "$REPO"/*/bom.json )
    shopt -u nullglob
    if [ "${#rust_boms[@]}" -gt 0 ]; then
        python3 "$REPO/tools/sign/sbom_merge.py" \
            --output "$RUST_SBOM" \
            --name vigil-agent --version "$VERSION" \
            "${rust_boms[@]}"
    else
        write_empty_sbom "$RUST_SBOM"
    fi
    # cargo-cyclonedx drops bom.json next to each Cargo.toml; clean up.
    find "$REPO" -maxdepth 3 -name bom.json -not -path "*/target/*" -delete 2>/dev/null || true
else
    echo "[sbom] cargo-cyclonedx not installed — writing empty Rust SBOM"
    write_empty_sbom "$RUST_SBOM"
fi

# --- Merge -----------------------------------------------------------------
if command -v cyclonedx-cli >/dev/null 2>&1; then
    echo "[sbom] merge: cyclonedx-cli merge"
    cyclonedx-cli merge \
        --input-files "$PY_SBOM" "$RUST_SBOM" \
        --output-file "$OUT_FILE" \
        --output-format json \
        --name vigil-edr \
        --version "$VERSION"
else
    echo "[sbom] merge: python fallback (cyclonedx-cli not installed)"
    python3 "$REPO/tools/sign/sbom_merge.py" \
        --output "$OUT_FILE" \
        --name vigil-edr \
        --version "$VERSION" \
        "$PY_SBOM" "$RUST_SBOM"
fi

echo "[sbom] wrote: $OUT_FILE ($(wc -c < "$OUT_FILE") bytes)"
