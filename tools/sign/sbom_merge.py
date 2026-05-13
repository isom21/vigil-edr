#!/usr/bin/env python3
"""Minimal CycloneDX 1.5 SBOM merger.

Used by tools/sign/sbom.sh when `cyclonedx-cli` is not installed.
Reads N CycloneDX JSON documents and emits a single combined document
with the concatenated `components` array and a fresh top-level
metadata block. Duplicate components (same bom-ref or purl) are
deduplicated.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


def load(path: Path) -> dict:
    if not path.exists():
        return {"components": []}
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[sbom_merge] skip {path}: {exc}", file=sys.stderr)
        return {"components": []}


def merge(inputs: list[Path], name: str, version: str) -> dict:
    seen_keys: set[str] = set()
    components: list[dict] = []
    for path in inputs:
        doc = load(path)
        for comp in doc.get("components") or []:
            key = comp.get("bom-ref") or comp.get("purl") or json.dumps(comp, sort_keys=True)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            components.append(comp)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "vigil-edr", "name": "sbom_merge.py", "version": "1.0"}],
            "component": {
                "type": "application",
                "name": name,
                "version": version,
                "bom-ref": f"pkg:generic/{name}@{version}",
            },
        },
        "components": components,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("inputs", nargs="+", type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--name", default="vigil-edr")
    ap.add_argument("--version", default="0.0.0")
    args = ap.parse_args()

    merged = merge(args.inputs, args.name, args.version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=2)
    print(
        f"[sbom_merge] wrote {args.output} with {len(merged['components'])} components",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
