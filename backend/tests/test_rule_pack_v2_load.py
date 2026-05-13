"""Curated rule pack v2 — content-only validation (Phase 3 #3.13).

Pins the four invariants every rule in the v2 pack must satisfy:

  1. Compiles. The YAML body parses and `OpensearchLuceneBackend`
     turns it into a non-empty Lucene clause via the existing
     `compile_yaml()` helper. A rule that doesn't compile would be
     silently dropped by the boot-time loader, which means we'd ship
     a rule that never fires — content drift the test must prevent.
  2. Exactly one MITRE technique tag. Each curated rule maps to a
     single ATT&CK technique so the rule library UI and downstream
     reporting can group cleanly. The tag must match
     `attack.t<digits>(.<digits>)?`.
  3. At least one `falsepositives` entry. Every rule in the pack is
     opinionated; the operator needs to know what we expect to be
     benign so they can tune at deploy time. Empty / missing lists
     are a tell that the author hasn't thought about precision.
  4. Severity in {low, medium, high, critical}. This is the set the
     loader's `_LEVEL_TO_SEVERITY` map handles cleanly; anything
     else gets quietly demoted to MEDIUM, which would mis-report
     critical-tier coverage.

The fifth assertion is end-to-end: drop every v2 rule into a tmp
directory and run `load_rule_pack()` against it; every row must land
tagged `curated_v1` (the loader marker stored in `Rule.description`).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select

from app.models import Rule
from app.services.rule_pack import (
    CURATED_TAG,
    _extract_mitre_techniques,
    load_rule_pack,
)
from app.services.sigma import SigmaCompileError, compile_yaml

# Path to the curated pack relative to this test file. The on-disk
# layout is `backend/sigma_rules/<tactic>/<file>.yml`; this file lives
# in `backend/tests/`, so siblings of the parent.
_PACK_ROOT = Path(__file__).resolve().parents[1] / "sigma_rules"

# v2 added these tactic subdirectories — previous pack only had four
# (initial_access / execution / persistence / credential_access).
_V2_TACTICS = (
    "command_and_control",
    "defense_evasion",
    "discovery",
    "exfiltration",
    "impact",
    "lateral_movement",
)

# Specific filenames added under the four existing tactics by v2. We
# enumerate them explicitly so this test won't accidentally include
# pre-existing v1 rules — those have their own coverage in
# `test_rule_pack_loader.py` and we don't want to double-count.
_V2_FILES_IN_EXISTING_TACTICS: dict[str, tuple[str, ...]] = {
    "credential_access": (
        "t1003.001_lsass_access_uncommon_caller.yml",
        "t1003.002_sam_save_via_reg_save.yml",
        "t1110.003_password_spray_per_user.yml",
        "t1555.003_chromium_login_data_read.yml",
    ),
    "execution": (
        "t1021.002_smb_admin_share_write_then_run.yml",
        "t1047_wmic_process_call_create.yml",
        "t1059.001_powershell_downloadstring.yml",
        "t1059.003_cmd_for_loop_remote_exec.yml",
        "t1129_unsigned_dll_load_into_signed_process.yml",
        "t1218.010_regsvr32_squiblydoo.yml",
    ),
    "initial_access": (
        "t1566.001_office_macro_spawning_powershell.yml",
        "t1566.002_browser_renders_html_then_writes_script_extension.yml",
    ),
    "persistence": (
        "t1053.005_schtasks_create_unusual_hour.yml",
        "t1547.001_run_key_write_uncommon_path.yml",
        "t1574.011_service_imagepath_replaced.yml",
    ),
}

# `attack.t<digits>(.<digits>)?` — Sigma's conventional spelling for
# a MITRE technique ID, case-insensitive. The loader normalises to
# upper-case before storing; we test the on-disk form (lower-case)
# here so authors writing `attack.T1059.001` would still fail.
_TECHNIQUE_TAG_RE = re.compile(r"^attack\.t\d+(\.\d+)?$")

_VALID_LEVELS = {"low", "medium", "high", "critical"}


def _collect_v2_rule_paths() -> list[Path]:
    """Enumerate every v2 rule on disk so each test can iterate.

    Two sources: every `*.yml` under the new tactic directories
    (`command_and_control/`, etc.) plus the explicit per-file
    additions under the four legacy tactic directories.
    """
    paths: list[Path] = []
    for tactic in _V2_TACTICS:
        d = _PACK_ROOT / tactic
        assert d.is_dir(), f"v2 tactic dir missing: {d}"
        paths.extend(sorted(d.glob("*.yml")))
    for tactic, files in _V2_FILES_IN_EXISTING_TACTICS.items():
        for fname in files:
            p = _PACK_ROOT / tactic / fname
            assert p.is_file(), f"v2 rule missing: {p}"
            paths.append(p)
    return paths


_V2_RULE_PATHS = _collect_v2_rule_paths()


def test_rule_pack_v2_minimum_size() -> None:
    """The v2 pack must add at least 50 new rules. Undershooting this
    target is a content-level regression — the spec calls for ~50."""
    assert len(_V2_RULE_PATHS) >= 50, (
        f"rule pack v2 has {len(_V2_RULE_PATHS)} rules; spec asks for ~50"
    )


@pytest.mark.parametrize("path", _V2_RULE_PATHS, ids=lambda p: p.relative_to(_PACK_ROOT).as_posix())
def test_rule_pack_v2_rule_compiles(path: Path) -> None:
    """Every v2 rule must compile via OpensearchLuceneBackend.

    The boot-time loader silently skips rules that don't compile, so a
    broken rule wouldn't fail the manager — it would just go missing
    from the rule library without warning. We want the test, not the
    operator, to discover that.
    """
    body = path.read_text(encoding="utf-8")
    try:
        compiled = compile_yaml(body)
    except SigmaCompileError as exc:
        pytest.fail(f"{path.relative_to(_PACK_ROOT)} failed to compile: {exc}")
    assert compiled.query, f"{path.relative_to(_PACK_ROOT)} produced an empty query"


@pytest.mark.parametrize("path", _V2_RULE_PATHS, ids=lambda p: p.relative_to(_PACK_ROOT).as_posix())
def test_rule_pack_v2_rule_metadata(path: Path) -> None:
    """Every v2 rule must carry exactly one MITRE technique tag, a
    non-empty `falsepositives` list, and a valid `level`."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    rel = path.relative_to(_PACK_ROOT)

    assert isinstance(doc, dict), f"{rel}: YAML root is not a mapping"

    # Technique tag — exactly one, well-formed.
    tags = doc.get("tags") or []
    assert isinstance(tags, list), f"{rel}: tags must be a list"
    technique_tags = [t for t in tags if isinstance(t, str) and _TECHNIQUE_TAG_RE.match(t.lower())]
    assert len(technique_tags) == 1, (
        f"{rel}: must carry exactly one attack.t<id> tag, found {technique_tags}"
    )
    # The loader's own extractor must also find exactly one technique
    # — this guards against future drift where the regex above and the
    # loader's logic disagree.
    extracted = _extract_mitre_techniques(tags)
    assert len(extracted) == 1, f"{rel}: loader extracted {extracted} from tags {tags}"

    # False-positives — at least one entry. Operators rely on this
    # field to decide what to whitelist before turning a rule on.
    fps = doc.get("falsepositives") or []
    assert isinstance(fps, list) and len(fps) >= 1, (
        f"{rel}: falsepositives must list at least one item"
    )
    assert all(isinstance(fp, str) and fp.strip() for fp in fps), (
        f"{rel}: every falsepositives entry must be a non-empty string"
    )

    # Severity level — must be one of the four the loader maps cleanly.
    # `informational` / `info` are valid Sigma but get demoted to INFO
    # by the loader; the spec restricts v2 to the four "actionable" tiers.
    level = str(doc.get("level") or "").strip().lower()
    assert level in _VALID_LEVELS, f"{rel}: level={level!r} not in {sorted(_VALID_LEVELS)}"

    # Description present — operator-friendly summary is part of the
    # spec's content contract. We don't grade on length, only on
    # existence and non-emptiness.
    description = doc.get("description")
    assert isinstance(description, str) and description.strip(), (
        f"{rel}: description must be a non-empty string"
    )


@pytest.mark.asyncio
async def test_rule_pack_v2_loads_with_curated_tag(db_session, tmp_path) -> None:
    """End-to-end: copy every v2 rule into a tmp tree and run the
    loader against it. Every rule must land as a Rule row whose
    description carries the `curated_v1` marker. This proves the
    content drops in to the existing pipeline without a code change.
    """
    # Mirror the on-disk layout into tmp_path so the loader's
    # relative-path bookkeeping works the same way.
    expected_ids: set[str] = set()
    for path in _V2_RULE_PATHS:
        rel = path.relative_to(_PACK_ROOT)
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        body = path.read_text(encoding="utf-8")
        dst.write_text(body, encoding="utf-8")
        doc = yaml.safe_load(body)
        expected_ids.add(str(doc["id"]))

    report = await load_rule_pack(db_session, root=tmp_path)
    # Every v2 rule should insert cleanly on a first run; none should
    # be skipped due to compile errors / bad UUIDs / etc.
    assert report.skipped == 0, f"loader skipped rules: {report.errors}"
    assert report.inserted == len(_V2_RULE_PATHS), (
        f"expected {len(_V2_RULE_PATHS)} inserts, got {report.inserted}"
    )

    # Scope the Rule query by the v2 rules' own UUIDs so leftover rows
    # in the shared dev DB (the v1 curated pack, prior test runs) can't
    # flip the assertion.
    from uuid import UUID

    rule_uuids = [UUID(rid) for rid in expected_ids]
    stmt = select(Rule).where(Rule.id.in_(rule_uuids))
    rows = (await db_session.execute(stmt)).scalars().all()
    assert len(rows) == len(_V2_RULE_PATHS), (
        f"expected {len(_V2_RULE_PATHS)} Rule rows, got {len(rows)}"
    )
    # The `curated_v1` marker must appear on every row — that's how
    # the operator UI filters curated rules from operator-authored
    # ones, and how this PR's content stays distinguishable from any
    # later pack revision.
    for row in rows:
        assert (row.description or "").rstrip().endswith(f"[{CURATED_TAG}]"), (
            f"rule {row.id} ({row.name}) missing [{CURATED_TAG}] tag in description: "
            f"{row.description!r}"
        )
