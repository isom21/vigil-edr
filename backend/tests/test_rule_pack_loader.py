"""Curated rule-pack loader behaviour (Phase 1 #1.14).

Pins the three invariants the operator and the rule-author both rely on:

  1. Idempotency. Running the loader twice against an unchanged tree
     inserts every rule once and updates none.
  2. Hand-edit propagation. When a YAML body changes between runs, the
     existing row updates in place and `revision` bumps by exactly one.
  3. Operator-override preservation. When the loader runs over a rule
     whose `enabled` / `action` / `severity` an operator has dialled
     down via the UI, the next load MUST NOT clobber those values
     even if the on-disk YAML still says otherwise.
  4. Bad-YAML resilience. The pack ships as content — one bad file
     must not abort the load. The loader logs a warning and continues.

Tests use a tmp_path-backed rule directory rather than the real
`backend/sigma_rules/` tree so they don't get coupled to the curated
pack's contents (which evolve PR by PR).
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import select

from app.models import Rule, RuleAction, Severity
from app.services.rule_pack import (
    CURATED_TAG,
    _extract_mitre_techniques,
    _hash_body,
    load_rule_pack,
)

# Per-test UUIDs are generated via `_test_uuid()` so the test rows don't
# collide with whatever rows happen to already exist in the shared dev DB
# (the curated pack itself, leftovers from previous unrelated runs, etc.).
# The fixture below sets them once per test.


_RULE_A_TEMPLATE = """
title: Test rule A
id: {id_a}
status: experimental
description: First test rule
references:
  - https://example.com/a
author: test
date: 2026-05-13
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process.name|endswith: 'powershell.exe'
    process.command_line|contains: '-enc'
  condition: selection
level: high
""".lstrip()

_RULE_B_TEMPLATE = """
title: Test rule B
id: {id_b}
status: experimental
description: Second test rule
references:
  - https://example.com/b
author: test
date: 2026-05-13
tags:
  - attack.persistence
  - attack.t1547.001
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    registry.path|contains: '\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\'
  condition: selection
level: medium
""".lstrip()

# Same id as RULE_A but a different (tightened) detection — modelling a
# real hand-edit between two manager restarts.
_RULE_A_EDITED_TEMPLATE = """
title: Test rule A
id: {id_a}
status: experimental
description: First test rule, tightened
references:
  - https://example.com/a
author: test
date: 2026-05-13
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process.name|endswith: 'powershell.exe'
    process.command_line|contains:
      - '-enc'
      - '-EncodedCommand'
  condition: selection
level: high
""".lstrip()


@pytest.fixture
def rule_ids() -> tuple[UUID, UUID]:
    """Per-test rule UUIDs, fresh each invocation.

    Tests scope their assertions to rows with these IDs so unrelated
    rows in the shared dev DB (the curated pack, leftovers) can't
    flip the result. The SAVEPOINT in `db_session` rolls back at
    teardown, but anything committed outside the savepoint persists,
    so we can't rely on `SELECT *`.
    """
    from uuid import uuid4

    return uuid4(), uuid4()


def _rule_a(rule_ids: tuple[UUID, UUID]) -> str:
    return _RULE_A_TEMPLATE.format(id_a=rule_ids[0])


def _rule_b(rule_ids: tuple[UUID, UUID]) -> str:
    return _RULE_B_TEMPLATE.format(id_b=rule_ids[1])


def _rule_a_edited(rule_ids: tuple[UUID, UUID]) -> str:
    return _RULE_A_EDITED_TEMPLATE.format(id_a=rule_ids[0])


def _seed_pack(root: Path, rule_ids: tuple[UUID, UUID]) -> None:
    """Write the two-rule fixture into a tmp directory."""
    (root / "execution").mkdir(parents=True, exist_ok=True)
    (root / "persistence").mkdir(parents=True, exist_ok=True)
    (root / "execution" / "rule_a.yml").write_text(_rule_a(rule_ids))
    (root / "persistence" / "rule_b.yml").write_text(_rule_b(rule_ids))


def test_extract_mitre_techniques_filters_and_normalises() -> None:
    """Sanity: technique extraction picks only `attack.t<digit>...` tags,
    upper-cases them, and dedupes. Tactic-only tags
    (`attack.execution`) are not technique IDs and must be dropped."""
    techniques = _extract_mitre_techniques(
        [
            "attack.execution",
            "attack.t1059.001",
            "attack.persistence",
            "attack.T1547.001",  # mixed case
            "attack.t1059.001",  # duplicate
            "not.an.attack.tag",
            42,  # type: ignore[list-item]  # exercises non-str path
        ]
    )
    assert techniques == ["T1059.001", "T1547.001"]


@pytest.mark.asyncio
async def test_load_rule_pack_inserts_then_is_idempotent(db_session, tmp_path, rule_ids) -> None:
    """Two back-to-back runs against an unchanged tree: 2 inserted on
    pass 1, 0 inserted + 2 unchanged on pass 2. No phantom updates."""
    _seed_pack(tmp_path, rule_ids)
    id_a, id_b = rule_ids

    report1 = await load_rule_pack(db_session, root=tmp_path)
    assert report1.inserted == 2
    assert report1.updated == 0
    assert report1.unchanged == 0
    assert report1.skipped == 0

    # Confirm both rows landed with the curated tag in description.
    # Filter by the per-test IDs so pre-existing dev-DB rows can't
    # flip the count.
    stmt = select(Rule).where(Rule.id.in_([id_a, id_b])).order_by(Rule.name)
    rows = (await db_session.execute(stmt)).scalars().all()
    assert len(rows) == 2
    assert all((r.description or "").endswith(f"[{CURATED_TAG}]") for r in rows)
    # Body is stored verbatim.
    by_id = {r.id: r for r in rows}
    assert by_id[id_a].body == _rule_a(rule_ids)
    assert by_id[id_b].body == _rule_b(rule_ids)
    # Severity from YAML `level` field maps correctly.
    assert by_id[id_a].severity is Severity.HIGH
    assert by_id[id_b].severity is Severity.MEDIUM
    # MITRE techniques extracted from `tags:` if the column exists.
    if hasattr(Rule, "mitre_techniques"):
        assert by_id[id_a].mitre_techniques == ["T1059.001"]

    report2 = await load_rule_pack(db_session, root=tmp_path)
    assert report2.inserted == 0
    assert report2.updated == 0
    assert report2.unchanged == 2
    # Revision did NOT bump on the idempotent re-run.
    rows_after = (await db_session.execute(stmt)).scalars().all()
    assert all(r.revision == 1 for r in rows_after)


@pytest.mark.asyncio
async def test_load_rule_pack_updates_on_body_change(db_session, tmp_path, rule_ids) -> None:
    """Hand-edit between runs: existing row updates in place, revision
    bumps by exactly one, body + sigma_compiled refresh."""
    _seed_pack(tmp_path, rule_ids)
    id_a, _ = rule_ids
    await load_rule_pack(db_session, root=tmp_path)

    # Swap rule A for the tightened version.
    edited = _rule_a_edited(rule_ids)
    (tmp_path / "execution" / "rule_a.yml").write_text(edited)
    report = await load_rule_pack(db_session, root=tmp_path)
    assert report.updated == 1
    assert report.unchanged == 1  # rule B was untouched
    assert report.inserted == 0

    rule_a = await db_session.get(Rule, id_a)
    assert rule_a is not None
    assert rule_a.revision == 2
    assert _hash_body(rule_a.body or "") == _hash_body(edited)
    # The new tightened query must contain the extra contains-clause
    # so we know the compile re-ran rather than reusing the cached one.
    assert "EncodedCommand" in (rule_a.sigma_compiled or "")


@pytest.mark.asyncio
async def test_load_rule_pack_preserves_operator_overrides(db_session, tmp_path, rule_ids) -> None:
    """Operator dials a rule's `enabled` off and `action` down; loader
    refreshes content on body change but leaves those operator-set
    columns alone. This is the safety property that lets us re-run
    the loader at every boot without trampling tuning work."""
    _seed_pack(tmp_path, rule_ids)
    id_a, _ = rule_ids
    await load_rule_pack(db_session, root=tmp_path)

    rule_a = await db_session.get(Rule, id_a)
    assert rule_a is not None
    # Operator-style override: dial down and disable.
    rule_a.enabled = False
    rule_a.action = RuleAction.BLOCK  # bump up to BLOCK to prove the loader doesn't reset to ALERT
    rule_a.severity = Severity.LOW
    await db_session.flush()

    # Now publish a hand-edit so the loader takes the update path.
    edited = _rule_a_edited(rule_ids)
    (tmp_path / "execution" / "rule_a.yml").write_text(edited)
    await load_rule_pack(db_session, root=tmp_path)

    refreshed = await db_session.get(Rule, id_a)
    assert refreshed is not None
    # Content fields updated…
    assert refreshed.revision == 2
    assert refreshed.body == edited
    # …but operator overrides are intact.
    assert refreshed.enabled is False, "loader trampled operator-set enabled=False"
    assert refreshed.action is RuleAction.BLOCK, "loader trampled operator-set action override"
    assert refreshed.severity is Severity.LOW, "loader trampled operator-set severity override"


@pytest.mark.asyncio
async def test_load_rule_pack_skips_invalid_yaml(db_session, tmp_path, rule_ids) -> None:
    """One bad YAML in the pack must not abort the load. The bad file
    counts toward `skipped` with a descriptive `errors` entry; the
    good files in the same directory still get inserted."""
    _seed_pack(tmp_path, rule_ids)
    id_a, id_b = rule_ids
    # Add a malformed rule alongside the good ones.
    (tmp_path / "execution" / "broken.yml").write_text(
        "title: nope\n"
        "id: not-a-uuid\n"
        "logsource:\n"
        "  product: windows\n"
        "  category: process_creation\n"
        "detection:\n"
        "  selection:\n"
        "    process.name: x\n"
        "  condition: selection\n"
    )
    # And a totally-malformed file (YAML parse error).
    (tmp_path / "execution" / "junk.yml").write_text(
        "this is: not valid yaml\n  - bad indent: x\n -wrong\n"
    )
    # And a Sigma-compile-error file (valid YAML, valid UUID, but
    # missing logsource so the backend can't produce a query).
    from uuid import uuid4

    (tmp_path / "execution" / "no_logsource.yml").write_text(
        f"title: missing logsource\n"
        f"id: {uuid4()}\n"
        f"detection:\n"
        f"  selection:\n"
        f"    process.name: x\n"
        f"  condition: selection\n"
    )

    report = await load_rule_pack(db_session, root=tmp_path)
    assert report.inserted == 2, "good rules must still land despite bad neighbours"
    assert report.skipped >= 2
    # Errors list captures the path + reason so operators can fix the file.
    error_messages = " ".join(msg for _, msg in report.errors)
    assert "invalid uuid" in error_messages or "compile failed" in error_messages
    # The good rules are queryable (scope to our per-test IDs).
    count = len(
        (await db_session.execute(select(Rule).where(Rule.id.in_([id_a, id_b])))).scalars().all()
    )
    assert count == 2


@pytest.mark.asyncio
async def test_load_rule_pack_handles_missing_root(db_session, tmp_path) -> None:
    """Pointed at a non-existent directory: empty report, no exception."""
    missing = tmp_path / "does_not_exist"
    report = await load_rule_pack(db_session, root=missing)
    assert report.total_seen == 0
    assert report.inserted == 0
    assert report.errors == []


@pytest.mark.asyncio
async def test_load_rule_pack_writes_audit_rows(db_session, tmp_path, rule_ids) -> None:
    """Every insert and update writes an audit_log row via the system
    actor (no `actor` arg). This is what makes the rule pack visible
    in the audit verifier's view of the chain."""
    from app.models import AuditLog

    _seed_pack(tmp_path, rule_ids)
    id_a, id_b = rule_ids
    await load_rule_pack(db_session, root=tmp_path)
    # Scope to the audit rows that name our two test rules so leftover
    # rows from prior runs can't inflate the count.
    create_actions = (
        (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.action == "rule.create")
                .where(AuditLog.resource_id.in_([str(id_a), str(id_b)]))
            )
        )
        .scalars()
        .all()
    )
    assert len(create_actions) == 2
    # System actor — no user_id / api_token_id.
    for row in create_actions:
        assert row.user_id is None
        assert row.api_token_id is None
        assert row.actor_kind == "system"
        # Payload should include the curated tag so the audit log makes
        # the source of the rule unambiguous.
        assert row.payload is not None
        assert row.payload.get("source") == "rule_pack"
        assert row.payload.get("tag") == CURATED_TAG
