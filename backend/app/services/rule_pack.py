"""Curated Sigma rule-pack loader (Phase 1 #1.14).

`load_rule_pack()` walks `backend/sigma_rules/` at boot and reflects the
on-disk pack into the `rules` table. The pack is idempotent — re-running
the loader on an unchanged tree is a no-op, and re-running on a tree
whose YAML body changed updates the existing row and bumps `revision`.

Idempotency keys off `sha256(yaml_body)` rather than the rule's Sigma
UUID alone, so a hand-edit to a rule (tighten a filter, add a tag)
flows through to running agents on the next manager restart without
needing a manual `revision++` from the rule author. The hash is
recomputed from the existing row's `body` on every load — no extra
state lives in the DB.

Operator overrides on `enabled` / `action` / `severity` are preserved:
the loader writes the *initial* values when a rule is first inserted,
and on subsequent updates only refreshes content fields (`name`,
`description`, `body`, `sigma_compiled`, `mitre_techniques`, `revision`).
That means an operator can dial `block` down to `alert` in the UI and
the next manager restart won't undo it.

Failure modes:

  * Unreadable file / YAML parse error / Sigma compile error: log a
    warning and skip. The pack ships as content, not infrastructure —
    one bad rule must not block manager boot.
  * Database error mid-load: propagates. The operator wants to know
    if the DB is unreachable; that's not a content problem.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

import structlog
import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Rule, RuleAction, RuleKind, Severity
from app.services import audit
from app.services.sigma import SigmaCompileError, compile_yaml

log = structlog.get_logger()


# Tag identifying every rule shipped via this loader. Stored verbatim
# in `Rule.description` so operators can filter on it in the UI and
# distinguish curated rules from rules they authored themselves.
CURATED_TAG = "curated_v1"


@dataclass
class RulePackReport:
    """Summary of a load run. Returned for logging + smoke tests."""

    inserted: int = 0
    updated: int = 0
    unchanged: int = 0
    skipped: int = 0
    errors: list[tuple[str, str]] = field(default_factory=list)

    @property
    def total_seen(self) -> int:
        return self.inserted + self.updated + self.unchanged + self.skipped


# Map Sigma's lower-case `level:` field to the project's Severity enum.
_LEVEL_TO_SEVERITY: dict[str, Severity] = {
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def _extract_mitre_techniques(tags: list[str]) -> list[str]:
    """Pick MITRE technique IDs out of Sigma's `tags:` block.

    Sigma convention is `attack.<tactic>` (e.g. `attack.execution`) and
    `attack.<technique_id>` (e.g. `attack.t1059.001`). We treat the
    second form as our source of truth and normalise to upper-case so
    queries against `Rule.mitre_techniques` are case-stable.
    """
    out: list[str] = []
    seen: set[str] = set()
    for tag in tags:
        if not isinstance(tag, str):
            continue
        s = tag.strip().lower()
        if not s.startswith("attack."):
            continue
        rest = s.removeprefix("attack.")
        # Tactic names are alphabetic; technique IDs start with `t<digit>`.
        if not rest.startswith("t") or len(rest) < 2 or not rest[1].isdigit():
            continue
        norm = rest.upper()
        if norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    return out


def _parse_rule_metadata(body: str) -> dict | None:
    """Re-parse the YAML body for fields the Sigma compiler doesn't expose.

    `compile_yaml()` returns title / description / rule_id but not the
    `id:`, `tags:` or `level:` we need to populate Rule rows. We parse
    once with PyYAML's safe loader to avoid pulling in pySigma's
    `SigmaRule` model just for metadata extraction.
    """
    try:
        doc = yaml.safe_load(body)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict):
        return None
    return doc


def _hash_body(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _format_description(sigma_description: str | None) -> str:
    """Compose the human description stored on the Rule row.

    Format: `<sigma description>\n\n[curated_v1]`. The trailing tag
    is the operator-visible marker the spec calls for and is the same
    string an operator would type into the UI search filter to scope
    to curated rules.
    """
    desc = (sigma_description or "").strip()
    if desc:
        return f"{desc}\n\n[{CURATED_TAG}]"
    return f"[{CURATED_TAG}]"


async def load_rule_pack(
    db: AsyncSession,
    root: str | Path = "backend/sigma_rules",
) -> RulePackReport:
    """Sync the on-disk rule library into the database.

    Idempotent: re-running with an unchanged tree is a no-op; re-running
    after a YAML edit bumps the existing row's `revision`. Operator
    overrides on `enabled`/`action`/`severity` survive updates.

    Parse / compile errors are logged and skipped — the rule pack is
    content, not infrastructure, and one bad file must not stop boot.
    """
    report = RulePackReport()
    root_path = Path(root)
    if not root_path.is_dir():
        log.warning("rule_pack.root_missing", root=str(root_path))
        return report

    # Pre-load all sigma rules in one query so we don't issue
    # `SELECT` per file on a 25-rule pack. The id field is the Sigma
    # YAML id (stable across commits), which is also the DB primary
    # key, so this is a single keyed lookup per file at this point.
    existing: dict[UUID, Rule] = {}
    for r in (await db.execute(select(Rule).where(Rule.kind == RuleKind.SIGMA))).scalars().all():
        existing[r.id] = r

    for path in sorted(root_path.rglob("*.yml")):
        try:
            body = path.read_text(encoding="utf-8")
        except OSError as exc:
            report.skipped += 1
            report.errors.append((str(path), f"read failed: {exc}"))
            log.warning("rule_pack.read_failed", path=str(path), error=str(exc))
            continue

        meta = _parse_rule_metadata(body)
        if meta is None or "id" not in meta or "title" not in meta:
            report.skipped += 1
            report.errors.append((str(path), "missing id or title"))
            log.warning("rule_pack.invalid_metadata", path=str(path))
            continue

        try:
            rule_uuid = UUID(str(meta["id"]))
        except (ValueError, TypeError):
            report.skipped += 1
            report.errors.append((str(path), f"invalid uuid: {meta.get('id')!r}"))
            log.warning("rule_pack.invalid_uuid", path=str(path), value=meta.get("id"))
            continue

        try:
            compiled = compile_yaml(body)
        except SigmaCompileError as exc:
            report.skipped += 1
            report.errors.append((str(path), f"compile failed: {exc}"))
            log.warning("rule_pack.compile_failed", path=str(path), error=str(exc))
            continue

        body_hash = _hash_body(body)
        tags = meta.get("tags") or []
        if not isinstance(tags, list):
            tags = []
        techniques = _extract_mitre_techniques(tags)
        level_raw = str(meta.get("level") or "").strip().lower()
        severity = _LEVEL_TO_SEVERITY.get(level_raw, Severity.MEDIUM)
        title = str(meta["title"]).strip()
        description = _format_description(compiled.description)
        rel_path = str(path.relative_to(root_path))

        existing_rule = existing.get(rule_uuid)
        if existing_rule is None:
            rule = Rule(
                id=rule_uuid,
                kind=RuleKind.SIGMA,
                name=title,
                description=description,
                severity=severity,
                action=RuleAction.ALERT,
                enabled=True,
                body=body,
                sigma_compiled=compiled.query,
                revision=1,
            )
            if hasattr(Rule, "mitre_techniques"):
                rule.mitre_techniques = techniques or None  # pyright: ignore[reportAttributeAccessIssue]
            db.add(rule)
            await db.flush()
            await audit.record(
                db,
                actor=None,
                action="rule.create",
                resource_type="rule",
                resource_id=str(rule.id),
                payload={
                    "source": "rule_pack",
                    "tag": CURATED_TAG,
                    "name": rule.name,
                    "mitre_techniques": techniques or None,
                    "path": rel_path,
                },
            )
            report.inserted += 1
            log.info(
                "rule_pack.inserted",
                rule_id=str(rule.id),
                name=rule.name,
                path=rel_path,
            )
            continue

        # Existing row — only update if the on-disk body changed.
        # Compare against the hash of the stored body so we don't need
        # any extra schema state to remember "what did the loader last
        # write".
        prev_body = existing_rule.body or ""
        if _hash_body(prev_body) == body_hash:
            report.unchanged += 1
            continue

        # Body changed. Refresh content fields but DO NOT touch operator
        # overrides on enabled / action / severity. The severity from the
        # YAML level: is intentionally skipped on update — once an
        # operator dials a rule down, redownloading the pack must not
        # undo that.
        existing_rule.name = title
        existing_rule.description = description
        existing_rule.body = body
        existing_rule.sigma_compiled = compiled.query
        existing_rule.revision += 1
        if hasattr(Rule, "mitre_techniques"):
            existing_rule.mitre_techniques = techniques or None  # pyright: ignore[reportAttributeAccessIssue]
        await db.flush()
        await audit.record(
            db,
            actor=None,
            action="rule.update",
            resource_type="rule",
            resource_id=str(existing_rule.id),
            payload={
                "source": "rule_pack",
                "tag": CURATED_TAG,
                "revision": existing_rule.revision,
                "name": existing_rule.name,
                "mitre_techniques": techniques or None,
                "path": rel_path,
            },
        )
        report.updated += 1
        log.info(
            "rule_pack.updated",
            rule_id=str(existing_rule.id),
            name=existing_rule.name,
            revision=existing_rule.revision,
            path=rel_path,
        )

    # Don't commit here — the caller owns the transaction. The boot hook
    # in `load_rule_pack_at_boot` runs us inside `async with SessionLocal()`
    # and commits on exit; tests run us inside a SAVEPOINT that rolls
    # back on teardown.
    log.info(
        "rule_pack.load_complete",
        inserted=report.inserted,
        updated=report.updated,
        unchanged=report.unchanged,
        skipped=report.skipped,
        total_seen=report.total_seen,
        root=str(root_path),
    )
    return report


def _resolve_default_root() -> Path:
    """Locate the bundled rule pack relative to this module.

    Returns `<backend>/sigma_rules`. The path is computed off
    `__file__` (not cwd) so the loader works regardless of where the
    manager process was launched from.
    """
    return Path(__file__).resolve().parents[2] / "sigma_rules"


async def load_rule_pack_at_boot() -> RulePackReport | None:
    """Boot hook: open a session, run the loader, log a summary.

    Opt out by setting `VIGIL_RULE_PACK_LOAD_ON_BOOT=0`. Errors here
    log and return None — the manager must boot even when the rule
    pack can't load (e.g. corrupted YAML, OS error). Audit-chain
    `rule.create` / `rule.update` rows are written for each inserted
    or updated rule via the system actor.
    """
    if os.environ.get("VIGIL_RULE_PACK_LOAD_ON_BOOT", "1") == "0":
        log.info("rule_pack.load_disabled")
        return None
    from app.core.db import SessionLocal

    root = _resolve_default_root()
    try:
        async with SessionLocal() as db:
            report = await load_rule_pack(db, root=root)
            await db.commit()
            return report
    except Exception as exc:  # noqa: BLE001
        # We deliberately swallow here — the alternative is refusing
        # to boot the manager because one rule was malformed, and
        # the pack is content, not infrastructure.
        log.warning("rule_pack.load_failed", error=str(exc), root=str(root))
        return None
