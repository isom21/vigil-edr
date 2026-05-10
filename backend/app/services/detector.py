"""In-process IOC detector.

For M2 we keep this simple: load all enabled IOC rules into memory at
startup, refresh periodically, and match each ingested event against
filename / filepath / sha256 lookups.

Sigma/YARA streaming detection lands in M3.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.db import SessionLocal
from app.models import (
    Alert,
    AlertState,
    AlertStateHistory,
    IocKind,
    Rule,
    RuleAction,
    RuleKind,
    Severity,
)

log = structlog.get_logger()


@dataclass
class IocSnapshot:
    """O(1)-lookup tables of enabled IOC entries.

    Each map: normalized value -> (rule_id, rule_name, severity, action).
    """

    by_sha256: dict[str, tuple[UUID, str, Severity, RuleAction]] = field(default_factory=dict)
    by_md5: dict[str, tuple[UUID, str, Severity, RuleAction]] = field(default_factory=dict)
    by_sha1: dict[str, tuple[UUID, str, Severity, RuleAction]] = field(default_factory=dict)
    by_filename: dict[str, tuple[UUID, str, Severity, RuleAction]] = field(default_factory=dict)
    by_filepath: dict[str, tuple[UUID, str, Severity, RuleAction]] = field(default_factory=dict)

    @classmethod
    async def load(cls, db: AsyncSession) -> IocSnapshot:
        from app.models import RuleGroup, clamp_action

        snap = cls()
        stmt = (
            select(Rule)
            .where(Rule.kind == RuleKind.IOC, Rule.enabled.is_(True))
            .options(selectinload(Rule.iocs))
        )
        rows = (await db.execute(stmt)).scalars().all()

        # Pre-load every referenced RuleGroup once so clamp_action
        # doesn't issue a query per rule.
        group_ids = {r.group_id for r in rows if r.group_id is not None}
        groups: dict[UUID, RuleGroup] = {}
        if group_ids:
            grp_rows = (
                (await db.execute(select(RuleGroup).where(RuleGroup.id.in_(group_ids))))
                .scalars()
                .all()
            )
            groups = {g.id: g for g in grp_rows}

        for r in rows:
            ceiling = (
                groups[r.group_id].max_action
                if r.group_id is not None and r.group_id in groups
                else None
            )
            effective = clamp_action(r.action, ceiling)
            tup = (r.id, r.name, r.severity, effective)
            for entry in r.iocs:
                target = {
                    IocKind.HASH_SHA256: snap.by_sha256,
                    IocKind.HASH_MD5: snap.by_md5,
                    IocKind.HASH_SHA1: snap.by_sha1,
                    IocKind.FILENAME: snap.by_filename,
                    IocKind.FILEPATH: snap.by_filepath,
                }[entry.kind]
                target[entry.value_normalized] = tup
        return snap


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return os.path.basename(path.replace("\\", "/")).lower()


def _norm_path(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("\\", "/").lower()


@dataclass
class Match:
    rule_id: UUID
    rule_name: str
    severity: Severity
    action: RuleAction
    summary: str
    matched_field: str
    matched_value: str


def evaluate(ecs: dict[str, Any], snap: IocSnapshot) -> list[Match]:
    """Return all IOC matches for one ECS event document."""
    hits: list[Match] = []

    process = ecs.get("process") or {}
    file_ = ecs.get("file") or {}

    # Hash matches (process executable hash or file hash).
    for src_label, src in (("process", process), ("file", file_)):
        h = src.get("hash") or {}
        for algo, table in (
            ("sha256", snap.by_sha256),
            ("md5", snap.by_md5),
            ("sha1", snap.by_sha1),
        ):
            v = (h.get(algo) or "").lower()
            if v and v in table:
                rid, name, sev, act = table[v]
                hits.append(
                    Match(
                        rid,
                        name,
                        sev,
                        act,
                        f"{src_label} hash {algo} matches IOC",
                        f"{src_label}.hash.{algo}",
                        v,
                    )
                )

    # Filename + filepath matches against process executable + file path.
    for src_label, src in (("process", process), ("file", file_)):
        path = src.get("executable") or src.get("path")
        if not path:
            continue
        bn = _basename(path)
        np = _norm_path(path)
        if bn and bn in snap.by_filename:
            rid, name, sev, act = snap.by_filename[bn]
            hits.append(Match(rid, name, sev, act, f"{src_label} basename matches IOC", "name", bn))
        if np and np in snap.by_filepath:
            rid, name, sev, act = snap.by_filepath[np]
            hits.append(Match(rid, name, sev, act, f"{src_label} path matches IOC", "path", np))

    return hits


async def emit_alerts(
    db: AsyncSession,
    *,
    host_id: UUID,
    matches: list[Match],
    ecs: dict[str, Any],
) -> list[UUID]:
    """Insert one alerts row per match. If the matched rule's action is
    kill or block, also queue a Command row so the agent enforces it
    (M5.5 auto-trigger). Caller must await db.commit().
    """
    from app.services.response import queue_command_for_match

    out: list[UUID] = []
    for m in matches:
        alert = Alert(
            host_id=host_id,
            rule_id=m.rule_id,
            severity=m.severity,
            action_taken=m.action,
            state=AlertState.NEW,
            summary=m.summary,
            details={
                "rule_name": m.rule_name,
                "matched_field": m.matched_field,
                "matched_value": m.matched_value,
                "event_id": ecs.get("event", {}).get("id"),
            },
        )
        alert.history.append(
            AlertStateHistory(
                from_state=None,
                to_state=AlertState.NEW,
                comment="auto-generated by IOC detector",
            )
        )
        db.add(alert)
        await db.flush()
        await queue_command_for_match(
            db,
            host_id=host_id,
            rule_id=m.rule_id,
            rule_action=m.action,
            alert_id=alert.id,
            ecs=ecs,
        )
        out.append(alert.id)
    return out


class DetectorState:
    """Holds the cached IOC snapshot and refreshes it periodically."""

    REFRESH_SECONDS = 30

    def __init__(self) -> None:
        self.snapshot = IocSnapshot()
        self._last_load: datetime | None = None

    async def get(self) -> IocSnapshot:
        now = datetime.now(UTC)
        if self._last_load is None or (now - self._last_load) > timedelta(
            seconds=self.REFRESH_SECONDS
        ):
            async with SessionLocal() as db:
                self.snapshot = await IocSnapshot.load(db)
            self._last_load = now
            log.info(
                "detector.snapshot_loaded",
                sha256=len(self.snapshot.by_sha256),
                filename=len(self.snapshot.by_filename),
                filepath=len(self.snapshot.by_filepath),
            )
        return self.snapshot
