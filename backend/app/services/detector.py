"""In-process IOC detector.

For M2 we keep this simple: load all enabled IOC rules into memory at
startup, refresh periodically, and match each ingested event against
filename / filepath / sha256 lookups.

Sigma/YARA streaming detection lands in M3.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
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
    IocEntry,
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
    async def load(cls, db: AsyncSession) -> "IocSnapshot":
        snap = cls()
        stmt = (
            select(Rule)
            .where(Rule.kind == RuleKind.IOC, Rule.enabled.is_(True))
            .options(selectinload(Rule.iocs))
        )
        rows = (await db.execute(stmt)).scalars().all()
        for r in rows:
            tup = (r.id, r.name, r.severity, r.action)
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
    """Insert one alerts row per match. Caller must await db.commit()."""
    out: list[UUID] = []
    for m in matches:
        alert = Alert(
            host_id=host_id,
            rule_id=m.rule_id,
            severity=m.severity,
            action_taken=RuleAction.DETECT,  # M2 is detect-only
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
        out.append(alert.id)
    return out


class DetectorState:
    """Holds the cached IOC snapshot and refreshes it periodically."""

    REFRESH_SECONDS = 30

    def __init__(self) -> None:
        self.snapshot = IocSnapshot()
        self._last_load: datetime | None = None

    async def get(self) -> IocSnapshot:
        now = datetime.now(timezone.utc)
        if (
            self._last_load is None
            or (now - self._last_load) > timedelta(seconds=self.REFRESH_SECONDS)
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
