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

from app.core.config import settings
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
from app.services.alert_dedup import bump_occurrence, dedup_key_for, find_open_dupe
from app.services.host_cache import resolve_alert_tenant_id

log = structlog.get_logger()


@dataclass
class IocSnapshot:
    """O(1)-lookup tables of enabled IOC entries.

    Each map: normalized value -> (rule_id, rule_name, severity, action, mitre_techniques).
    """

    by_sha256: dict[str, tuple[UUID, str, Severity, RuleAction, tuple[str, ...] | None]] = field(
        default_factory=dict
    )
    by_md5: dict[str, tuple[UUID, str, Severity, RuleAction, tuple[str, ...] | None]] = field(
        default_factory=dict
    )
    by_sha1: dict[str, tuple[UUID, str, Severity, RuleAction, tuple[str, ...] | None]] = field(
        default_factory=dict
    )
    by_filename: dict[str, tuple[UUID, str, Severity, RuleAction, tuple[str, ...] | None]] = field(
        default_factory=dict
    )
    by_filepath: dict[str, tuple[UUID, str, Severity, RuleAction, tuple[str, ...] | None]] = field(
        default_factory=dict
    )

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
            techniques: tuple[str, ...] | None = (
                tuple(r.mitre_techniques) if r.mitre_techniques else None
            )
            tup = (r.id, r.name, r.severity, effective, techniques)
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
    # Phase 1 #1.8: MITRE ATT&CK technique IDs snapshotted from the rule.
    mitre_techniques: tuple[str, ...] | None = None


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
                rid, name, sev, act, techniques = table[v]
                hits.append(
                    Match(
                        rid,
                        name,
                        sev,
                        act,
                        f"{src_label} hash {algo} matches IOC",
                        f"{src_label}.hash.{algo}",
                        v,
                        techniques,
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
            rid, name, sev, act, techniques = snap.by_filename[bn]
            hits.append(
                Match(
                    rid,
                    name,
                    sev,
                    act,
                    f"{src_label} basename matches IOC",
                    "name",
                    bn,
                    techniques,
                )
            )
        if np and np in snap.by_filepath:
            rid, name, sev, act, techniques = snap.by_filepath[np]
            hits.append(
                Match(
                    rid,
                    name,
                    sev,
                    act,
                    f"{src_label} path matches IOC",
                    "path",
                    np,
                    techniques,
                )
            )

    return hits


async def emit_alerts(
    db: AsyncSession,
    *,
    host_id: UUID,
    matches: list[Match],
    ecs: dict[str, Any],
) -> list[tuple[UUID, bool]]:
    """Insert one alerts row per match unless a recent open alert with
    the same dedup key already exists — in which case bump its
    occurrence_count instead (Phase 1 #1.10).

    Returns one (alert_id, created) tuple per match, in order. `created`
    is True for freshly-inserted rows and False for dedup-bumped rows;
    the caller uses it to decide whether to index an alerts-* doc into
    OpenSearch and whether to fire a response action (deduped rows
    don't re-queue commands — the original command from the first
    detonation is already pending or done).

    If the matched rule's action is kill or block, also queue a Command
    row so the agent enforces it (M5.5 auto-trigger). Caller must await
    db.commit().
    """
    from app.services.response import queue_command_for_match

    # CODE-25: stamp tenant_id from the originating host so a cross-
    # tenant event doesn't land on DEFAULT_TENANT_ID via the column
    # default. Helper prefers ECS tenant.id (the normalizer stamps
    # it) and falls back to db.get(Host) so test sessions see the
    # uncommitted host.
    host_tenant_id = await resolve_alert_tenant_id(
        db,
        host_id=host_id,
        ecs_tenant_id=(ecs.get("tenant") or {}).get("id"),
    )
    if host_tenant_id is None:
        log.warning("detector.tenant_lookup_miss", host_id=str(host_id))
        return []

    now = datetime.now(UTC)
    out: list[tuple[UUID, bool]] = []
    for m in matches:
        dkey = dedup_key_for(m.rule_id, host_id, ecs)
        existing = await find_open_dupe(
            db,
            dedup_key=dkey,
            window_seconds=settings.alert_dedup_window_s,
            now=now,
        )
        if existing is not None:
            bump_occurrence(existing, now=now)
            await db.flush()
            log.info(
                "detector.alert_deduped",
                alert_id=str(existing.id),
                rule_id=str(m.rule_id),
                occurrence_count=existing.occurrence_count,
            )
            out.append((existing.id, False))
            continue

        alert = Alert(
            tenant_id=host_tenant_id,
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
            dedup_key=dkey,
            last_occurred_at=now,
            # Phase 1 #1.8: snapshot the rule's ATT&CK tags so later
            # rule edits don't rewrite alert history.
            mitre_techniques=list(m.mitre_techniques) if m.mitre_techniques else None,
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
        out.append((alert.id, True))
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
