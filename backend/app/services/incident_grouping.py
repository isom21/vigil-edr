"""Phase 1 #1.11 — incident grouping; Phase 2 #2.13 — tree refinement.

Groups recently-opened alerts into Incident rows so analysts triage
chains, not individual events. v1 rule: same `host_id`, alert
`opened_at` inside a sliding window (default `VIGIL_INCIDENT_WINDOW_S`
= 600 s), any rule kind.

The algorithm is intentionally simple:

  1. Pick up alerts opened in the last `2 * window_s` that don't yet
     have an `incident_id` AND have a real `host_id` (synthetic
     null-host alerts don't group in v1).
  2. Bucket them by host_id, ordered by opened_at ascending.
  3. Walk each bucket: if the previous alert was within `window_s`
     and already has an incident, attach this one to it; otherwise
     open a new incident for the alert (and any subsequent alerts in
     the same window).

The lookback (`2 * window_s`) is a safety margin — if a new alert
arrives slightly before the worker's next tick, the existing incident
boundary is still findable.

`regroup_recent` is idempotent: rows that already have an
`incident_id` are skipped. Severity / `closed_at` on the incident are
not updated by this pass — the incident is what the analyst sees and
the worker shouldn't reshape it underneath them once it exists.

Phase 2 #2.13 adds a post-pass that re-labels window-grouped incidents
as `process_tree` when 2+ attached alerts trace back to a shared
process ancestor on the same host. The label is informational — the
underlying alert→incident mapping is not changed.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Alert,
    Incident,
    IncidentGroupingReason,
    IncidentStatus,
    Rule,
    Severity,
)

# Cap how far we'll walk parent_pid links so a broken / circular chain
# can't loop forever. Real process trees on a typical endpoint are
# nowhere near this deep.
_TREE_DEPTH_LIMIT = 32

log = structlog.get_logger()

# Severity ranking — higher wins. Used to set the incident's severity
# to the max of its grouped alerts at creation time.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _max_severity(a: Severity, b: Severity) -> Severity:
    return a if _SEVERITY_RANK[a] >= _SEVERITY_RANK[b] else b


async def regroup_recent(db: AsyncSession, window_s: int) -> int:
    """Group recently-opened, ungrouped alerts. Returns the number of
    alerts attached to (existing or new) incidents this pass.

    Caller owns the transaction — this function flushes but does not
    commit, so tests can run it under SAVEPOINT isolation.
    """
    if window_s <= 0:
        return 0
    window = timedelta(seconds=window_s)
    lookback = timedelta(seconds=window_s * 2)
    cutoff = datetime.now(UTC) - lookback

    # Ungrouped alerts in the window, with a real host_id.
    stmt = (
        select(Alert)
        .where(
            Alert.incident_id.is_(None),
            Alert.host_id.is_not(None),
            Alert.opened_at >= cutoff,
        )
        .order_by(Alert.host_id, Alert.opened_at)
    )
    rows = (await db.execute(stmt)).scalars().all()
    if not rows:
        return 0

    # Batch-fetch rule names once so new-incident titles don't N+1.
    rule_ids = {a.rule_id for a in rows}
    rule_name_by_id: dict[UUID, str] = {}
    if rule_ids:
        rule_rows = (
            await db.execute(select(Rule.id, Rule.name).where(Rule.id.in_(rule_ids)))
        ).all()
        rule_name_by_id = {rid: name for rid, name in rule_rows if name}

    by_host: dict[UUID, list[Alert]] = defaultdict(list)
    for a in rows:
        assert a.host_id is not None  # SELECT filters NULLs out
        by_host[a.host_id].append(a)

    grouped = 0
    touched_incident_ids: set[UUID] = set()
    for host_id, alerts in by_host.items():
        # Look back inside the live `incidents` table too, so an alert
        # that lands just after a worker tick still glues onto the
        # most-recent open incident on the same host if it's still
        # within the window.
        prev_open = (
            await db.execute(
                select(Incident)
                .where(
                    Incident.host_id == host_id,
                    Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]),
                )
                .order_by(Incident.opened_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

        # `current_incident` tracks the rolling head; `head_ts` is the
        # opened_at of the most recent alert attached to it so the
        # window check stays anchored on the *latest* alert, not the
        # incident's start.
        current_incident: Incident | None = None
        head_ts: datetime | None = None
        if prev_open is not None:
            # Use the most recent attached alert's opened_at as the
            # window anchor; fall back to incident.opened_at when there
            # are no attached alerts (shouldn't happen after creation,
            # but defensive).
            latest_attached = (
                await db.execute(
                    select(Alert.opened_at)
                    .where(Alert.incident_id == prev_open.id)
                    .order_by(Alert.opened_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            head_ts = latest_attached or prev_open.opened_at
            # Only adopt the existing incident if the first ungrouped
            # alert lands within the window.
            if alerts[0].opened_at - head_ts <= window:
                current_incident = prev_open

        for alert in alerts:
            if (
                current_incident is not None
                and head_ts is not None
                and (alert.opened_at - head_ts <= window)
            ):
                alert.incident_id = current_incident.id
                touched_incident_ids.add(current_incident.id)
                head_ts = alert.opened_at
                grouped += 1
                continue
            rule_name = rule_name_by_id.get(alert.rule_id)
            title = f"{rule_name} on host {host_id}" if rule_name else f"Incident on host {host_id}"
            incident = Incident(
                host_id=host_id,
                title=title[:256],
                summary=alert.summary[:512] if alert.summary else None,
                severity=alert.severity,
                status=IncidentStatus.OPEN,
                opened_at=alert.opened_at,
            )
            db.add(incident)
            await db.flush()  # populate incident.id
            alert.incident_id = incident.id
            touched_incident_ids.add(incident.id)
            current_incident = incident
            head_ts = alert.opened_at
            grouped += 1

        # Bump the incident's severity if any attached alert outranks
        # the current value. Recompute at the end of the per-host pass
        # so we don't re-issue UPDATEs row-by-row.
        if current_incident is not None:
            # Recompute over the in-memory pass + the persisted rows
            # already attached to this incident.
            existing_max: Severity = current_incident.severity
            for a in alerts:
                if a.incident_id == current_incident.id:
                    existing_max = _max_severity(existing_max, a.severity)
            if existing_max != current_incident.severity:
                await db.execute(
                    update(Incident)
                    .where(Incident.id == current_incident.id)
                    .values(severity=existing_max)
                )

    if grouped:
        # Persist the pending `alert.incident_id = ...` assignments so
        # callers that refresh() (tests) and the worker's `db.commit()`
        # see a consistent state.
        await db.flush()
        log.info("incident_grouping.regrouped", count=grouped, hosts=len(by_host))

    if touched_incident_ids:
        await _refine_process_tree(db, touched_incident_ids)

    return grouped


def _alert_pid(alert: Alert) -> int | None:
    """Pull a process pid out of the alert payload.

    Defensive: producers historically split between
    `details["process"]["pid"]` (Sigma path) and
    `details["metadata"]["process"]["pid"]` (IOC/anomaly path). Try
    both before giving up.
    """
    details: Any = alert.details
    if not isinstance(details, dict):
        return None
    candidates: list[Any] = [details.get("process")]
    metadata = details.get("metadata")
    if isinstance(metadata, dict):
        candidates.append(metadata.get("process"))
    for proc in candidates:
        if isinstance(proc, dict):
            pid = proc.get("pid")
            if isinstance(pid, int) and pid > 0:
                return pid
    return None


async def _ancestor_pids_from_pg(db: AsyncSession, host_id: UUID, pid: int) -> list[int]:
    """Walk parent_pid in the `process_chain` table back toward init.

    Returns the chain of ancestor pids (excluding `pid` itself), or
    `[]` if `process_chain` doesn't exist yet (Phase 2 #2.6 hasn't
    shipped on this deployment) or the row isn't there.
    """
    chain: list[int] = []
    seen: set[int] = {pid}
    current = pid
    try:
        for _ in range(_TREE_DEPTH_LIMIT):
            row = (
                await db.execute(
                    text("SELECT parent_pid FROM process_chain WHERE host_id = :h AND pid = :p"),
                    {"h": str(host_id), "p": current},
                )
            ).first()
            if row is None or row[0] is None:
                break
            parent = int(row[0])
            if parent in seen or parent <= 0:
                break
            chain.append(parent)
            seen.add(parent)
            current = parent
    except Exception:
        # process_chain table may not exist yet — Phase 2 #2.6 sibling.
        # Caller falls back to OpenSearch.
        return []
    return chain


async def _ancestor_pids_from_os(host_id: UUID, pid: int) -> list[int]:
    """Fallback ancestor walk via OpenSearch process_started events."""
    try:
        from app.services import opensearch as os_svc

        client = os_svc._client()
    except Exception:
        return []

    chain: list[int] = []
    seen: set[int] = {pid}
    current = pid
    now = datetime.now(UTC)
    try:
        for _ in range(_TREE_DEPTH_LIMIT):
            doc = await os_svc.fetch_process_started(
                client, host_id=str(host_id), pid=current, before=now
            )
            if not doc:
                break
            proc = doc.get("process") or {}
            parent = proc.get("parent", {}).get("pid") if isinstance(proc, dict) else None
            if not isinstance(parent, int) or parent <= 0 or parent in seen:
                break
            chain.append(parent)
            seen.add(parent)
            current = parent
    except Exception:
        return chain
    return chain


async def _refine_process_tree(db: AsyncSession, incident_ids: set[UUID]) -> None:
    """For each touched incident, mark it `process_tree` if 2+ of its
    attached alerts share any process ancestor on the same host.

    Best-effort: any failure in the probe (missing table, OS down,
    malformed pids) leaves the incident at its current reason.
    """
    if not incident_ids:
        return

    alert_objs = (
        (await db.execute(select(Alert).where(Alert.incident_id.in_(incident_ids)))).scalars().all()
    )
    by_incident: dict[UUID, list[tuple[UUID, Alert]]] = defaultdict(list)
    for a in alert_objs:
        if a.incident_id is not None and a.host_id is not None:
            by_incident[a.incident_id].append((a.host_id, a))

    incidents_to_promote: list[UUID] = []
    for inc_id, host_alerts in by_incident.items():
        if len(host_alerts) < 2:
            continue
        # Build {alert: set(ancestor pids incl. itself)} via process_chain;
        # fall back to OpenSearch only if PG produced nothing for *any*
        # alert in this incident.
        per_alert_ancestors: list[set[int]] = []
        pg_yielded_any = False
        host_pid_pairs: list[tuple[UUID, int]] = []
        for host_id, alert in host_alerts:
            pid = _alert_pid(alert)
            if pid is None:
                continue
            host_pid_pairs.append((host_id, pid))
            ancestors = await _ancestor_pids_from_pg(db, host_id, pid)
            if ancestors:
                pg_yielded_any = True
            per_alert_ancestors.append({pid, *ancestors})

        if not pg_yielded_any:
            # No PG data — try the OpenSearch fallback.
            per_alert_ancestors = []
            for host_id, pid in host_pid_pairs:
                ancestors = await _ancestor_pids_from_os(host_id, pid)
                per_alert_ancestors.append({pid, *ancestors})

        if len(per_alert_ancestors) < 2:
            continue
        # Count how many alerts each pid appears in. 2+ alerts sharing
        # any pid means a common ancestor.
        pid_hits: dict[int, int] = defaultdict(int)
        for pids in per_alert_ancestors:
            for p in pids:
                pid_hits[p] += 1
        if any(count >= 2 for count in pid_hits.values()):
            incidents_to_promote.append(inc_id)

    if incidents_to_promote:
        await db.execute(
            update(Incident)
            .where(Incident.id.in_(incidents_to_promote))
            .values(grouping_reason=IncidentGroupingReason.PROCESS_TREE)
        )
        await db.flush()
        log.info(
            "incident_grouping.process_tree_promoted",
            count=len(incidents_to_promote),
        )
