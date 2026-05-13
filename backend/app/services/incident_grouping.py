"""Phase 1 #1.11 — incident grouping.

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
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from uuid import UUID

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, Incident, IncidentStatus, Rule, Severity

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
    return grouped
