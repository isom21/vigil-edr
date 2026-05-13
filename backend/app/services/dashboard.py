"""Dashboard widget resolution (Phase 3 #3.4).

`resolve_widget(db, widget, actor)` is the dispatcher. For each widget
kind we reuse the SAME aggregation primitives the per-resource stats
endpoints already expose — KPI counts, donut buckets, top-N rules,
hourly timeline, table previews — so the dashboard never diverges
from the per-page numbers. Every query passes through `apply_host_scope`
(or, for resource lists, the same join shape) so analyst-scoped
dashboards show only the hosts that analyst is allowed to see.

When a single widget blows up (e.g. an OpenSearch hiccup on a future
widget kind) the error is captured into the per-widget payload rather
than failing the whole `/data` call — the dashboard then renders the
other widgets with a per-card error indicator instead of going blank.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import Actor
from app.models import (
    Alert,
    AlertState,
    Host,
    HostStatus,
    Incident,
    Job,
    JobStatus,
    Rule,
)
from app.schemas.dashboard import Widget, WidgetData
from app.services.scoping import apply_host_scope


def _key_str(v: Any) -> str:
    if v is None:
        return "unknown"
    if hasattr(v, "value"):
        return v.value
    return str(v)


async def _kpi_value(db: AsyncSession, actor: Actor, *, query: str) -> dict[str, Any]:
    if query == "alerts_open":
        # Open = anything that hasn't been resolved either way. Mirrors
        # the dashboard "open alerts" pill from the hardcoded layout.
        stmt = select(func.count(Alert.id)).where(
            Alert.state.in_([AlertState.NEW, AlertState.INVESTIGATING])
        )
        stmt = apply_host_scope(stmt, actor, host_column=Alert.host_id)
        value = int((await db.execute(stmt)).scalar_one() or 0)
        return {"value": value, "unit": None}

    if query == "alerts_today":
        cutoff = datetime.now(UTC) - timedelta(hours=24)
        stmt = select(func.count(Alert.id)).where(Alert.opened_at >= cutoff)
        stmt = apply_host_scope(stmt, actor, host_column=Alert.host_id)
        value = int((await db.execute(stmt)).scalar_one() or 0)
        return {"value": value, "unit": None}

    if query == "hosts_online":
        stmt = select(func.count(Host.id)).where(Host.status == HostStatus.ONLINE)
        stmt = apply_host_scope(stmt, actor)
        value = int((await db.execute(stmt)).scalar_one() or 0)
        return {"value": value, "unit": None}

    if query == "hosts_total":
        stmt = select(func.count(Host.id)).where(Host.status != HostStatus.DECOMMISSIONED)
        stmt = apply_host_scope(stmt, actor)
        value = int((await db.execute(stmt)).scalar_one() or 0)
        return {"value": value, "unit": None}

    if query == "jobs_failed_24h":
        cutoff = datetime.now(UTC) - timedelta(hours=24)
        # Jobs have no per-host scoping of their own (a Job fans out
        # across many hosts), so admins see everything and analysts
        # see jobs they themselves created. This matches the convention
        # used by `/api/jobs` for non-admin actors.
        stmt = select(func.count(Job.id)).where(
            Job.status == JobStatus.FAILED,
            Job.updated_at >= cutoff,
        )
        if not _is_admin(actor):
            stmt = stmt.where(Job.created_by_user_id == actor.user.id)
        value = int((await db.execute(stmt)).scalar_one() or 0)
        return {"value": value, "unit": None}

    if query == "avg_mttr_hours":
        # Mean time to resolution: average of
        # (closed_at - opened_at) over the last 24h of closed alerts.
        # Returns 0.0 when no alerts have closed in the window.
        cutoff = datetime.now(UTC) - timedelta(hours=24)
        seconds = func.extract("epoch", Alert.closed_at - Alert.opened_at)
        stmt = select(func.avg(seconds)).where(
            Alert.closed_at.is_not(None),
            Alert.closed_at >= cutoff,
        )
        stmt = apply_host_scope(stmt, actor, host_column=Alert.host_id)
        raw = (await db.execute(stmt)).scalar_one_or_none()
        hours = float(raw) / 3600.0 if raw else 0.0
        return {"value": round(hours, 2), "unit": "h"}

    raise ValueError(f"unknown kpi query: {query}")


def _is_admin(actor: Actor) -> bool:
    from app.models import UserRole

    return actor.has_role(UserRole.ADMIN)


async def _severity_donut(db: AsyncSession, actor: Actor) -> list[dict[str, Any]]:
    stmt = select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    stmt = apply_host_scope(stmt, actor, host_column=Alert.host_id)
    rows = (await db.execute(stmt)).all()
    return [{"key": _key_str(k), "count": int(c)} for k, c in rows]


async def _state_donut(db: AsyncSession, actor: Actor) -> list[dict[str, Any]]:
    stmt = select(Alert.state, func.count(Alert.id)).group_by(Alert.state)
    stmt = apply_host_scope(stmt, actor, host_column=Alert.host_id)
    rows = (await db.execute(stmt)).all()
    return [{"key": _key_str(k), "count": int(c)} for k, c in rows]


async def _host_status_donut(db: AsyncSession, actor: Actor) -> list[dict[str, Any]]:
    stmt = select(Host.status, func.count(Host.id)).group_by(Host.status)
    stmt = apply_host_scope(stmt, actor)
    rows = (await db.execute(stmt)).all()
    return [{"key": _key_str(k), "count": int(c)} for k, c in rows]


async def _top_rules(db: AsyncSession, actor: Actor, *, limit: int) -> list[dict[str, Any]]:
    stmt = (
        select(Rule.name, func.count(Alert.id))
        .join(Rule, Rule.id == Alert.rule_id)
        .group_by(Rule.name)
        .order_by(func.count(Alert.id).desc())
        .limit(limit)
    )
    stmt = apply_host_scope(stmt, actor, host_column=Alert.host_id)
    rows = (await db.execute(stmt)).all()
    return [{"key": _key_str(k), "count": int(c)} for k, c in rows]


async def _timeline_24h(db: AsyncSession, actor: Actor) -> list[dict[str, Any]]:
    bucket_col = func.date_trunc("hour", Alert.opened_at)
    cutoff = datetime.now(UTC) - timedelta(hours=23)
    stmt = (
        select(bucket_col.label("bucket"), func.count(Alert.id))
        .where(Alert.opened_at >= cutoff)
        .group_by(bucket_col)
        .order_by(bucket_col)
    )
    stmt = apply_host_scope(stmt, actor, host_column=Alert.host_id)
    rows = (await db.execute(stmt)).all()
    by_bucket: dict[datetime, int] = {}
    for ts, c in rows:
        if ts is not None:
            by_bucket[ts.replace(minute=0, second=0, microsecond=0)] = int(c)
    out: list[dict[str, Any]] = []
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    for i in range(23, -1, -1):
        ts = now - timedelta(hours=i)
        out.append({"key": ts.isoformat(), "count": by_bucket.get(ts, 0)})
    return out


async def _hosts_table(db: AsyncSession, actor: Actor, *, limit: int) -> list[dict[str, Any]]:
    stmt = (
        select(
            Host.id,
            Host.hostname,
            Host.status,
            Host.os_family,
            Host.last_seen_at,
        )
        .order_by(Host.last_seen_at.desc().nulls_last())
        .limit(limit)
    )
    stmt = apply_host_scope(stmt, actor)
    rows = (await db.execute(stmt)).all()
    return [
        {
            "id": str(r.id),
            "hostname": r.hostname,
            "status": _key_str(r.status),
            "os_family": _key_str(r.os_family),
            "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
        }
        for r in rows
    ]


async def _incidents_table(db: AsyncSession, actor: Actor, *, limit: int) -> list[dict[str, Any]]:
    stmt = (
        select(
            Incident.id,
            Incident.title,
            Incident.severity,
            Incident.status,
            Incident.opened_at,
            Host.hostname,
        )
        .outerjoin(Host, Host.id == Incident.host_id)
        .order_by(Incident.opened_at.desc())
        .limit(limit)
    )
    stmt = apply_host_scope(stmt, actor, host_column=Incident.host_id)
    rows = (await db.execute(stmt)).all()
    return [
        {
            "id": str(r.id),
            "title": r.title,
            "severity": _key_str(r.severity),
            "status": _key_str(r.status),
            "opened_at": r.opened_at.isoformat() if r.opened_at else None,
            "host_hostname": r.hostname,
        }
        for r in rows
    ]


async def resolve_widget(db: AsyncSession, widget: Widget, actor: Actor) -> WidgetData:
    """Dispatch on the widget's discriminator and return a `WidgetData`
    payload. Per-widget exceptions surface as `error` on the response
    rather than failing the whole `/data` call — the dashboard can still
    render the rest of the grid when one widget can't compute."""
    try:
        if widget.type == "kpi":
            data = await _kpi_value(db, actor, query=widget.query)
        elif widget.type == "severity_donut":
            data = await _severity_donut(db, actor)
        elif widget.type == "state_donut":
            data = await _state_donut(db, actor)
        elif widget.type == "host_status_donut":
            data = await _host_status_donut(db, actor)
        elif widget.type == "top_rules":
            data = await _top_rules(db, actor, limit=widget.limit)
        elif widget.type == "timeline_24h":
            data = await _timeline_24h(db, actor)
        elif widget.type == "hosts_table":
            data = await _hosts_table(db, actor, limit=widget.limit)
        elif widget.type == "incidents_table":
            data = await _incidents_table(db, actor, limit=widget.limit)
        else:  # pragma: no cover - exhaustive over the Pydantic union
            return WidgetData(type=str(widget.type), data=None, error="unknown widget type")
        return WidgetData(type=widget.type, data=data)
    except Exception as exc:  # noqa: BLE001
        return WidgetData(type=widget.type, data=None, error=str(exc))


def default_layout() -> list[dict[str, Any]]:
    """The bootstrap layout for a fresh user's default dashboard. The
    shape mirrors the hardcoded Dashboard.tsx that this unit replaces:
    severity donut, state donut, top rules, and the 24h timeline. On
    the 12-column grid each donut takes 4 cells wide × 4 tall, the
    top-rules bar widget takes 4 wide × 4 tall, and the timeline
    spans the full width below."""
    return [
        {
            "type": "severity_donut",
            "position": {"x": 0, "y": 0, "w": 4, "h": 4},
        },
        {
            "type": "state_donut",
            "position": {"x": 4, "y": 0, "w": 4, "h": 4},
        },
        {
            "type": "top_rules",
            "position": {"x": 8, "y": 0, "w": 4, "h": 4},
            "limit": 10,
        },
        {
            "type": "timeline_24h",
            "position": {"x": 0, "y": 4, "w": 12, "h": 3},
        },
    ]


__all__ = ("resolve_widget", "default_layout")
