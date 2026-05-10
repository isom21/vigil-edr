"""Alerts: list, detail, state transitions, assignment, stats."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.core.deps import DbSession, RequireAnalyst
from app.core.errors import bad_request, forbidden, not_found
from app.models import (
    ALERT_STATE_TRANSITIONS,
    Alert,
    AlertState,
    AlertStateHistory,
    Host,
    Rule,
    Severity,
    User,
)
from app.schemas.alert import (
    AlertAssign,
    AlertDetail,
    AlertOut,
    AlertStateChange,
)
from app.schemas.common import Page
from app.schemas.stats import StatBucket
from app.services import audit
from app.services.scoping import apply_host_scope, host_visible_to
from app.services.sorting import parse_sort

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


_SORTABLE = {
    "opened_at": Alert.opened_at,
    "severity": Alert.severity,
    "state": Alert.state,
    "updated_at": Alert.updated_at,
    "host_hostname": Host.hostname,
    "rule_name": Rule.name,
}


def _alert_out(a: Alert, host_hostname: str | None, rule_name: str | None) -> AlertOut:
    out = AlertOut.model_validate(a)
    out.host_hostname = host_hostname
    out.rule_name = rule_name
    return out


@router.get("", response_model=Page[AlertOut])
async def list_alerts(
    db: DbSession,
    actor: RequireAnalyst,
    state: AlertState | None = None,
    severity: Severity | None = None,
    host_id: UUID | None = None,
    rule_id: UUID | None = None,
    host_hostname: str | None = None,
    rule_name: str | None = None,
    q: str | None = None,
    sort: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[AlertOut]:
    stmt = (
        select(Alert, Host.hostname, Rule.name)
        .join(Host, Host.id == Alert.host_id)
        .join(Rule, Rule.id == Alert.rule_id)
    )
    count_stmt = (
        select(func.count(Alert.id))
        .join(Host, Host.id == Alert.host_id)
        .join(Rule, Rule.id == Alert.rule_id)
    )
    if state:
        stmt = stmt.where(Alert.state == state)
        count_stmt = count_stmt.where(Alert.state == state)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
        count_stmt = count_stmt.where(Alert.severity == severity)
    if host_id:
        stmt = stmt.where(Alert.host_id == host_id)
        count_stmt = count_stmt.where(Alert.host_id == host_id)
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
        count_stmt = count_stmt.where(Alert.rule_id == rule_id)
    if host_hostname:
        stmt = stmt.where(Host.hostname == host_hostname)
        count_stmt = count_stmt.where(Host.hostname == host_hostname)
    if rule_name:
        stmt = stmt.where(Rule.name == rule_name)
        count_stmt = count_stmt.where(Rule.name == rule_name)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(Alert.summary.ilike(like))
        count_stmt = count_stmt.where(Alert.summary.ilike(like))
    # M7.5: scope alerts by host visibility (admins are pass-through).
    stmt = apply_host_scope(stmt, actor, host_column=Alert.host_id)
    count_stmt = apply_host_scope(count_stmt, actor, host_column=Alert.host_id)
    order = parse_sort(sort, _SORTABLE, default=[Alert.opened_at.desc()])
    stmt = stmt.order_by(*order).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[_alert_out(a, hn, rn) for a, hn, rn in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=list[StatBucket])
async def alert_stats(
    db: DbSession,
    actor: RequireAnalyst,
    bucket: str,
) -> list[StatBucket]:
    """Aggregations for the alert console charts.

    bucket=severity|state|host|rule|hour
    Honours host-scope so analysts only see counts for their groups.
    """
    if bucket == "severity":
        stmt = select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    elif bucket == "state":
        stmt = select(Alert.state, func.count(Alert.id)).group_by(Alert.state)
    elif bucket == "host":
        stmt = (
            select(Host.hostname, func.count(Alert.id))
            .join(Host, Host.id == Alert.host_id)
            .group_by(Host.hostname)
            .order_by(func.count(Alert.id).desc())
            .limit(10)
        )
    elif bucket == "rule":
        stmt = (
            select(Rule.name, func.count(Alert.id))
            .join(Rule, Rule.id == Alert.rule_id)
            .group_by(Rule.name)
            .order_by(func.count(Alert.id).desc())
            .limit(10)
        )
    elif bucket == "hour":
        stmt = _hourly_stmt()
    else:
        raise bad_request("bucket must be one of: severity, state, host, rule, hour")
    stmt = apply_host_scope(stmt, actor, host_column=Alert.host_id)
    rows = (await db.execute(stmt)).all()
    if bucket == "hour":
        return _fill_hourly(rows)
    return [StatBucket(key=_key_str(k), count=int(c)) for k, c in rows]


def _hourly_stmt():
    bucket_col = func.date_trunc("hour", Alert.opened_at)
    cutoff = datetime.now(UTC) - timedelta(hours=23)
    return (
        select(bucket_col.label("bucket"), func.count(Alert.id))
        .where(Alert.opened_at >= cutoff)
        .group_by(bucket_col)
        .order_by(bucket_col)
    )


def _fill_hourly(rows) -> list[StatBucket]:
    """Pad a 24-hour series so empty buckets still appear as count=0."""
    by_bucket: dict[datetime, int] = {}
    for ts, c in rows:
        if ts is not None:
            by_bucket[ts.replace(minute=0, second=0, microsecond=0)] = int(c)
    out: list[StatBucket] = []
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    for i in range(23, -1, -1):
        ts = now - timedelta(hours=i)
        out.append(StatBucket(key=ts.isoformat(), count=by_bucket.get(ts, 0)))
    return out


def _key_str(v) -> str:
    if v is None:
        return "unknown"
    if hasattr(v, "value"):
        return v.value
    return str(v)


@router.get("/{alert_id}", response_model=AlertDetail)
async def get_alert(alert_id: UUID, db: DbSession, actor: RequireAnalyst) -> AlertDetail:
    stmt = (
        select(Alert, Host.hostname, Rule.name)
        .join(Host, Host.id == Alert.host_id)
        .join(Rule, Rule.id == Alert.rule_id)
        .where(Alert.id == alert_id)
        .options(selectinload(Alert.history))
    )
    row = (await db.execute(stmt)).one_or_none()
    if row is None:
        raise not_found("alert", str(alert_id))
    alert, hostname, rule_name = row
    if not await host_visible_to(actor, alert.host_id, db):
        raise forbidden("alert refers to a host outside your groups")
    detail = AlertDetail.model_validate(alert)
    detail.host_hostname = hostname
    detail.rule_name = rule_name
    return detail


@router.post("/{alert_id}/state", response_model=AlertDetail)
async def change_state(
    alert_id: UUID,
    payload: AlertStateChange,
    db: DbSession,
    actor: RequireAnalyst,
) -> AlertDetail:
    stmt = (
        select(Alert, Host.hostname, Rule.name)
        .join(Host, Host.id == Alert.host_id)
        .join(Rule, Rule.id == Alert.rule_id)
        .where(Alert.id == alert_id)
        .options(selectinload(Alert.history))
    )
    row = (await db.execute(stmt)).one_or_none()
    if row is None:
        raise not_found("alert", str(alert_id))
    alert, hostname, rule_name = row
    allowed = ALERT_STATE_TRANSITIONS.get(alert.state, set())
    if payload.to_state not in allowed:
        raise bad_request(f"transition {alert.state.value} -> {payload.to_state.value} not allowed")

    alert.history.append(
        AlertStateHistory(
            from_state=alert.state,
            to_state=payload.to_state,
            by_user_id=actor.user.id,
            comment=payload.comment,
        )
    )
    alert.state = payload.to_state
    if payload.to_state in (AlertState.FALSE_POSITIVE, AlertState.TRUE_POSITIVE):
        alert.closed_at = datetime.now(UTC)

    await audit.record(
        db,
        actor=actor,
        action="alert.state_change",
        resource_type="alert",
        resource_id=str(alert.id),
        payload={"to_state": payload.to_state.value, "comment": payload.comment},
    )
    detail = AlertDetail.model_validate(alert)
    detail.host_hostname = hostname
    detail.rule_name = rule_name
    return detail


@router.post("/{alert_id}/assign", response_model=AlertDetail)
async def assign(
    alert_id: UUID, payload: AlertAssign, db: DbSession, actor: RequireAnalyst
) -> AlertDetail:
    stmt = (
        select(Alert, Host.hostname, Rule.name)
        .join(Host, Host.id == Alert.host_id)
        .join(Rule, Rule.id == Alert.rule_id)
        .where(Alert.id == alert_id)
        .options(selectinload(Alert.history))
    )
    row = (await db.execute(stmt)).one_or_none()
    if row is None:
        raise not_found("alert", str(alert_id))
    alert, hostname, rule_name = row
    if payload.assignee_id is not None:
        target = await db.get(User, payload.assignee_id)
        if target is None:
            raise not_found("user", str(payload.assignee_id))
    alert.assignee_id = payload.assignee_id
    await audit.record(
        db,
        actor=actor,
        action="alert.assign",
        resource_type="alert",
        resource_id=str(alert.id),
        payload={"assignee_id": str(payload.assignee_id) if payload.assignee_id else None},
    )
    detail = AlertDetail.model_validate(alert)
    detail.host_hostname = hostname
    detail.rule_name = rule_name
    return detail
