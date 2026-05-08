"""Alerts: list, detail, state transitions, assignment."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.core.deps import DbSession, RequireAnalyst
from app.core.errors import bad_request, not_found
from app.models import (
    ALERT_STATE_TRANSITIONS,
    Alert,
    AlertState,
    AlertStateHistory,
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
from app.services import audit

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=Page[AlertOut])
async def list_alerts(
    db: DbSession,
    actor: RequireAnalyst,
    state: AlertState | None = None,
    severity: Severity | None = None,
    host_id: UUID | None = None,
    rule_id: UUID | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[AlertOut]:
    stmt = select(Alert)
    count_stmt = select(func.count(Alert.id))
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
    stmt = stmt.order_by(Alert.opened_at.desc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[AlertOut.model_validate(a) for a in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{alert_id}", response_model=AlertDetail)
async def get_alert(alert_id: UUID, db: DbSession, actor: RequireAnalyst) -> AlertDetail:
    stmt = select(Alert).where(Alert.id == alert_id).options(selectinload(Alert.history))
    alert = (await db.execute(stmt)).scalar_one_or_none()
    if alert is None:
        raise not_found("alert", str(alert_id))
    return AlertDetail.model_validate(alert)


@router.post("/{alert_id}/state", response_model=AlertDetail)
async def change_state(
    alert_id: UUID,
    payload: AlertStateChange,
    db: DbSession,
    actor: RequireAnalyst,
) -> AlertDetail:
    stmt = select(Alert).where(Alert.id == alert_id).options(selectinload(Alert.history))
    alert = (await db.execute(stmt)).scalar_one_or_none()
    if alert is None:
        raise not_found("alert", str(alert_id))
    allowed = ALERT_STATE_TRANSITIONS.get(alert.state, set())
    if payload.to_state not in allowed:
        raise bad_request(
            f"transition {alert.state.value} -> {payload.to_state.value} not allowed"
        )

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
        alert.closed_at = datetime.now(timezone.utc)

    await audit.record(
        db,
        actor=actor,
        action="alert.state_change",
        resource_type="alert",
        resource_id=str(alert.id),
        payload={"to_state": payload.to_state.value, "comment": payload.comment},
    )
    return AlertDetail.model_validate(alert)


@router.post("/{alert_id}/assign", response_model=AlertDetail)
async def assign(
    alert_id: UUID, payload: AlertAssign, db: DbSession, actor: RequireAnalyst
) -> AlertDetail:
    stmt = select(Alert).where(Alert.id == alert_id).options(selectinload(Alert.history))
    alert = (await db.execute(stmt)).scalar_one_or_none()
    if alert is None:
        raise not_found("alert", str(alert_id))
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
    return AlertDetail.model_validate(alert)
