"""Incidents — list, detail, state transitions, assignment (Phase 1 #1.11)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter
from sqlalchemy import func, select
from sqlalchemy.orm import aliased

from app.core.deps import DbSession, RequireAnalyst, RequireViewer
from app.core.errors import bad_request, not_found
from app.models import (
    INCIDENT_STATUS_TRANSITIONS,
    Alert,
    Host,
    Incident,
    IncidentStatus,
    Rule,
    User,
)
from app.schemas.alert import AlertOut
from app.schemas.common import Page
from app.schemas.incident import (
    IncidentAssign,
    IncidentDetail,
    IncidentOut,
    IncidentStateChange,
)
from app.services import audit
from app.services.scoping import apply_host_scope, host_visible_to
from app.services.sorting import parse_sort

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


_SORTABLE = {
    "opened_at": Incident.opened_at,
    "severity": Incident.severity,
    "status": Incident.status,
    "updated_at": Incident.updated_at,
    "host_hostname": Host.hostname,
}


def _incident_out(
    incident: Incident,
    host_hostname: str | None,
    alert_count: int,
) -> IncidentOut:
    out = IncidentOut.model_validate(incident)
    out.host_hostname = host_hostname
    out.alert_count = int(alert_count or 0)
    return out


@router.get("", response_model=Page[IncidentOut])
async def list_incidents(
    db: DbSession,
    actor: RequireViewer,
    status: IncidentStatus | None = None,
    host_id: UUID | None = None,
    sort: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[IncidentOut]:
    """List incidents visible to the actor.

    Host scoping inherits from the incident's `host_id`. v1 incidents
    always carry a real host_id (the grouper skips synthetic null-host
    alerts), so we can scope directly on `Incident.host_id` via
    `apply_host_scope` — no JOIN-through-alerts gymnastics needed.
    """
    alert_count_sq = (
        select(Alert.incident_id.label("incident_id"), func.count(Alert.id).label("alert_count"))
        .where(Alert.incident_id.is_not(None))
        .group_by(Alert.incident_id)
        .subquery()
    )

    stmt = (
        select(Incident, Host.hostname, func.coalesce(alert_count_sq.c.alert_count, 0))
        .outerjoin(Host, Host.id == Incident.host_id)
        .outerjoin(alert_count_sq, alert_count_sq.c.incident_id == Incident.id)
    )
    count_stmt = select(func.count(Incident.id))
    if status is not None:
        stmt = stmt.where(Incident.status == status)
        count_stmt = count_stmt.where(Incident.status == status)
    if host_id is not None:
        stmt = stmt.where(Incident.host_id == host_id)
        count_stmt = count_stmt.where(Incident.host_id == host_id)
    # Inherit alert-style host scoping. Admins pass through.
    stmt = apply_host_scope(stmt, actor, host_column=Incident.host_id)
    count_stmt = apply_host_scope(count_stmt, actor, host_column=Incident.host_id)
    order = parse_sort(sort, _SORTABLE, default=[Incident.opened_at.desc()])
    stmt = stmt.order_by(*order).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[_incident_out(i, hn, ac) for i, hn, ac in rows],
        total=int(total or 0),
        limit=limit,
        offset=offset,
    )


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(incident_id: UUID, db: DbSession, actor: RequireViewer) -> IncidentDetail:
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise not_found("incident", str(incident_id))
    if not await host_visible_to(actor, incident.host_id, db):
        # M-audit-and-auth #7: 404 (not 403) so a non-admin can't
        # probe for the existence of incidents on hosts outside their
        # groups.
        raise not_found("incident", str(incident_id))

    # Pull the host hostname for display + the grouped alerts in one go.
    host_hostname = (
        (
            await db.execute(select(Host.hostname).where(Host.id == incident.host_id))
        ).scalar_one_or_none()
        if incident.host_id
        else None
    )

    # Alert rows for the detail page. Order by opened_at to mirror the
    # natural triage flow (first event first).
    rule_alias = aliased(Rule)
    alert_rows = (
        await db.execute(
            select(Alert, Host.hostname, rule_alias.name)
            .outerjoin(Host, Host.id == Alert.host_id)
            .join(rule_alias, rule_alias.id == Alert.rule_id)
            .where(Alert.incident_id == incident.id)
            .order_by(Alert.opened_at)
        )
    ).all()

    alerts: list[AlertOut] = []
    for alert, hn, rn in alert_rows:
        out = AlertOut.model_validate(alert)
        out.host_hostname = hn
        out.rule_name = rn
        alerts.append(out)

    detail = IncidentDetail.model_validate(incident)
    detail.host_hostname = host_hostname
    detail.alert_count = len(alerts)
    detail.alerts = alerts
    return detail


@router.post("/{incident_id}/state", response_model=IncidentDetail)
async def change_state(
    incident_id: UUID,
    payload: IncidentStateChange,
    db: DbSession,
    actor: RequireAnalyst,
) -> IncidentDetail:
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise not_found("incident", str(incident_id))
    if not await host_visible_to(actor, incident.host_id, db):
        raise not_found("incident", str(incident_id))

    allowed = INCIDENT_STATUS_TRANSITIONS.get(incident.status, set())
    if payload.to_state not in allowed:
        raise bad_request(
            f"transition {incident.status.value} -> {payload.to_state.value} not allowed"
        )
    incident.status = payload.to_state
    if payload.to_state in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
        incident.closed_at = datetime.now(UTC)
    elif payload.to_state in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING):
        # Re-opening unsets the close timestamp so the next close is
        # accurate.
        incident.closed_at = None

    await audit.record(
        db,
        actor=actor,
        action="incident.state_change",
        resource_type="incident",
        resource_id=str(incident.id),
        payload={"to_state": payload.to_state.value, "comment": payload.comment},
    )
    await db.flush()
    return await get_incident(incident.id, db, actor)


@router.post("/{incident_id}/assign", response_model=IncidentDetail)
async def assign(
    incident_id: UUID,
    payload: IncidentAssign,
    db: DbSession,
    actor: RequireAnalyst,
) -> IncidentDetail:
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise not_found("incident", str(incident_id))
    if not await host_visible_to(actor, incident.host_id, db):
        raise not_found("incident", str(incident_id))

    if payload.assignee_id is not None:
        target = await db.get(User, payload.assignee_id)
        if target is None:
            raise not_found("user", str(payload.assignee_id))
    incident.assignee_id = payload.assignee_id
    await audit.record(
        db,
        actor=actor,
        action="incident.assign",
        resource_type="incident",
        resource_id=str(incident.id),
        payload={"assignee_id": str(payload.assignee_id) if payload.assignee_id else None},
    )
    await db.flush()
    return await get_incident(incident.id, db, actor)
