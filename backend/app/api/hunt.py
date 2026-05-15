"""Threat-hunting workbench endpoints (Phase 2 #2.11).

Two surface areas:

  * `/api/hunt/run` — ad-hoc query execution. Audited per call so the
    audit trail captures every operator-driven search, regardless of
    whether they save the query.
  * `/api/hunt/saved/*` — CRUD on stored hunts + manual run + history.

Admin gate on `alert_on_hit` or `schedule_cron`: those features can
emit Alert rows / consume background-worker capacity, so analysts can
author personal hunts but only admins can wire up the side effects.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import structlog
from fastapi import APIRouter, status
from sqlalchemy import desc, func, select

from app.core.deps import DbSession, RequireAnalyst, RequireViewer
from app.core.errors import bad_request, forbidden, not_found
from app.models import HuntRun, SavedHunt, UserRole
from app.schemas.common import Page
from app.schemas.hunt import (
    HuntAdhocRequest,
    HuntResultHit,
    HuntRunOut,
    HuntRunResult,
    SavedHuntCreate,
    SavedHuntOut,
    SavedHuntUpdate,
)
from app.services import audit
from app.services.hunt import (
    HuntCompileError,
    build_search_body,
    effective_host_filter_empty,
    execute_search,
    run_hunt,
    translate_to_dsl,
    validate_cron,
)
from app.services.scoping import visible_host_ids

log = structlog.get_logger()

router = APIRouter(prefix="/api/hunt", tags=["hunt"])


def _hunt_to_out(h: SavedHunt) -> SavedHuntOut:
    return SavedHuntOut.model_validate(h)


def _run_to_out(r: HuntRun) -> HuntRunOut:
    return HuntRunOut.model_validate(r)


def _project(hits: list[dict]) -> list[HuntResultHit]:
    out: list[HuntResultHit] = []
    for h in hits:
        src = h.get("_source") or {}
        out.append(
            HuntResultHit(
                timestamp=src.get("@timestamp"),
                host_id=(src.get("host") or {}).get("id"),
                event_id=(src.get("event") or {}).get("id"),
                source=src,
            )
        )
    return out


def _require_admin_for_side_effects(
    actor,
    *,
    alert_on_hit: bool | None,
    schedule_cron: str | None,
) -> None:
    """Admins can wire up `alert_on_hit` / `schedule_cron`; analysts
    can't. Refusing at the API boundary keeps the admin gate explicit
    rather than buried in the worker."""
    if not (alert_on_hit or schedule_cron):
        return
    if not actor.has_role(UserRole.ADMIN):
        raise forbidden("only admins can configure alert_on_hit or schedule_cron")


@router.post("/run", response_model=HuntRunResult)
async def run_adhoc(
    payload: HuntAdhocRequest,
    actor: RequireAnalyst,
    db: DbSession,
    tenant_id: UUID | None = None,
) -> HuntRunResult:
    try:
        query_clause = translate_to_dsl(payload.query, payload.language)
    except HuntCompileError as exc:
        raise bad_request(str(exc)) from exc

    visible = await visible_host_ids(actor, db)

    await audit.record(
        db,
        actor=actor,
        action="hunt.run_adhoc",
        resource_type="hunt",
        payload={
            "language": payload.language,
            "lookback_hours": payload.lookback_hours,
            "size": payload.size,
        },
    )
    await db.commit()

    if effective_host_filter_empty(visible, host_scope=None):
        return HuntRunResult(query_dsl=payload.query, total=0, hits=[], truncated=False)

    # CODE-22: non-super-admins pin to their tenant; super-admins
    # optionally narrow to ?tenant_id=, else cross-tenant view.
    eff_tenant = (
        tenant_id
        if actor.is_super_admin and tenant_id is not None
        else (None if actor.is_super_admin else actor.tenant_id)
    )

    upper = datetime.now(UTC)
    lower = upper - timedelta(hours=payload.lookback_hours)
    body = build_search_body(
        query_clause,
        lower=lower,
        upper=upper,
        visible_host_ids=visible,
        host_scope=None,
        size=payload.size,
        tenant_id=eff_tenant,
    )
    total, hits = await execute_search(query_dsl=payload.query, body=body)
    hit_objs = _project(hits)
    return HuntRunResult(
        query_dsl=payload.query,
        total=total,
        hits=hit_objs,
        truncated=total > len(hit_objs),
    )


@router.get("/saved", response_model=Page[SavedHuntOut])
async def list_saved(
    db: DbSession,
    actor: RequireViewer,
    limit: int = 50,
    offset: int = 0,
) -> Page[SavedHuntOut]:
    # Non-admin actors see only their own hunts. Admins see everything;
    # they're the ones managing scheduler load + alert-emitting hunts.
    stmt = select(SavedHunt).order_by(SavedHunt.name).limit(limit).offset(offset)
    count_stmt = select(func.count(SavedHunt.id))
    if not actor.has_role(UserRole.ADMIN):
        stmt = stmt.where(SavedHunt.owner_user_id == actor.user.id)
        count_stmt = count_stmt.where(SavedHunt.owner_user_id == actor.user.id)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[_hunt_to_out(r) for r in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@router.post("/saved", response_model=SavedHuntOut, status_code=status.HTTP_201_CREATED)
async def create_saved(
    payload: SavedHuntCreate,
    db: DbSession,
    actor: RequireAnalyst,
) -> SavedHuntOut:
    _require_admin_for_side_effects(
        actor,
        alert_on_hit=payload.alert_on_hit,
        schedule_cron=payload.schedule_cron,
    )
    # Validate the query compiles before we let the row land — saves a
    # round-trip to the run endpoint to discover the typo.
    try:
        translate_to_dsl(payload.query_dsl, payload.query_language)
    except HuntCompileError as exc:
        raise bad_request(str(exc)) from exc
    if payload.schedule_cron:
        try:
            validate_cron(payload.schedule_cron)
        except ValueError as exc:
            raise bad_request(f"invalid cron: {exc}") from exc

    hunt = SavedHunt(
        owner_user_id=actor.user.id,
        name=payload.name,
        description=payload.description,
        query_dsl=payload.query_dsl,
        query_language=payload.query_language,
        schedule_cron=payload.schedule_cron,
        alert_on_hit=payload.alert_on_hit,
        severity=payload.severity,
        mitre_techniques=payload.mitre_techniques,
        host_scope_json=payload.host_scope_json,
    )
    db.add(hunt)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="hunt.create",
        resource_type="saved_hunt",
        resource_id=str(hunt.id),
        payload={
            "name": hunt.name,
            "query_language": hunt.query_language,
            "alert_on_hit": hunt.alert_on_hit,
            "schedule_cron": hunt.schedule_cron,
        },
    )
    await db.commit()
    return _hunt_to_out(hunt)


async def _load_or_404(db, hunt_id: UUID) -> SavedHunt:
    hunt = await db.get(SavedHunt, hunt_id)
    if hunt is None:
        raise not_found("saved_hunt", str(hunt_id))
    return hunt


def _assert_owner_or_admin(actor, hunt: SavedHunt) -> None:
    if actor.has_role(UserRole.ADMIN):
        return
    if hunt.owner_user_id != actor.user.id:
        raise forbidden("not the hunt owner")


@router.get("/saved/{hunt_id}", response_model=SavedHuntOut)
async def get_saved(
    hunt_id: UUID,
    db: DbSession,
    actor: RequireViewer,
) -> SavedHuntOut:
    hunt = await _load_or_404(db, hunt_id)
    _assert_owner_or_admin(actor, hunt)
    return _hunt_to_out(hunt)


@router.patch("/saved/{hunt_id}", response_model=SavedHuntOut)
async def update_saved(
    hunt_id: UUID,
    payload: SavedHuntUpdate,
    db: DbSession,
    actor: RequireAnalyst,
) -> SavedHuntOut:
    hunt = await _load_or_404(db, hunt_id)
    _assert_owner_or_admin(actor, hunt)
    # The side-effects gate looks at the EFFECTIVE post-patch values,
    # not just the deltas — flipping alert_on_hit OFF stays open to
    # analysts.
    next_alert = payload.alert_on_hit if payload.alert_on_hit is not None else hunt.alert_on_hit
    next_cron = (
        payload.schedule_cron if "schedule_cron" in payload.model_fields_set else hunt.schedule_cron
    )
    _require_admin_for_side_effects(actor, alert_on_hit=next_alert, schedule_cron=next_cron)

    if payload.name is not None:
        hunt.name = payload.name
    if "description" in payload.model_fields_set:
        hunt.description = payload.description
    if payload.query_dsl is not None or payload.query_language is not None:
        new_dsl = payload.query_dsl if payload.query_dsl is not None else hunt.query_dsl
        new_lang = (
            payload.query_language if payload.query_language is not None else hunt.query_language
        )
        try:
            translate_to_dsl(new_dsl, new_lang)
        except HuntCompileError as exc:
            raise bad_request(str(exc)) from exc
        hunt.query_dsl = new_dsl
        hunt.query_language = new_lang
    if "schedule_cron" in payload.model_fields_set:
        if payload.schedule_cron:
            try:
                validate_cron(payload.schedule_cron)
            except ValueError as exc:
                raise bad_request(f"invalid cron: {exc}") from exc
        hunt.schedule_cron = payload.schedule_cron
    if payload.alert_on_hit is not None:
        hunt.alert_on_hit = payload.alert_on_hit
    if "severity" in payload.model_fields_set:
        hunt.severity = payload.severity
    if "mitre_techniques" in payload.model_fields_set:
        hunt.mitre_techniques = payload.mitre_techniques
    if "host_scope_json" in payload.model_fields_set:
        hunt.host_scope_json = payload.host_scope_json

    await audit.record(
        db,
        actor=actor,
        action="hunt.update",
        resource_type="saved_hunt",
        resource_id=str(hunt.id),
        payload={"name": hunt.name},
    )
    await db.commit()
    await db.refresh(hunt)
    return _hunt_to_out(hunt)


@router.delete("/saved/{hunt_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_saved(
    hunt_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
) -> None:
    hunt = await _load_or_404(db, hunt_id)
    _assert_owner_or_admin(actor, hunt)
    await db.delete(hunt)
    await audit.record(
        db,
        actor=actor,
        action="hunt.delete",
        resource_type="saved_hunt",
        resource_id=str(hunt_id),
    )
    await db.commit()


@router.post("/saved/{hunt_id}/run", response_model=HuntRunResult)
async def run_saved(
    hunt_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
    tenant_id: UUID | None = None,
) -> HuntRunResult:
    hunt = await _load_or_404(db, hunt_id)
    _assert_owner_or_admin(actor, hunt)

    await audit.record(
        db,
        actor=actor,
        action="hunt.run_saved",
        resource_type="saved_hunt",
        resource_id=str(hunt.id),
        payload={"name": hunt.name},
    )
    await db.commit()

    # Manual runs always honour the actor's RBAC + the hunt's saved
    # scope — even an admin-owned hunt manually run by an analyst gets
    # the analyst's host visibility.
    visible = await visible_host_ids(actor, db)
    if effective_host_filter_empty(visible, host_scope=hunt.host_scope_json):
        # Persist an empty run so the history view records the
        # operator-driven trigger.
        run = HuntRun(
            hunt_id=hunt.id,
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
            hit_count=0,
            alert_count=0,
        )
        db.add(run)
        await db.commit()
        return HuntRunResult(
            query_dsl=hunt.query_dsl,
            total=0,
            hits=[],
            truncated=False,
            run=_run_to_out(run),
        )

    try:
        query_clause = translate_to_dsl(hunt.query_dsl, hunt.query_language)
    except HuntCompileError as exc:
        raise bad_request(str(exc)) from exc

    # CODE-22: the saved hunt's own tenant_id is the natural scope.
    # Super-admins can drill into a different tenant via ?tenant_id=.
    eff_tenant = (
        tenant_id
        if actor.is_super_admin and tenant_id is not None
        else (None if actor.is_super_admin else actor.tenant_id)
    )

    upper = datetime.now(UTC)
    lower = upper - timedelta(hours=24)
    body = build_search_body(
        query_clause,
        lower=lower,
        upper=upper,
        visible_host_ids=visible,
        host_scope=hunt.host_scope_json,
        size=1000,
        tenant_id=eff_tenant,
    )
    total, hits = await execute_search(query_dsl=hunt.query_dsl, body=body)

    # Manual runs don't emit alerts even when alert_on_hit is true —
    # only the scheduler's full-power runs do, so an analyst running a
    # hunt for triage doesn't spam the alert queue. The run row still
    # gets recorded so audit shows the trigger.
    run = HuntRun(
        hunt_id=hunt.id,
        started_at=upper,
        finished_at=datetime.now(UTC),
        hit_count=total,
        alert_count=0,
    )
    db.add(run)
    await db.commit()

    hit_objs = _project(hits)
    return HuntRunResult(
        query_dsl=hunt.query_dsl,
        total=total,
        hits=hit_objs,
        truncated=total > len(hit_objs),
        run=_run_to_out(run),
    )


@router.get("/saved/{hunt_id}/runs", response_model=Page[HuntRunOut])
async def list_runs(
    hunt_id: UUID,
    db: DbSession,
    actor: RequireViewer,
    limit: int = 50,
    offset: int = 0,
) -> Page[HuntRunOut]:
    hunt = await _load_or_404(db, hunt_id)
    _assert_owner_or_admin(actor, hunt)
    stmt = (
        select(HuntRun)
        .where(HuntRun.hunt_id == hunt.id)
        .order_by(desc(HuntRun.started_at))
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.execute(stmt)).scalars().all()
    total = (
        await db.execute(select(func.count(HuntRun.id)).where(HuntRun.hunt_id == hunt.id))
    ).scalar_one()
    return Page(
        items=[_run_to_out(r) for r in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


# Expose the helper to the scheduler unit tests without re-importing
# the run lifecycle through `app.services.hunt`.
__all__ = ("router", "run_hunt")
