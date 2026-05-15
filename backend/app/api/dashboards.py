"""Operator-authored dashboards (Phase 3 #3.4).

Endpoints:

  * `GET    /api/dashboards`               — list (own + shared)
  * `POST   /api/dashboards`               — create
  * `GET    /api/dashboards/default`       — owner default, auto-created
  * `GET    /api/dashboards/{id}`          — fetch one
  * `PUT    /api/dashboards/{id}`          — update (owner or admin)
  * `DELETE /api/dashboards/{id}`          — delete (owner or admin)
  * `POST   /api/dashboards/{id}/duplicate`— clone into the caller's namespace
  * `GET    /api/dashboards/{id}/data`     — resolved widget data array

Read access: viewers can list/read their own dashboards plus any
shared dashboard. Write access (create/update/delete) gates on
RequireAnalyst — analysts manage their own dashboards; admins can
edit anyone's.

Sharing semantics: a dashboard with `shared=true` is visible to every
analyst+ in the deployment. Edit/delete still require ownership (or
admin); cloning makes the caller the owner of the new copy.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import or_, select

from app.core.deps import DbSession, RequireAnalyst, RequireViewer
from app.core.errors import forbidden, not_found
from app.models import Dashboard, UserRole
from app.schemas.dashboard import (
    DashboardCreate,
    DashboardOut,
    DashboardUpdate,
    WidgetData,
)
from app.services import audit
from app.services.dashboard import default_layout, resolve_widget

router = APIRouter(prefix="/api/dashboards", tags=["dashboards"])


def _to_out(d: Dashboard) -> DashboardOut:
    return DashboardOut.model_validate(d)


async def _load_or_404(db, dashboard_id: UUID, actor) -> Dashboard:
    """Load a dashboard with tenant scope.

    CODE-20: pre-PR, `_load_or_404` returned any dashboard by id
    regardless of tenant, and the `_can_read` check let `shared=true`
    rows leak cross-tenant — every analyst in every tenant could see
    every tenant's shared layouts. 404 on cross-tenant ids keeps
    existence opaque.
    """
    d = await db.get(Dashboard, dashboard_id)
    if d is None or d.tenant_id != actor.tenant_id:
        raise not_found("dashboard", str(dashboard_id))
    return d


def _can_read(actor, d: Dashboard) -> bool:
    """Owner, shared, or admin can read. Assumes `_load_or_404` has
    already enforced same-tenant — sharing is tenant-internal only."""
    if actor.has_role(UserRole.ADMIN):
        return True
    if d.owner_user_id == actor.user.id:
        return True
    return bool(d.shared)


def _assert_can_edit(actor, d: Dashboard) -> None:
    """Owner or admin can edit. Sharing doesn't grant write access."""
    if actor.has_role(UserRole.ADMIN):
        return
    if d.owner_user_id != actor.user.id:
        raise forbidden("not the dashboard owner")


async def _clear_existing_default(db, *, owner_user_id: UUID) -> None:
    """Flip any current default off for this owner. The partial UNIQUE
    index `(owner_user_id) WHERE is_default = true` would otherwise
    reject the next INSERT. Called from both the create-default path
    in `/default` (idempotent) and the explicit `is_default=true`
    update path so an operator can promote any dashboard."""
    stmt = select(Dashboard).where(
        Dashboard.owner_user_id == owner_user_id,
        Dashboard.is_default.is_(True),
    )
    rows = (await db.execute(stmt)).scalars().all()
    for r in rows:
        r.is_default = False


@router.get("", response_model=list[DashboardOut])
async def list_dashboards(
    db: DbSession,
    actor: RequireViewer,
) -> list[DashboardOut]:
    """List dashboards visible to the caller — owned ones plus any
    shared dashboard. Admins see every dashboard so they can audit
    layouts across the team.

    CODE-20: all branches gate on `Dashboard.tenant_id` first so a
    shared layout in tenant A doesn't leak into tenant B's analyst
    sidebar."""
    stmt = select(Dashboard).where(Dashboard.tenant_id == actor.tenant_id).order_by(Dashboard.name)
    if not actor.has_role(UserRole.ADMIN):
        stmt = stmt.where(
            or_(
                Dashboard.owner_user_id == actor.user.id,
                Dashboard.shared.is_(True),
            )
        )
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_out(d) for d in rows]


@router.get("/default", response_model=DashboardOut)
async def get_default(
    db: DbSession,
    actor: RequireAnalyst,
) -> DashboardOut:
    """Return the caller's default dashboard, auto-creating one
    populated with the historical hardcoded layout on first call.

    The default is per-owner unique by partial UNIQUE index, so on
    second + Nth call the SELECT finds the existing row. The /default
    contract is what `Dashboard.tsx` hits on every page load — the
    auto-create keeps the page from rendering an empty grid for a new
    user.
    """
    stmt = select(Dashboard).where(
        Dashboard.owner_user_id == actor.user.id,
        Dashboard.is_default.is_(True),
        Dashboard.tenant_id == actor.tenant_id,
    )
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing is not None:
        return _to_out(existing)

    d = Dashboard(
        tenant_id=actor.tenant_id,
        owner_user_id=actor.user.id,
        name="Overview",
        description="Auto-generated default dashboard.",
        shared=False,
        is_default=True,
        widgets_json=default_layout(),
    )
    db.add(d)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="dashboard.create",
        resource_type="dashboard",
        resource_id=str(d.id),
        payload={"name": d.name, "is_default": True, "auto": True},
    )
    await db.commit()
    await db.refresh(d)
    return _to_out(d)


@router.post("", response_model=DashboardOut, status_code=status.HTTP_201_CREATED)
async def create_dashboard(
    payload: DashboardCreate,
    db: DbSession,
    actor: RequireAnalyst,
) -> DashboardOut:
    d = Dashboard(
        tenant_id=actor.tenant_id,
        owner_user_id=actor.user.id,
        name=payload.name,
        description=payload.description,
        shared=payload.shared,
        is_default=False,
        widgets_json=[w.model_dump(mode="json") for w in payload.widgets_json],
    )
    db.add(d)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="dashboard.create",
        resource_type="dashboard",
        resource_id=str(d.id),
        payload={"name": d.name, "shared": d.shared},
    )
    await db.commit()
    await db.refresh(d)
    return _to_out(d)


@router.get("/{dashboard_id}", response_model=DashboardOut)
async def get_dashboard(
    dashboard_id: UUID,
    db: DbSession,
    actor: RequireViewer,
) -> DashboardOut:
    d = await _load_or_404(db, dashboard_id, actor)
    if not _can_read(actor, d):
        # 404 instead of 403 so existence isn't leaked across teams.
        raise not_found("dashboard", str(dashboard_id))
    return _to_out(d)


@router.put("/{dashboard_id}", response_model=DashboardOut)
async def update_dashboard(
    dashboard_id: UUID,
    payload: DashboardUpdate,
    db: DbSession,
    actor: RequireAnalyst,
) -> DashboardOut:
    d = await _load_or_404(db, dashboard_id, actor)
    # Non-owners need the existence cloaking — but a shared dashboard
    # is fine to "fail to edit" with 403 because the GET already
    # confirms existence. Use the standard owner check.
    if not _can_read(actor, d):
        raise not_found("dashboard", str(dashboard_id))
    _assert_can_edit(actor, d)

    if payload.name is not None:
        d.name = payload.name
    if "description" in payload.model_fields_set:
        d.description = payload.description
    if payload.shared is not None:
        d.shared = payload.shared
    if payload.widgets_json is not None:
        d.widgets_json = [w.model_dump(mode="json") for w in payload.widgets_json]
    if payload.is_default is not None:
        if payload.is_default:
            # Demote any current default before promoting this one —
            # the partial UNIQUE index would reject the second true.
            await _clear_existing_default(db, owner_user_id=d.owner_user_id)
            d.is_default = True
        else:
            d.is_default = False
    d.updated_at = datetime.now(d.updated_at.tzinfo) if d.updated_at else datetime.now()

    await audit.record(
        db,
        actor=actor,
        action="dashboard.update",
        resource_type="dashboard",
        resource_id=str(d.id),
        payload={"name": d.name, "shared": d.shared, "is_default": d.is_default},
    )
    await db.commit()
    await db.refresh(d)
    return _to_out(d)


@router.delete("/{dashboard_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_dashboard(
    dashboard_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
) -> None:
    d = await _load_or_404(db, dashboard_id, actor)
    if not _can_read(actor, d):
        raise not_found("dashboard", str(dashboard_id))
    _assert_can_edit(actor, d)
    await db.delete(d)
    await audit.record(
        db,
        actor=actor,
        action="dashboard.delete",
        resource_type="dashboard",
        resource_id=str(dashboard_id),
        payload={"name": d.name},
    )
    await db.commit()


@router.post(
    "/{dashboard_id}/duplicate",
    response_model=DashboardOut,
    status_code=status.HTTP_201_CREATED,
)
async def duplicate_dashboard(
    dashboard_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
) -> DashboardOut:
    """Clone an existing dashboard into the caller's namespace. The
    clone is owned by the caller (regardless of who owned the source),
    starts unshared, and is never the default — so duplicating someone
    else's shared overview gives the analyst their own editable copy
    without changing anything visible to the rest of the team."""
    src = await _load_or_404(db, dashboard_id, actor)
    if not _can_read(actor, src):
        raise not_found("dashboard", str(dashboard_id))

    clone = Dashboard(
        tenant_id=actor.tenant_id,
        owner_user_id=actor.user.id,
        name=f"{src.name} (copy)",
        description=src.description,
        shared=False,
        is_default=False,
        widgets_json=list(src.widgets_json or []),
    )
    db.add(clone)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="dashboard.create",
        resource_type="dashboard",
        resource_id=str(clone.id),
        payload={"name": clone.name, "source_id": str(src.id), "duplicated": True},
    )
    await db.commit()
    await db.refresh(clone)
    return _to_out(clone)


@router.get("/{dashboard_id}/data", response_model=list[WidgetData])
async def get_dashboard_data(
    dashboard_id: UUID,
    db: DbSession,
    actor: RequireViewer,
) -> list[WidgetData]:
    """Resolve every widget on the dashboard in its persisted order.

    The response array is positional — `data[i]` is the resolved
    payload for `widgets_json[i]`. Per-widget failures land as an
    `error` string on the entry so the renderer can show "this card
    couldn't load" without dropping the rest of the grid.
    """
    d = await _load_or_404(db, dashboard_id, actor)
    if not _can_read(actor, d):
        raise not_found("dashboard", str(dashboard_id))
    # The DB stores widgets as raw JSON; re-validate through the
    # Pydantic union so the dispatcher sees typed objects (and a
    # mid-rollout schema mismatch surfaces as a per-widget error rather
    # than a 500).
    from pydantic import TypeAdapter

    from app.schemas.dashboard import Widget

    adapter: TypeAdapter[Any] = TypeAdapter(list[Widget])
    try:
        widgets = adapter.validate_python(d.widgets_json or [])
    except Exception as exc:  # noqa: BLE001
        # Whole-payload parse failure (somehow a non-list landed in
        # widgets_json). Return a single error stub so the UI can show
        # "dashboard layout is corrupted" rather than crashing.
        return [WidgetData(type="unknown", data=None, error=str(exc))]
    return [await resolve_widget(db, w, actor) for w in widgets]


__all__ = ("router",)
