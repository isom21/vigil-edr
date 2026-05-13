"""Tenant CRUD — super-admin only (Phase 3 #3.1).

Endpoints under ``/api/tenants``:

* ``GET    /api/tenants``        — list all tenants
* ``POST   /api/tenants``        — create a tenant
* ``GET    /api/tenants/{id}``   — fetch one
* ``PATCH  /api/tenants/{id}``   — rename / disable / re-enable
* ``DELETE /api/tenants/{id}``   — refuse if the tenant still owns rows

Every endpoint is gated on the super-admin bit and every mutating
endpoint writes an audit row. The mutating endpoints intentionally
audit-record under the *target* tenant so each tenant's audit chain
sees its own lifecycle events — a super-admin creating tenant B
from inside tenant A logs the create in B's chain.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import func, select

from app.core.deps import DbSession, RequireSuperAdmin
from app.core.errors import bad_request, conflict, not_found
from app.models import Host, Tenant, User
from app.models.tenant import DEFAULT_TENANT_ID
from app.schemas.tenant import TenantCreate, TenantOut, TenantUpdate
from app.services import audit

router = APIRouter(prefix="/api/tenants", tags=["tenants"])


@router.get("", response_model=list[TenantOut])
async def list_tenants(db: DbSession, actor: RequireSuperAdmin) -> list[TenantOut]:
    rows = (await db.execute(select(Tenant).order_by(Tenant.slug.asc()))).scalars().all()
    return [TenantOut.model_validate(t) for t in rows]


@router.post("", response_model=TenantOut, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    payload: TenantCreate, db: DbSession, actor: RequireSuperAdmin
) -> TenantOut:
    existing = (
        await db.execute(select(Tenant).where(Tenant.slug == payload.slug))
    ).scalar_one_or_none()
    if existing is not None:
        raise conflict("slug already in use")
    tenant = Tenant(slug=payload.slug, name=payload.name)
    db.add(tenant)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="tenant.create",
        resource_type="tenant",
        resource_id=str(tenant.id),
        payload={"slug": tenant.slug, "name": tenant.name},
        # The new tenant has no chain yet — record under its own
        # tenant_id so the row becomes the genesis of that chain.
        tenant_id=tenant.id,
    )
    return TenantOut.model_validate(tenant)


@router.get("/{tenant_id}", response_model=TenantOut)
async def get_tenant(tenant_id: UUID, db: DbSession, actor: RequireSuperAdmin) -> TenantOut:
    tenant = await db.get(Tenant, tenant_id)
    if tenant is None:
        raise not_found("tenant", str(tenant_id))
    return TenantOut.model_validate(tenant)


@router.patch("/{tenant_id}", response_model=TenantOut)
async def update_tenant(
    tenant_id: UUID,
    payload: TenantUpdate,
    db: DbSession,
    actor: RequireSuperAdmin,
) -> TenantOut:
    tenant = await db.get(Tenant, tenant_id)
    if tenant is None:
        raise not_found("tenant", str(tenant_id))
    changes: dict[str, str | bool] = {}
    if payload.name is not None and payload.name != tenant.name:
        tenant.name = payload.name
        changes["name"] = payload.name
    if payload.disabled is not None and payload.disabled != tenant.disabled:
        # Refuse to disable the default tenant — too easy to brick
        # the install since every fixture and seeded resource lives
        # there.
        if tenant.id == DEFAULT_TENANT_ID and payload.disabled is True:
            raise bad_request("cannot disable the default tenant")
        tenant.disabled = payload.disabled
        changes["disabled"] = payload.disabled
    if changes:
        await audit.record(
            db,
            actor=actor,
            action="tenant.update",
            resource_type="tenant",
            resource_id=str(tenant.id),
            payload=changes,
            tenant_id=tenant.id,
        )
    return TenantOut.model_validate(tenant)


@router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant(tenant_id: UUID, db: DbSession, actor: RequireSuperAdmin) -> None:
    if tenant_id == DEFAULT_TENANT_ID:
        raise bad_request("cannot delete the default tenant")
    tenant = await db.get(Tenant, tenant_id)
    if tenant is None:
        raise not_found("tenant", str(tenant_id))
    # Refuse to delete a tenant that still owns rows. The FK is
    # ``ON DELETE RESTRICT`` at the DB level, so the DELETE would
    # blow up anyway — but a friendly 400 is nicer than a generic
    # integrity-error 500.
    host_count = (
        await db.execute(select(func.count(Host.id)).where(Host.tenant_id == tenant_id))
    ).scalar_one()
    user_count = (
        await db.execute(select(func.count(User.id)).where(User.tenant_id == tenant_id))
    ).scalar_one()
    if host_count or user_count:
        raise bad_request(
            f"tenant still owns rows (hosts={host_count}, users={user_count}); "
            "move or delete dependents first"
        )
    await db.delete(tenant)
    await audit.record(
        db,
        actor=actor,
        action="tenant.delete",
        resource_type="tenant",
        resource_id=str(tenant_id),
        payload={"slug": tenant.slug},
        # Record under the actor's tenant — the deleted tenant's
        # chain is going away with it.
        tenant_id=actor.tenant_id,
    )
