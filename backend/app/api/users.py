"""User CRUD (admin-only)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, insert, select

from app.core.deps import DbSession, RequireAdmin
from app.core.errors import bad_request, conflict, not_found
from app.core.security import hash_password
from app.models import HostGroup, User, UserRole, user_host_group
from app.schemas.user import UserCreate, UserOut, UserUpdate
from app.services import audit
from app.services.scoping import apply_tenant_scope

router = APIRouter(prefix="/api/users", tags=["users"])


async def _enabled_admin_count(
    db: DbSession,
    *,
    tenant_id: UUID,
    exclude_user_id: UUID | None = None,
) -> int:
    """How many admins would remain enabled IN THIS TENANT if the user
    identified by `exclude_user_id` were either deleted or had their
    role/disabled flag flipped.

    Phase 3 #3.1 (CODE-2): the last-admin check is per-tenant.
    Deleting tenant A's only admin must fail even when tenant B has
    other admins, because tenant A's analysts can't bootstrap a new
    admin from tenant B's roster.
    """
    stmt = select(func.count(User.id)).where(
        User.role == UserRole.ADMIN,
        User.disabled.is_(False),
        User.tenant_id == tenant_id,
    )
    if exclude_user_id is not None:
        stmt = stmt.where(User.id != exclude_user_id)
    return int((await db.execute(stmt)).scalar_one())


async def _load_in_tenant(db, user_id: UUID, actor) -> User:
    """Fetch a user, enforcing tenant scope. 404 on cross-tenant id
    (existence stays opaque). Super-admins still see across tenants
    via `apply_tenant_scope`'s active-tenant convention — their
    actor.tenant_id is the active tenant set from the cookie."""
    user = await db.get(User, user_id)
    if user is None or user.tenant_id != actor.tenant_id:
        raise not_found("user", str(user_id))
    return user


class UserGroupAssignment(BaseModel):
    """M17.h: list of host_group ids the user can see. Mirrors
    HostGroupMembership shape but inverted (per-user view of groups
    rather than per-group view of users)."""

    host_group_ids: list[UUID] = Field(default_factory=list)


@router.get("", response_model=list[UserOut])
async def list_users(db: DbSession, actor: RequireAdmin) -> list[UserOut]:
    # CODE-2: scope the roster to the actor's tenant. Without this an
    # admin in tenant A could enumerate every tenant's users + email
    # addresses.
    stmt = apply_tenant_scope(select(User), actor, User.tenant_id).order_by(User.created_at.desc())
    rows = (await db.execute(stmt)).scalars().all()
    return [UserOut.model_validate(u) for u in rows]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(payload: UserCreate, db: DbSession, actor: RequireAdmin) -> UserOut:
    email = payload.email.lower()
    # Email uniqueness is global across tenants — User.email has a
    # unique index — so an existence check needs no tenant filter.
    existing = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if existing:
        raise conflict("email already in use")
    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        tenant_id=actor.tenant_id,
    )
    db.add(user)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="user.create",
        resource_type="user",
        resource_id=str(user.id),
        payload={"email": email, "role": payload.role.value},
    )
    return UserOut.model_validate(user)


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: UUID, payload: UserUpdate, db: DbSession, actor: RequireAdmin
) -> UserOut:
    user = await _load_in_tenant(db, user_id, actor)

    # LOW #1: refuse the operation if it would drop the count of
    # enabled admins to zero. Two paths get us there: demote the last
    # admin to analyst/viewer, or disable the last admin. Both are
    # reversible — but only by another admin, so they bricks the
    # console.
    would_become_non_admin = payload.role is not None and payload.role != UserRole.ADMIN
    would_become_disabled = payload.disabled is True
    if (
        user.role == UserRole.ADMIN
        and not user.disabled
        and (would_become_non_admin or would_become_disabled)
    ):
        remaining = await _enabled_admin_count(
            db, tenant_id=user.tenant_id, exclude_user_id=user.id
        )
        if remaining == 0:
            raise bad_request(
                "cannot disable or demote the last enabled admin; promote another admin first"
            )

    if payload.role is not None:
        user.role = payload.role
    if payload.disabled is not None:
        user.disabled = payload.disabled
    if payload.password is not None:
        user.password_hash = hash_password(payload.password)
    await audit.record(
        db,
        actor=actor,
        action="user.update",
        resource_type="user",
        resource_id=str(user.id),
        payload=payload.model_dump(exclude={"password"}, exclude_none=True),
    )
    return UserOut.model_validate(user)


@router.post("/{user_id}/2fa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def admin_disable_2fa(user_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    """Admin force-disable of another user's 2FA. Account-recovery
    path for users who've lost both their authenticator and recovery
    codes. The target user re-enrolls from scratch on their next
    login. Always audited; never silent."""
    user = await _load_in_tenant(db, user_id, actor)
    if not user.totp_enabled and user.totp_pending_secret_encrypted is None:
        raise bad_request("2fa is not enabled on this account")
    user.totp_enabled = False
    user.totp_secret_encrypted = None
    user.totp_pending_secret_encrypted = None
    user.totp_recovery_codes_hashed = None
    await audit.record(
        db,
        actor=actor,
        action="user.2fa.admin_disabled",
        resource_type="user",
        resource_id=str(user_id),
    )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    user = await _load_in_tenant(db, user_id, actor)

    # LOW #1: same lockout guard as update_user — deleting the last
    # enabled admin bricks the console. Two SOC admins each clicking
    # "delete me" at the same time get one through and one bounced;
    # the loser sees a 400 with a clear message.
    if user.role == UserRole.ADMIN and not user.disabled:
        remaining = await _enabled_admin_count(
            db, tenant_id=user.tenant_id, exclude_user_id=user.id
        )
        if remaining == 0:
            raise bad_request("cannot delete the last enabled admin; promote another admin first")

    await db.delete(user)
    await audit.record(
        db, actor=actor, action="user.delete", resource_type="user", resource_id=str(user_id)
    )


# ---------- M17.h: per-user host-group assignment -----------------------


@router.get("/{user_id}/groups", response_model=UserGroupAssignment)
async def get_user_groups(user_id: UUID, db: DbSession, actor: RequireAdmin) -> UserGroupAssignment:
    await _load_in_tenant(db, user_id, actor)
    rows = (
        (
            await db.execute(
                select(user_host_group.c.host_group_id).where(user_host_group.c.user_id == user_id)
            )
        )
        .scalars()
        .all()
    )
    return UserGroupAssignment(host_group_ids=list(rows))


@router.post("/{user_id}/groups", response_model=UserGroupAssignment)
async def replace_user_groups(
    user_id: UUID,
    body: UserGroupAssignment,
    db: DbSession,
    actor: RequireAdmin,
) -> UserGroupAssignment:
    """Atomic-replace the user's host-group membership. Mirror of
    /api/host-groups/{id}/members but inverted. Idempotent: any
    unknown group id is silently ignored."""
    await _load_in_tenant(db, user_id, actor)

    # CODE-3: validate group ids against actor.tenant_id; drop unknowns
    # AND drop cross-tenant references silently (same convention as
    # /api/host-groups/{id}/members). Without the tenant_id filter
    # here, an admin in tenant A could grant their analysts visibility
    # into tenant B's hosts via a tenant-B host_group id.
    valid_groups: list[UUID] = []
    if body.host_group_ids:
        valid_groups = list(
            (
                await db.execute(
                    select(HostGroup.id)
                    .where(HostGroup.id.in_(body.host_group_ids))
                    .where(HostGroup.tenant_id == actor.tenant_id)
                )
            )
            .scalars()
            .all()
        )

    await db.execute(delete(user_host_group).where(user_host_group.c.user_id == user_id))
    for gid in valid_groups:
        await db.execute(insert(user_host_group).values(user_id=user_id, host_group_id=gid))

    await audit.record(
        db,
        actor=actor,
        action="user.groups.replace",
        resource_type="user",
        resource_id=str(user_id),
        payload={"host_group_ids": [str(g) for g in valid_groups]},
    )
    await db.commit()
    return UserGroupAssignment(host_group_ids=list(valid_groups))
