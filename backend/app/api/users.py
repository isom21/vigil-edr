"""User CRUD (admin-only)."""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.deps import DbSession, RequireAdmin
from app.core.errors import conflict, not_found
from app.core.security import hash_password
from app.models import User
from app.schemas.user import UserCreate, UserOut, UserUpdate
from app.services import audit

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserOut])
async def list_users(db: DbSession, actor: RequireAdmin) -> list[UserOut]:
    rows = (await db.execute(select(User).order_by(User.created_at.desc()))).scalars().all()
    return [UserOut.model_validate(u) for u in rows]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(payload: UserCreate, db: DbSession, actor: RequireAdmin) -> UserOut:
    email = payload.email.lower()
    existing = (
        await db.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()
    if existing:
        raise conflict("email already in use")
    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        role=payload.role,
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
    user = await db.get(User, user_id)
    if user is None:
        raise not_found("user", str(user_id))
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


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    user = await db.get(User, user_id)
    if user is None:
        raise not_found("user", str(user_id))
    await db.delete(user)
    await audit.record(
        db, actor=actor, action="user.delete", resource_type="user", resource_id=str(user_id)
    )
