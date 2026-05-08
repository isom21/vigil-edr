"""Login, refresh, logout."""
from __future__ import annotations

from uuid import UUID

import jwt
from fastapi import APIRouter

from app.core.deps import DbSession
from app.core.errors import unauthorized
from app.core.security import decode_jwt, issue_jwt
from app.models import User
from app.schemas.auth import LoginRequest, RefreshRequest, TokenPair
from app.services import audit, auth as auth_service

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenPair)
async def login(payload: LoginRequest, db: DbSession) -> TokenPair:
    user = await auth_service.authenticate(db, email=payload.email, password=payload.password)
    await audit.record(
        db, actor=None, action="user.login", resource_type="user", resource_id=str(user.id)
    )
    return TokenPair(**auth_service.issue_token_pair(user))


@router.post("/refresh", response_model=TokenPair)
async def refresh(payload: RefreshRequest, db: DbSession) -> TokenPair:
    try:
        decoded = decode_jwt(payload.refresh_token)
    except jwt.ExpiredSignatureError as exc:
        raise unauthorized("refresh token expired") from exc
    except jwt.PyJWTError as exc:
        raise unauthorized("invalid refresh token") from exc
    if decoded.get("type") != "refresh":
        raise unauthorized("not a refresh token")
    user = await db.get(User, UUID(decoded["sub"]))
    if user is None or user.disabled:
        raise unauthorized("user inactive")
    return TokenPair(**auth_service.issue_token_pair(user))
