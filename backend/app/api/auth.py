"""Login, refresh, logout."""

from __future__ import annotations

from uuid import UUID

import jwt
from fastapi import APIRouter, Request

from app.core.db import SessionLocal
from app.core.deps import DbSession
from app.core.errors import unauthorized
from app.core.security import decode_jwt
from app.models import User
from app.schemas.auth import LoginRequest, RefreshRequest, TokenPair
from app.services import audit
from app.services import auth as auth_service

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenPair)
async def login(payload: LoginRequest, request: Request, db: DbSession) -> TokenPair:
    ip = request.client.host if request.client else None
    try:
        user = await auth_service.authenticate(db, email=payload.email, password=payload.password)
    except auth_service.InvalidCredentials as exc:
        # M-audit-and-auth #1: record failed logins so brute-force /
        # credential-stuffing has a trip-wire. We can't write through
        # `db` because the request session will rollback on the raised
        # 401 — open a fresh session that commits independently.
        async with SessionLocal() as audit_db:
            await audit.record(
                audit_db,
                actor=None,
                action="user.login.failed",
                resource_type="user",
                resource_id=exc.user_id,
                payload={"email": payload.email.lower(), "reason": exc.reason},
                ip=ip,
            )
            await audit_db.commit()
        raise unauthorized("invalid credentials") from exc

    await audit.record(
        db,
        actor=None,
        action="user.login",
        resource_type="user",
        resource_id=str(user.id),
        ip=ip,
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
