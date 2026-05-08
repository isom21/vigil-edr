"""Append-only audit log helper."""
from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import Actor
from app.models import AuditLog


async def record(
    db: AsyncSession,
    *,
    actor: Actor | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    payload: dict[str, Any] | None = None,
    ip: str | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=actor.user.id if actor else None,
            actor_kind=actor.kind if actor else "system",
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            payload=payload,
            ip=ip,
        )
    )
