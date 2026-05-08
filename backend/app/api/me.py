"""Current actor / self endpoints."""
from __future__ import annotations

from fastapi import APIRouter

from app.core.deps import CurrentActor
from app.schemas.user import UserOut

router = APIRouter(prefix="/api/me", tags=["me"])


@router.get("", response_model=UserOut)
async def get_me(actor: CurrentActor) -> UserOut:
    return UserOut.model_validate(actor.user)
