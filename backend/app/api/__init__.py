"""Aggregate FastAPI routers."""
from fastapi import APIRouter

from app.api import (
    alerts,
    api_tokens,
    auth,
    commands,
    enrollment,
    host_groups,
    hosts,
    me,
    policies,
    rules,
    sigma,
    users,
)

api_router = APIRouter()
for module in (
    auth, me, users, hosts, host_groups, rules, policies,
    alerts, enrollment, api_tokens, sigma, commands,
):
    api_router.include_router(module.router)
# Cross-host commands listing (M7.6) lives on a separate router so it
# doesn't collide with /api/hosts/{host_id}/commands.
api_router.include_router(commands.all_router)

__all__ = ["api_router"]
