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

__all__ = ["api_router"]
