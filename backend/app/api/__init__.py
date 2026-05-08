"""Aggregate FastAPI routers."""
from fastapi import APIRouter

from app.api import (
    alerts,
    api_tokens,
    auth,
    enrollment,
    hosts,
    me,
    policies,
    rules,
    users,
)

api_router = APIRouter()
for module in (auth, me, users, hosts, rules, policies, alerts, enrollment, api_tokens):
    api_router.include_router(module.router)

__all__ = ["api_router"]
