"""Aggregate FastAPI routers."""

from fastapi import APIRouter

from app.api import (
    alerts,
    allowlist,
    api_tokens,
    archive,
    audit,
    auth,
    case_destinations,
    commands,
    dashboards,
    device_policies,
    dns_block,
    enrollment,
    host_groups,
    host_terminal,
    hosts,
    hunt,
    incidents,
    intel,
    jobs,
    me,
    metrics,
    mitre,
    notifications,
    playbooks,
    policies,
    process_chain,
    quarantine,
    rollouts,
    routing,
    rule_groups,
    rules,
    scim,
    scim_tokens,
    sequence_rules,
    siem_destinations,
    sigma,
    tenants,
    uploads,
    users,
    vulnerabilities,
    webhooks,
)

api_router = APIRouter()
for module in (
    auth,
    me,
    users,
    hosts,
    host_groups,
    rules,
    rule_groups,
    policies,
    alerts,
    incidents,
    enrollment,
    api_tokens,
    audit,
    sigma,
    commands,
    metrics,
    mitre,
    intel,
    siem_destinations,
    notifications,
    routing,
    allowlist,
    dns_block,
    device_policies,
    hunt,
    dashboards,
    process_chain,
    rollouts,
    sequence_rules,
    webhooks,
    playbooks,
    case_destinations,
    scim_tokens,
    archive,
    tenants,
):
    api_router.include_router(module.router)
# Cross-host commands listing (M7.6) lives on a separate router so it
# doesn't collide with /api/hosts/{host_id}/commands.
api_router.include_router(commands.all_router)
# M20.c: quarantine inventory uses two prefixes — list-per-host under
# /api/hosts/:id/quarantined, mutations under /api/quarantined/:id.
api_router.include_router(quarantine.per_host_router)
api_router.include_router(quarantine.flat_router)
# M23.b: Jobs engine — /api/jobs for the user-facing primitive,
# /api/artifacts for download links.
api_router.include_router(jobs.router)
api_router.include_router(jobs.artifacts_router)
# M23.k: agent → manager → MinIO upload proxy + analyst download
# proxy. Agents never see MinIO directly.
api_router.include_router(uploads.upload_router)
api_router.include_router(uploads.download_router)
# Phase 1 #1.4: live-response remote shell. The router exposes both
# the REST `POST /api/hosts/{id}/terminal` (mint session) and the
# `GET /api/hosts/{id}/terminal/ws` WebSocket relay.
api_router.include_router(host_terminal.router)
# Phase 2 #2.7: vulnerability assessment. Three prefixes — the
# fleet-wide list at `/api/vulnerabilities`, the per-host list under
# `/api/hosts/{id}/vulnerabilities` (mounted on the shared `hosts`
# prefix router), and the admin suppress action under
# `/api/host-vulnerabilities/{id}/suppress`.
api_router.include_router(vulnerabilities.router)
api_router.include_router(vulnerabilities.host_scoped_router)
api_router.include_router(vulnerabilities.suppress_router)

# Phase 3 #3.8: SCIM 2.0. SCIM mounts at `/scim/v2` (root, NOT under
# `/api/`) per RFC 7644 — most IdPs hardcode `/scim/v2` as the
# endpoint prefix and won't tolerate a custom prefix at the IdP-config
# layer. The router carries its own `prefix=settings.scim_base_path`.
scim_router = scim.router

__all__ = ["api_router", "scim_router"]
