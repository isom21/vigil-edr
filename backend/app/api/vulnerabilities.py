"""Vulnerability assessment API (Phase 2 #2.7).

Read endpoints are open to viewers; suppression is admin-only and
audited. The host-scoped list applies `host_visible_to` so analysts
limited to a host-group only see CVEs for their hosts.

Routes:
  * `GET  /api/vulnerabilities`                — list CVEs across
    visible hosts. Pages via limit/offset; filters on severity +
    host_id + suppression state.
  * `GET  /api/vulnerabilities/{cve_id}`       — single CVE summary.
  * `GET  /api/hosts/{id}/vulnerabilities`     — per-host list.
  * `POST /api/host-vulnerabilities/{id}/suppress` — admin toggle.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import structlog
from fastapi import APIRouter, Query, status
from sqlalchemy import and_, func, select

from app.core.deps import DbSession, RequireAdmin, RequireViewer
from app.core.errors import bad_request, not_found
from app.models import HostVulnerability, Vulnerability
from app.schemas.common import Page
from app.schemas.vulnerability import (
    HostVulnerabilityOut,
    SuppressRequest,
    VulnerabilityOut,
)
from app.services import audit
from app.services.scoping import apply_host_scope, host_visible_to

log = structlog.get_logger()

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])
host_scoped_router = APIRouter(prefix="/api/hosts", tags=["vulnerabilities"])
suppress_router = APIRouter(prefix="/api/host-vulnerabilities", tags=["vulnerabilities"])


def _hv_to_out(row: HostVulnerability, vuln: Vulnerability | None) -> HostVulnerabilityOut:
    return HostVulnerabilityOut(
        id=row.id,
        host_id=row.host_id,
        cve_id=row.cve_id,
        cpe=row.cpe,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        suppressed=row.suppressed,
        suppressed_at=row.suppressed_at,
        suppressed_by_user_id=row.suppressed_by_user_id,
        severity=vuln.severity if vuln else None,
        cvss_v3_score=vuln.cvss_v3_score if vuln else None,
        summary=vuln.summary if vuln else None,
    )


def _scope_to_visible(stmt, actor):
    """Restrict a HostVulnerability-joined query to hosts the actor
    can see. Reuses the shared `apply_host_scope` helper, keyed on
    `HostVulnerability.host_id` instead of the default `Host.id`."""
    return apply_host_scope(stmt, actor, host_column=HostVulnerability.host_id)


@router.get("", response_model=Page[HostVulnerabilityOut])
async def list_vulnerabilities(
    db: DbSession,
    actor: RequireViewer,
    host_id: UUID | None = None,
    cve_id: str | None = None,
    severity: str | None = None,
    include_suppressed: bool = False,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page[HostVulnerabilityOut]:
    stmt = (
        select(HostVulnerability, Vulnerability)
        .join(Vulnerability, Vulnerability.cve_id == HostVulnerability.cve_id)
        .order_by(
            Vulnerability.cvss_v3_score.desc().nulls_last(),
            HostVulnerability.last_seen.desc(),
        )
        .limit(limit)
        .offset(offset)
    )
    count_stmt = (
        select(func.count())
        .select_from(HostVulnerability)
        .join(Vulnerability, Vulnerability.cve_id == HostVulnerability.cve_id)
    )

    filters = []
    if host_id is not None:
        filters.append(HostVulnerability.host_id == host_id)
    if cve_id is not None:
        filters.append(HostVulnerability.cve_id == cve_id)
    if severity is not None:
        filters.append(Vulnerability.severity == severity.lower())
    if not include_suppressed:
        filters.append(HostVulnerability.suppressed.is_(False))
    if filters:
        stmt = stmt.where(and_(*filters))
        count_stmt = count_stmt.where(and_(*filters))

    stmt = _scope_to_visible(stmt, actor)
    count_stmt = _scope_to_visible(count_stmt, actor)

    if host_id is not None and not await host_visible_to(actor, host_id, db):
        raise not_found("host", str(host_id))

    rows = (await db.execute(stmt)).all()
    total = int((await db.execute(count_stmt)).scalar_one())
    items = [_hv_to_out(hv, v) for hv, v in rows]
    return Page(items=items, total=total, limit=limit, offset=offset)


@router.get("/{cve_id}", response_model=VulnerabilityOut)
async def get_vulnerability(cve_id: str, db: DbSession, actor: RequireViewer) -> VulnerabilityOut:
    vuln = await db.get(Vulnerability, cve_id)
    if vuln is None:
        raise not_found("vulnerability", cve_id)
    return VulnerabilityOut.model_validate(vuln)


@host_scoped_router.get(
    "/{host_id}/vulnerabilities",
    response_model=Page[HostVulnerabilityOut],
)
async def list_host_vulnerabilities(
    host_id: UUID,
    db: DbSession,
    actor: RequireViewer,
    include_suppressed: bool = False,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page[HostVulnerabilityOut]:
    if not await host_visible_to(actor, host_id, db):
        raise not_found("host", str(host_id))
    stmt = (
        select(HostVulnerability, Vulnerability)
        .join(Vulnerability, Vulnerability.cve_id == HostVulnerability.cve_id)
        .where(HostVulnerability.host_id == host_id)
        .order_by(
            Vulnerability.cvss_v3_score.desc().nulls_last(),
            HostVulnerability.last_seen.desc(),
        )
        .limit(limit)
        .offset(offset)
    )
    count_stmt = (
        select(func.count())
        .select_from(HostVulnerability)
        .where(HostVulnerability.host_id == host_id)
    )
    if not include_suppressed:
        stmt = stmt.where(HostVulnerability.suppressed.is_(False))
        count_stmt = count_stmt.where(HostVulnerability.suppressed.is_(False))
    rows = (await db.execute(stmt)).all()
    total = int((await db.execute(count_stmt)).scalar_one())
    items = [_hv_to_out(hv, v) for hv, v in rows]
    return Page(items=items, total=total, limit=limit, offset=offset)


@suppress_router.post(
    "/{host_vuln_id}/suppress",
    response_model=HostVulnerabilityOut,
    status_code=status.HTTP_200_OK,
)
async def suppress_host_vulnerability(
    host_vuln_id: UUID,
    payload: SuppressRequest,
    db: DbSession,
    actor: RequireAdmin,
) -> HostVulnerabilityOut:
    """Toggle suppression on a (host, CVE) row. Admin-only; audited.

    `suppressed` flips, `suppressed_at` becomes now / NULL, and the
    audit payload captures the operator's `reason` so reviewers can
    answer "why is this CVE hidden?" without digging through chat
    transcripts.
    """
    row = await db.get(HostVulnerability, host_vuln_id)
    if row is None:
        raise not_found("host_vulnerability", str(host_vuln_id))

    new_state = not row.suppressed
    if new_state:
        row.suppressed = True
        row.suppressed_at = datetime.now(UTC)
        row.suppressed_by_user_id = actor.user.id
        action = "host_vulnerability.suppress"
    else:
        row.suppressed = False
        row.suppressed_at = None
        row.suppressed_by_user_id = None
        action = "host_vulnerability.unsuppress"
    audit_payload: dict = {
        "cve_id": row.cve_id,
        "host_id": str(row.host_id),
    }
    if payload.reason is not None:
        reason = payload.reason.strip()
        if reason:
            if len(reason) > 1024:
                raise bad_request("reason must be 1024 characters or fewer")
            audit_payload["reason"] = reason
    await audit.record(
        db,
        actor=actor,
        action=action,
        resource_type="host_vulnerability",
        resource_id=str(row.id),
        payload=audit_payload,
    )
    await db.commit()
    await db.refresh(row)
    vuln = await db.get(Vulnerability, row.cve_id)
    return _hv_to_out(row, vuln)
