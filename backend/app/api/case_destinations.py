"""External case-management destinations CRUD (Phase 3 #3.6).

Admin-only. Every mutation is audited; the audit payload elides the
`config` blob entirely — the credential never round-trips through
the audit log (matches `siem_destinations.py`'s shape modulo
redaction, because we don't bother decrypting + redacting here when
we can just drop the field).

The `POST /:id/test` endpoint runs a dry-run `create_issue` with a
synthetic alert and returns the outcome. Operators use this to
validate that a freshly-registered destination's credentials actually
work without having to drive a real alert into the new state.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.deps import DbSession, RequireAdmin
from app.core.errors import bad_request, conflict, not_found
from app.models import Alert, AlertState, CaseDestination, CaseDestinationKind, RuleAction, Severity
from app.schemas.case import (
    CaseDestinationCreate,
    CaseDestinationOut,
    CaseDestinationTestResult,
    CaseDestinationUpdate,
)
from app.services import audit
from app.services.case import CaseSyncError
from app.services.case_management import _create_external_issue
from app.services.encryption import encrypt_config

router = APIRouter(prefix="/api/case-destinations", tags=["case-destinations"])


def _kind_required_fields(kind: CaseDestinationKind) -> tuple[str, ...]:
    """Per-kind required-keys gate. Mirrors the validation each per-kind
    client does at call time so the operator gets a 400 at registration
    instead of a vague 500 on the first state transition."""
    if kind is CaseDestinationKind.JIRA:
        return ("base_url", "email", "api_token", "project_key")
    if kind is CaseDestinationKind.SERVICENOW:
        return ("instance_url", "username", "password")
    return ()


def _check_required(kind: CaseDestinationKind, config: dict) -> None:
    missing = [k for k in _kind_required_fields(kind) if not config.get(k)]
    if missing:
        raise bad_request(f"missing required config fields for {kind.value}: {','.join(missing)}")


def _to_out(dest: CaseDestination) -> CaseDestinationOut:
    return CaseDestinationOut(
        id=dest.id,
        kind=CaseDestinationKind.coerce(dest.kind),
        name=dest.name,
        enabled=dest.enabled,
        created_at=dest.created_at,
        updated_at=dest.updated_at,
    )


@router.get("", response_model=list[CaseDestinationOut])
async def list_destinations(db: DbSession, _actor: RequireAdmin) -> list[CaseDestinationOut]:
    rows = (
        (await db.execute(select(CaseDestination).order_by(CaseDestination.created_at.desc())))
        .scalars()
        .all()
    )
    return [_to_out(d) for d in rows]


@router.post("", response_model=CaseDestinationOut, status_code=status.HTTP_201_CREATED)
async def create_destination(
    payload: CaseDestinationCreate, db: DbSession, actor: RequireAdmin
) -> CaseDestinationOut:
    existing = (
        await db.execute(select(CaseDestination).where(CaseDestination.name == payload.name))
    ).scalar_one_or_none()
    if existing is not None:
        raise conflict("case destination name already in use")

    _check_required(payload.kind, payload.config)

    dest = CaseDestination(
        kind=payload.kind.value,
        name=payload.name,
        config_encrypted=encrypt_config(payload.config),
        enabled=payload.enabled,
    )
    db.add(dest)
    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="case_destination.create",
        resource_type="case_destination",
        resource_id=str(dest.id),
        payload={"name": payload.name, "kind": payload.kind.value, "enabled": payload.enabled},
    )
    return _to_out(dest)


@router.patch("/{dest_id}", response_model=CaseDestinationOut)
async def update_destination(
    dest_id: UUID,
    payload: CaseDestinationUpdate,
    db: DbSession,
    actor: RequireAdmin,
) -> CaseDestinationOut:
    dest = await db.get(CaseDestination, dest_id)
    if dest is None:
        raise not_found("case_destination", str(dest_id))

    audit_payload: dict = {}
    if payload.name is not None and payload.name != dest.name:
        clash = (
            await db.execute(
                select(CaseDestination.id).where(
                    CaseDestination.name == payload.name, CaseDestination.id != dest_id
                )
            )
        ).scalar_one_or_none()
        if clash is not None:
            raise conflict("case destination name already in use")
        dest.name = payload.name
        audit_payload["name"] = payload.name
    if payload.enabled is not None:
        dest.enabled = payload.enabled
        audit_payload["enabled"] = payload.enabled
    if payload.config is not None:
        _check_required(CaseDestinationKind.coerce(dest.kind), payload.config)
        dest.config_encrypted = encrypt_config(payload.config)
        # Don't audit the plaintext config — record only the fact of
        # rotation, which is what an operator reviewing the log needs.
        audit_payload["config_rotated"] = True

    await audit.record(
        db,
        actor=actor,
        action="case_destination.update",
        resource_type="case_destination",
        resource_id=str(dest.id),
        payload=audit_payload,
    )
    return _to_out(dest)


@router.delete("/{dest_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_destination(dest_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    dest = await db.get(CaseDestination, dest_id)
    if dest is None:
        raise not_found("case_destination", str(dest_id))
    name = dest.name
    kind_val = CaseDestinationKind.coerce(dest.kind).value
    await db.delete(dest)
    await audit.record(
        db,
        actor=actor,
        action="case_destination.delete",
        resource_type="case_destination",
        resource_id=str(dest_id),
        payload={"name": name, "kind": kind_val},
    )


@router.post("/{dest_id}/test", response_model=CaseDestinationTestResult)
async def test_destination(
    dest_id: UUID, db: DbSession, actor: RequireAdmin
) -> CaseDestinationTestResult:
    """Dry-run: open a synthetic issue against this destination.

    Uses a fake Alert (never persisted) so the credentials and routing
    are exercised without polluting the real alert table. The created
    issue is left in place on the tracker side — the operator deletes
    it manually after they confirm the integration works. The result
    is audited (operators want a "who poked at the integration" trail)
    but the audit payload elides the external URL since the test
    issue's URL counts as a tracker-internal artefact.
    """
    dest = await db.get(CaseDestination, dest_id)
    if dest is None:
        raise not_found("case_destination", str(dest_id))

    fake_alert = Alert(
        id=uuid.uuid4(),
        host_id=None,
        rule_id=uuid.uuid4(),
        severity=Severity.INFO,
        action_taken=RuleAction.ALERT,
        state=AlertState.NEW,
        summary="[Vigil] test issue — safe to delete",
        details={"reason": "case_destination.test"},
        opened_at=datetime.now(UTC),
        occurrence_count=1,
        last_occurred_at=datetime.now(UTC),
    )

    result: CaseDestinationTestResult
    try:
        external_id, external_url = await _create_external_issue(dest, fake_alert)
    except CaseSyncError as exc:
        result = CaseDestinationTestResult(ok=False, error=str(exc))
    else:
        result = CaseDestinationTestResult(
            ok=True, external_id=external_id, external_url=external_url
        )

    await audit.record(
        db,
        actor=actor,
        action="case_destination.test",
        resource_type="case_destination",
        resource_id=str(dest.id),
        payload={"ok": result.ok, "error": result.error},
    )
    return result
