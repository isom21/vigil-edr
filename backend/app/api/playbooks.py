"""Playbook CRUD + run history (Phase 3 #3.5).

Admin gate on every mutation; analysts + viewers read. Per-run rows
are listable under a playbook (`/api/playbooks/:id/runs`) or singly
(`/api/playbooks/runs/:id`). Runs themselves aren't audited
(high-volume); the audit log captures the playbook write that
authored them.
"""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, HTTPException, status
from sqlalchemy import desc, func, select

from app.core.deps import DbSession, RequireAdmin, RequireViewer
from app.core.errors import bad_request, not_found
from app.models import Playbook, PlaybookRun
from app.schemas.common import Page
from app.schemas.playbook import (
    PlaybookCreate,
    PlaybookOut,
    PlaybookRunOut,
    PlaybookUpdate,
)
from app.services import audit
from app.services.playbooks import PlaybookParseError, parse_yaml

log = structlog.get_logger()

router = APIRouter(prefix="/api/playbooks", tags=["playbooks"])


def _to_out(pb: Playbook) -> PlaybookOut:
    return PlaybookOut.model_validate(pb)


def _to_run_out(run: PlaybookRun) -> PlaybookRunOut:
    return PlaybookRunOut.model_validate(run)


def _validate_yaml_or_422(body: str) -> None:
    """Playbook YAML parse errors map to 422 (the request body was
    syntactically valid JSON / form but its content failed semantic
    validation). Matches FastAPI's own convention for body validation."""
    try:
        parse_yaml(body)
    except PlaybookParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"playbook yaml invalid: {exc}",
        ) from exc


# --------- Playbook CRUD ---------


@router.get("", response_model=Page[PlaybookOut])
async def list_playbooks(
    db: DbSession,
    actor: RequireViewer,
    enabled: bool | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[PlaybookOut]:
    stmt = select(Playbook).order_by(Playbook.name)
    count_stmt = select(func.count(Playbook.id))
    if enabled is not None:
        stmt = stmt.where(Playbook.enabled == enabled)
        count_stmt = count_stmt.where(Playbook.enabled == enabled)
    stmt = stmt.limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[_to_out(r) for r in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@router.get("/{playbook_id}", response_model=PlaybookOut)
async def get_playbook(playbook_id: UUID, db: DbSession, actor: RequireViewer) -> PlaybookOut:
    pb = await db.get(Playbook, playbook_id)
    if pb is None:
        raise not_found("playbook", str(playbook_id))
    return _to_out(pb)


@router.post("", response_model=PlaybookOut, status_code=status.HTTP_201_CREATED)
async def create_playbook(
    payload: PlaybookCreate,
    db: DbSession,
    actor: RequireAdmin,
) -> PlaybookOut:
    dup = (
        await db.execute(select(Playbook).where(Playbook.name == payload.name))
    ).scalar_one_or_none()
    if dup is not None:
        raise bad_request(f"playbook '{payload.name}' already exists")
    _validate_yaml_or_422(payload.yaml_body)
    pb = Playbook(
        name=payload.name,
        description=payload.description,
        yaml_body=payload.yaml_body,
        enabled=payload.enabled,
        trigger_rule_id=payload.trigger_rule_id,
        trigger_severity=payload.trigger_severity,
        trigger_mitre_techniques=payload.trigger_mitre_techniques,
    )
    db.add(pb)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="playbook.create",
        resource_type="playbook",
        resource_id=str(pb.id),
        payload={
            "name": pb.name,
            "enabled": pb.enabled,
            "trigger_rule_id": str(pb.trigger_rule_id) if pb.trigger_rule_id else None,
            "trigger_severity": pb.trigger_severity,
            "trigger_mitre_techniques": pb.trigger_mitre_techniques,
        },
    )
    await db.commit()
    await db.refresh(pb)
    return _to_out(pb)


@router.patch("/{playbook_id}", response_model=PlaybookOut)
async def update_playbook(
    playbook_id: UUID,
    payload: PlaybookUpdate,
    db: DbSession,
    actor: RequireAdmin,
) -> PlaybookOut:
    pb = await db.get(Playbook, playbook_id)
    if pb is None:
        raise not_found("playbook", str(playbook_id))
    if payload.name is not None and payload.name != pb.name:
        dup = (
            await db.execute(select(Playbook).where(Playbook.name == payload.name))
        ).scalar_one_or_none()
        if dup is not None:
            raise bad_request(f"playbook '{payload.name}' already exists")
        pb.name = payload.name
    if payload.description is not None:
        pb.description = payload.description
    if payload.yaml_body is not None:
        _validate_yaml_or_422(payload.yaml_body)
        pb.yaml_body = payload.yaml_body
    if payload.enabled is not None:
        pb.enabled = payload.enabled
    if payload.trigger_rule_id is not None:
        pb.trigger_rule_id = payload.trigger_rule_id
    if payload.trigger_severity is not None:
        pb.trigger_severity = payload.trigger_severity
    if payload.trigger_mitre_techniques is not None:
        pb.trigger_mitre_techniques = payload.trigger_mitre_techniques
    await audit.record(
        db,
        actor=actor,
        action="playbook.update",
        resource_type="playbook",
        resource_id=str(pb.id),
        payload=payload.model_dump(exclude_none=True, mode="json"),
    )
    await db.commit()
    await db.refresh(pb)
    return _to_out(pb)


@router.delete("/{playbook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_playbook(playbook_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    pb = await db.get(Playbook, playbook_id)
    if pb is None:
        raise not_found("playbook", str(playbook_id))
    name = pb.name
    await db.delete(pb)
    await audit.record(
        db,
        actor=actor,
        action="playbook.delete",
        resource_type="playbook",
        resource_id=str(playbook_id),
        payload={"name": name},
    )
    await db.commit()


# --------- Run history ---------


@router.get("/{playbook_id}/runs", response_model=Page[PlaybookRunOut])
async def list_playbook_runs(
    playbook_id: UUID,
    db: DbSession,
    actor: RequireViewer,
    limit: int = 50,
    offset: int = 0,
) -> Page[PlaybookRunOut]:
    pb = await db.get(Playbook, playbook_id)
    if pb is None:
        raise not_found("playbook", str(playbook_id))
    stmt = (
        select(PlaybookRun)
        .where(PlaybookRun.playbook_id == playbook_id)
        .order_by(desc(PlaybookRun.started_at))
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.execute(stmt)).scalars().all()
    total = (
        await db.execute(
            select(func.count(PlaybookRun.id)).where(PlaybookRun.playbook_id == playbook_id)
        )
    ).scalar_one()
    return Page(
        items=[_to_run_out(r) for r in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@router.get("/runs/{run_id}", response_model=PlaybookRunOut)
async def get_playbook_run(run_id: UUID, db: DbSession, actor: RequireViewer) -> PlaybookRunOut:
    run = await db.get(PlaybookRun, run_id)
    if run is None:
        raise not_found("playbook_run", str(run_id))
    return _to_run_out(run)
