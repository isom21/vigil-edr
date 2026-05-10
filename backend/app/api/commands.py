"""Response-action command API: queue commands for an agent."""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import desc, func, select

from app.core.deps import DbSession, RequireAnalyst
from app.core.errors import bad_request, forbidden, not_found
from app.models import Command, CommandKind, CommandStatus, Host
from app.schemas.command import CommandIn, CommandOut
from app.schemas.common import Page
from app.services import audit
from app.services.scoping import apply_host_scope, host_visible_to

router = APIRouter(prefix="/api/hosts", tags=["commands"])
all_router = APIRouter(prefix="/api/commands", tags=["commands"])


def _validate_payload(kind: CommandKind, payload: dict) -> None:
    if kind == CommandKind.KILL_PROCESS:
        pid = payload.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            bad_request("kill_process payload requires integer pid > 0")
    elif kind in (
        CommandKind.BLOCK_PROCESS,
        CommandKind.BLOCK_FILE,
        CommandKind.UNBLOCK_PROCESS,
        CommandKind.UNBLOCK_FILE,
    ):
        pattern = payload.get("pattern")
        if not isinstance(pattern, str) or not pattern.strip():
            bad_request(f"{kind.value} payload requires non-empty 'pattern' string")
        if len(pattern.encode("utf-16-le")) > 512:
            bad_request("pattern is longer than the driver's 512-byte UTF-16 limit")


@router.post("/{host_id}/commands", response_model=CommandOut, status_code=status.HTTP_201_CREATED)
async def queue_command(
    host_id: UUID,
    body: CommandIn,
    db: DbSession,
    actor: RequireAnalyst,
) -> CommandOut:
    host = await db.get(Host, host_id)
    if host is None:
        not_found("host")
    if not await host_visible_to(actor, host_id, db):
        raise forbidden("host not in any of your groups")

    _validate_payload(body.kind, body.payload)

    cmd = Command(
        host_id=host_id,
        kind=body.kind,
        status=CommandStatus.PENDING,
        payload=body.payload,
        issued_by_user_id=actor.user.id,
    )
    db.add(cmd)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="command.queue",
        resource_type="host",
        resource_id=str(host_id),
        payload={"command_id": str(cmd.id), "kind": body.kind.value, "payload": body.payload},
    )
    await db.commit()
    return CommandOut.model_validate(cmd)


@router.get("/{host_id}/commands", response_model=Page[CommandOut])
async def list_commands(
    host_id: UUID,
    db: DbSession,
    actor: RequireAnalyst,
    status_: CommandStatus | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[CommandOut]:
    host = await db.get(Host, host_id)
    if host is None:
        not_found("host")
    if not await host_visible_to(actor, host_id, db):
        raise forbidden("host not in any of your groups")

    stmt = select(Command).where(Command.host_id == host_id)
    count_stmt = select(func.count(Command.id)).where(Command.host_id == host_id)
    if status_:
        stmt = stmt.where(Command.status == status_)
        count_stmt = count_stmt.where(Command.status == status_)
    stmt = stmt.order_by(desc(Command.created_at)).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[CommandOut.model_validate(c) for c in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@all_router.get("", response_model=Page[CommandOut])
async def list_all_commands(
    db: DbSession,
    actor: RequireAnalyst,
    status_: CommandStatus | None = None,
    kind: CommandKind | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[CommandOut]:
    """Cross-host command list. M7.6 UI consumes this for the
    `/commands` page. Honours M7.5 host-group scoping so non-admins
    only see commands targeting hosts in their groups."""
    stmt = select(Command)
    count_stmt = select(func.count(Command.id))
    if status_:
        stmt = stmt.where(Command.status == status_)
        count_stmt = count_stmt.where(Command.status == status_)
    if kind:
        stmt = stmt.where(Command.kind == kind)
        count_stmt = count_stmt.where(Command.kind == kind)
    stmt = apply_host_scope(stmt, actor, host_column=Command.host_id)
    count_stmt = apply_host_scope(count_stmt, actor, host_column=Command.host_id)
    stmt = stmt.order_by(desc(Command.created_at)).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[CommandOut.model_validate(c) for c in rows],
        total=total,
        limit=limit,
        offset=offset,
    )
