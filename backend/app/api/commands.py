"""Response-action command API: queue commands for an agent."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import desc, func, select

from app.core.deps import DbSession, RequireAnalyst
from app.core.errors import bad_request, not_found
from app.models import Command, CommandKind, CommandStatus, Host
from app.schemas.command import CommandIn, CommandOut
from app.schemas.common import Page
from app.schemas.stats import StatBucket
from app.services import audit
from app.services.isolation_guard import ensure_manager_in_allowlist
from app.services.scoping import apply_host_scope, host_visible_to
from app.services.sorting import parse_sort

router = APIRouter(prefix="/api/hosts", tags=["commands"])
all_router = APIRouter(prefix="/api/commands", tags=["commands"])


_SORTABLE = {
    "created_at": Command.created_at,
    "kind": Command.kind,
    "status": Command.status,
    "completed_at": Command.completed_at,
    "dispatched_at": Command.dispatched_at,
}


def _validate_payload(kind: CommandKind, payload: dict) -> None:
    if kind == CommandKind.KILL_PROCESS:
        pid = payload.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            raise bad_request("kill_process payload requires integer pid > 0")
    elif kind in (
        CommandKind.BLOCK_PROCESS,
        CommandKind.BLOCK_FILE,
        CommandKind.UNBLOCK_PROCESS,
        CommandKind.UNBLOCK_FILE,
    ):
        pattern = payload.get("pattern")
        if not isinstance(pattern, str) or not pattern.strip():
            raise bad_request(f"{kind.value} payload requires non-empty 'pattern' string")
        if len(pattern.encode("utf-16-le")) > 512:
            raise bad_request("pattern is longer than the driver's 512-byte UTF-16 limit")


@router.post("/{host_id}/commands", response_model=CommandOut, status_code=status.HTTP_201_CREATED)
async def queue_command(
    host_id: UUID,
    body: CommandIn,
    db: DbSession,
    actor: RequireAnalyst,
) -> CommandOut:
    host = await db.get(Host, host_id)
    if host is None:
        raise not_found("host")
    if not await host_visible_to(actor, host_id, db):
        # M-audit-and-auth #7: 404 not 403 so existence isn't leaked.
        raise not_found("host", str(host_id))

    _validate_payload(body.kind, body.payload)

    # Defense-in-depth for IsolateHostCmd: stamp the manager's
    # resolved IPs into the allowlist before persisting the command,
    # so the operator can't accidentally cut off the manager's own
    # recovery path. The agent applies the same invariant locally, so
    # this is redundant for current agents — it covers older agents
    # without the agent-side fix.
    effective_payload = body.payload
    if body.kind == CommandKind.ISOLATE and effective_payload.get("isolate"):
        effective_payload = ensure_manager_in_allowlist(effective_payload)

    cmd = Command(
        host_id=host_id,
        kind=body.kind,
        status=CommandStatus.PENDING,
        payload=effective_payload,
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
        payload={
            "command_id": str(cmd.id),
            "kind": body.kind.value,
            "payload": effective_payload,
        },
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
        raise not_found("host")
    if not await host_visible_to(actor, host_id, db):
        # M-audit-and-auth #7: 404 not 403 so existence isn't leaked.
        raise not_found("host", str(host_id))

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
    sort: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[CommandOut]:
    """Cross-host command list. M7.6 UI consumes this for the
    `/commands` page. Honours M7.5 host-group scoping so non-admins
    only see commands targeting hosts in their groups."""
    # Join Host.hostname so the table can display a real name instead
    # of an opaque uuid. Outer join to keep deleted hosts visible.
    stmt = select(Command, Host.hostname).join(Host, Host.id == Command.host_id, isouter=True)
    count_stmt = select(func.count(Command.id))
    if status_:
        stmt = stmt.where(Command.status == status_)
        count_stmt = count_stmt.where(Command.status == status_)
    if kind:
        stmt = stmt.where(Command.kind == kind)
        count_stmt = count_stmt.where(Command.kind == kind)
    stmt = apply_host_scope(stmt, actor, host_column=Command.host_id)
    count_stmt = apply_host_scope(count_stmt, actor, host_column=Command.host_id)
    order = parse_sort(sort, _SORTABLE, default=[desc(Command.created_at)])
    stmt = stmt.order_by(*order).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).all()
    total = (await db.execute(count_stmt)).scalar_one()
    items = []
    for cmd, hostname in rows:
        out = CommandOut.model_validate(cmd)
        out.host_hostname = hostname
        items.append(out)
    return Page(items=items, total=total, limit=limit, offset=offset)


@all_router.get("/stats", response_model=list[StatBucket])
async def command_stats(
    db: DbSession,
    actor: RequireAnalyst,
    bucket: str,
) -> list[StatBucket]:
    """bucket=status|kind."""
    if bucket == "status":
        stmt = select(Command.status, func.count(Command.id)).group_by(Command.status)
    elif bucket == "kind":
        stmt = (
            select(Command.kind, func.count(Command.id))
            .group_by(Command.kind)
            .order_by(func.count(Command.id).desc())
        )
    else:
        raise bad_request("bucket must be one of: status, kind")
    stmt = apply_host_scope(stmt, actor, host_column=Command.host_id)
    rows = (await db.execute(stmt)).all()
    return [StatBucket(key=_key_str(k), count=int(c)) for k, c in rows]


def _key_str(v) -> str:
    if v is None:
        return "unknown"
    if hasattr(v, "value"):
        return v.value
    return str(v)
