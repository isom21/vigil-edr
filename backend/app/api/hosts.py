"""Host CRUD (read for analyst+, write for admin) + stats."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import DbSession, RequireAdmin, RequireViewer
from app.core.errors import bad_request, not_found
from app.models import AttestationEvent, AttestationGolden, Host, HostStatus, OsFamily
from app.schemas.attestation import (
    AttestationBlock,
    AttestationEventOut,
    AttestationGoldenOut,
)
from app.schemas.common import Page
from app.schemas.host import (
    HostDetail,
    HostOut,
    HostUpdate,
    LiveTelemetryEvent,
    LiveTelemetryPage,
)
from app.schemas.stats import StatBucket
from app.services import audit
from app.services import opensearch as os_svc
from app.services.scoping import apply_host_scope, host_visible_to
from app.services.sorting import parse_sort

router = APIRouter(prefix="/api/hosts", tags=["hosts"])


_SORTABLE = {
    "hostname": Host.hostname,
    "last_seen_at": Host.last_seen_at,
    "status": Host.status,
    "agent_version": Host.agent_version,
    "enrolled_at": Host.enrolled_at,
    "os_family": Host.os_family,
}


@router.get("", response_model=Page[HostOut])
async def list_hosts(
    db: DbSession,
    actor: RequireViewer,
    status_: HostStatus | None = None,
    os_family: OsFamily | None = None,
    q: str | None = None,
    sort: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[HostOut]:
    stmt = select(Host)
    count_stmt = select(func.count(Host.id))
    if status_:
        stmt = stmt.where(Host.status == status_)
        count_stmt = count_stmt.where(Host.status == status_)
    if os_family:
        stmt = stmt.where(Host.os_family == os_family)
        count_stmt = count_stmt.where(Host.os_family == os_family)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(Host.hostname.ilike(like))
        count_stmt = count_stmt.where(Host.hostname.ilike(like))
    stmt = apply_host_scope(stmt, actor)
    count_stmt = apply_host_scope(count_stmt, actor)
    order = parse_sort(sort, _SORTABLE, default=[Host.last_seen_at.desc().nulls_last()])
    stmt = stmt.order_by(*order).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[HostOut.model_validate(h) for h in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=list[StatBucket])
async def host_stats(
    db: DbSession,
    actor: RequireViewer,
    bucket: str,
) -> list[StatBucket]:
    """Aggregations for the fleet charts.

    bucket=status|os_family|agent_version|last_seen
    """
    if bucket == "status":
        stmt = select(Host.status, func.count(Host.id)).group_by(Host.status)
    elif bucket == "os_family":
        stmt = select(Host.os_family, func.count(Host.id)).group_by(Host.os_family)
    elif bucket == "agent_version":
        stmt = (
            select(Host.agent_version, func.count(Host.id))
            .group_by(Host.agent_version)
            .order_by(func.count(Host.id).desc())
            .limit(10)
        )
    elif bucket == "last_seen":
        cutoff_5m = datetime.now(UTC) - timedelta(minutes=5)
        cutoff_24h = datetime.now(UTC) - timedelta(hours=24)
        bucket_expr = case(
            (Host.last_seen_at.is_(None), "never"),
            (Host.last_seen_at >= cutoff_5m, "online"),
            (Host.last_seen_at >= cutoff_24h, "idle"),
            else_="stale",
        )
        stmt = select(bucket_expr.label("b"), func.count(Host.id)).group_by("b")
    else:
        raise bad_request("bucket must be one of: status, os_family, agent_version, last_seen")
    stmt = apply_host_scope(stmt, actor)
    rows = (await db.execute(stmt)).all()
    return [StatBucket(key=_key_str(k), count=int(c)) for k, c in rows]


def _key_str(v) -> str:
    if v is None:
        return "unknown"
    if hasattr(v, "value"):
        return v.value
    return str(v)


@router.get("/{host_id}", response_model=HostDetail)
async def get_host(host_id: UUID, db: DbSession, actor: RequireViewer) -> HostDetail:
    host = await db.get(Host, host_id)
    if host is None:
        raise not_found("host", str(host_id))
    if not await host_visible_to(actor, host_id, db):
        # M-audit-and-auth #7: 404 not 403 so existence isn't leaked.
        raise not_found("host", str(host_id))
    runtimes = await _container_runtimes_seen(str(host_id))
    detail = HostDetail.model_validate(host)
    detail.container_runtimes_seen = runtimes
    detail.attestation = await _attestation_block(db, host_id)
    return detail


async def _attestation_block(db: AsyncSession, host_id: UUID) -> AttestationBlock:
    """Phase 4 #4.10: assemble the per-host attestation pane.

    * No golden + no events → ``unknown``.
    * Latest event but no golden → ``unverified``.
    * Latest event matches golden → ``ok``.
    * Latest event differs from golden → ``diverged``.
    """
    golden = await db.get(AttestationGolden, host_id)
    latest_stmt = (
        select(AttestationEvent)
        .where(AttestationEvent.host_id == host_id)
        .order_by(AttestationEvent.recorded_at.desc())
        .limit(1)
    )
    latest = (await db.execute(latest_stmt)).scalar_one_or_none()

    if latest is None and golden is None:
        return AttestationBlock(status="unknown")
    if latest is None:
        return AttestationBlock(
            status="unverified",
            golden=AttestationGoldenOut.model_validate(golden) if golden else None,
        )
    if golden is None:
        return AttestationBlock(
            status="unverified",
            latest=AttestationEventOut.model_validate(latest),
        )
    status_label = "ok" if latest.matches_golden else "diverged"
    return AttestationBlock(
        status=status_label,
        latest=AttestationEventOut.model_validate(latest),
        golden=AttestationGoldenOut.model_validate(golden),
    )


async def _container_runtimes_seen(host_id_str: str) -> list[str]:
    """Phase 2 #2.9: 24h terms agg over `container.runtime` for this
    host. Best-effort — any OpenSearch hiccup (cluster down, index
    missing on a fresh install) returns an empty list rather than
    failing the whole host detail endpoint.
    """
    client = os_svc._client()
    try:
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"host.id": host_id_str}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": (datetime.now(UTC) - timedelta(hours=24)).isoformat(),
                                }
                            }
                        },
                        {"exists": {"field": "container.runtime"}},
                    ]
                }
            },
            "aggs": {
                "runtimes": {"terms": {"field": "container.runtime", "size": 5}},
            },
        }
        resp = await client.search(
            index="telemetry-*",
            body=body,
            request_timeout=10,  # pyright: ignore[reportCallIssue]
        )
    except Exception:
        return []
    finally:
        await client.close()
    buckets = (resp.get("aggregations") or {}).get("runtimes", {}).get("buckets") or []
    return [str(b["key"]) for b in buckets if b.get("key")]


@router.patch("/{host_id}", response_model=HostOut)
async def update_host(
    host_id: UUID, payload: HostUpdate, db: DbSession, actor: RequireAdmin
) -> HostOut:
    host = await db.get(Host, host_id)
    if host is None:
        raise not_found("host", str(host_id))
    if payload.policy_id is not None:
        host.policy_id = payload.policy_id
    if payload.status is not None:
        host.status = payload.status
    await audit.record(
        db,
        actor=actor,
        action="host.update",
        resource_type="host",
        resource_id=str(host.id),
        payload=payload.model_dump(exclude_none=True),
    )
    return HostOut.model_validate(host)


@router.get("/{host_id}/telemetry", response_model=LiveTelemetryPage)
async def host_live_telemetry(
    host_id: UUID,
    db: DbSession,
    actor: RequireViewer,
    since: datetime | None = None,
    limit: int = 200,
) -> LiveTelemetryPage:
    """M20.j: poll-based live telemetry feed for one host.

    Returns events newer than `since`, sorted by @timestamp asc. The
    frontend tab polls every couple of seconds and walks `since`
    forward — there's no kafka consumer churn on the manager side,
    we just tail OpenSearch which already has every event.
    """
    if limit <= 0 or limit > 1000:
        raise bad_request("limit must be in (0, 1000]")
    host = await db.get(Host, host_id)
    if host is None:
        raise not_found("host", str(host_id))
    if not await host_visible_to(actor, host_id, db):
        # M-audit-and-auth #7: 404 not 403 so existence isn't leaked.
        raise not_found("host", str(host_id))

    client = os_svc._client()
    try:
        hits = await os_svc.fetch_host_since(
            client,
            host_id=str(host_id),
            since=since,
            size=limit,
        )
    finally:
        await client.close()

    events: list[LiveTelemetryEvent] = []
    latest: datetime | None = None
    for h in hits:
        src = h.get("_source") or {}
        ts_str = src.get("@timestamp")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else None
        except (AttributeError, ValueError):
            ts = None
        if ts is None:
            continue
        latest = ts if latest is None or ts > latest else latest
        events.append(_map_live_event(h, src, ts))

    return LiveTelemetryPage(
        host_id=host_id,
        events=events,
        latest_timestamp=latest,
        truncated=len(hits) >= limit,
    )


def _map_live_event(h: dict, src: dict, ts: datetime) -> LiveTelemetryEvent:
    """Flatten one OpenSearch ECS doc into a LiveTelemetryEvent row.

    The schema is intentionally wide enough to drive the per-category
    tabs in the UI (Processes / Files / Network / Auth / Modules / Other)
    without a follow-up roundtrip per row.
    """
    event: dict = src.get("event") or {}
    proc: dict = src.get("process") or {}
    parent: dict = proc.get("parent") or {} if isinstance(proc.get("parent"), dict) else {}
    user: dict = src.get("user") or {}
    file_: dict = src.get("file") or {}
    sig: dict = (
        file_.get("code_signature") or {} if isinstance(file_.get("code_signature"), dict) else {}
    )
    source: dict = src.get("source") or {}
    dest: dict = src.get("destination") or {}
    net: dict = src.get("network") or {}
    dns: dict = src.get("dns") or {}
    dns_q: dict = dns.get("question") or {} if isinstance(dns.get("question"), dict) else {}
    rule: dict = src.get("rule") or {}
    hashes = (
        (proc.get("hash") if isinstance(proc.get("hash"), dict) else None)
        or (file_.get("hash") if isinstance(file_.get("hash"), dict) else None)
        or {}
    )

    def _int(v: object) -> int | None:
        return v if isinstance(v, int) and not isinstance(v, bool) else None

    def _str(v: object) -> str | None:
        return v if isinstance(v, str) else None

    def _bool(v: object) -> bool | None:
        return v if isinstance(v, bool) else None

    categories = list(event.get("category") or [])
    module_path = _str(file_.get("path")) if "library" in categories else None

    return LiveTelemetryEvent(
        event_id=event.get("id") or h.get("_id") or "",
        timestamp=ts,
        category=categories,
        action=_str(event.get("action")),
        outcome=_str(event.get("outcome")),
        pid=_int(proc.get("pid")),
        parent_pid=_int(parent.get("pid")),
        executable=_str(proc.get("executable")),
        command_line=_str(proc.get("command_line")),
        working_directory=_str(proc.get("working_directory")),
        user_name=_str(user.get("name")),
        file_path=_str(file_.get("path")),
        file_action=_str(file_.get("action")),
        file_size=_int(file_.get("size")),
        source_ip=_str(source.get("ip")),
        source_port=_int(source.get("port")),
        destination_ip=_str(dest.get("ip")),
        destination_port=_int(dest.get("port")),
        destination_domain=_str(dest.get("domain")),
        transport=_str(net.get("transport")),
        direction=_str(net.get("direction")),
        dns_question_name=_str(dns_q.get("name")),
        module_path=module_path,
        module_signed=_bool(sig.get("signed")),
        module_signer=_str(sig.get("subject_name")),
        event_provider=_str(event.get("provider")),
        event_code=_str(event.get("code")),
        rule_name=_str(rule.get("name")),
        sha256=hashes.get("sha256") if isinstance(hashes, dict) else None,
    )


@router.delete("/{host_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_host(host_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    host = await db.get(Host, host_id)
    if host is None:
        raise not_found("host", str(host_id))
    await db.delete(host)
    await audit.record(
        db, actor=actor, action="host.delete", resource_type="host", resource_id=str(host_id)
    )
