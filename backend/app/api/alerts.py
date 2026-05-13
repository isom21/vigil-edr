"""Alerts: list, detail, state transitions, assignment, stats."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Request
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload
from sse_starlette.sse import EventSourceResponse

from app.core.deps import CurrentActorStream, DbSession, RequireAnalyst, RequireViewer
from app.core.errors import bad_request, not_found
from app.models import (
    ALERT_STATE_TRANSITIONS,
    Alert,
    AlertState,
    AlertStateHistory,
    Host,
    Rule,
    Severity,
    User,
)
from app.schemas.alert import (
    AlertAssign,
    AlertContext,
    AlertDetail,
    AlertOut,
    AlertStateChange,
    ContainerInfo,
    ProcessChainNode,
    ProcessDetail,
    ProcessFileEvent,
    ProcessImageLoad,
    ProcessNetworkEvent,
    ProcessOtherEvent,
    TimelineEvent,
)
from app.schemas.common import Page
from app.schemas.stats import StatBucket
from app.services import audit
from app.services import opensearch as os_svc
from app.services.scoping import apply_host_scope, host_visible_to
from app.services.sorting import parse_sort

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


_SORTABLE = {
    "opened_at": Alert.opened_at,
    "severity": Alert.severity,
    "state": Alert.state,
    "updated_at": Alert.updated_at,
    "host_hostname": Host.hostname,
    "rule_name": Rule.name,
}


def _alert_out(a: Alert, host_hostname: str | None, rule_name: str | None) -> AlertOut:
    out = AlertOut.model_validate(a)
    out.host_hostname = host_hostname
    out.rule_name = rule_name
    return out


@router.get("/stream")
async def stream_alerts(
    request: Request,
    actor: CurrentActorStream,
) -> EventSourceResponse:
    """SSE stream of newly-inserted alerts.

    Subscribers receive `event: alert\\ndata: {...}` lines. Heartbeats
    (`event: ping`) fire every 20s to keep proxies from idling the
    connection. RBAC scoping is applied per-event using
    `host_visible_to` so analysts only get events for hosts in their
    groups.

    M-grpc-hygiene #4: each visibility check opens its own short-lived
    session (and commits/closes via `async with`). The previous shape
    closed over a `DbSession` FastAPI dependency, which for an SSE
    handler lives until the browser tab closes — at 20 concurrent
    analyst tabs that's 20 pool checkouts held idle, plus a long-open
    idle-in-transaction connection visible to ops. Per-event sessions
    cost ~one connection-pool checkout per fresh alert, which is small
    compared to the rate-limit ceiling we already enforce upstream.
    """
    from app.core.db import SessionLocal
    from app.services.alert_broker import broker
    from app.services.scoping import host_visible_to

    async def gen():
        async with broker.subscribe() as q:
            # Initial comment so EventSource fires its `open` event
            # promptly instead of waiting for the first real message.
            yield {"event": "ready", "data": ""}
            heartbeat_at = asyncio.get_event_loop().time() + 20.0
            while True:
                if await request.is_disconnected():
                    return
                timeout = max(1.0, heartbeat_at - asyncio.get_event_loop().time())
                try:
                    event = await asyncio.wait_for(q.get(), timeout=timeout)
                except TimeoutError:
                    heartbeat_at = asyncio.get_event_loop().time() + 20.0
                    yield {"event": "ping", "data": ""}
                    continue
                # RBAC: drop events for hosts the actor can't see.
                # `host_id` is null for synthetic alerts (audit chain
                # breaks); host_visible_to handles None natively —
                # admins get True, others get False.
                host_id_raw = event.get("host_id")
                host_uuid: UUID | None
                if host_id_raw is None:
                    host_uuid = None
                else:
                    try:
                        host_uuid = UUID(host_id_raw)
                    except (TypeError, ValueError):
                        continue
                async with SessionLocal() as evdb:
                    visible = await host_visible_to(actor, host_uuid, evdb)
                if not visible:
                    continue
                yield {"event": "alert", "data": json.dumps(event)}

    return EventSourceResponse(gen())


@router.get("", response_model=Page[AlertOut])
async def list_alerts(
    db: DbSession,
    actor: RequireViewer,
    state: AlertState | None = None,
    severity: Severity | None = None,
    host_id: UUID | None = None,
    rule_id: UUID | None = None,
    host_hostname: str | None = None,
    rule_name: str | None = None,
    q: str | None = None,
    sort: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[AlertOut]:
    # M-audit-and-auth #10: synthetic alerts (audit-chain breaks) have
    # `host_id IS NULL`. LEFT OUTER JOIN on Host so admins still see
    # those rows in the list. Non-admins are filtered by
    # `apply_host_scope` below, which uses `Alert.host_id IN (...)` —
    # SQL UNKNOWN for NULL, so synthetic alerts stay hidden from them
    # without extra plumbing.
    stmt = (
        select(Alert, Host.hostname, Rule.name)
        .outerjoin(Host, Host.id == Alert.host_id)
        .join(Rule, Rule.id == Alert.rule_id)
    )
    count_stmt = (
        select(func.count(Alert.id))
        .outerjoin(Host, Host.id == Alert.host_id)
        .join(Rule, Rule.id == Alert.rule_id)
    )
    if state:
        stmt = stmt.where(Alert.state == state)
        count_stmt = count_stmt.where(Alert.state == state)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
        count_stmt = count_stmt.where(Alert.severity == severity)
    if host_id:
        stmt = stmt.where(Alert.host_id == host_id)
        count_stmt = count_stmt.where(Alert.host_id == host_id)
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
        count_stmt = count_stmt.where(Alert.rule_id == rule_id)
    if host_hostname:
        stmt = stmt.where(Host.hostname == host_hostname)
        count_stmt = count_stmt.where(Host.hostname == host_hostname)
    if rule_name:
        stmt = stmt.where(Rule.name == rule_name)
        count_stmt = count_stmt.where(Rule.name == rule_name)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(Alert.summary.ilike(like))
        count_stmt = count_stmt.where(Alert.summary.ilike(like))
    # M7.5: scope alerts by host visibility (admins are pass-through).
    stmt = apply_host_scope(stmt, actor, host_column=Alert.host_id)
    count_stmt = apply_host_scope(count_stmt, actor, host_column=Alert.host_id)
    order = parse_sort(sort, _SORTABLE, default=[Alert.opened_at.desc()])
    stmt = stmt.order_by(*order).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[_alert_out(a, hn, rn) for a, hn, rn in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=list[StatBucket])
async def alert_stats(
    db: DbSession,
    actor: RequireViewer,
    bucket: str,
) -> list[StatBucket]:
    """Aggregations for the alert console charts.

    bucket=severity|state|host|rule|hour
    Honours host-scope so analysts only see counts for their groups.
    """
    if bucket == "severity":
        stmt = select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    elif bucket == "state":
        stmt = select(Alert.state, func.count(Alert.id)).group_by(Alert.state)
    elif bucket == "host":
        stmt = (
            select(Host.hostname, func.count(Alert.id))
            .join(Host, Host.id == Alert.host_id)
            .group_by(Host.hostname)
            .order_by(func.count(Alert.id).desc())
            .limit(10)
        )
    elif bucket == "rule":
        stmt = (
            select(Rule.name, func.count(Alert.id))
            .join(Rule, Rule.id == Alert.rule_id)
            .group_by(Rule.name)
            .order_by(func.count(Alert.id).desc())
            .limit(10)
        )
    elif bucket == "hour":
        stmt = _hourly_stmt()
    else:
        raise bad_request("bucket must be one of: severity, state, host, rule, hour")
    stmt = apply_host_scope(stmt, actor, host_column=Alert.host_id)
    rows = (await db.execute(stmt)).all()
    if bucket == "hour":
        return _fill_hourly(rows)
    return [StatBucket(key=_key_str(k), count=int(c)) for k, c in rows]


def _hourly_stmt():
    bucket_col = func.date_trunc("hour", Alert.opened_at)
    cutoff = datetime.now(UTC) - timedelta(hours=23)
    return (
        select(bucket_col.label("bucket"), func.count(Alert.id))
        .where(Alert.opened_at >= cutoff)
        .group_by(bucket_col)
        .order_by(bucket_col)
    )


def _fill_hourly(rows) -> list[StatBucket]:
    """Pad a 24-hour series so empty buckets still appear as count=0."""
    by_bucket: dict[datetime, int] = {}
    for ts, c in rows:
        if ts is not None:
            by_bucket[ts.replace(minute=0, second=0, microsecond=0)] = int(c)
    out: list[StatBucket] = []
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    for i in range(23, -1, -1):
        ts = now - timedelta(hours=i)
        out.append(StatBucket(key=ts.isoformat(), count=by_bucket.get(ts, 0)))
    return out


def _key_str(v) -> str:
    if v is None:
        return "unknown"
    if hasattr(v, "value"):
        return v.value
    return str(v)


@router.get("/{alert_id}", response_model=AlertDetail)
async def get_alert(alert_id: UUID, db: DbSession, actor: RequireViewer) -> AlertDetail:
    # LEFT OUTER JOIN so synthetic (null-host) alerts still match.
    stmt = (
        select(Alert, Host.hostname, Rule.name)
        .outerjoin(Host, Host.id == Alert.host_id)
        .join(Rule, Rule.id == Alert.rule_id)
        .where(Alert.id == alert_id)
        .options(selectinload(Alert.history))
    )
    row = (await db.execute(stmt)).one_or_none()
    if row is None:
        raise not_found("alert", str(alert_id))
    alert, hostname, rule_name = row
    if not await host_visible_to(actor, alert.host_id, db):
        # M-audit-and-auth #7: return 404 (not 403) so the response
        # doesn't distinguish "this alert id is real but you can't
        # see it" from "this alert id doesn't exist". The 403/404
        # split let a low-priv account confirm shared cross-team
        # alert ids without seeing their contents.
        raise not_found("alert", str(alert_id))
    detail = AlertDetail.model_validate(alert)
    detail.host_hostname = hostname
    detail.rule_name = rule_name
    detail.container = await _resolve_alert_container(alert)
    return detail


async def _resolve_alert_container(alert: Alert) -> ContainerInfo | None:
    """Phase 2 #2.9: pull container.* off the alert's triggering
    telemetry doc (when present). Returns None for synthetic alerts,
    or when the triggering doc has no container attribution.
    """
    trigger_ids: list[str] = list(alert.telemetry_doc_ids or [])
    if isinstance(alert.details, dict):
        extra = alert.details.get("event_id")
        if isinstance(extra, str) and extra and extra not in trigger_ids:
            trigger_ids.append(extra)
    if not trigger_ids:
        return None
    client = os_svc._client()
    try:
        docs = await os_svc.fetch_events_by_ids(client, trigger_ids)
    except Exception:
        return None
    finally:
        await client.close()
    for doc in docs:
        container = doc.get("container") if isinstance(doc, dict) else None
        if isinstance(container, dict) and container.get("id"):
            image = container.get("image") or {}
            image_name = image.get("name") if isinstance(image, dict) else None
            runtime = container.get("runtime")
            return ContainerInfo(
                id=str(container["id"]),
                image=image_name if isinstance(image_name, str) else None,
                runtime=runtime if isinstance(runtime, str) else None,
            )
    return None


@router.post("/{alert_id}/state", response_model=AlertDetail)
async def change_state(
    alert_id: UUID,
    payload: AlertStateChange,
    db: DbSession,
    actor: RequireAnalyst,
) -> AlertDetail:
    # LEFT OUTER JOIN so synthetic (null-host) alerts still match.
    stmt = (
        select(Alert, Host.hostname, Rule.name)
        .outerjoin(Host, Host.id == Alert.host_id)
        .join(Rule, Rule.id == Alert.rule_id)
        .where(Alert.id == alert_id)
        .options(selectinload(Alert.history))
    )
    row = (await db.execute(stmt)).one_or_none()
    if row is None:
        raise not_found("alert", str(alert_id))
    alert, hostname, rule_name = row
    if not await host_visible_to(actor, alert.host_id, db):
        raise not_found("alert", str(alert_id))
    allowed = ALERT_STATE_TRANSITIONS.get(alert.state, set())
    if payload.to_state not in allowed:
        raise bad_request(f"transition {alert.state.value} -> {payload.to_state.value} not allowed")

    alert.history.append(
        AlertStateHistory(
            from_state=alert.state,
            to_state=payload.to_state,
            by_user_id=actor.user.id,
            comment=payload.comment,
        )
    )
    alert.state = payload.to_state
    if payload.to_state in (AlertState.FALSE_POSITIVE, AlertState.TRUE_POSITIVE):
        alert.closed_at = datetime.now(UTC)

    await audit.record(
        db,
        actor=actor,
        action="alert.state_change",
        resource_type="alert",
        resource_id=str(alert.id),
        payload={"to_state": payload.to_state.value, "comment": payload.comment},
    )
    # The just-appended AlertStateHistory needs id (python uuid4 default)
    # and ts (server-default now()) populated before pydantic validates
    # it. When the HMAC chain is dormant, audit.record emits no SQL, so
    # autoflush wouldn't fire on its own.
    await db.flush()
    detail = AlertDetail.model_validate(alert)
    detail.host_hostname = hostname
    detail.rule_name = rule_name
    return detail


@router.get("/{alert_id}/context", response_model=AlertContext)
async def get_alert_context(
    alert_id: UUID,
    db: DbSession,
    actor: RequireViewer,
    window_minutes: int = 15,
    max_chain_depth: int = 8,
    max_events: int = 500,
) -> AlertContext:
    """M20.d: power the alert investigation page.

    Returns the process ancestry that led to the alert and the
    surrounding window of telemetry for the same host. Both tabs of
    the UI hydrate from this single payload.
    """
    if window_minutes <= 0 or window_minutes > 360:
        raise bad_request("window_minutes must be in (0, 360]")
    if max_chain_depth <= 0 or max_chain_depth > 32:
        raise bad_request("max_chain_depth must be in (0, 32]")
    if max_events <= 0 or max_events > 2000:
        raise bad_request("max_events must be in (0, 2000]")

    # /context requires a real host (we need to fetch its telemetry
    # window from OpenSearch). Synthetic / null-host alerts have no
    # investigation page — 404 instead of crashing on host_id None.
    stmt = (
        select(Alert, Host.hostname, Rule.name)
        .join(Host, Host.id == Alert.host_id)
        .join(Rule, Rule.id == Alert.rule_id)
        .where(Alert.id == alert_id)
    )
    row = (await db.execute(stmt)).one_or_none()
    if row is None:
        raise not_found("alert", str(alert_id))
    alert, hostname, rule_name = row
    if not await host_visible_to(actor, alert.host_id, db):
        # M-audit-and-auth #7: return 404 (not 403) so the response
        # doesn't distinguish "this alert id is real but you can't
        # see it" from "this alert id doesn't exist". The 403/404
        # split let a low-priv account confirm shared cross-team
        # alert ids without seeing their contents.
        raise not_found("alert", str(alert_id))

    start = alert.opened_at - timedelta(minutes=window_minutes)
    end = alert.opened_at + timedelta(minutes=window_minutes)
    host_id_str = str(alert.host_id)
    trigger_event_ids = list(alert.telemetry_doc_ids or [])
    # Fallback: detector and sigma workers stuff the triggering event_id
    # into `alert.details["event_id"]` even when telemetry_doc_ids is
    # empty. Treat that as a trigger so the chain builder has something
    # to seed from.
    details_event_id = alert.details.get("event_id") if isinstance(alert.details, dict) else None
    if details_event_id and details_event_id not in trigger_event_ids:
        trigger_event_ids.append(details_event_id)

    client = os_svc._client()
    try:
        trigger_docs = await os_svc.fetch_events_by_ids(client, trigger_event_ids)
        chain = await _build_process_chain(
            client,
            host_id_str=host_id_str,
            trigger_docs=trigger_docs,
            opened_at=alert.opened_at,
            max_depth=max_chain_depth,
        )
        hits = await os_svc.fetch_host_window(
            client,
            host_id=host_id_str,
            start=start,
            end=end,
            size=max_events,
        )
    finally:
        await client.close()

    trigger_ids_set = set(trigger_event_ids)
    events = [_hit_to_timeline(h, trigger_ids_set) for h in hits]
    events_truncated = len(events) >= max_events

    return AlertContext(
        alert_id=alert.id,
        host_id=alert.host_id,
        host_hostname=hostname,
        rule_id=alert.rule_id,
        rule_name=rule_name,
        opened_at=alert.opened_at,
        window_start=start,
        window_end=end,
        trigger_event_ids=trigger_event_ids,
        chain=chain,
        events=events,
        events_truncated=events_truncated,
    )


async def _build_process_chain(
    client,
    *,
    host_id_str: str,
    trigger_docs: list[dict],
    opened_at: datetime,
    max_depth: int,
    siblings_per_node: int = 8,
) -> list[ProcessChainNode]:
    """Walk parent pids backwards from the triggering event(s), then
    attach sibling children (M22.c) to each node so the UI can render
    a tree instead of a flat list."""
    chain: list[ProcessChainNode] = []
    seen: set[int] = set()

    # Pick a starting pid: prefer process events, fall back to the first
    # trigger doc that has any pid attribution.
    start_pid: int | None = None
    for doc in trigger_docs:
        pid = (doc.get("process") or {}).get("pid")
        if isinstance(pid, int) and pid > 0:
            start_pid = pid
            break

    # Seed: if the first trigger doc IS a process_started event, use it
    # directly so its hash/user/integrity show up without a re-fetch.
    seed_used = False
    if trigger_docs:
        first = trigger_docs[0]
        if (first.get("event") or {}).get("action") == "process_started" and start_pid:
            chain.append(_doc_to_chain_node(first, inferred=False))
            seen.add(start_pid)
            seed_used = True

    if start_pid is None:
        return chain

    current_pid: int | None = (
        start_pid
        if not seed_used
        else ((trigger_docs[0].get("process") or {}).get("parent", {}).get("pid"))
    )

    while current_pid is not None and current_pid > 0 and len(chain) < max_depth:
        if current_pid in seen:
            break
        seen.add(current_pid)
        doc = await os_svc.fetch_process_started(
            client,
            host_id=host_id_str,
            pid=current_pid,
            before=opened_at,
        )
        if doc is None:
            chain.append(
                ProcessChainNode(
                    pid=current_pid,
                    inferred=True,
                )
            )
            break
        chain.append(_doc_to_chain_node(doc, inferred=False))
        parent = (doc.get("process") or {}).get("parent") or {}
        next_pid = parent.get("pid")
        current_pid = next_pid if isinstance(next_pid, int) and next_pid > 0 else None

    # M22.c: attach sibling children for each node that has a parent
    # pid in the chain. Walk pairs (child, parent_on_chain) and for the
    # child node ask "what other processes did the same parent spawn?".
    # Pids already in the chain are excluded so the tree doesn't loop
    # back on itself.
    chain_pids = {n.pid for n in chain}
    for i, node in enumerate(chain):
        if node.parent_pid is None or node.parent_pid <= 0:
            continue
        try:
            sib_docs = await os_svc.fetch_process_children(
                client,
                host_id=host_id_str,
                parent_pid=node.parent_pid,
                before=opened_at,
                exclude_pids=chain_pids,
                size=siblings_per_node,
            )
        except Exception:
            sib_docs = []
        node.siblings = [_doc_to_chain_node(d, inferred=False) for d in sib_docs]
        # Avoid mypy/pyright warning about modifying loop var.
        _ = i

    # Leaf-children: what did the alert-triggering process go on to
    # spawn? Look both before and after the alert (a malicious process
    # can spawn children either side of the detection edge). Window is
    # ±24h on each side, capped at 32 entries.
    if chain:
        leaf = chain[-1]
        if leaf.pid > 0:
            try:
                child_docs = await os_svc.fetch_process_children(
                    client,
                    host_id=host_id_str,
                    parent_pid=leaf.pid,
                    before=opened_at - timedelta(hours=24),
                    after=opened_at + timedelta(hours=24),
                    exclude_pids=chain_pids,
                    size=32,
                )
            except Exception:
                child_docs = []
            leaf.children = [_doc_to_chain_node(d, inferred=False) for d in child_docs]

    return chain


def _doc_to_chain_node(doc: dict, *, inferred: bool) -> ProcessChainNode:
    proc = doc.get("process") or {}
    parent = proc.get("parent") or {}
    hashes = proc.get("hash") or {}
    user = proc.get("user") or {}
    started_raw = proc.get("start") or (doc.get("event") or {}).get("created")
    parent_pid_raw = parent.get("pid")
    parent_pid = parent_pid_raw if isinstance(parent_pid_raw, int) else None
    pid_raw = proc.get("pid")
    pid = pid_raw if isinstance(pid_raw, int) else 0
    return ProcessChainNode(
        pid=pid,
        parent_pid=parent_pid,
        name=proc.get("name"),
        executable=proc.get("executable"),
        command_line=proc.get("command_line"),
        sha256=hashes.get("sha256"),
        user_name=user.get("name") if isinstance(user, dict) else None,
        integrity_level=proc.get("integrity_level"),
        working_directory=proc.get("working_directory"),
        started_at=_parse_iso(started_raw),
        event_id=(doc.get("event") or {}).get("id"),
        inferred=inferred,
    )


def _hit_to_timeline(hit: dict, trigger_ids: set[str]) -> TimelineEvent:
    src = hit.get("_source") or {}
    event = src.get("event") or {}
    proc = src.get("process") or {}
    file_ = src.get("file") or {}
    dest = src.get("destination") or {}
    event_id = event.get("id") or hit.get("_id") or ""
    pid_raw = proc.get("pid")
    pid = pid_raw if isinstance(pid_raw, int) else None
    port_raw = dest.get("port")
    port = port_raw if isinstance(port_raw, int) else None
    return TimelineEvent(
        event_id=str(event_id),
        timestamp=_parse_iso(src.get("@timestamp")) or datetime.now(UTC),
        category=list(event.get("category") or []),
        action=event.get("action"),
        outcome=event.get("outcome"),
        pid=pid,
        executable=proc.get("executable"),
        command_line=proc.get("command_line"),
        file_path=file_.get("path"),
        destination_ip=dest.get("ip"),
        destination_port=port,
        is_trigger=event_id in trigger_ids,
    )


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@router.get("/{alert_id}/process/{pid}", response_model=ProcessDetail)
async def get_process_detail(
    alert_id: UUID,
    pid: int,
    db: DbSession,
    actor: RequireViewer,
    window_minutes: int = 15,
    max_events: int = 1000,
) -> ProcessDetail:
    """M20.i: what a specific pid did during the alert's investigation
    window. Powers the selected-process detail panel that appears when
    the analyst clicks a node in the process chain.
    """
    if window_minutes <= 0 or window_minutes > 360:
        raise bad_request("window_minutes must be in (0, 360]")
    if pid <= 0:
        raise bad_request("pid must be > 0")

    stmt = select(Alert).where(Alert.id == alert_id)
    alert = (await db.execute(stmt)).scalar_one_or_none()
    if alert is None:
        raise not_found("alert", str(alert_id))
    if not await host_visible_to(actor, alert.host_id, db):
        # M-audit-and-auth #7: return 404 (not 403) so the response
        # doesn't distinguish "this alert id is real but you can't
        # see it" from "this alert id doesn't exist". The 403/404
        # split let a low-priv account confirm shared cross-team
        # alert ids without seeing their contents.
        raise not_found("alert", str(alert_id))
    if alert.host_id is None:
        # Synthetic / null-host alert (e.g. audit-chain break). No host
        # → no per-pid investigation window. 404 keeps the response
        # shape consistent with "not visible".
        raise not_found("alert", str(alert_id))

    start = alert.opened_at - timedelta(minutes=window_minutes)
    end = alert.opened_at + timedelta(minutes=window_minutes)
    host_id_str = str(alert.host_id)

    client = os_svc._client()
    try:
        process_started = await os_svc.fetch_process_started(
            client,
            host_id=host_id_str,
            pid=pid,
            before=end,
        )
        hits = await os_svc.fetch_pid_window(
            client,
            host_id=host_id_str,
            pid=pid,
            start=start,
            end=end,
            size=max_events,
        )
    finally:
        await client.close()

    image_loads: list[ProcessImageLoad] = []
    files: list[ProcessFileEvent] = []
    network: list[ProcessNetworkEvent] = []
    other: list[ProcessOtherEvent] = []
    for h in hits:
        src = h.get("_source") or {}
        event = src.get("event") or {}
        action = event.get("action") or ""
        ts = _parse_iso(src.get("@timestamp")) or datetime.now(UTC)
        cats: list[str] = list(event.get("category") or [])

        if action in {"image_loaded", "library_loaded"} or "library" in cats:
            file_doc = src.get("file") or {}
            hashes = file_doc.get("hash") or {}
            sig = file_doc.get("code_signature") or {}
            image_loads.append(
                ProcessImageLoad(
                    timestamp=ts,
                    path=file_doc.get("path"),
                    sha256=hashes.get("sha256"),
                    signed=sig.get("signed") if isinstance(sig.get("signed"), bool) else None,
                    signer=sig.get("signer_name") or sig.get("signer"),
                )
            )
            continue

        if "file" in cats or action.startswith("file_"):
            file_doc = src.get("file") or {}
            hashes = file_doc.get("hash") or {}
            size_raw = file_doc.get("size")
            files.append(
                ProcessFileEvent(
                    timestamp=ts,
                    action=action or None,
                    path=file_doc.get("path"),
                    target_path=file_doc.get("target_path"),
                    sha256=hashes.get("sha256"),
                    size=int(size_raw) if isinstance(size_raw, int) else None,
                )
            )
            continue

        if "network" in cats or "dns" in cats:
            net = src.get("network") or {}
            dest = src.get("destination") or {}
            source = src.get("source") or {}
            dest_port_raw = dest.get("port")
            src_port_raw = source.get("port")
            network.append(
                ProcessNetworkEvent(
                    timestamp=ts,
                    action=action or None,
                    transport=net.get("transport"),
                    direction=net.get("direction"),
                    destination_ip=dest.get("ip"),
                    destination_port=dest_port_raw if isinstance(dest_port_raw, int) else None,
                    source_ip=source.get("ip"),
                    source_port=src_port_raw if isinstance(src_port_raw, int) else None,
                )
            )
            continue

        other.append(
            ProcessOtherEvent(
                timestamp=ts,
                category=cats,
                action=action or None,
                outcome=event.get("outcome"),
            )
        )

    process_node = _doc_to_chain_node(process_started, inferred=False) if process_started else None

    return ProcessDetail(
        alert_id=alert_id,
        host_id=alert.host_id,
        pid=pid,
        window_start=start,
        window_end=end,
        process=process_node,
        image_loads=image_loads,
        files=files,
        network=network,
        other=other,
        truncated=len(hits) >= max_events,
    )


@router.post("/{alert_id}/assign", response_model=AlertDetail)
async def assign(
    alert_id: UUID, payload: AlertAssign, db: DbSession, actor: RequireAnalyst
) -> AlertDetail:
    # LEFT OUTER JOIN so synthetic (null-host) alerts still match.
    stmt = (
        select(Alert, Host.hostname, Rule.name)
        .outerjoin(Host, Host.id == Alert.host_id)
        .join(Rule, Rule.id == Alert.rule_id)
        .where(Alert.id == alert_id)
        .options(selectinload(Alert.history))
    )
    row = (await db.execute(stmt)).one_or_none()
    if row is None:
        raise not_found("alert", str(alert_id))
    alert, hostname, rule_name = row
    if not await host_visible_to(actor, alert.host_id, db):
        raise not_found("alert", str(alert_id))
    if payload.assignee_id is not None:
        target = await db.get(User, payload.assignee_id)
        if target is None:
            raise not_found("user", str(payload.assignee_id))
    alert.assignee_id = payload.assignee_id
    await audit.record(
        db,
        actor=actor,
        action="alert.assign",
        resource_type="alert",
        resource_id=str(alert.id),
        payload={"assignee_id": str(payload.assignee_id) if payload.assignee_id else None},
    )
    detail = AlertDetail.model_validate(alert)
    detail.host_hostname = hostname
    detail.rule_name = rule_name
    return detail
