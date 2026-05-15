"""Threat-intel feed CRUD + trigger-pull (Phase 1 #1.9).

Operators register feeds here; the ingest worker (run_forever in
`app.workers.intel_ingest`) pulls each enabled row on its own cadence
and materialises indicators under a managed `Rule` of kind=IOC. The
feed's `auth` field is encrypted at write time and never sent back
out — the API surfaces `has_auth` instead.

All mutations + trigger-pull are admin-only and audited. We redact
the raw auth from the audit payload so a leaked audit row can't be
turned into a TAXII credential.
"""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, status
from sqlalchemy import func, select

from app.core.deps import DbSession, RequireAdmin, RequireViewer
from app.core.errors import bad_request, not_found
from app.models import IntelFeed, Rule
from app.schemas.common import Page
from app.schemas.intel import IntelFeedCreate, IntelFeedOut, IntelFeedUpdate
from app.services import audit
from app.services.intel.crypto import encrypt_auth
from app.services.scoping import apply_tenant_scope

log = structlog.get_logger()

router = APIRouter(prefix="/api/intel/feeds", tags=["intel"])


def _to_out(feed: IntelFeed) -> IntelFeedOut:
    return IntelFeedOut(
        id=feed.id,
        name=feed.name,
        kind=feed.kind,
        url=feed.url,
        has_auth=feed.encrypted_auth is not None,
        interval_s=feed.interval_s,
        last_pulled_at=feed.last_pulled_at,
        entry_count=feed.entry_count,
        last_error=feed.last_error,
        enabled=feed.enabled,
        managed_rule_id=feed.managed_rule_id,
        created_at=feed.created_at,
        updated_at=feed.updated_at,
    )


def _audit_payload(name: str | None, *, has_auth: bool | None = None) -> dict:
    """Build an audit payload that never includes the raw auth value.
    `has_auth` is encoded as a boolean so the audit row records the
    operator's intent without leaking the credential."""
    payload: dict = {}
    if name is not None:
        payload["name"] = name
    if has_auth is not None:
        payload["auth_set"] = bool(has_auth)
    return payload


async def _load_in_tenant(db, feed_id: UUID, actor) -> IntelFeed:
    """Fetch a feed, enforcing tenant scope. 404 (not 403) on cross-
    tenant id (CODE-10)."""
    feed = await db.get(IntelFeed, feed_id)
    if feed is None or feed.tenant_id != actor.tenant_id:
        raise not_found("intel_feed", str(feed_id))
    return feed


@router.get("", response_model=Page[IntelFeedOut])
async def list_feeds(
    db: DbSession,
    actor: RequireViewer,
    limit: int = 50,
    offset: int = 0,
) -> Page[IntelFeedOut]:
    # CODE-10: scope to actor's tenant. Pre-PR, tenant A could list
    # (and via update/trigger_pull below mutate) tenant B's TAXII /
    # abuse.ch / custom-JSON feed credentials.
    stmt = (
        apply_tenant_scope(select(IntelFeed), actor, IntelFeed.tenant_id)
        .order_by(IntelFeed.name)
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.execute(stmt)).scalars().all()
    total = (
        await db.execute(
            apply_tenant_scope(select(func.count(IntelFeed.id)), actor, IntelFeed.tenant_id)
        )
    ).scalar_one()
    return Page(
        items=[_to_out(r) for r in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=IntelFeedOut, status_code=status.HTTP_201_CREATED)
async def create_feed(
    payload: IntelFeedCreate,
    db: DbSession,
    actor: RequireAdmin,
) -> IntelFeedOut:
    # Name uniqueness is per-tenant — tenant A and tenant B can each
    # have a feed named "abuse.ch-urlhaus".
    dup = (
        await db.execute(
            select(IntelFeed)
            .where(IntelFeed.name == payload.name)
            .where(IntelFeed.tenant_id == actor.tenant_id)
        )
    ).scalar_one_or_none()
    if dup is not None:
        raise bad_request(f"intel feed '{payload.name}' already exists")
    encrypted: bytes | None = None
    if payload.auth:
        encrypted = encrypt_auth(payload.auth)
    feed = IntelFeed(
        tenant_id=actor.tenant_id,
        name=payload.name,
        kind=payload.kind,
        url=str(payload.url),
        encrypted_auth=encrypted,
        interval_s=payload.interval_s,
        enabled=payload.enabled,
    )
    db.add(feed)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="intel_feed.create",
        resource_type="intel_feed",
        resource_id=str(feed.id),
        payload=_audit_payload(feed.name, has_auth=encrypted is not None)
        | {"kind": feed.kind.value, "url": feed.url, "interval_s": feed.interval_s},
    )
    await db.commit()
    return _to_out(feed)


@router.get("/{feed_id}", response_model=IntelFeedOut)
async def get_feed(feed_id: UUID, db: DbSession, actor: RequireViewer) -> IntelFeedOut:
    feed = await _load_in_tenant(db, feed_id, actor)
    return _to_out(feed)


@router.patch("/{feed_id}", response_model=IntelFeedOut)
async def update_feed(
    feed_id: UUID,
    payload: IntelFeedUpdate,
    db: DbSession,
    actor: RequireAdmin,
) -> IntelFeedOut:
    feed = await _load_in_tenant(db, feed_id, actor)
    if payload.name is not None and payload.name != feed.name:
        dup = (
            await db.execute(
                select(IntelFeed)
                .where(IntelFeed.name == payload.name)
                .where(IntelFeed.tenant_id == actor.tenant_id)
            )
        ).scalar_one_or_none()
        if dup is not None:
            raise bad_request(f"intel feed '{payload.name}' already exists")
        feed.name = payload.name
    if payload.url is not None:
        feed.url = str(payload.url)
    if payload.interval_s is not None:
        feed.interval_s = payload.interval_s
    if payload.enabled is not None:
        feed.enabled = payload.enabled
    auth_changed: bool | None = None
    if payload.auth is not None:
        if payload.auth == "":
            feed.encrypted_auth = None
            auth_changed = False
        else:
            feed.encrypted_auth = encrypt_auth(payload.auth)
            auth_changed = True
    await audit.record(
        db,
        actor=actor,
        action="intel_feed.update",
        resource_type="intel_feed",
        resource_id=str(feed.id),
        payload=_audit_payload(feed.name, has_auth=auth_changed)
        | {"interval_s": feed.interval_s, "enabled": feed.enabled},
    )
    await db.commit()
    await db.refresh(feed)
    return _to_out(feed)


@router.delete("/{feed_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_feed(feed_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    feed = await _load_in_tenant(db, feed_id, actor)
    # The managed Rule has FK ondelete=SET NULL pointing at this row;
    # delete the rule explicitly so its IocEntry cascade fires and we
    # don't leave orphaned entries with source_id=NULL on a rule named
    # "intel:<deleted-feed>". Operator can recreate the feed cleanly.
    rule_id = feed.managed_rule_id
    if rule_id is not None:
        rule = await db.get(Rule, rule_id)
        if rule is not None:
            await db.delete(rule)
    await db.delete(feed)
    await audit.record(
        db,
        actor=actor,
        action="intel_feed.delete",
        resource_type="intel_feed",
        resource_id=str(feed_id),
    )
    await db.commit()


@router.post(
    "/{feed_id}/pull",
    response_model=IntelFeedOut,
    status_code=status.HTTP_200_OK,
)
async def trigger_pull(
    feed_id: UUID,
    db: DbSession,
    actor: RequireAdmin,
) -> IntelFeedOut:
    """Force a single feed to pull now, regardless of its cadence.

    The handler audits the trigger, then delegates to the worker's
    `trigger_pull` helper so the diff/insert logic lives in one place.
    """
    feed = await _load_in_tenant(db, feed_id, actor)
    await audit.record(
        db,
        actor=actor,
        action="intel_feed.pull_triggered",
        resource_type="intel_feed",
        resource_id=str(feed_id),
        payload=_audit_payload(feed.name),
    )
    await db.commit()
    # The worker takes its own session out of the pool so it can commit
    # the pull results independently of this request's transaction.
    from app.workers.intel_ingest import trigger_pull as _do_pull

    await _do_pull(feed_id)
    # Re-read to surface the new last_pulled_at / entry_count to the UI.
    await db.refresh(feed)
    return _to_out(feed)
