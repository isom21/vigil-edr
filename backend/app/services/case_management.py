"""Glue between the alert lifecycle and the per-tracker case clients.

Two entry points:

  * `sync_alert_to_destinations(db, alert)` — called from the alert
    state-change hook. Iterates the enabled destinations, asks each
    per-kind client to open an issue, and persists a CaseLink row per
    successful mirror. Idempotent against the (alert, destination)
    unique constraint: a re-fire that finds an existing link skips
    the create call and leaves the row alone.

  * `poll_destination(db, destination)` — called from the
    `case_sync` worker on its tick. Walks the destination's active
    links (sync_state NOT IN ('closed', 'failed')) and refreshes
    each one from the external tracker. Updates `last_synced_at`
    on every successful poll, and `sync_state` only when it changed.

These are mutation-heavy paths; the caller (lifecycle hook or worker
loop) owns the commit.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, CaseDestination, CaseDestinationKind, CaseLink, CaseSyncState
from app.services.case import CaseSyncError
from app.services.case import jira as jira_client
from app.services.case import servicenow as servicenow_client
from app.services.encryption import decrypt_config

log = structlog.get_logger()


async def _create_external_issue(destination: CaseDestination, alert: Alert) -> tuple[str, str]:
    """Dispatch to the right per-kind client. Raises CaseSyncError."""
    config = decrypt_config(destination.config_encrypted)
    try:
        kind = CaseDestinationKind.coerce(destination.kind)
    except ValueError as exc:
        raise CaseSyncError(str(exc), transient=False) from exc
    if kind is CaseDestinationKind.JIRA:
        return await jira_client.create_issue(config, alert)
    if kind is CaseDestinationKind.SERVICENOW:
        return await servicenow_client.create_issue(config, alert)
    raise CaseSyncError(f"unknown case destination kind: {kind.value}", transient=False)


async def _fetch_external_status(destination: CaseDestination, external_id: str) -> CaseSyncState:
    config = decrypt_config(destination.config_encrypted)
    try:
        kind = CaseDestinationKind.coerce(destination.kind)
    except ValueError as exc:
        raise CaseSyncError(str(exc), transient=False) from exc
    if kind is CaseDestinationKind.JIRA:
        return await jira_client.fetch_status(config, external_id)
    if kind is CaseDestinationKind.SERVICENOW:
        return await servicenow_client.fetch_status(config, external_id)
    raise CaseSyncError(f"unknown case destination kind: {kind.value}", transient=False)


async def sync_alert_to_destinations(db: AsyncSession, alert: Alert) -> list[CaseLink]:
    """Open a mirror in every enabled destination for `alert`.

    Returns the list of CaseLink rows created or already-present for
    this alert. Failures are recorded as CaseLink rows with
    `sync_state=failed` + `error` populated so the UI can show the
    operator what went wrong without a follow-up call. Skips
    destinations the alert is already linked to (idempotent against
    repeated state transitions).
    """
    dests = (
        (await db.execute(select(CaseDestination).where(CaseDestination.enabled.is_(True))))
        .scalars()
        .all()
    )
    if not dests:
        return []
    existing_links = (
        (await db.execute(select(CaseLink).where(CaseLink.alert_id == alert.id))).scalars().all()
    )
    existing_by_dest = {link.destination_id: link for link in existing_links}
    results: list[CaseLink] = []
    for dest in dests:
        if dest.id in existing_by_dest:
            # Already mirrored. Don't re-create on a second state
            # transition; the poller is responsible for keeping the
            # link's sync_state fresh.
            results.append(existing_by_dest[dest.id])
            continue
        try:
            external_id, external_url = await _create_external_issue(dest, alert)
        except CaseSyncError as exc:
            log.warning(
                "case_management.create_failed",
                alert_id=str(alert.id),
                destination_id=str(dest.id),
                destination_name=dest.name,
                transient=exc.transient,
                error=str(exc),
            )
            link = CaseLink(
                alert_id=alert.id,
                destination_id=dest.id,
                external_id="",
                external_url=None,
                sync_state=CaseSyncState.FAILED,
                error=str(exc)[:512],
            )
            db.add(link)
            results.append(link)
            continue
        link = CaseLink(
            alert_id=alert.id,
            destination_id=dest.id,
            external_id=external_id,
            external_url=external_url,
            last_synced_at=datetime.now(UTC),
            sync_state=CaseSyncState.OPEN,
            error=None,
        )
        db.add(link)
        results.append(link)
        log.info(
            "case_management.created",
            alert_id=str(alert.id),
            destination_id=str(dest.id),
            destination_name=dest.name,
            external_id=external_id,
        )
    return results


async def poll_destination(db: AsyncSession, destination: CaseDestination) -> int:
    """Refresh the sync_state of every active link for `destination`.

    Returns the number of links whose state actually changed. Walks
    only links that are still 'live' (not closed/failed) so a closed
    issue doesn't keep getting polled forever.
    """
    if not destination.enabled:
        return 0
    rows = (
        (
            await db.execute(
                select(CaseLink).where(
                    CaseLink.destination_id == destination.id,
                    CaseLink.sync_state.notin_(
                        [CaseSyncState.CLOSED.value, CaseSyncState.FAILED.value]
                    ),
                )
            )
        )
        .scalars()
        .all()
    )
    changed = 0
    for link in rows:
        if not link.external_id:
            # Defensive: a previous create-failure could in theory have
            # left external_id empty even though sync_state should
            # already be FAILED. Skip cleanly.
            continue
        try:
            new_state = await _fetch_external_status(destination, link.external_id)
        except CaseSyncError as exc:
            log.warning(
                "case_management.poll_failed",
                destination_id=str(destination.id),
                link_id=str(link.id),
                external_id=link.external_id,
                transient=exc.transient,
                error=str(exc),
            )
            # Don't flip a previously-good link to FAILED on a transient
            # blip. Record the error message but keep the existing
            # sync_state so the next tick can recover.
            link.error = str(exc)[:512]
            continue
        link.last_synced_at = datetime.now(UTC)
        link.error = None
        # `sync_state` round-trips as a raw string from the DB (TEXT
        # column) — coerce before comparing so we don't double-write
        # rows whose state is already correct.
        current = (
            link.sync_state.value
            if isinstance(link.sync_state, CaseSyncState)
            else str(link.sync_state)
        )
        if current != new_state.value:
            link.sync_state = new_state
            changed += 1
            log.info(
                "case_management.poll_state_change",
                destination_id=str(destination.id),
                link_id=str(link.id),
                external_id=link.external_id,
                new_state=new_state.value,
            )
    return changed


__all__ = ["poll_destination", "sync_alert_to_destinations"]
