"""Phase 3 #3.6 external case management.

Covers:
  * Encryption helper round-trips a plaintext config under the
    dev-default Fernet key.
  * `sync_alert_to_destinations` opens a Jira issue via respx and
    persists a CaseLink with the returned key + URL.
  * Re-firing the same alert against the same destination is
    idempotent (the unique constraint on (alert_id, destination_id)
    keeps the operator's repeated state transitions from spamming
    Jira).
  * The same shape works against the ServiceNow client — different
    URL, different payload, same CaseLink row out the back.
  * `poll_destination` walks active links and transitions a Jira
    issue whose status moved to "Done" into `closed`, closing the
    UI's view of the loop.
  * A failing create surfaces as a CaseLink row with sync_state=failed
    rather than a 500 / DB rollback — the operator finds the failure
    on the alert detail page.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

import pytest
import pytest_asyncio
import respx
from httpx import Response


def _test_session_maker(db_session):
    @asynccontextmanager
    async def _maker():
        yield db_session

    return _maker


# ---------- crypto round-trip ----------


def test_encryption_round_trip(monkeypatch) -> None:
    """Encrypt/decrypt is symmetric under the dev-default key."""
    from app.core import config
    from app.services.encryption import decrypt_config, encrypt_config

    monkeypatch.setattr(config.settings, "notification_encryption_key", "")
    blob = encrypt_config({"base_url": "https://x", "api_token": "abc"})
    assert decrypt_config(blob) == {"base_url": "https://x", "api_token": "abc"}


# ---------- DB fixtures ----------


@pytest_asyncio.fixture
async def _host(db_session):
    from app.models import Host, HostStatus, OsFamily

    h = Host(
        hostname=f"case-host-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add(h)
    await db_session.flush()
    return h


@pytest_asyncio.fixture
async def _rule(db_session):
    from app.models import Rule, RuleKind, Severity

    r = Rule(
        kind=RuleKind.IOC,
        name=f"case-rule-{os.urandom(3).hex()}",
        severity=Severity.HIGH,
    )
    db_session.add(r)
    await db_session.flush()
    return r


@pytest_asyncio.fixture
async def _alert(db_session, _host, _rule):
    from app.models import Alert, AlertState, Severity

    a = Alert(
        host_id=_host.id,
        rule_id=_rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="Case-management test alert",
    )
    db_session.add(a)
    await db_session.flush()
    return a


@pytest_asyncio.fixture
async def _jira_dest(db_session):
    from app.models import CaseDestination, CaseDestinationKind
    from app.services.encryption import encrypt_config

    config = {
        "base_url": "https://jira.example.com",
        "email": "soc@example.com",
        "api_token": "tok-xyz",
        "project_key": "SEC",
        "issue_type": "Task",
    }
    d = CaseDestination(
        kind=CaseDestinationKind.JIRA.value,
        name=f"jira-test-{os.urandom(3).hex()}",
        config_encrypted=encrypt_config(config),
        enabled=True,
    )
    db_session.add(d)
    await db_session.flush()
    return d


@pytest_asyncio.fixture
async def _servicenow_dest(db_session):
    from app.models import CaseDestination, CaseDestinationKind
    from app.services.encryption import encrypt_config

    config = {
        "instance_url": "https://acme.service-now.com",
        "username": "vigil_int",
        "password": "secret",
    }
    d = CaseDestination(
        kind=CaseDestinationKind.SERVICENOW.value,
        name=f"sn-test-{os.urandom(3).hex()}",
        config_encrypted=encrypt_config(config),
        enabled=True,
    )
    db_session.add(d)
    await db_session.flush()
    return d


# ---------- sync_alert_to_destinations ----------


@pytest.mark.asyncio
@respx.mock
async def test_sync_creates_jira_issue(db_session, _alert, _jira_dest) -> None:
    """A state transition pushes the alert into Jira and records a
    CaseLink with the returned issue key + URL."""
    from sqlalchemy import select

    from app.models import CaseLink, CaseSyncState
    from app.services.case_management import sync_alert_to_destinations

    respx.post("https://jira.example.com/rest/api/3/issue").mock(
        return_value=Response(201, json={"id": "10001", "key": "SEC-42"})
    )

    links = await sync_alert_to_destinations(db_session, _alert)
    assert len(links) == 1
    link = links[0]
    assert link.destination_id == _jira_dest.id
    assert link.external_id == "SEC-42"
    assert link.external_url == "https://jira.example.com/browse/SEC-42"
    assert link.sync_state == CaseSyncState.OPEN
    assert link.last_synced_at is not None
    assert link.error is None

    persisted = (
        await db_session.execute(select(CaseLink).where(CaseLink.alert_id == _alert.id))
    ).scalar_one()
    assert persisted.external_id == "SEC-42"


@pytest.mark.asyncio
@respx.mock
async def test_sync_is_idempotent_per_destination(db_session, _alert, _jira_dest) -> None:
    """A second sync against the same (alert, destination) doesn't call
    Jira again — the existing link is returned as-is."""
    from app.services.case_management import sync_alert_to_destinations

    route = respx.post("https://jira.example.com/rest/api/3/issue").mock(
        return_value=Response(201, json={"key": "SEC-99"})
    )

    first = await sync_alert_to_destinations(db_session, _alert)
    assert len(first) == 1
    assert route.call_count == 1

    second = await sync_alert_to_destinations(db_session, _alert)
    assert len(second) == 1
    # Same row, second time round.
    assert second[0].external_id == "SEC-99"
    # No extra Jira POST.
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_sync_records_failure_inline(db_session, _alert, _jira_dest) -> None:
    """A 4xx from Jira lands as a CaseLink with sync_state=failed +
    error populated, not a 500 / DB rollback."""
    from app.models import CaseSyncState
    from app.services.case_management import sync_alert_to_destinations

    respx.post("https://jira.example.com/rest/api/3/issue").mock(
        return_value=Response(400, text="project key SEC does not exist")
    )

    links = await sync_alert_to_destinations(db_session, _alert)
    assert len(links) == 1
    link = links[0]
    assert link.sync_state == CaseSyncState.FAILED
    assert link.error is not None
    assert "400" in link.error


@pytest.mark.asyncio
@respx.mock
async def test_sync_creates_servicenow_incident(db_session, _alert, _servicenow_dest) -> None:
    """Same contract as Jira but against ServiceNow's Table API."""
    from sqlalchemy import select

    from app.models import CaseLink, CaseSyncState
    from app.services.case_management import sync_alert_to_destinations

    respx.post("https://acme.service-now.com/api/now/table/incident").mock(
        return_value=Response(
            201,
            json={"result": {"sys_id": "abc123def456", "number": "INC0010001"}},
        )
    )

    links = await sync_alert_to_destinations(db_session, _alert)
    assert len(links) == 1
    link = links[0]
    assert link.external_id == "abc123def456"
    assert "abc123def456" in (link.external_url or "")
    assert link.sync_state == CaseSyncState.OPEN

    persisted = (
        await db_session.execute(select(CaseLink).where(CaseLink.alert_id == _alert.id))
    ).scalar_one()
    assert persisted.destination_id == _servicenow_dest.id


# ---------- poll_destination ----------


@pytest.mark.asyncio
@respx.mock
async def test_poll_jira_closes_link_when_issue_done(db_session, _alert, _jira_dest) -> None:
    """A Jira issue whose statusCategory is `done` flips the link's
    sync_state to closed and pulls it out of the active-poll set."""
    from app.models import CaseLink, CaseSyncState
    from app.services.case_management import poll_destination, sync_alert_to_destinations

    respx.post("https://jira.example.com/rest/api/3/issue").mock(
        return_value=Response(201, json={"key": "SEC-7"})
    )
    await sync_alert_to_destinations(db_session, _alert)
    await db_session.flush()

    respx.get("https://jira.example.com/rest/api/3/issue/SEC-7").mock(
        return_value=Response(
            200,
            json={
                "fields": {
                    "status": {
                        "name": "Done",
                        "statusCategory": {"key": "done", "name": "Done"},
                    }
                }
            },
        )
    )
    changed = await poll_destination(db_session, _jira_dest)
    assert changed == 1

    from sqlalchemy import select

    link = (
        await db_session.execute(select(CaseLink).where(CaseLink.alert_id == _alert.id))
    ).scalar_one()
    state = link.sync_state.value if hasattr(link.sync_state, "value") else link.sync_state
    assert state == CaseSyncState.CLOSED.value
    assert link.last_synced_at is not None


@pytest.mark.asyncio
@respx.mock
async def test_poll_jira_skips_closed_links(db_session, _alert, _jira_dest) -> None:
    """Already-closed links are excluded from the poll set so we don't
    burn rate-limit budget on cases nobody's watching any more."""
    from app.models import CaseLink, CaseSyncState
    from app.services.case_management import poll_destination

    closed = CaseLink(
        alert_id=_alert.id,
        destination_id=_jira_dest.id,
        external_id="SEC-OLD",
        external_url="https://jira.example.com/browse/SEC-OLD",
        sync_state=CaseSyncState.CLOSED,
    )
    db_session.add(closed)
    await db_session.flush()

    route = respx.get("https://jira.example.com/rest/api/3/issue/SEC-OLD").mock(
        return_value=Response(200, json={"fields": {"status": {}}})
    )
    changed = await poll_destination(db_session, _jira_dest)
    assert changed == 0
    assert route.called is False


@pytest.mark.asyncio
@respx.mock
async def test_poll_servicenow_maps_state_code_to_resolved(
    db_session, _alert, _servicenow_dest
) -> None:
    """ServiceNow's integer state code 6 (resolved) maps to RESOLVED in
    Vigil's enum."""
    from app.models import CaseLink, CaseSyncState
    from app.services.case_management import poll_destination

    link = CaseLink(
        alert_id=_alert.id,
        destination_id=_servicenow_dest.id,
        external_id="sysid-1",
        external_url="https://acme.service-now.com/incident.do?sys_id=sysid-1",
        sync_state=CaseSyncState.IN_PROGRESS,
    )
    db_session.add(link)
    await db_session.flush()

    respx.get("https://acme.service-now.com/api/now/table/incident/sysid-1").mock(
        return_value=Response(200, json={"result": {"sys_id": "sysid-1", "state": "6"}})
    )

    changed = await poll_destination(db_session, _servicenow_dest)
    assert changed == 1
    # Compare on `.value` because `sync_state` is stored as TEXT +
    # CHECK constraint (not a Postgres enum type — see the model for
    # the rationale), and `poll_destination` writes the enum object
    # back so the in-memory attribute is either a `CaseSyncState`
    # member or the raw string depending on whether SQLAlchemy has
    # round-tripped it. Normalise to the value for the assertion.
    state = link.sync_state.value if hasattr(link.sync_state, "value") else link.sync_state
    assert state == CaseSyncState.RESOLVED.value


# ---------- worker tick ----------


@pytest.mark.asyncio
@respx.mock
async def test_worker_run_once_iterates_destinations(
    db_session, _alert, _jira_dest, _servicenow_dest
) -> None:
    """The worker's outer loop walks every enabled destination and
    polls each one's live links."""
    from app.models import CaseLink, CaseSyncState
    from app.workers.case_sync import _run_once

    # Seed live links for both destinations so the poller has work.
    db_session.add(
        CaseLink(
            alert_id=_alert.id,
            destination_id=_jira_dest.id,
            external_id="SEC-1",
            external_url="https://jira.example.com/browse/SEC-1",
            sync_state=CaseSyncState.OPEN,
        )
    )
    db_session.add(
        CaseLink(
            alert_id=_alert.id,
            destination_id=_servicenow_dest.id,
            external_id="sn-1",
            external_url="https://acme.service-now.com/incident.do?sys_id=sn-1",
            sync_state=CaseSyncState.OPEN,
        )
    )
    await db_session.flush()

    respx.get("https://jira.example.com/rest/api/3/issue/SEC-1").mock(
        return_value=Response(
            200,
            json={
                "fields": {
                    "status": {"statusCategory": {"key": "done"}},
                }
            },
        )
    )
    respx.get("https://acme.service-now.com/api/now/table/incident/sn-1").mock(
        return_value=Response(200, json={"result": {"sys_id": "sn-1", "state": "7"}})
    )

    changed = await _run_once(session_maker=_test_session_maker(db_session))
    # Both links transitioned this pass.
    assert changed == 2


# ---------- env knob ----------


def test_case_sync_interval_floor_30s() -> None:
    """A 1-second tick would hammer external trackers' rate limits.
    Floor 30s regardless of operator input."""
    from app.workers.case_sync import _interval_seconds

    os.environ["VIGIL_CASE_SYNC_INTERVAL_S"] = "1"
    try:
        assert _interval_seconds() == 30
    finally:
        os.environ.pop("VIGIL_CASE_SYNC_INTERVAL_S", None)


# ---------- destination kind validation ----------


def test_check_required_fields_jira() -> None:
    from fastapi import HTTPException

    from app.api.case_destinations import _check_required
    from app.models import CaseDestinationKind

    with pytest.raises(HTTPException) as excinfo:
        _check_required(CaseDestinationKind.JIRA, {"base_url": "https://x"})
    assert "email" in str(excinfo.value.detail)


def test_check_required_fields_servicenow() -> None:
    from fastapi import HTTPException

    from app.api.case_destinations import _check_required
    from app.models import CaseDestinationKind

    # Complete config — no raise.
    _check_required(
        CaseDestinationKind.SERVICENOW,
        {"instance_url": "https://x", "username": "u", "password": "p"},
    )
    with pytest.raises(HTTPException):
        _check_required(CaseDestinationKind.SERVICENOW, {"instance_url": "https://x"})


# ---------- jira status mapping ----------


def test_jira_status_categories_map_correctly() -> None:
    from app.models import CaseSyncState
    from app.services.case.jira import _map_category

    assert _map_category("done") == CaseSyncState.CLOSED
    assert _map_category("indeterminate") == CaseSyncState.IN_PROGRESS
    assert _map_category("new") == CaseSyncState.OPEN
    # Unknown category falls back to OPEN — don't accidentally label a
    # live issue as closed.
    assert _map_category("custom-cat") == CaseSyncState.OPEN
    assert _map_category(None) == CaseSyncState.OPEN
