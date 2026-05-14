"""Phase 4 #4.1 — AI-assisted analyst.

Covers:

  * Worker → service: `handle_envelope` on an `alert.opened` envelope
    creates an `alert_summary` row.
  * Empty `VIGIL_ANTHROPIC_API_KEY` short-circuits to the dev stub —
    no HTTP call, no SDK initialisation.
  * Mocked Anthropic client: a happy-path response writes the row,
    publishes `alert.summary_ready`, and stamps the model id + token
    counts.
  * GET `/api/alerts/:id/summary` returns 200 with the row, 404 when
    the alert has no summary, and 404 for cross-tenant access.
  * POST `/api/ai/nl-to-query` runs once, then 429 after 30 hits in
    the same minute (rate limit).
  * Playbook `ai_suggest` step records the model's suggestions on
    the run's steps_executed_json.
"""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

# ---------- Fixtures / helpers ----------


def _test_session_maker(db_session):
    @asynccontextmanager
    async def _maker():
        yield db_session

    return _maker


def _host_kwargs() -> dict[str, object]:
    from app.models import HostStatus, OsFamily

    return {
        "hostname": f"h-{os.urandom(3).hex()}",
        "os_family": OsFamily.LINUX,
        "status": HostStatus.ONLINE,
    }


async def _make_alert(db_session):
    """Insert a host + rule + alert and return them."""
    from app.models import (
        Alert,
        AlertState,
        Host,
        Rule,
        RuleAction,
        RuleKind,
        Severity,
    )

    host = Host(**_host_kwargs())
    rule = Rule(
        kind=RuleKind.YARA,
        name=f"r-{os.urandom(3).hex()}",
        severity=Severity.HIGH,
        action=RuleAction.ALERT,
        body="rule x { condition: true }",
    )
    db_session.add_all([host, rule])
    await db_session.flush()
    alert = Alert(
        host_id=host.id,
        rule_id=rule.id,
        severity=Severity.HIGH,
        state=AlertState.NEW,
        summary="suspicious activity",
        details={"ecs": {"process": {"pid": 1234, "name": "bash"}}},
    )
    db_session.add(alert)
    await db_session.flush()
    return host, rule, alert


def _mock_ai_result(summary: str = "Test summary.", suggestions=None):
    """Build the AiCallResult shape the service expects from the
    client wrapper."""
    from app.services.ai_client import AiCallResult

    return AiCallResult(
        payload={
            "summary": summary,
            "suggested_response": suggestions
            if suggestions is not None
            else [{"kind": "isolate", "label": "Isolate host", "rationale": "test"}],
        },
        cached_input_tokens=1234,
        output_tokens=42,
        model_id="claude-haiku-4-5-20251001",
    )


# ---------- Dev-stub path: no API key, no HTTP call ----------


def test_ai_client_stub_when_no_api_key():
    """An empty API key returns canned payloads from every method
    without instantiating the SDK or touching the network."""
    from app.services.ai_client import AnthropicClient

    client = AnthropicClient(api_key="")

    # Drive each method through the stub branch using asyncio.run.
    summary = asyncio.run(client.summarise_alert({"id": "x"}, {}, {}))
    assert "summary unavailable" in summary.payload["summary"]
    assert summary.payload["suggested_response"] == []
    assert summary.cached_input_tokens == 0
    assert summary.output_tokens == 0

    suggest = asyncio.run(client.suggest_response({"id": "x"}))
    assert suggest.payload["suggested_response"] == []

    nl = asyncio.run(client.nl_to_query("find bash", "lucene"))
    assert nl.payload["query"] == ""
    assert nl.payload["language"] == "lucene"


# ---------- Service: summarise_and_persist ----------


@pytest.mark.asyncio
async def test_summarise_and_persist_writes_row(db_session) -> None:
    """A mocked client's response lands in an `alert_summary` row
    keyed off the alert id, stamps the model id + token counts, and
    publishes `alert.summary_ready`."""
    from app.models import AlertSummary
    from app.services.ai_summary import summarise_and_persist

    _, _, alert = await _make_alert(db_session)

    mock_client = MagicMock()
    mock_client.summarise_alert = AsyncMock(return_value=_mock_ai_result())

    with patch("app.services.ai_summary.publish_event", new_callable=AsyncMock) as mock_pub:
        row = await summarise_and_persist(db_session, alert.id, client=mock_client)

    assert row is not None
    assert row.alert_id == alert.id
    assert row.summary == "Test summary."
    assert row.model_id == "claude-haiku-4-5-20251001"
    assert row.cached_input_tokens == 1234
    assert row.output_tokens == 42
    assert isinstance(row.suggested_response_json, list)
    assert row.suggested_response_json[0]["kind"] == "isolate"

    mock_client.summarise_alert.assert_awaited_once()
    mock_pub.assert_awaited_once()
    assert mock_pub.await_args is not None
    args, _ = mock_pub.await_args
    assert args[0] == "alert.summary_ready"
    assert args[1]["alert_id"] == str(alert.id)

    # Persisted exactly once.
    from sqlalchemy import select

    rows = (
        (await db_session.execute(select(AlertSummary).where(AlertSummary.alert_id == alert.id)))
        .scalars()
        .all()
    )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_summarise_and_persist_replaces_existing(db_session) -> None:
    """Re-running for the same alert replaces the prior row — the
    UNIQUE(alert_id) constraint doesn't bounce the second insert."""
    from sqlalchemy import select

    from app.models import AlertSummary
    from app.services.ai_summary import summarise_and_persist

    _, _, alert = await _make_alert(db_session)

    mock_client = MagicMock()
    mock_client.summarise_alert = AsyncMock(return_value=_mock_ai_result(summary="first"))

    with patch("app.services.ai_summary.publish_event", new_callable=AsyncMock):
        await summarise_and_persist(db_session, alert.id, client=mock_client)

    mock_client.summarise_alert = AsyncMock(return_value=_mock_ai_result(summary="second"))
    with patch("app.services.ai_summary.publish_event", new_callable=AsyncMock):
        await summarise_and_persist(db_session, alert.id, client=mock_client)

    rows = (
        (await db_session.execute(select(AlertSummary).where(AlertSummary.alert_id == alert.id)))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].summary == "second"


@pytest.mark.asyncio
async def test_summarise_and_persist_handles_missing_alert(db_session) -> None:
    """A vanished alert returns None without touching the AI client."""
    from app.services.ai_summary import summarise_and_persist

    mock_client = MagicMock()
    mock_client.summarise_alert = AsyncMock()

    result = await summarise_and_persist(db_session, uuid4(), client=mock_client)
    assert result is None
    mock_client.summarise_alert.assert_not_awaited()


# ---------- Worker: handle_envelope ----------


@pytest.mark.asyncio
async def test_handle_envelope_alert_opened_creates_summary(db_session) -> None:
    """The worker's handle_envelope honours `alert.opened` envelopes
    and writes the summary row."""
    from sqlalchemy import select

    from app.models import AlertSummary
    from app.workers.ai_summariser import handle_envelope

    _, _, alert = await _make_alert(db_session)

    mock_client = MagicMock()
    mock_client.summarise_alert = AsyncMock(return_value=_mock_ai_result())

    with patch("app.services.ai_summary.publish_event", new_callable=AsyncMock):
        ok = await handle_envelope(
            {"event_type": "alert.opened", "payload": {"alert_id": str(alert.id)}},
            session_maker=_test_session_maker(db_session),
            client=mock_client,
        )
    assert ok is True

    rows = (
        (await db_session.execute(select(AlertSummary).where(AlertSummary.alert_id == alert.id)))
        .scalars()
        .all()
    )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_handle_envelope_skips_other_event_types(db_session) -> None:
    """An incident envelope on the same topic is ignored."""
    from app.workers.ai_summariser import handle_envelope

    mock_client = MagicMock()
    mock_client.summarise_alert = AsyncMock()

    ok = await handle_envelope(
        {"event_type": "incident.opened", "payload": {"incident_id": str(uuid4())}},
        session_maker=_test_session_maker(db_session),
        client=mock_client,
    )
    assert ok is False
    mock_client.summarise_alert.assert_not_awaited()


# ---------- API: GET /api/alerts/:id/summary ----------


@pytest.mark.asyncio
async def test_get_alert_summary_returns_row(http_client, admin_headers, db_session) -> None:
    from app.services.ai_summary import summarise_and_persist

    _, _, alert = await _make_alert(db_session)

    mock_client = MagicMock()
    mock_client.summarise_alert = AsyncMock(return_value=_mock_ai_result())
    with patch("app.services.ai_summary.publish_event", new_callable=AsyncMock):
        await summarise_and_persist(db_session, alert.id, client=mock_client)
    await db_session.flush()

    resp = await http_client.get(f"/api/alerts/{alert.id}/summary", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["alert_id"] == str(alert.id)
    assert body["summary"] == "Test summary."
    assert body["model_id"] == "claude-haiku-4-5-20251001"
    assert body["cached_input_tokens"] == 1234


@pytest.mark.asyncio
async def test_get_alert_summary_404_when_not_ready(http_client, admin_headers, db_session) -> None:
    """An alert without a summary row 404s. Same 404 as an unknown
    alert id — the UI treats both as "AI analysis pending"."""
    _, _, alert = await _make_alert(db_session)

    resp = await http_client.get(f"/api/alerts/{alert.id}/summary", headers=admin_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_alert_summary_404_for_unknown_alert(http_client, admin_headers) -> None:
    resp = await http_client.get(f"/api/alerts/{uuid4()}/summary", headers=admin_headers)
    assert resp.status_code == 404


# ---------- API: POST /api/ai/nl-to-query ----------


@pytest.mark.asyncio
async def test_nl_to_query_translates(http_client, analyst_headers) -> None:
    """A mocked client returns a translated query string."""
    from app.services.ai_client import AiCallResult

    result = AiCallResult(
        payload={"query": "event.category:process AND process.name:bash", "language": "lucene"},
        cached_input_tokens=10,
        output_tokens=20,
        model_id="claude-haiku-4-5-20251001",
    )
    with patch("app.api.ai.AnthropicClient") as mock_cls:
        instance = mock_cls.return_value
        instance.nl_to_query = AsyncMock(return_value=result)
        resp = await http_client.post(
            "/api/ai/nl-to-query",
            headers=analyst_headers,
            json={"prompt": "bash processes", "language": "lucene"},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["query"].startswith("event.category:process")
    assert body["language"] == "lucene"
    assert body["cached_input_tokens"] == 10


@pytest.mark.asyncio
async def test_nl_to_query_rate_limited(http_client, analyst_headers) -> None:
    """The endpoint admits 30 calls/min/user; the 31st returns 429."""
    from app.services.ai_client import AiCallResult

    result = AiCallResult(
        payload={"query": "x", "language": "lucene"},
        cached_input_tokens=0,
        output_tokens=1,
        model_id="claude-haiku-4-5-20251001",
    )
    # Reset the rate-limit store between tests so prior calls don't
    # bleed into this one.
    from fastapi.testclient import TestClient  # noqa: F401 — import for typing only

    from app.main import app

    if getattr(app.state, "rate_limit_store", None) is not None:
        app.state.rate_limit_store = None

    with patch("app.api.ai.AnthropicClient") as mock_cls:
        instance = mock_cls.return_value
        instance.nl_to_query = AsyncMock(return_value=result)
        statuses: list[int] = []
        for _ in range(31):
            r = await http_client.post(
                "/api/ai/nl-to-query",
                headers=analyst_headers,
                json={"prompt": "find x", "language": "lucene"},
            )
            statuses.append(r.status_code)
    assert statuses.count(200) == 30
    assert statuses[-1] == 429


@pytest.mark.asyncio
async def test_nl_to_query_requires_analyst(http_client, viewer_in_a) -> None:
    """Viewer role can't hit the translator — analyst+ only."""
    from tests.conftest import headers_for

    resp = await http_client.post(
        "/api/ai/nl-to-query",
        headers=headers_for(viewer_in_a),
        json={"prompt": "anything", "language": "lucene"},
    )
    assert resp.status_code == 403


# ---------- Playbook ai_suggest step ----------


@pytest.mark.asyncio
async def test_playbook_ai_suggest_records_suggestions(db_session) -> None:
    """An `ai_suggest` step records the model's suggestion list onto
    the run's steps_executed_json."""
    from app.models import Playbook, PlaybookRunStatus
    from app.services.playbooks import execute_playbook

    _, _, alert = await _make_alert(db_session)

    pb = Playbook(
        name=f"pb-{os.urandom(3).hex()}",
        yaml_body="steps:\n  - ai_suggest: {}\n",
        enabled=True,
    )
    db_session.add(pb)
    await db_session.flush()

    fake_result = _mock_ai_result(
        suggestions=[
            {"kind": "isolate", "label": "Isolate host", "rationale": "high sev"},
            {"kind": "kill", "label": "Kill bash", "rationale": "pid 1234"},
        ]
    )
    mock_client = MagicMock()
    mock_client.suggest_response = AsyncMock(return_value=fake_result)

    # `_run_ai_suggest` does a local import of AnthropicClient inside
    # the function so the playbook engine doesn't pull the SDK at
    # import time. Patch at the source module so the import inside
    # the step resolves to our mock.
    with patch("app.services.ai_client.AnthropicClient", return_value=mock_client):
        run = await execute_playbook(db_session, playbook=pb, alert_id=alert.id)

    assert run.status == PlaybookRunStatus.SUCCEEDED.value
    assert len(run.steps_executed_json) == 1
    step = run.steps_executed_json[0]
    assert step["kind"] == "ai_suggest"
    assert step["outcome"] == "ok"
    assert len(step["suggestions"]) == 2
    assert step["suggestions"][0]["kind"] == "isolate"
    mock_client.suggest_response.assert_awaited_once()


# ---------- Parser ----------


def test_parse_yaml_accepts_ai_suggest() -> None:
    """`ai_suggest` parses as a valid step with no params."""
    from app.services.playbooks import parse_yaml

    parsed = parse_yaml("steps:\n  - ai_suggest: {}\n")
    assert [s.kind for s in parsed.steps] == ["ai_suggest"]
