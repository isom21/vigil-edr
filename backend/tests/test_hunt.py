"""Threat-hunting workbench (Phase 2 #2.11).

Covers:

  * `translate_to_dsl` shapes — lucene/kql pass-through to a
    `query_string` clause; sigma YAML compiles via the existing backend.
  * `build_search_body` applies the host-scope filter intersection
    correctly (mirrors `_build_search_body` from /api/sigma/test).
  * Five-field cron matcher: stars, ranges, lists, steps, weekday/DOM
    OR-semantics.
  * Saved-hunt CRUD: admin-gate on `alert_on_hit` / `schedule_cron`,
    owner-or-admin scoping.
  * Ad-hoc + manual run paths short-circuit when the actor's visible
    host list is empty.
  * `run_hunt` creates a managed Rule + Alert rows when `alert_on_hit=True`.
  * Scheduler `_run_once` fires due hunts and skips dormant ones.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select


def _test_session_maker(db_session):
    @asynccontextmanager
    async def _maker():
        yield db_session

    return _maker


# ---------- translate_to_dsl ----------


def test_translate_to_dsl_lucene_passthrough() -> None:
    from app.services.hunt import translate_to_dsl

    out = translate_to_dsl("event.category:process AND host.os.type:linux", "lucene")
    assert out == {"query_string": {"query": "event.category:process AND host.os.type:linux"}}


def test_translate_to_dsl_kql_passthrough() -> None:
    from app.services.hunt import translate_to_dsl

    out = translate_to_dsl("process.name: bash", "kql")
    assert out == {"query_string": {"query": "process.name: bash"}}


def test_translate_to_dsl_sigma_compiles() -> None:
    from app.services.hunt import translate_to_dsl

    sigma_yaml = (
        "title: t\nlogsource:\n  product: linux\ndetection:\n  s:\n"
        "    event.category: process\n  condition: s\n"
    )
    out = translate_to_dsl(sigma_yaml, "sigma")
    assert "query_string" in out
    # Lucene backend produces a colon clause for ECS event.category.
    assert "event.category" in out["query_string"]["query"]


def test_translate_to_dsl_rejects_empty() -> None:
    from app.services.hunt import HuntCompileError, translate_to_dsl

    with pytest.raises(HuntCompileError):
        translate_to_dsl("   ", "lucene")


def test_translate_to_dsl_rejects_unknown_language() -> None:
    from app.services.hunt import HuntCompileError, translate_to_dsl

    with pytest.raises(HuntCompileError):
        translate_to_dsl("x", "spl")  # type: ignore[arg-type]


# ---------- build_search_body ----------


def test_build_search_body_admin_omits_host_terms() -> None:
    from app.services.hunt import build_search_body

    upper = datetime.now(UTC)
    lower = upper - timedelta(hours=1)
    body = build_search_body(
        {"query_string": {"query": "*"}},
        lower=lower,
        upper=upper,
        visible_host_ids=None,
        host_scope=None,
        size=10,
    )
    filters = body["query"]["bool"]["filter"]
    assert len(filters) == 2  # range + query_string
    assert all("terms" not in f for f in filters)


def test_build_search_body_intersects_rbac_with_scope() -> None:
    from app.services.hunt import build_search_body

    upper = datetime.now(UTC)
    lower = upper - timedelta(hours=1)
    visible = [uuid4(), uuid4()]
    body = build_search_body(
        {"query_string": {"query": "*"}},
        lower=lower,
        upper=upper,
        visible_host_ids=visible,
        # Scope mentions one in-scope host and one the actor can't see.
        host_scope={"host_ids": [str(visible[0]), str(uuid4())]},
        size=10,
    )
    filters = body["query"]["bool"]["filter"]
    terms = next(f for f in filters if "terms" in f)
    # Intersection should keep only the in-scope host.
    assert terms == {"terms": {"host.id": [str(visible[0])]}}


def test_effective_host_filter_empty_short_circuits() -> None:
    from app.services.hunt import effective_host_filter_empty

    # Non-admin with zero visible hosts → empty.
    assert effective_host_filter_empty([], None) is True
    # Admin (None) with empty saved scope list → empty (operator
    # explicitly scoped to nothing).
    assert effective_host_filter_empty(None, {"host_ids": []}) is True
    # Admin (None) with no scope → not empty.
    assert effective_host_filter_empty(None, None) is False
    # Non-admin with non-overlapping scope → empty.
    h = uuid4()
    assert effective_host_filter_empty([h], {"host_ids": [str(uuid4())]}) is True


# ---------- cron_matches ----------


def test_cron_matches_star_every_minute() -> None:
    from app.services.hunt import cron_matches

    when = datetime(2026, 5, 13, 12, 34, tzinfo=UTC)
    assert cron_matches("* * * * *", when) is True


def test_cron_matches_specific_minute() -> None:
    from app.services.hunt import cron_matches

    when = datetime(2026, 5, 13, 12, 0, tzinfo=UTC)
    assert cron_matches("0 * * * *", when) is True
    assert cron_matches("30 * * * *", when) is False


def test_cron_matches_step_and_list() -> None:
    from app.services.hunt import cron_matches

    when = datetime(2026, 5, 13, 12, 15, tzinfo=UTC)
    assert cron_matches("*/15 * * * *", when) is True
    assert cron_matches("0,15,30,45 * * * *", when) is True
    assert cron_matches("5,20 * * * *", when) is False


def test_cron_matches_range() -> None:
    from app.services.hunt import cron_matches

    # 2026-05-13 is a Wednesday → cron dow = 3.
    when = datetime(2026, 5, 13, 10, 0, tzinfo=UTC)
    assert cron_matches("0 9-17 * * 1-5", when) is True
    when_sat = datetime(2026, 5, 16, 10, 0, tzinfo=UTC)
    assert cron_matches("0 9-17 * * 1-5", when_sat) is False


def test_cron_matches_invalid_field_count() -> None:
    from app.services.hunt import cron_matches

    with pytest.raises(ValueError):
        cron_matches("0 0 * *", datetime.now(UTC))


# ---------- API: ad-hoc run (audit + short-circuit) ----------


@pytest.mark.asyncio
async def test_adhoc_run_audited_and_short_circuits_for_zero_scope_analyst(
    http_client, analyst_headers, monkeypatch
) -> None:
    """An analyst with zero visible hosts gets an empty result without
    the handler reaching OpenSearch — same contract as /api/sigma/test."""
    import app.services.hunt as hunt_svc

    async def _explode(**_kwargs):
        raise AssertionError("must not hit OpenSearch when scope is empty")

    monkeypatch.setattr(hunt_svc, "execute_search", _explode)

    resp = await http_client.post(
        "/api/hunt/run",
        json={"query": "*", "language": "lucene", "lookback_hours": 1, "size": 10},
        headers=analyst_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 0
    assert body["hits"] == []


@pytest.mark.asyncio
async def test_adhoc_run_rejects_bad_sigma(http_client, analyst_headers) -> None:
    resp = await http_client.post(
        "/api/hunt/run",
        json={"query": "not: yaml: at all:", "language": "sigma", "lookback_hours": 1},
        headers=analyst_headers,
    )
    assert resp.status_code == 400


# ---------- API: saved CRUD ----------


@pytest.mark.asyncio
async def test_saved_create_analyst_blocked_from_alert_on_hit(http_client, analyst_headers) -> None:
    resp = await http_client.post(
        "/api/hunt/saved",
        json={
            "name": "x",
            "query_dsl": "*",
            "query_language": "lucene",
            "alert_on_hit": True,
        },
        headers=analyst_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_saved_create_analyst_blocked_from_schedule(http_client, analyst_headers) -> None:
    resp = await http_client.post(
        "/api/hunt/saved",
        json={
            "name": "x",
            "query_dsl": "*",
            "query_language": "lucene",
            "schedule_cron": "0 * * * *",
        },
        headers=analyst_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_saved_create_admin_ok(http_client, admin_headers) -> None:
    resp = await http_client.post(
        "/api/hunt/saved",
        json={
            "name": f"hunt-{os.urandom(2).hex()}",
            "description": "test",
            "query_dsl": "event.category:process",
            "query_language": "lucene",
            "alert_on_hit": True,
            "schedule_cron": "*/5 * * * *",
            "severity": "high",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["alert_on_hit"] is True
    assert body["schedule_cron"] == "*/5 * * * *"
    assert body["severity"] == "high"


@pytest.mark.asyncio
async def test_saved_create_rejects_bad_cron(http_client, admin_headers) -> None:
    resp = await http_client.post(
        "/api/hunt/saved",
        json={
            "name": "bad-cron",
            "query_dsl": "*",
            "query_language": "lucene",
            "schedule_cron": "every minute please",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_saved_list_non_admin_scoped_to_owner(
    http_client, analyst_user, analyst_headers, admin_user, admin_headers, db_session
) -> None:
    """An analyst sees only their own hunts; admins see all."""
    from app.models import SavedHunt

    mine = SavedHunt(
        owner_user_id=analyst_user.id,
        name=f"mine-{os.urandom(2).hex()}",
        query_dsl="*",
        query_language="lucene",
    )
    theirs = SavedHunt(
        owner_user_id=admin_user.id,
        name=f"theirs-{os.urandom(2).hex()}",
        query_dsl="*",
        query_language="lucene",
    )
    db_session.add_all([mine, theirs])
    await db_session.flush()

    resp = await http_client.get("/api/hunt/saved", headers=analyst_headers)
    assert resp.status_code == 200
    names = {h["name"] for h in resp.json()["items"]}
    assert mine.name in names
    assert theirs.name not in names

    resp = await http_client.get("/api/hunt/saved", headers=admin_headers)
    names = {h["name"] for h in resp.json()["items"]}
    assert mine.name in names
    assert theirs.name in names


@pytest.mark.asyncio
async def test_saved_get_non_owner_analyst_forbidden(
    http_client, admin_user, analyst_headers, db_session
) -> None:
    from app.models import SavedHunt

    other = SavedHunt(
        owner_user_id=admin_user.id,
        name=f"other-{os.urandom(2).hex()}",
        query_dsl="*",
        query_language="lucene",
    )
    db_session.add(other)
    await db_session.flush()
    resp = await http_client.get(f"/api/hunt/saved/{other.id}", headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_saved_patch_owner_can_edit(
    http_client, analyst_user, analyst_headers, db_session
) -> None:
    from app.models import SavedHunt

    mine = SavedHunt(
        owner_user_id=analyst_user.id,
        name=f"editable-{os.urandom(2).hex()}",
        query_dsl="*",
        query_language="lucene",
    )
    db_session.add(mine)
    await db_session.flush()

    resp = await http_client.patch(
        f"/api/hunt/saved/{mine.id}",
        json={"description": "now with words"},
        headers=analyst_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["description"] == "now with words"


@pytest.mark.asyncio
async def test_saved_delete_owner_can_remove(
    http_client, analyst_user, analyst_headers, db_session
) -> None:
    from app.models import SavedHunt

    mine = SavedHunt(
        owner_user_id=analyst_user.id,
        name=f"doomed-{os.urandom(2).hex()}",
        query_dsl="*",
        query_language="lucene",
    )
    db_session.add(mine)
    await db_session.flush()
    hid = mine.id

    resp = await http_client.delete(f"/api/hunt/saved/{hid}", headers=analyst_headers)
    assert resp.status_code == 204
    gone = await db_session.get(SavedHunt, hid)
    assert gone is None


# ---------- run_hunt: emits alerts under managed rule ----------


@pytest.mark.asyncio
async def test_run_hunt_creates_managed_rule_and_alerts(
    db_session, analyst_user, monkeypatch
) -> None:
    """When alert_on_hit=True and the search returns hits with a
    resolvable host.id, run_hunt creates a managed Rule (one per hunt)
    + Alert rows pointing at it. Mirrors intel_ingest's managed-rule
    pattern."""
    import app.services.hunt as hunt_svc
    from app.models import Alert, Host, OsFamily, Rule, RuleKind, SavedHunt

    host = Host(hostname=f"h-{os.urandom(2).hex()}", os_family=OsFamily.LINUX)
    db_session.add(host)
    await db_session.flush()

    hunt = SavedHunt(
        owner_user_id=analyst_user.id,
        name=f"alerting-{os.urandom(2).hex()}",
        query_dsl="*",
        query_language="lucene",
        alert_on_hit=True,
        severity="high",
        mitre_techniques=["T1059.004"],
    )
    db_session.add(hunt)
    await db_session.flush()

    async def _fake_search(**kwargs):
        return (
            2,
            [
                {
                    "_source": {
                        "@timestamp": "2026-05-13T12:00:00Z",
                        "host": {"id": str(host.id)},
                        "event": {"id": "ev-1"},
                    }
                },
                {
                    "_source": {
                        "@timestamp": "2026-05-13T12:01:00Z",
                        "host": {"id": str(host.id)},
                        "event": {"id": "ev-2"},
                    }
                },
            ],
        )

    monkeypatch.setattr(hunt_svc, "execute_search", _fake_search)

    run = await hunt_svc.run_hunt(db_session, hunt.id)
    assert run.hit_count == 2
    assert run.alert_count == 2
    assert run.error is None

    await db_session.refresh(hunt)
    assert hunt.managed_rule_id is not None
    rule = await db_session.get(Rule, hunt.managed_rule_id)
    assert rule is not None
    assert rule.kind is RuleKind.SIGMA
    assert rule.name == f"hunt:{hunt.name}"

    alerts = (
        (await db_session.execute(select(Alert).where(Alert.rule_id == rule.id))).scalars().all()
    )
    assert len(alerts) == 2
    # MITRE techniques copied from the hunt onto the alert row (mirrors
    # the sigma realtime path's freeze-at-fire-time behaviour).
    assert all(a.mitre_techniques == ["T1059.004"] for a in alerts)


@pytest.mark.asyncio
async def test_run_hunt_records_error_on_compile_failure(db_session, analyst_user) -> None:
    import app.services.hunt as hunt_svc
    from app.models import SavedHunt

    hunt = SavedHunt(
        owner_user_id=analyst_user.id,
        name=f"broken-{os.urandom(2).hex()}",
        # malformed sigma — the compile step blows up.
        query_dsl="not: yaml: at all:",
        query_language="sigma",
    )
    db_session.add(hunt)
    await db_session.flush()

    run = await hunt_svc.run_hunt(db_session, hunt.id)
    assert run.error is not None
    assert run.hit_count == 0


# ---------- scheduler: cron-driven fire ----------


@pytest.mark.asyncio
async def test_scheduler_fires_due_hunt(db_session, admin_user, monkeypatch) -> None:
    """`_run_once` triggers a hunt whose cron matches `now`, and skips
    dormant rows."""
    import app.services.hunt as hunt_svc
    import app.workers.hunt_scheduler as scheduler
    from app.models import SavedHunt

    # Hunt that runs every minute.
    due = SavedHunt(
        owner_user_id=admin_user.id,
        name=f"due-{os.urandom(2).hex()}",
        query_dsl="*",
        query_language="lucene",
        schedule_cron="* * * * *",
    )
    # Hunt that runs only at minute 99 (impossible) — never due.
    dormant = SavedHunt(
        owner_user_id=admin_user.id,
        name=f"dormant-{os.urandom(2).hex()}",
        query_dsl="*",
        query_language="lucene",
        schedule_cron="0 0 1 1 *",  # Jan 1 00:00
    )
    db_session.add_all([due, dormant])
    await db_session.flush()

    async def _fake_search(**kwargs):
        return 0, []

    monkeypatch.setattr(hunt_svc, "execute_search", _fake_search)

    when = datetime(2026, 5, 13, 12, 34, tzinfo=UTC)
    fired = await scheduler._run_once(session_maker=_test_session_maker(db_session), now=when)
    assert fired == 1
    await db_session.refresh(due)
    assert due.last_run_at is not None
    await db_session.refresh(dormant)
    assert dormant.last_run_at is None


@pytest.mark.asyncio
async def test_scheduler_skips_already_run_this_minute(db_session, admin_user, monkeypatch) -> None:
    """When the worker's interval is shorter than 60 s, the same
    matching minute mustn't re-fire."""
    import app.services.hunt as hunt_svc
    import app.workers.hunt_scheduler as scheduler
    from app.models import SavedHunt

    when = datetime(2026, 5, 13, 12, 34, tzinfo=UTC)
    h = SavedHunt(
        owner_user_id=admin_user.id,
        name=f"reentry-{os.urandom(2).hex()}",
        query_dsl="*",
        query_language="lucene",
        schedule_cron="* * * * *",
        last_run_at=when,
    )
    db_session.add(h)
    await db_session.flush()

    async def _fake_search(**kwargs):
        return 0, []

    monkeypatch.setattr(hunt_svc, "execute_search", _fake_search)
    fired = await scheduler._run_once(session_maker=_test_session_maker(db_session), now=when)
    assert fired == 0


# ---------- runs history endpoint ----------


@pytest.mark.asyncio
async def test_runs_history_returns_in_reverse_chronological(
    http_client, admin_user, admin_headers, db_session
) -> None:
    from app.models import HuntRun, SavedHunt

    hunt = SavedHunt(
        owner_user_id=admin_user.id,
        name=f"with-history-{os.urandom(2).hex()}",
        query_dsl="*",
        query_language="lucene",
    )
    db_session.add(hunt)
    await db_session.flush()
    older = HuntRun(
        hunt_id=hunt.id,
        started_at=datetime(2026, 5, 12, 12, 0, tzinfo=UTC),
        finished_at=datetime(2026, 5, 12, 12, 0, tzinfo=UTC),
        hit_count=1,
        alert_count=0,
    )
    newer = HuntRun(
        hunt_id=hunt.id,
        started_at=datetime(2026, 5, 13, 12, 0, tzinfo=UTC),
        finished_at=datetime(2026, 5, 13, 12, 0, tzinfo=UTC),
        hit_count=5,
        alert_count=0,
    )
    db_session.add_all([older, newer])
    await db_session.flush()

    resp = await http_client.get(f"/api/hunt/saved/{hunt.id}/runs", headers=admin_headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 2
    assert UUID(items[0]["id"]) == newer.id
    assert UUID(items[1]["id"]) == older.id
