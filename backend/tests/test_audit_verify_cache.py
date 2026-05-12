"""GET /api/audit/verify serves the cached verifier result.

Review findings.md Top-20 #11: the endpoint re-walked the whole
`audit_log` table on every call, which on a multi-million-row table
will time out a UI poll. The background loop already does this work
on a schedule; the request path should serve its last result and
only re-walk on `?refresh=1`.

These tests drive the cache primitives directly + the endpoint:

  * `cache_get` returns (None, None) before any record.
  * `cache_record` stores a result + ts.
  * Endpoint serves cached when present, with `cached=True`.
  * Endpoint cold-starts a live walk when the cache is empty, then
    populates the cache for next time.
  * `?refresh=1` always runs live and overwrites the cache.
"""

from __future__ import annotations

import pytest

from app.services import audit_verifier as av_mod
from app.services.audit_verifier import VerifyResult


@pytest.fixture(autouse=True)
def _reset_cache(monkeypatch):
    monkeypatch.setattr(av_mod, "_last_result", None)
    monkeypatch.setattr(av_mod, "_last_run_at", None)


def test_cache_starts_empty() -> None:
    res, ran_at = av_mod.cache_get()
    assert res is None
    assert ran_at is None


def test_cache_record_populates() -> None:
    r = VerifyResult(rows_examined=42, chain_rows=40, breaks=[])
    av_mod.cache_record(r)
    res, ran_at = av_mod.cache_get()
    assert res is r
    assert ran_at is not None


@pytest.mark.asyncio
async def test_verify_endpoint_serves_cache_when_populated(http_client, admin_headers) -> None:
    canned = VerifyResult(rows_examined=999, chain_rows=999, breaks=[])
    av_mod.cache_record(canned)

    resp = await http_client.get("/api/audit/verify", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["cached"] is True
    assert body["rows_examined"] == 999
    assert body["chain_rows"] == 999
    assert body["ok"] is True
    assert body["last_run_at"] is not None


@pytest.mark.asyncio
async def test_verify_endpoint_cold_starts_live_walk(http_client, admin_headers) -> None:
    """If the loop hasn't recorded a pass yet, the endpoint walks
    once and populates the cache so subsequent calls are free."""
    # Cache is empty (autouse fixture).
    resp = await http_client.get("/api/audit/verify", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    # Cold start ran live — cached=False.
    assert body["cached"] is False
    # And the cache is now populated for next call.
    res, _ = av_mod.cache_get()
    assert res is not None

    resp2 = await http_client.get("/api/audit/verify", headers=admin_headers)
    assert resp2.status_code == 200
    assert resp2.json()["cached"] is True


@pytest.mark.asyncio
async def test_verify_refresh_overrides_cache(http_client, admin_headers) -> None:
    stale = VerifyResult(rows_examined=0, chain_rows=0, breaks=[])
    av_mod.cache_record(stale)

    resp = await http_client.get("/api/audit/verify?refresh=1", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["cached"] is False
    # The cache now holds the fresh walk's result.
    res, _ = av_mod.cache_get()
    assert res is not None
    # In test DB there are zero or more audit rows; the key point is
    # the response reflects the live walk, not the stale `rows_examined=0`
    # only if there ARE rows. So we just confirm the cache pointer moved.
    assert res is not stale


@pytest.mark.asyncio
async def test_verify_non_admin_rejected(http_client, analyst_headers) -> None:
    """Belt-and-braces: the verify endpoint is admin-only. The cache
    path must not lower that bar."""
    av_mod.cache_record(VerifyResult(rows_examined=1, chain_rows=1, breaks=[]))
    resp = await http_client.get("/api/audit/verify", headers=analyst_headers)
    assert resp.status_code == 403
