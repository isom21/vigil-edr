"""Smoke test that verifies the FastAPI app + DB engine wire up cleanly.

The CI service container provides Postgres; this test fails fast if the
URL / dialect / migrations are misaligned. Acts as a canary for
subsequent test files.
"""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_health_endpoint(http_client) -> None:
    resp = await http_client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
