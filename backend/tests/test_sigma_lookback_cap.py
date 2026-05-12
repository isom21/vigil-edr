"""POST /api/sigma/test rejects out-of-bounds lookback_hours.

Review MEDIUM #20 / Security LOW: `SigmaTestRequest.lookback_hours`
already carries a Pydantic Field(ge=1, le=168) bound (schemas/sigma.py)
so a year-long scan can't be requested. This pins the contract so a
future relaxation surfaces in CI rather than at the OpenSearch wire.
"""

from __future__ import annotations

import pytest

_VALID_RULE = (
    "title: smoke\n"
    "logsource:\n"
    "  product: linux\n"
    "  category: process_creation\n"
    "detection:\n"
    "  selection:\n"
    "    process.name: nc\n"
    "  condition: selection\n"
)


@pytest.mark.asyncio
async def test_sigma_test_lookback_too_low_422(http_client, analyst_headers):
    resp = await http_client.post(
        "/api/sigma/test",
        json={"body": _VALID_RULE, "lookback_hours": 0},
        headers=analyst_headers,
    )
    assert resp.status_code == 422
    assert "lookback_hours" in resp.text


@pytest.mark.asyncio
async def test_sigma_test_lookback_too_high_422(http_client, analyst_headers):
    resp = await http_client.post(
        "/api/sigma/test",
        json={"body": _VALID_RULE, "lookback_hours": 9999},
        headers=analyst_headers,
    )
    assert resp.status_code == 422
    assert "lookback_hours" in resp.text


@pytest.mark.asyncio
async def test_sigma_test_lookback_at_upper_bound_accepted(http_client, analyst_headers):
    # 168h (a week) is the documented cap. Should pass validation.
    # Whether the OpenSearch call succeeds depends on the dev env; we
    # only care that the request body wasn't rejected by Pydantic.
    resp = await http_client.post(
        "/api/sigma/test",
        json={"body": _VALID_RULE, "lookback_hours": 168},
        headers=analyst_headers,
    )
    # 200 if OS is reachable; 5xx if OS is down. 422 (validation) is the
    # only outcome that signals a contract regression.
    assert resp.status_code != 422, resp.text
