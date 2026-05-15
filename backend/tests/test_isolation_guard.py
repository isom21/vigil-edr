"""Regression: `IsolateHostCmd` payloads always carry the manager's
resolved IPs in `allowlist_ips`, even if the operator omits them.

Without this, an operator who issues an isolate with a sparse allowlist
that doesn't include the manager severs the manager's own control
channel — the matching `isolate=false` recovery command then can't
land. The agent applies the same invariant locally; this suite pins
the manager-side defense-in-depth path.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.services.isolation_guard import ensure_manager_in_allowlist


def _fake_resolve(_host: str) -> list[str]:
    return ["10.0.0.5", "fd00::5"]


@pytest.mark.asyncio
async def test_injects_manager_ips_when_allowlist_empty() -> None:
    payload = {"isolate": True, "allowlist_ips": []}
    with patch("app.services.isolation_guard._resolve_to_ips", side_effect=_fake_resolve):
        out = ensure_manager_in_allowlist(payload)
    assert out["allowlist_ips"] == ["10.0.0.5", "fd00::5"]
    # input must not be mutated
    assert payload["allowlist_ips"] == []


@pytest.mark.asyncio
async def test_appends_to_operator_allowlist_without_duplicates() -> None:
    payload = {"isolate": True, "allowlist_ips": ["10.0.0.5", "10.0.0.99"]}
    with patch("app.services.isolation_guard._resolve_to_ips", side_effect=_fake_resolve):
        out = ensure_manager_in_allowlist(payload)
    # 10.0.0.5 already present (operator-supplied) → not duplicated.
    # fd00::5 newly injected from manager resolution.
    assert out["allowlist_ips"] == ["10.0.0.5", "10.0.0.99", "fd00::5"]


@pytest.mark.asyncio
async def test_idempotent_on_already_augmented_payload() -> None:
    payload = {"isolate": True, "allowlist_ips": ["10.0.0.5", "fd00::5"]}
    with patch("app.services.isolation_guard._resolve_to_ips", side_effect=_fake_resolve):
        out = ensure_manager_in_allowlist(payload)
    assert out["allowlist_ips"] == ["10.0.0.5", "fd00::5"]


@pytest.mark.asyncio
async def test_resolution_failure_leaves_payload_unchanged() -> None:
    """When DNS / configuration can't produce a manager IP, the helper
    logs a warning and returns the payload as-is. The agent's own
    `apply_network_isolation` will refuse the command if its
    independent resolution also comes back empty — that's the real
    safety check, not this one."""
    payload = {"isolate": True, "allowlist_ips": ["10.0.0.99"]}
    with patch("app.services.isolation_guard._resolve_to_ips", return_value=[]):
        out = ensure_manager_in_allowlist(payload)
    assert out["allowlist_ips"] == ["10.0.0.99"]


@pytest.mark.asyncio
async def test_non_list_allowlist_returns_input_unchanged() -> None:
    """Schema validation already rejects this shape upstream; the
    helper just refuses to operate rather than mutate something
    unexpected."""
    payload = {"isolate": True, "allowlist_ips": "not a list"}
    with patch("app.services.isolation_guard._resolve_to_ips", side_effect=_fake_resolve):
        out = ensure_manager_in_allowlist(payload)
    assert out == payload


def test_extract_host_handles_url_and_bare_host() -> None:
    from app.services.isolation_guard import _extract_host

    assert _extract_host("https://manager.example.com:50051") == "manager.example.com"
    assert _extract_host("http://10.0.0.5:8000") == "10.0.0.5"
    assert _extract_host("manager.example.com") == "manager.example.com"
    assert _extract_host("manager.example.com:50051") == "manager.example.com"
    # IPv6 in brackets, with and without port
    assert _extract_host("https://[fd00::5]:50051") == "fd00::5"
    assert _extract_host("[fd00::5]") == "fd00::5"
    # Trailing path + userinfo
    assert _extract_host("https://user@manager.example.com:50051/api") == "manager.example.com"
    # Empty / malformed
    assert _extract_host("") is None
    assert _extract_host("https://[unterminated") is None
