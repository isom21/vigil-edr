"""`sign_csr` rejects hostnames that don't fit a DNSName SAN.

Review findings.md Top-20 #15: the manager silently truncated
hostnames to 253 chars when building the SAN. That paper-overs a
real failure — the agent presents a slice of its own hostname which
then never matches the cert SAN, and the next mTLS handshake fails
with an opaque error. Reject at enrollment so the operator sees a
clear 400 instead.

The gate sits before the CSR-parse + key-size + curve gates, so we
can exercise it without standing up a CA + DB.
"""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_hostname_at_limit_passes_gate() -> None:
    """253 chars is the RFC 1035 cap. The gate must accept it — the
    follow-on failure (no CA / DB) is what we look for to confirm we
    got past the length check."""
    from app.services.ca import CaService

    csr_pem = b"-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n"
    svc = CaService(db=None)  # type: ignore[arg-type]
    with pytest.raises(Exception) as exc_info:
        await svc.sign_csr(csr_pem, host_id="abc", hostname="a" * 253)
    # The hostname check should have passed. We hit the next gate
    # (CSR parse) instead.
    assert "hostname too long" not in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_hostname_overlong_rejected_with_400() -> None:
    from fastapi import HTTPException

    from app.services.ca import CaService

    svc = CaService(db=None)  # type: ignore[arg-type]
    with pytest.raises(HTTPException) as exc_info:
        await svc.sign_csr(b"unused", host_id="abc", hostname="a" * 254)
    assert exc_info.value.status_code == 400
    assert "hostname too long" in str(exc_info.value.detail).lower()
    assert "254" in str(exc_info.value.detail)
    assert "253" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_hostname_obviously_overlong_rejected() -> None:
    """A truly absurd hostname (1 KiB) shouldn't reach CSR parsing."""
    from fastapi import HTTPException

    from app.services.ca import CaService

    svc = CaService(db=None)  # type: ignore[arg-type]
    with pytest.raises(HTTPException) as exc_info:
        await svc.sign_csr(b"unused", host_id="abc", hostname="a" * 1024)
    assert exc_info.value.status_code == 400
    assert "hostname too long" in str(exc_info.value.detail).lower()
