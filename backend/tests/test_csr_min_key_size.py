"""M-grpc-hygiene #5: `sign_csr` rejects undersized keys + weak curves.

Reviewer's MEDIUM finding: the manager validated CSR signatures and
checked that the public key was RSA-or-EC but didn't enforce a
minimum size. A malicious agent (or whoever owns a freshly-issued
enrollment token) could submit a 512-bit RSA CSR, get a manager-
signed cert, brute-force the private half offline, and impersonate
the host indefinitely until the cert expires.

We test the validation gate directly — exercising the full sign path
needs a CA + DB session which is more setup than this single-line
gate warrants.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import NameOID


def _csr_pem_rsa(bits: int) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-host")]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _csr_pem_ec(curve: ec.EllipticCurve) -> bytes:
    key = ec.generate_private_key(curve)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-host")]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


@pytest.mark.asyncio
async def test_rsa_1024_rejected() -> None:
    """1024-bit RSA is the smallest size `cryptography` will even
    generate (it refuses 512 outright); it's also a comfortable
    distance below the 2048-bit gate so this test exercises the
    rejection path without any library workaround."""
    from fastapi import HTTPException

    from app.services.ca import CaService

    csr_pem = _csr_pem_rsa(1024)
    svc = CaService(db=None)  # type: ignore[arg-type]
    with pytest.raises(HTTPException) as exc_info:
        await svc.sign_csr(csr_pem, host_id="abc", hostname="test-host")
    assert exc_info.value.status_code == 400
    assert "RSA" in str(exc_info.value.detail)
    assert "2048" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_ec_secp192r1_rejected() -> None:
    from fastapi import HTTPException

    from app.services.ca import CaService

    csr_pem = _csr_pem_ec(ec.SECP192R1())
    svc = CaService(db=None)  # type: ignore[arg-type]
    with pytest.raises(HTTPException) as exc_info:
        await svc.sign_csr(csr_pem, host_id="abc", hostname="test-host")
    assert exc_info.value.status_code == 400
    assert "secp192r1" in str(exc_info.value.detail).lower() or "P-256" in str(
        exc_info.value.detail
    )


@pytest.mark.asyncio
async def test_ec_secp224r1_rejected() -> None:
    from fastapi import HTTPException

    from app.services.ca import CaService

    csr_pem = _csr_pem_ec(ec.SECP224R1())
    svc = CaService(db=None)  # type: ignore[arg-type]
    with pytest.raises(HTTPException) as exc_info:
        await svc.sign_csr(csr_pem, host_id="abc", hostname="test-host")
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_rsa_2048_passes_validation() -> None:
    """RSA 2048 is the lower bound the gate accepts. We don't run the
    full sign path (no CA / DB here) — the gate raises before the
    DB-touching code, so we look for failure to short-circuit at
    validation rather than at the next DB op."""
    from app.services.ca import CaService

    csr_pem = _csr_pem_rsa(2048)
    svc = CaService(db=None)  # type: ignore[arg-type]
    with pytest.raises(Exception) as exc_info:
        await svc.sign_csr(csr_pem, host_id="abc", hostname="test-host")
    # The validation gate would surface as HTTPException(400). Any
    # other exception means we got past the gate and hit the
    # CA-loading code (which fails on db=None).
    msg = str(exc_info.value).lower()
    assert "rsa" not in msg or "2048" not in msg


@pytest.mark.asyncio
async def test_ec_secp256r1_passes_validation() -> None:
    from app.services.ca import CaService

    csr_pem = _csr_pem_ec(ec.SECP256R1())
    svc = CaService(db=None)  # type: ignore[arg-type]
    with pytest.raises(Exception) as exc_info:
        await svc.sign_csr(csr_pem, host_id="abc", hostname="test-host")
    msg = str(exc_info.value).lower()
    assert "curve" not in msg
