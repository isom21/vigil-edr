"""Internal Certificate Authority for agent enrollment.

The manager runs a single self-signed CA, generated lazily on first use.
The CA private key is encrypted at rest with a Fernet key derived from
`settings.ca_master_key`. Issued client certs are P-256 by default and
short-lived (90d) for rotation.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import bad_request
from app.models import CertificateAuthority

CA_VALIDITY_DAYS = 365 * 10
CLIENT_CERT_VALIDITY_DAYS = 90


def _fernet() -> Fernet:
    # Derive 32 raw bytes from the master key, then base64-url-encode for Fernet.
    raw = hashlib.sha256(settings.ca_master_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


@dataclass
class IssuedCert:
    cert_pem: str
    ca_chain_pem: str
    fingerprint_sha256: str
    not_after: datetime


class CaService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_or_bootstrap(self) -> CertificateAuthority:
        ca = (
            await self.db.execute(select(CertificateAuthority).limit(1))
        ).scalar_one_or_none()
        if ca is not None:
            return ca
        return await self._bootstrap()

    async def _bootstrap(self) -> CertificateAuthority:
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        now = datetime.now(timezone.utc)
        not_after = now + timedelta(days=CA_VALIDITY_DAYS)

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "EDR Manager Internal CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EDR"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .sign(key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        encrypted = _fernet().encrypt(key_pem)

        row = CertificateAuthority(
            cert_pem=cert_pem,
            key_encrypted=encrypted,
            not_after=not_after,
            fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
        )
        self.db.add(row)
        await self.db.flush()
        return row

    async def _load_signing_key(self, ca: CertificateAuthority) -> rsa.RSAPrivateKey:
        pem = _fernet().decrypt(ca.key_encrypted)
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise RuntimeError("CA key is not an RSA key")
        return key

    async def sign_csr(
        self, csr_pem: bytes, *, host_id: str, hostname: str
    ) -> IssuedCert:
        try:
            csr = x509.load_pem_x509_csr(csr_pem)
        except ValueError as exc:
            raise bad_request(f"invalid CSR: {exc}") from exc
        if not csr.is_signature_valid:
            raise bad_request("CSR signature invalid")

        public_key = csr.public_key()
        if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            raise bad_request("CSR uses unsupported public-key algorithm")

        ca = await self.get_or_bootstrap()
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
        ca_key = await self._load_signing_key(ca)

        now = datetime.now(timezone.utc)
        not_after = now + timedelta(days=CLIENT_CERT_VALIDITY_DAYS)

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EDR"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "agents"),
                x509.NameAttribute(NameOID.COMMON_NAME, host_id),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(not_after)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname[:253])]),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        return IssuedCert(
            cert_pem=cert_pem,
            ca_chain_pem=ca.cert_pem,
            fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
            not_after=not_after,
        )
