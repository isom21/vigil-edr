"""Internal Certificate Authority for agent enrollment + manager TLS.

The manager runs a single self-signed CA, generated lazily on first use.
The CA private key is encrypted at rest with a Fernet key derived from
`settings.ca_master_key`. Two kinds of leaf cert are issued:

  1. Agent client certs (P-256 CSR from agent → SAN=hostname, EKU=clientAuth).
  2. Manager server cert (RSA, generated locally, EKU=serverAuth) — used to
     terminate TLS for the gRPC ingest endpoint that agents connect to.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
SERVER_CERT_VALIDITY_DAYS = 365


def _fernet() -> Fernet:
    raw = hashlib.sha256(settings.ca_master_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


@dataclass
class IssuedCert:
    cert_pem: str
    ca_chain_pem: str
    fingerprint_sha256: str
    not_after: datetime


@dataclass
class ServerCertMaterial:
    cert_pem: bytes
    key_pem: bytes
    ca_chain_pem: bytes


class CaService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_or_bootstrap(self) -> CertificateAuthority:
        ca = (await self.db.execute(select(CertificateAuthority).limit(1))).scalar_one_or_none()
        if ca is not None:
            return ca
        return await self._bootstrap()

    async def _bootstrap(self) -> CertificateAuthority:
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        now = datetime.now(UTC)
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
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
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

    async def sign_csr(self, csr_pem: bytes, *, host_id: str, hostname: str) -> IssuedCert:
        # DNS names are bounded to 253 octets by RFC 1035 §2.3.4 and
        # x509.DNSName won't accept anything longer. Reject overlong
        # hostnames at enrollment instead of silently truncating —
        # the agent presents a slice of its own hostname which then
        # never matches the cert SAN, and the failure surfaces as
        # an opaque TLS handshake error during the next mTLS attempt.
        if len(hostname) > 253:
            raise bad_request(
                f"hostname too long ({len(hostname)} chars); RFC 1035 caps DNS names at 253"
            )
        try:
            csr = x509.load_pem_x509_csr(csr_pem)
        except ValueError as exc:
            raise bad_request(f"invalid CSR: {exc}") from exc
        if not csr.is_signature_valid:
            raise bad_request("CSR signature invalid")

        public_key = csr.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            # M-grpc-hygiene #5: a malicious agent (or whoever owns an
            # enrollment token) could request a 512-bit RSA cert,
            # brute-force the private half once the manager has
            # signed, and impersonate the host indefinitely until the
            # cert expires. 2048 is the NIST minimum for 2030+.
            if public_key.key_size < 2048:
                raise bad_request(
                    f"RSA key too small ({public_key.key_size} bits); require >= 2048"
                )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            # Same idea for EC — restrict to the curves we trust. P-192 is
            # weak enough to brute-force today; brainpool / secp224 etc.
            # have either weak parameters or limited tooling support.
            allowed_curves = (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)
            if not isinstance(public_key.curve, allowed_curves):
                raise bad_request(
                    f"EC curve {public_key.curve.name} not allowed; use P-256, P-384, or P-521"
                )
        else:
            raise bad_request("CSR uses unsupported public-key algorithm")

        ca = await self.get_or_bootstrap()
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
        ca_key = await self._load_signing_key(ca)

        now = datetime.now(UTC)
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
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
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

    async def get_or_issue_server_cert(self, *, dns_names: list[str]) -> ServerCertMaterial:
        """Return a manager server cert, persisted to disk on first use.

        Cached on disk under settings.grpc_tls_cert / grpc_tls_key.  We don't
        store this in PG because the server process needs it on disk for grpcio.
        """
        cert_path = Path(settings.grpc_tls_cert)
        key_path = Path(settings.grpc_tls_key)
        ca = await self.get_or_bootstrap()

        if cert_path.exists() and key_path.exists():
            return ServerCertMaterial(
                cert_pem=cert_path.read_bytes(),
                key_pem=key_path.read_bytes(),
                ca_chain_pem=ca.cert_pem.encode(),
            )

        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
        ca_key = await self._load_signing_key(ca)

        srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(UTC)
        not_after = now + timedelta(days=SERVER_CERT_VALIDITY_DAYS)

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EDR"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "manager"),
                x509.NameAttribute(NameOID.COMMON_NAME, dns_names[0]),
            ]
        )
        san_entries: list[x509.GeneralName] = []
        for n in dns_names:
            try:
                san_entries.append(x509.IPAddress(ipaddress.ip_address(n)))
            except ValueError:
                san_entries.append(x509.DNSName(n))
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(srv_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(not_after)
            .add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = srv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        cert_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_bytes(cert_pem)
        os.chmod(cert_path, 0o644)
        key_path.write_bytes(key_pem)
        os.chmod(key_path, 0o600)

        return ServerCertMaterial(
            cert_pem=cert_pem, key_pem=key_pem, ca_chain_pem=ca.cert_pem.encode()
        )
