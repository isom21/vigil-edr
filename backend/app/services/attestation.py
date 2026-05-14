"""TPM-backed boot-state attestation (Phase 4 #4.10).

Responsibilities, kept in one module so the gRPC ingest path and the
REST API share semantics:

  * ``hex_digest`` / ``pcrs_from_pb`` — wire-bytes → JSONB list.
  * ``verify_quote`` — best-effort signature verification. Bound by the
    ``VIGIL_ATTESTATION_TRUST_ANCHOR_PEM`` setting; empty (dev) accepts
    self-signed AK certs so swtpm + a CI fixture both work.
  * ``compare_to_golden`` — diff a current PCR set against the
    promoted golden row. Returns the set of indices that diverged.
  * ``record_event`` — append one ``AttestationEvent`` row and, on a
    divergence against an existing golden, attach a HIGH alert via
    the synthetic rule.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterable
from typing import Any
from uuid import UUID

import structlog
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import (
    Alert,
    AlertState,
    AttestationEvent,
    AttestationGolden,
    Host,
    Rule,
    RuleAction,
    RuleKind,
    Severity,
)
from app.models.synthetic_rules import ATTESTATION_FAILED_RULE_ID

log = structlog.get_logger()


def hex_digest(raw: bytes) -> str:
    """Hex-encode a raw PCR digest. Lowercase so equality comparisons
    against operator-pasted goldens stay deterministic."""
    return raw.hex()


def pcrs_from_pb(pb_pcrs: Iterable) -> list[dict]:
    """Translate a protobuf ``repeated PcrValue`` into the JSONB shape
    we store. Skips entries with empty digests so we never persist a
    zero-byte slot that would diff against every golden value."""
    out: list[dict] = []
    for pcr in pb_pcrs:
        digest = bytes(pcr.digest or b"")
        if not digest:
            continue
        out.append(
            {
                "index": int(pcr.index),
                "bank": (pcr.bank or "sha256"),
                "digest_hex": hex_digest(digest),
            }
        )
    out.sort(key=lambda p: (p["bank"], p["index"]))
    return out


def verify_quote(
    quote_signature: bytes,
    ak_cert: bytes,
    expected_nonce: str,
    pcrs: list[dict],
) -> bool:
    """Best-effort cryptographic check of an attestation quote.

    Three failure modes:

      1. No signature or AK cert (agent shipped a plain PCR report, not
         a quote). Returns False — the caller decides whether to accept
         the report on its own (e.g. on first contact) or treat it as
         a missing quote.
      2. AK cert can't be parsed at all → False.
      3. Trust anchor is configured (production) and the AK cert
         doesn't chain to it → False.

    The signed-blob verification itself is intentionally simplified
    in v1 because the wire shape we ship is the raw TPM Quote +
    Signature; full TPM2_Quote parsing belongs in a follow-up. We
    settle for "the AK cert is well-formed and (if a trust anchor is
    set) chains to it"; the divergence signal comes from PCR
    comparison, not the quote bytes themselves.
    """
    if not quote_signature or not ak_cert:
        return False
    # PEM first, then DER. Real TPM2_Quote signatures + cert encodings
    # come from the TSS stack as DER; agent-side test fixtures hand us
    # PEM. Accept both so the same wire path covers fixtures and prod.
    try:
        cert = x509.load_pem_x509_certificate(ak_cert)
    except ValueError:
        with contextlib.suppress(ValueError):
            return _check_trust_anchor(x509.load_der_x509_certificate(ak_cert))
        log.warning("attestation.verify.bad_ak_cert_encoding")
        return False
    # `expected_nonce` + `pcrs` plug into the TPM2_Quote signed-blob
    # parse in v2. v1 settles for AK trust-anchor verification; the
    # PCR-vs-golden compare lives in `compare_to_golden` and runs
    # regardless of whether the quote bytes are valid.
    del expected_nonce, pcrs
    return _check_trust_anchor(cert)


def _check_trust_anchor(ak_cert) -> bool:
    """Return True when the AK cert is acceptable under the current
    trust policy. Empty trust anchor (dev / fresh install) accepts
    any well-formed cert; once an operator sets the PEM the cert
    must chain to it."""
    trust_pem = (settings.attestation_trust_anchor_pem or "").strip()
    if not trust_pem:
        return True
    try:
        anchor = x509.load_pem_x509_certificate(trust_pem.encode())
    except ValueError:
        log.error("attestation.verify.bad_trust_anchor_pem")
        return False
    anchor_pub: Any = anchor.public_key()
    try:
        anchor_pub.verify(
            ak_cert.signature,
            ak_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            ak_cert.signature_hash_algorithm,
        )
    except (InvalidSignature, TypeError, ValueError):
        log.warning("attestation.verify.ak_not_signed_by_trust_anchor")
        return False
    return True


def compare_to_golden(
    golden: AttestationGolden | None,
    current_pcrs: list[dict],
) -> tuple[bool, list[int]]:
    """Return ``(matches, diverged_indices)``.

    With no golden recorded, ``matches=False`` and ``diverged`` is the
    full set of current PCR indices — the caller renders this as the
    ``unverified`` status (every value is "divergent" from nothing).
    """
    if golden is None or not golden.pcr_values_json:
        return False, sorted({int(p["index"]) for p in current_pcrs})

    golden_map = {(p["bank"], int(p["index"])): p["digest_hex"] for p in golden.pcr_values_json}
    current_map = {(p["bank"], int(p["index"])): p["digest_hex"] for p in current_pcrs}
    diverged: set[int] = set()
    for key, digest in current_map.items():
        if golden_map.get(key) != digest:
            diverged.add(int(key[1]))
    # Indices recorded in golden but missing from the current report are
    # also a divergence — agent dropped a slot it used to report.
    for key in golden_map:
        if key not in current_map:
            diverged.add(int(key[1]))
    return len(diverged) == 0, sorted(diverged)


async def _ensure_attestation_rule(db: AsyncSession, tenant_id: UUID) -> None:
    """Idempotently create the synthetic Rule that attestation-mismatch
    alerts attach to. Mirrors `_ensure_reenrollment_rule` in the
    enrollment service — both REST promote and gRPC ingest paths call
    this so every divergence alert lands under the same rule_id."""
    existing = await db.get(Rule, ATTESTATION_FAILED_RULE_ID)
    if existing is not None:
        return
    rule = Rule(
        id=ATTESTATION_FAILED_RULE_ID,
        tenant_id=tenant_id,
        name="Phase 4 #4.10: TPM attestation diverged from golden baseline",
        kind=RuleKind.IOC,
        action=RuleAction.ALERT,
        severity=Severity.HIGH,
        enabled=True,
        description=(
            "Synthetic rule — fires when a host's PCR report diverges "
            "from its promoted golden baseline. Indicates a measured-"
            "boot drift: firmware change, bootloader replacement, "
            "rootkit, or operator-initiated kernel upgrade. MITRE "
            "T1542 (Pre-OS Boot)."
        ),
        mitre_techniques=["T1542"],
    )
    db.add(rule)
    await db.flush()


async def record_event(
    db: AsyncSession,
    *,
    host: Host,
    current_pcrs: list[dict],
    golden: AttestationGolden | None,
) -> AttestationEvent:
    """Persist one attestation event, attach a HIGH alert on divergence
    against an existing golden. Caller commits."""
    matches, diverged = compare_to_golden(golden, current_pcrs)
    event = AttestationEvent(
        tenant_id=host.tenant_id,
        host_id=host.id,
        pcr_values_json=current_pcrs,
        matches_golden=matches,
        diverged_pcrs=diverged,
    )
    db.add(event)
    await db.flush()

    # Only alert when an actual golden exists and a divergence occurred.
    # Pre-promote reports just sit on the event log under status=unverified.
    if golden is not None and not matches:
        await _ensure_attestation_rule(db, host.tenant_id)
        alert = Alert(
            tenant_id=host.tenant_id,
            host_id=host.id,
            rule_id=ATTESTATION_FAILED_RULE_ID,
            severity=Severity.HIGH,
            action_taken=RuleAction.ALERT,
            state=AlertState.NEW,
            summary=(
                f"TPM attestation diverged on '{host.hostname}' "
                f"(PCRs: {', '.join(str(i) for i in diverged)})"
            ),
            details={
                "host_id": str(host.id),
                "diverged_pcrs": diverged,
                "current_pcrs": current_pcrs,
                "golden_pcrs": golden.pcr_values_json,
                "detector": "tpm_attestation_v1",
            },
            mitre_techniques=["T1542"],
        )
        db.add(alert)
    return event
