"""Stable UUIDs for synthetic (system-generated) rules.

The detector pipeline generates a handful of alerts that don't come
from a Sigma / IOC rule the operator wrote — re-enrollment anomaly,
audit-chain break, etc. We want all such alerts to attach to a
single `Rule` row in the alerts UI rather than fragmenting across
rows, so each detector references a hard-coded UUID here.

LOW #8: previously every synthetic-rule UUID was defined at its
detector's call site. If a future migration reseeded rule UUIDs (or
a future contributor copy-pasted the value without realising it was
a sentinel) the synthetic rule could end up with two rows. Single
source of truth lives here; the migration in
`20260512_0900_synthetic_rules_unique.py` adds a UNIQUE(id) check at
the DB level (id is already the primary key, so that's the natural
gate — the migration documents the constraint intent rather than
adding a new index).

When you add a new synthetic rule:
  1. Pick the next ``a0a0a0a0-0000-0000-0000-00000000000X`` slot.
  2. Add a constant + a description here.
  3. Reference the constant from the detector.

Don't recycle a slot. Don't hand out the same value to two detectors.
"""

from __future__ import annotations

from typing import Final
from uuid import UUID

# M12.e — agent re-enrollment within VIGIL_REENROLLMENT_WINDOW_SECONDS
# under the same hostname. Fires on both REST and gRPC enroll paths
# (after the M-audit-and-auth #6 work).
REENROLLMENT_RULE_ID: Final[UUID] = UUID("a0a0a0a0-0000-0000-0000-000000000005")

# M16.a — HMAC chain break observed by the audit verifier background
# task (M-audit-and-auth #6).
AUDIT_CHAIN_BREAK_RULE_ID: Final[UUID] = UUID("a0a0a0a0-0000-0000-0000-000000000006")

# Phase 4 #4.10 — TPM attestation diverged from the promoted golden
# baseline. MITRE T1542 (Pre-OS Boot).
ATTESTATION_FAILED_RULE_ID: Final[UUID] = UUID("a0a0a0a0-0000-0000-0000-000000000007")
# Phase 4 #4.2 — AWS CloudTrail IAM-role anomaly detector (new principal,
# new action for principal, new region for principal, or unexpected root
# console login).
CLOUD_IAM_ANOMALY_RULE_ID: Final[UUID] = UUID("a0a0a0a0-0000-0000-0000-000000000011")
# Phase 4 #4.5 — agent observed a touch on a deployed honeytoken
# (fake file / fake regkey / fake creds). Anything that interacts with
# the decoy is high-signal; the alert is CRITICAL by default.
HONEYTOKEN_HIT_RULE_ID: Final[UUID] = UUID("a0a0a0a0-0000-0000-0000-000000000013")
# Phase 4 #4.3 — identity threat detectors. One synthetic Rule per
# detector class so the alerts UI groups them sensibly (filter by
# rule_id) without exploding into per-tenant or per-source rows. All
# four are bootstrapped on first detection via the worker's lazy
# `_ensure_rule` helper — same pattern as `anomaly.py`'s
# ANOMALY_RULE_ID.
IDENTITY_IMPOSSIBLE_TRAVEL_RULE_ID: Final[UUID] = UUID("a0a0a0a0-0000-0000-0000-000000000011")
IDENTITY_BRUTE_FORCE_RULE_ID: Final[UUID] = UUID("a0a0a0a0-0000-0000-0000-000000000012")
IDENTITY_MFA_BOMB_RULE_ID: Final[UUID] = UUID("a0a0a0a0-0000-0000-0000-000000000013")
IDENTITY_PASSWORD_SPRAY_RULE_ID: Final[UUID] = UUID("a0a0a0a0-0000-0000-0000-000000000014")


# Convenience iterable for tests / migration sanity checks: every
# synthetic rule UUID this module knows about. Adding a new one above
# without appending here is a typecheck miss waiting to happen.
ALL_SYNTHETIC_RULE_IDS: Final[tuple[UUID, ...]] = (
    REENROLLMENT_RULE_ID,
    AUDIT_CHAIN_BREAK_RULE_ID,
    ATTESTATION_FAILED_RULE_ID,
    CLOUD_IAM_ANOMALY_RULE_ID,
    HONEYTOKEN_HIT_RULE_ID,
    IDENTITY_IMPOSSIBLE_TRAVEL_RULE_ID,
    IDENTITY_BRUTE_FORCE_RULE_ID,
    IDENTITY_MFA_BOMB_RULE_ID,
    IDENTITY_PASSWORD_SPRAY_RULE_ID,
)
