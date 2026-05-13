"""Cohort assignment + rollout gating (Phase 3 #3.3).

A host's cohort bucket is a stable integer in [0, 99] derived from
the host's UUID + a manager-wide seed. The seed is configurable so
operators can re-bucket the fleet without rotating hostnames (e.g.
after a bad canary picks the same handful of hosts twice in a row).

The cohort *label* the UI shows is a coarse band over the bucket:

  * 0–4   → ``canary``  (5%)
  * 5–24  → ``early``   (20%)
  * 25–99 → ``mainline`` (75%)

Gate semantics: a host is eligible for the policy's pending update
iff ``host_bucket < policy.cohort_rolled_out_pct`` AND the host's
``agent_version`` differs from ``cohort_target_version``. Setting
``cohort_rolled_out_pct = 0`` therefore halts further rollout
without retracting in-flight updates — the rollout monitor relies
on this exact contract when it trips the breaker.
"""

from __future__ import annotations

import hashlib
from uuid import UUID

# Cohort band thresholds. Inclusive lower, exclusive upper.
CANARY_UPPER = 5
EARLY_UPPER = 25

CANARY = "canary"
EARLY = "early"
MAINLINE = "mainline"


def assign_cohort(host_id: UUID, seed: str) -> int:
    """Stable [0, 99] bucket for the host.

    ``hashlib.blake2b`` digest is taken over ``seed || host_id_bytes``
    and the first 8 bytes are read as a big-endian integer modulo 100.
    blake2b is overkill cryptographically — the only property we need
    is uniform distribution — but it's in the stdlib and faster than
    sha256 on the small inputs we feed it. Same algorithm, same seed,
    same host_id → same bucket forever.
    """
    h = hashlib.blake2b(seed.encode("utf-8") + host_id.bytes, digest_size=8)
    return int.from_bytes(h.digest(), "big") % 100


def cohort_label(bucket: int) -> str:
    """Map a bucket to its cohort label. Out-of-range buckets snap
    to the closest band; callers shouldn't pass those (the bucket
    comes from ``assign_cohort``), but the snap keeps log lines and
    audit rows from carrying a synthetic-looking ``unknown`` label."""
    if bucket < CANARY_UPPER:
        return CANARY
    if bucket < EARLY_UPPER:
        return EARLY
    return MAINLINE


def eligible_for_update(host, policy) -> bool:
    """Decide whether ``host`` should receive the pending update.

    A ``True`` result means the caller may queue a ``JobKind.UPDATE``;
    a ``False`` result must skip the queue (the host either isn't in
    the rolled-out fraction, or has no work to do, or the policy
    has no target version configured).
    """
    from app.core.config import settings

    target = policy.cohort_target_version
    if not target:
        return False
    pct = int(policy.cohort_rolled_out_pct or 0)
    if pct <= 0:
        return False
    if pct < 100:
        bucket = assign_cohort(host.id, settings.rollout_cohort_seed)
        if bucket >= pct:
            return False
    return (host.agent_version or "") != target
