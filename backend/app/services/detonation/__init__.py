"""Network sandbox / detonation providers (Phase 4 #4.4).

Each provider exposes the same minimal contract:

    submit(config, sample_bytes, sample_name) -> task_id
    poll(config, task_id) -> dict with at least:
        {"status": "running" | "verdict" | "failed",
         "score": float | None,      # only when status == "verdict"
         "signatures": list[str] | None}

Cuckoo is implemented today (free OSS). VMRay + ANY.RUN are stubs that
raise NotImplementedError — they require paid APIs we don't have
credentials for. Adding a real client only requires implementing the
two functions and registering them in ``PROVIDER_CLIENTS`` below.

Verdict-label thresholds (applied at the worker / submitter layer,
not in the per-provider client):

  * score >= 5 → "malicious"
  * 2 <= score < 5 → "suspicious"
  * score < 2 → "benign"
"""

from __future__ import annotations

from typing import Any, Protocol

from app.models import DetonationProviderKind, DetonationVerdictLabel

from . import anyrun, cuckoo, vmray


class _ProviderClient(Protocol):
    async def submit(
        self,
        config: dict[str, Any],
        sample_bytes: bytes,
        sample_name: str,
    ) -> str: ...

    async def poll(self, config: dict[str, Any], task_id: str) -> dict[str, Any]: ...


PROVIDER_CLIENTS: dict[DetonationProviderKind, _ProviderClient] = {
    DetonationProviderKind.CUCKOO: cuckoo,
    DetonationProviderKind.VMRAY: vmray,
    DetonationProviderKind.ANYRUN: anyrun,
}


def get_client(kind: DetonationProviderKind) -> _ProviderClient:
    """Return the per-kind submit/poll module. Raises KeyError when a
    new provider was added to the enum but no client implementation
    was registered — same shape as ``app.services.intel.get_puller``.
    """
    try:
        return PROVIDER_CLIENTS[DetonationProviderKind.coerce(kind)]
    except (KeyError, ValueError) as exc:
        raise KeyError(f"no detonation client registered for kind={kind!r}") from exc


def label_for_score(score: float | None) -> DetonationVerdictLabel:
    """Bucket a raw sandbox score into the coarse verdict label. None
    falls back to benign — the poller writes ``error`` separately when
    the provider reported a failure without a numeric score."""
    if score is None:
        return DetonationVerdictLabel.BENIGN
    if score >= 5:
        return DetonationVerdictLabel.MALICIOUS
    if score >= 2:
        return DetonationVerdictLabel.SUSPICIOUS
    return DetonationVerdictLabel.BENIGN


__all__ = ["PROVIDER_CLIENTS", "get_client", "label_for_score"]
