"""VMRay detonation client (Phase 4 #4.4) — stub.

VMRay's REST API requires a paid subscription; we ship the same
contract as ``cuckoo.py`` so the submitter / poller can fan out to it
once an operator wires up credentials, but the call sites raise
NotImplementedError until that lands. Tests assert the stub raises
cleanly rather than silently no-op-ing.
"""

from __future__ import annotations

from typing import Any

_MESSAGE = "VMRay integration TODO — requires paid API"


async def submit(
    config: dict[str, Any],  # noqa: ARG001
    sample_bytes: bytes,  # noqa: ARG001
    sample_name: str,  # noqa: ARG001
) -> str:
    raise NotImplementedError(_MESSAGE)


async def poll(
    config: dict[str, Any],  # noqa: ARG001
    task_id: str,  # noqa: ARG001
) -> dict[str, Any]:
    raise NotImplementedError(_MESSAGE)
