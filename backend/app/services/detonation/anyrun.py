"""ANY.RUN detonation client (Phase 4 #4.4) — stub.

ANY.RUN's REST API requires a paid subscription; same shape as the
VMRay stub. The submitter / poller fans out to it once credentials are
wired up; until then both functions raise NotImplementedError.
"""

from __future__ import annotations

from typing import Any

_MESSAGE = "ANY.RUN integration TODO — requires paid API"


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
