"""Lightweight aggregation payloads for the `/stats` endpoints.

Used by the UI's chart strips. Each bucket carries a string ``key``
(severity name, hour ISO, hostname, …) and an integer ``count``.
"""

from __future__ import annotations

from pydantic import BaseModel


class StatBucket(BaseModel):
    key: str
    count: int
