"""Helper for parsing `?sort=field:dir` query params.

Each resource declares an allow-list mapping field name → SQL column.
Anything outside the allow-list raises a 400 so we never accidentally
expose internal columns or break query plans on un-indexed sorts.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.core.errors import bad_request

OrderBy = list[Any]


def parse_sort(sort: str | None, allowed: dict[str, Any], default: OrderBy) -> OrderBy:
    """Translate ``field:asc|desc`` into a SQLAlchemy ORDER BY clause list.

    ``allowed`` maps the public field name to the SQLAlchemy column
    expression. ``default`` is returned untouched when ``sort`` is None.
    """
    if not sort:
        return default
    field, _, direction = sort.partition(":")
    direction = direction or "asc"
    if field not in allowed:
        raise bad_request(f"sort field '{field}' not allowed (allowed: {','.join(_keys(allowed))})")
    if direction not in ("asc", "desc"):
        raise bad_request("sort direction must be 'asc' or 'desc'")
    col = allowed[field]
    return [col.desc() if direction == "desc" else col.asc()]


def _keys(allowed: dict[str, Any]) -> Iterable[str]:
    return sorted(allowed.keys())
