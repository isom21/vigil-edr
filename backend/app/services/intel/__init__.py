"""Threat-intel feed puller registry (Phase 1 #1.9).

Each puller is an async callable that takes a feed row + decrypted
auth string (or None) and returns a list of `ParsedIndicator` tuples.
The worker calls the right puller based on `IntelFeed.kind` and is
otherwise puller-agnostic.

Indicator kinds the current `IocKind` enum doesn't cover (domain, ip,
url) are dropped at parse time by the individual pullers — the worker
sees only what it can materialise.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from app.models import IntelFeed, IntelFeedKind, IocKind


@dataclass(frozen=True)
class ParsedIndicator:
    """One indicator pulled from a feed, ready to materialise as an
    `IocEntry`. `value` is the raw string; the caller normalises before
    insert (same path as the manual rules UI uses)."""

    kind: IocKind
    value: str


PullerFn = Callable[[IntelFeed, str | None], Awaitable[list[ParsedIndicator]]]


_REGISTRY: dict[IntelFeedKind, PullerFn] = {}


def register(kind: IntelFeedKind, fn: PullerFn) -> None:
    """Plug a puller into the registry. Module-level call from each
    puller's import side."""
    _REGISTRY[kind] = fn


def get_puller(kind: IntelFeedKind) -> PullerFn:
    """Look up the puller for a feed kind. Raises KeyError if missing —
    the worker treats a missing puller as a permanent error and marks
    the feed's last_error so the operator notices in the UI."""
    return _REGISTRY[kind]


# Side-effect imports register the pullers. Keep these at the bottom so
# the registry is fully wired by the time anything imports from this
# package.
from app.services.intel import abusech, custom_json, taxii  # noqa: E402,F401

__all__ = ["ParsedIndicator", "PullerFn", "get_puller", "register"]
