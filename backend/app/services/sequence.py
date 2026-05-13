"""Sequence rule parser + evaluator (Phase 2 #2.3).

A sequence rule is a YAML document describing an initial trigger
event followed by one or more `followed_by` legs that must occur on
the same host within a sliding window. When the full chain completes,
the rule emits an alert.

Example shape:

    trigger:
      event_kind: process_started
      where: executable_basename == "rundll32.exe"
    followed_by:
      within: 5s
      event_kind: network_connection
      where: dst_port == 443
    then:
      emit_alert:
        severity: high
        message: "rundll32 network connect"

`event_kind` is a logical label mapped from the ECS document:

  * process_started     — ECS `process.*` payload with action=start
  * file_created        — ECS `file.*` payload with action=create
  * file_modified       — ECS `file.*` (default for the file category)
  * file_deleted        — ECS `file.*` with action=delete
  * network_connection  — ECS `network.*` with destination set
  * image_loaded        — ECS `file.*` with loader pid (image_load branch)
  * registry_set        — ECS registry payload (best-effort)
  * any                 — any event (catch-all)

`where` accepts a tiny expression language over a flattened event
view: `field op literal` with optional `and`/`or` chains and
parentheses. Supported ops:

    ==  !=  ~  !~  >  >=  <  <=  in  not in

`~` is "ilike contains" (case-insensitive substring); `!~` is its
negation. `in` accepts a parenthesised, comma-separated literal list
of strings or numbers.

Available view fields (flattened from ECS):

    event_id, event_action, event_kind_label, host_id
    pid, parent_pid, executable, executable_basename, command_line,
        working_directory, user_name, integrity_level
    file_path, file_name, file_basename, file_sha256
    dst_ip, dst_port, src_ip, src_port, transport, direction
    registry_path, registry_value, registry_data

The evaluator is stateless on its own; the worker keeps a
`SequenceEvaluator` instance per process, indexed by `(rule_id,
host_id)` → list of pending partial matches. Each partial expires
when its deadline (= trigger_ts + rule.window_s OR the leg's own
`within`) passes. Concurrent advances on the same host are fine —
each pending match advances independently.

Note on `event_kind` mapping vs. ECS's own `event.kind` field: ECS
uses `event.kind` for {event, alert, state}. We deliberately don't
reuse that name in user-facing rule YAML because the categorical
distinction we care about ("process started" vs "file deleted") lives
in `event.action` + `event.category` + the payload presence flags.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import yaml


class SequenceParseError(ValueError):
    """Raised when a sequence rule's YAML body fails validation."""


# ---------------------------------------------------------------------------
# AST + parser
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Predicate:
    """Compiled `where:` clause. `apply(view)` returns True/False."""

    fn: Any  # callable view -> bool

    def apply(self, view: dict[str, Any]) -> bool:
        try:
            return bool(self.fn(view))
        except Exception:  # noqa: BLE001
            # A predicate that blows up on a missing field is a non-match,
            # not a worker-killer. The author wrote `dst_port == 443` and
            # we got a process_started event with no `dst_port`; that's
            # just "this event isn't what we're looking for".
            return False


_TRUE_PRED = Predicate(fn=lambda _v: True)


@dataclass(frozen=True)
class TriggerSpec:
    event_kind: str
    where: Predicate


@dataclass(frozen=True)
class FollowedBySpec:
    event_kind: str
    where: Predicate
    # Per-leg window (seconds). Falls back to the rule's outer window_s
    # when omitted in YAML.
    within_s: float


@dataclass(frozen=True)
class EmitSpec:
    severity: str | None
    message: str


@dataclass(frozen=True)
class ParsedSequence:
    trigger: TriggerSpec
    legs: tuple[FollowedBySpec, ...]
    emit: EmitSpec
    window_s: int  # outer cap; the worker uses this to expire orphan partials


# Supported event_kind labels. `any` is the catch-all; rules using it
# pay attention only to the `where:` clause.
_KNOWN_EVENT_KINDS = frozenset(
    {
        "process_started",
        "file_created",
        "file_modified",
        "file_deleted",
        "network_connection",
        "image_loaded",
        "registry_set",
        "any",
    }
)


_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h)?\s*$")


def parse_duration(raw: str | int | float) -> float:
    """Parse `5s`, `200ms`, `2m`, `1h`, or a bare number-of-seconds.

    Returns seconds as a float. Raises SequenceParseError on bad input.
    """
    if isinstance(raw, int | float):
        if raw < 0:
            raise SequenceParseError(f"duration cannot be negative: {raw}")
        return float(raw)
    s = str(raw)
    m = _DURATION_RE.match(s)
    if m is None:
        raise SequenceParseError(f"unparseable duration: {s!r}")
    value = float(m.group(1))
    unit = (m.group(2) or "s").lower()
    if unit == "ms":
        return value / 1000.0
    if unit == "s":
        return value
    if unit == "m":
        return value * 60.0
    if unit == "h":
        return value * 3600.0
    raise SequenceParseError(f"unsupported duration unit: {unit}")


# --- mini expression language ----------------------------------------------


_TOKEN_RE = re.compile(
    r"""
    \s*(?:
        (?P<lparen>\() |
        (?P<rparen>\)) |
        (?P<comma>,) |
        (?P<op>==|!=|>=|<=|>|<|~|!~) |
        (?P<kw>\b(?:and|or|not|in)\b) |
        (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*') |
        (?P<num>-?\d+(?:\.\d+)?) |
        (?P<ident>[A-Za-z_][A-Za-z0-9_.]*)
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _tokenize(expr: str) -> list[tuple[str, str]]:
    pos = 0
    out: list[tuple[str, str]] = []
    while pos < len(expr):
        # Skip whitespace explicitly so re's `\s*` doesn't loop on
        # nothing-matched.
        while pos < len(expr) and expr[pos].isspace():
            pos += 1
        if pos >= len(expr):
            break
        m = _TOKEN_RE.match(expr, pos)
        if m is None or m.end() == pos:
            raise SequenceParseError(
                f"unexpected character {expr[pos]!r} at offset {pos} in {expr!r}"
            )
        for name, val in m.groupdict().items():
            if val is not None:
                out.append((name, val))
                break
        pos = m.end()
    return out


def _literal_value(tok_kind: str, raw: str) -> Any:
    if tok_kind == "str":
        # Strip quotes; handle simple backslash escapes.
        return bytes(raw[1:-1], "utf-8").decode("unicode_escape")
    if tok_kind == "num":
        if "." in raw:
            return float(raw)
        return int(raw)
    raise SequenceParseError(f"expected literal, got {tok_kind!r}")


def _field_getter(field_name: str):
    """Build a closure that pulls `field_name` out of a flat view dict.

    Allows dotted access (`process.executable`) so rule authors writing
    against ECS dot-paths can address fields without us flattening
    every possible path upfront. The view shipped by `flatten_event` is
    flat, so the fast-path is the direct lookup; the dotted-walk is
    the fallback.
    """

    def get(view: dict[str, Any]) -> Any:
        if field_name in view:
            return view[field_name]
        cur: Any = view
        for part in field_name.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return None
        return cur

    return get


def _build_comparison(field_name: str, op: str, right: Any) -> Any:
    """Return a callable view->bool for a single comparison."""

    get = _field_getter(field_name)

    if op == "==":
        return lambda v: get(v) == right
    if op == "!=":
        return lambda v: get(v) != right
    if op == ">":
        return lambda v: _gt(get(v), right)
    if op == ">=":
        return lambda v: _ge(get(v), right)
    if op == "<":
        return lambda v: _lt(get(v), right)
    if op == "<=":
        return lambda v: _le(get(v), right)
    if op == "~":
        # case-insensitive substring; right side coerced to string
        needle = str(right).lower()
        return lambda v: needle in str(get(v) or "").lower()
    if op == "!~":
        needle = str(right).lower()
        return lambda v: needle not in str(get(v) or "").lower()
    raise SequenceParseError(f"unsupported op: {op}")


def _gt(a: Any, b: Any) -> bool:
    try:
        return a is not None and a > b
    except TypeError:
        return False


def _ge(a: Any, b: Any) -> bool:
    try:
        return a is not None and a >= b
    except TypeError:
        return False


def _lt(a: Any, b: Any) -> bool:
    try:
        return a is not None and a < b
    except TypeError:
        return False


def _le(a: Any, b: Any) -> bool:
    try:
        return a is not None and a <= b
    except TypeError:
        return False


def _combine_or(left, right):
    def fn(v):
        return left(v) or right(v)

    return fn


def _combine_and(left, right):
    def fn(v):
        return left(v) and right(v)

    return fn


def _combine_not(inner):
    def fn(v):
        return not inner(v)

    return fn


class _Parser:
    """Recursive-descent parser for the mini expression language.

    Grammar:

        or_expr   := and_expr ( "or" and_expr )*
        and_expr  := not_expr ( "and" not_expr )*
        not_expr  := "not" not_expr | primary
        primary   := "(" or_expr ")" | comparison | in_expr
        comparison:= IDENT OP literal
        in_expr   := IDENT ("not")? "in" "(" literal ("," literal)* ")"
    """

    def __init__(self, tokens: list[tuple[str, str]]):
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> tuple[str, str] | None:
        if self.pos >= len(self.tokens):
            return None
        return self.tokens[self.pos]

    def _eat(self, kind: str, raw: str | None = None) -> tuple[str, str]:
        tok = self._peek()
        if tok is None:
            raise SequenceParseError(f"unexpected end of expression, expected {kind}")
        if tok[0] != kind:
            raise SequenceParseError(f"expected {kind}, got {tok[0]} ({tok[1]!r})")
        if raw is not None and tok[1].lower() != raw.lower():
            raise SequenceParseError(f"expected {raw}, got {tok[1]!r}")
        self.pos += 1
        return tok

    def parse(self) -> Any:
        fn = self.or_expr()
        if self.pos != len(self.tokens):
            tok = self.tokens[self.pos]
            raise SequenceParseError(f"unexpected trailing token {tok[1]!r}")
        return fn

    def or_expr(self) -> Any:
        left = self.and_expr()
        while self._is_keyword("or"):
            self.pos += 1
            right = self.and_expr()
            left = _combine_or(left, right)
        return left

    def and_expr(self) -> Any:
        left = self.not_expr()
        while self._is_keyword("and"):
            self.pos += 1
            right = self.not_expr()
            left = _combine_and(left, right)
        return left

    def not_expr(self) -> Any:
        if self._is_keyword("not"):
            self.pos += 1
            inner = self.not_expr()
            return _combine_not(inner)
        return self.primary()

    def _is_keyword(self, name: str) -> bool:
        tok = self._peek()
        return tok is not None and tok[0] == "kw" and tok[1].lower() == name

    def primary(self) -> Any:
        tok = self._peek()
        if tok is None:
            raise SequenceParseError("expected primary expression, got end of input")
        if tok[0] == "lparen":
            self.pos += 1
            inner = self.or_expr()
            self._eat("rparen")
            return inner
        if tok[0] == "ident":
            return self.comparison_or_in()
        raise SequenceParseError(f"unexpected token {tok[1]!r}")

    def comparison_or_in(self) -> Any:
        ident = self._eat("ident")[1]
        # `field [not] in (lit, lit, …)`
        negated = False
        if self._is_keyword("not"):
            self.pos += 1
            negated = True
        if self._is_keyword("in"):
            self.pos += 1
            self._eat("lparen")
            values: list[Any] = []
            while True:
                tok = self._peek()
                if tok is None:
                    raise SequenceParseError("expected literal inside `in (...)`")
                if tok[0] in ("str", "num"):
                    values.append(_literal_value(tok[0], tok[1]))
                    self.pos += 1
                else:
                    raise SequenceParseError(f"expected literal, got {tok[0]} ({tok[1]!r})")
                nxt = self._peek()
                if nxt is None:
                    raise SequenceParseError("unterminated `in (...)` list")
                if nxt[0] == "comma":
                    self.pos += 1
                    continue
                if nxt[0] == "rparen":
                    self.pos += 1
                    break
                raise SequenceParseError(f"expected ',' or ')' in `in (...)`, got {nxt[1]!r}")
            values_t = tuple(values)
            get = _field_getter(ident)

            def _check(view: dict[str, Any], _g=get, _vs=values_t, _neg=negated) -> bool:
                hit = _g(view) in _vs
                return (not hit) if _neg else hit

            return _check
        if negated:
            raise SequenceParseError("`not` must be followed by `in` for `<field> not in (...)`")
        # plain comparison
        op_tok = self._peek()
        if op_tok is None or op_tok[0] != "op":
            raise SequenceParseError(f"expected operator after {ident!r}")
        self.pos += 1
        right_tok = self._peek()
        if right_tok is None or right_tok[0] not in ("str", "num"):
            raise SequenceParseError(f"expected literal on right of {op_tok[1]!r}")
        right_val = _literal_value(right_tok[0], right_tok[1])
        self.pos += 1
        return _build_comparison(ident, op_tok[1], right_val)


def compile_predicate(where: str | None) -> Predicate:
    if where is None or not str(where).strip():
        return _TRUE_PRED
    tokens = _tokenize(str(where))
    parser = _Parser(tokens)
    fn = parser.parse()
    return Predicate(fn=fn)


def parse_yaml(body: str, *, default_window_s: int | None = None) -> ParsedSequence:
    """Parse a sequence-rule YAML body.

    `default_window_s` falls back to the global default when the YAML
    doesn't specify per-leg `within` and no rule-level `window_s` is in
    play; the worker normally passes the SequenceRule.window_s here.
    """
    if not body or not body.strip():
        raise SequenceParseError("empty rule body")
    try:
        doc = yaml.safe_load(body)
    except yaml.YAMLError as exc:
        raise SequenceParseError(f"yaml parse error: {exc}") from exc
    if not isinstance(doc, dict):
        raise SequenceParseError("top-level must be a mapping")

    trigger_raw = doc.get("trigger")
    if not isinstance(trigger_raw, dict):
        raise SequenceParseError("`trigger:` is required and must be a mapping")
    trigger_kind = trigger_raw.get("event_kind", "any")
    if trigger_kind not in _KNOWN_EVENT_KINDS:
        raise SequenceParseError(
            f"unknown trigger event_kind {trigger_kind!r}; allowed: {sorted(_KNOWN_EVENT_KINDS)}"
        )
    trigger = TriggerSpec(
        event_kind=str(trigger_kind),
        where=compile_predicate(trigger_raw.get("where")),
    )

    legs_raw = doc.get("followed_by")
    if legs_raw is None:
        raise SequenceParseError("`followed_by:` is required (one mapping or a list of them)")
    if isinstance(legs_raw, dict):
        legs_raw_list: list[dict[str, Any]] = [legs_raw]
    elif isinstance(legs_raw, list):
        legs_raw_list = legs_raw  # type: ignore[assignment]
    else:
        raise SequenceParseError("`followed_by:` must be a mapping or a list of mappings")
    if not legs_raw_list:
        raise SequenceParseError("`followed_by:` cannot be empty")

    fallback = (
        float(default_window_s) if default_window_s is not None else float(_default_window_s())
    )

    legs: list[FollowedBySpec] = []
    for i, leg in enumerate(legs_raw_list):
        if not isinstance(leg, dict):
            raise SequenceParseError(f"`followed_by[{i}]` must be a mapping")
        kind = leg.get("event_kind", "any")
        if kind not in _KNOWN_EVENT_KINDS:
            raise SequenceParseError(
                f"`followed_by[{i}].event_kind` is {kind!r}; allowed: {sorted(_KNOWN_EVENT_KINDS)}"
            )
        within_raw = leg.get("within")
        within_s = parse_duration(within_raw) if within_raw is not None else fallback
        legs.append(
            FollowedBySpec(
                event_kind=str(kind),
                where=compile_predicate(leg.get("where")),
                within_s=within_s,
            )
        )

    then_raw = doc.get("then") or {}
    if not isinstance(then_raw, dict):
        raise SequenceParseError("`then:` must be a mapping")
    emit_raw = then_raw.get("emit_alert") or {}
    if not isinstance(emit_raw, dict):
        raise SequenceParseError("`then.emit_alert:` must be a mapping")
    emit = EmitSpec(
        severity=emit_raw.get("severity"),
        message=str(emit_raw.get("message") or "sequence rule matched"),
    )

    outer = doc.get("window_s")
    if outer is None:
        if default_window_s is not None:
            outer = default_window_s
        else:
            outer = int(max(leg.within_s for leg in legs))
    return ParsedSequence(
        trigger=trigger,
        legs=tuple(legs),
        emit=emit,
        window_s=int(outer),
    )


def _default_window_s() -> int:
    raw = os.environ.get("VIGIL_SEQUENCE_RULE_DEFAULT_WINDOW_S")
    if raw and raw.isdigit():
        return int(raw)
    return 60


# ---------------------------------------------------------------------------
# ECS → flat view + event_kind classification
# ---------------------------------------------------------------------------


def flatten_event(ecs: dict[str, Any]) -> dict[str, Any]:
    """Return a flat dict the predicate language reads from.

    Fields not present in the source event simply don't appear; the
    predicate's missing-field handling (any compare with None on the
    left fails non-fatally) takes care of the absence case.
    """
    out: dict[str, Any] = {}
    event = ecs.get("event") or {}
    out["event_id"] = event.get("id")
    out["event_action"] = event.get("action")
    out["event_kind_label"] = classify_event_kind(ecs)
    host = ecs.get("host") or {}
    out["host_id"] = host.get("id")
    proc = ecs.get("process") or {}
    if proc:
        out["pid"] = proc.get("pid")
        out["executable"] = proc.get("executable")
        if out["executable"]:
            # Cross-platform basename: forward + backslash both split.
            exe = str(out["executable"]).replace("\\", "/")
            out["executable_basename"] = exe.rsplit("/", 1)[-1]
        out["command_line"] = proc.get("command_line")
        out["working_directory"] = proc.get("working_directory")
        parent = proc.get("parent") or {}
        if parent:
            out["parent_pid"] = parent.get("pid")
        user = proc.get("user") or {}
        if user:
            out["user_name"] = user.get("name")
        out["integrity_level"] = proc.get("integrity_level")
        hashes = proc.get("hash") or {}
        if hashes:
            out["process_sha256"] = hashes.get("sha256")
    fil = ecs.get("file") or {}
    if fil:
        out["file_path"] = fil.get("path")
        out["file_name"] = fil.get("name")
        if out["file_path"]:
            fp = str(out["file_path"]).replace("\\", "/")
            out["file_basename"] = fp.rsplit("/", 1)[-1]
        fhash = fil.get("hash") or {}
        out["file_sha256"] = fhash.get("sha256")
    dst = ecs.get("destination") or {}
    if dst:
        out["dst_ip"] = dst.get("ip")
        out["dst_port"] = dst.get("port")
    src = ecs.get("source") or {}
    if src:
        out["src_ip"] = src.get("ip")
        out["src_port"] = src.get("port")
    net = ecs.get("network") or {}
    if net:
        out["transport"] = net.get("transport")
        out["direction"] = net.get("direction")
    reg = ecs.get("registry") or {}
    if reg:
        out["registry_path"] = reg.get("path")
        out["registry_value"] = reg.get("value")
        out["registry_data"] = reg.get("data")
    return out


def classify_event_kind(ecs: dict[str, Any]) -> str:
    """Map an ECS doc to one of the supported `event_kind` labels.

    Best-effort: an event that doesn't match any specific label maps
    to `"any"`. The dispatch is intentionally simple — these labels
    are intended as a coarse pre-filter; precise discrimination is
    the `where:` clause's job.
    """
    event = ecs.get("event") or {}
    action = (event.get("action") or "").lower()
    categories = event.get("category") or []
    if isinstance(categories, str):
        categories = [categories]
    cats = {str(c).lower() for c in categories}

    # Agent-emitted process_started events usually have action == "start"
    # or "process_started"; some normalisers set neither.
    if (
        ecs.get("process")
        and "process" in cats
        and action in {"", "start", "process_started", "started"}
    ):
        return "process_started"
    if ecs.get("network") or "network" in cats:
        return "network_connection"
    if ecs.get("file") and ("file" in cats or not cats):
        if action in {"create", "creation", "created", "file_created"}:
            return "file_created"
        if action in {"delete", "deletion", "deleted", "file_deleted"}:
            return "file_deleted"
        if action in {"modify", "modification", "modified", "file_modified", "write"}:
            return "file_modified"
        # An image_load event normaliser surfaces under file.* with
        # an action like "loaded" / "image_load".
        if action in {"image_load", "image_loaded", "loaded", "load"}:
            return "image_loaded"
        return "file_modified"
    if ecs.get("registry") or "registry" in cats:
        return "registry_set"
    return "any"


# ---------------------------------------------------------------------------
# Stateful evaluator
# ---------------------------------------------------------------------------


@dataclass
class _Partial:
    """A trigger has matched; we're waiting for the remaining legs."""

    leg_idx: int  # next leg index expected (1-based offset into ParsedSequence.legs)
    deadline_ts: float  # epoch seconds; partial expires after this
    matched_event_ids: list[str] = field(default_factory=list)


@dataclass
class SequenceMatch:
    """A completed sequence emitted by the evaluator."""

    rule_id: str
    host_id: str
    severity: str | None
    message: str
    event_ids: list[str]


class SequenceEvaluator:
    """In-memory per-host state machine.

    The caller (the worker) holds one of these per process and feeds
    every ECS event through `feed_event`. `register_rule(rule_id,
    parsed)` replaces (or adds) a rule's parsed form; `forget_rule`
    drops it. `gc(now)` (called opportunistically) trims expired
    partials so memory stays bounded.
    """

    def __init__(self) -> None:
        # rule_id -> ParsedSequence
        self._rules: dict[str, ParsedSequence] = {}
        # (rule_id, host_id) -> list[Partial]
        self._partials: dict[tuple[str, str], list[_Partial]] = {}

    # --- rule lifecycle ----------------------------------------------------

    def register_rule(self, rule_id: str, parsed: ParsedSequence) -> None:
        self._rules[rule_id] = parsed
        # Don't drop existing partials on a rule edit — they belong to
        # the previous compilation. The next gc() pass clears them as
        # they expire.

    def forget_rule(self, rule_id: str) -> None:
        self._rules.pop(rule_id, None)
        for key in list(self._partials.keys()):
            if key[0] == rule_id:
                self._partials.pop(key, None)

    # --- event feed --------------------------------------------------------

    def feed_event(
        self, ecs: dict[str, Any], *, now_ts: float | None = None
    ) -> list[SequenceMatch]:
        """Advance state for one event. Returns any sequences completed
        by this event (usually zero; never more than `len(self._rules)`
        for a single event, since each rule emits at most once per
        completing event)."""
        if not self._rules:
            return []
        now = now_ts if now_ts is not None else time.time()
        host = ((ecs.get("host") or {}).get("id")) or ""
        if not host:
            return []
        view = flatten_event(ecs)
        event_id = view.get("event_id") or ""

        matches: list[SequenceMatch] = []
        for rule_id, parsed in self._rules.items():
            # 1. Advance any existing partials for this (rule, host).
            key = (rule_id, host)
            pending = self._partials.get(key, [])
            survivors: list[_Partial] = []
            for partial in pending:
                if partial.deadline_ts < now:
                    continue  # expired
                leg = parsed.legs[partial.leg_idx - 1]
                if _event_kind_matches(leg.event_kind, view) and leg.where.apply(view):
                    # Leg matched. If this is the final leg, emit.
                    new_event_ids = [*partial.matched_event_ids, str(event_id)]
                    if partial.leg_idx >= len(parsed.legs):
                        matches.append(
                            SequenceMatch(
                                rule_id=rule_id,
                                host_id=host,
                                severity=parsed.emit.severity,
                                message=parsed.emit.message,
                                event_ids=new_event_ids,
                            )
                        )
                        # Don't carry this partial forward — sequence
                        # completed.
                        continue
                    # Otherwise, advance to the next leg with a fresh
                    # deadline (`within` from the next leg).
                    next_leg = parsed.legs[partial.leg_idx]
                    survivors.append(
                        _Partial(
                            leg_idx=partial.leg_idx + 1,
                            deadline_ts=now + next_leg.within_s,
                            matched_event_ids=new_event_ids,
                        )
                    )
                else:
                    # Still waiting on the same leg.
                    survivors.append(partial)
            if survivors:
                self._partials[key] = survivors
            else:
                self._partials.pop(key, None)

            # 2. Does this event start a fresh partial?
            if _event_kind_matches(parsed.trigger.event_kind, view) and parsed.trigger.where.apply(
                view
            ):
                first_leg = parsed.legs[0]
                deadline = now + min(first_leg.within_s, float(parsed.window_s))
                self._partials.setdefault(key, []).append(
                    _Partial(
                        leg_idx=1,
                        deadline_ts=deadline,
                        matched_event_ids=[str(event_id)],
                    )
                )

        return matches

    def gc(self, now_ts: float | None = None) -> int:
        """Drop expired partials. Returns the number of partials trimmed.

        Cheap to call on every event — average case is "no expired
        rows" — but the worker calls it lazily (every N events) to
        keep the hot path tight.
        """
        now = now_ts if now_ts is not None else time.time()
        trimmed = 0
        for key in list(self._partials.keys()):
            kept = [p for p in self._partials[key] if p.deadline_ts >= now]
            trimmed += len(self._partials[key]) - len(kept)
            if kept:
                self._partials[key] = kept
            else:
                self._partials.pop(key, None)
        return trimmed

    # --- introspection (tests / debug) -------------------------------------

    def pending_count(self) -> int:
        return sum(len(v) for v in self._partials.values())


def _event_kind_matches(spec: str, view: dict[str, Any]) -> bool:
    if spec == "any":
        return True
    return view.get("event_kind_label") == spec


__all__ = (
    "EmitSpec",
    "FollowedBySpec",
    "ParsedSequence",
    "Predicate",
    "SequenceEvaluator",
    "SequenceMatch",
    "SequenceParseError",
    "TriggerSpec",
    "classify_event_kind",
    "compile_predicate",
    "flatten_event",
    "parse_duration",
    "parse_yaml",
)


def all_event_kinds() -> Iterable[str]:
    return tuple(sorted(_KNOWN_EVENT_KINDS))
