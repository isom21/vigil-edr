"""Sigma rule compilation and evaluation helpers.

Rules are written against ECS field names (e.g. process.name, process.command_line).
We compile each Sigma rule once via pySigma's OpenSearch backend to a Lucene
query string; the sigma-scheduler worker then runs that query periodically
against the live telemetry-* indices to find matches and emit alerts.

Field-mapping pipelines (sysmon → ECS, windows → ECS) are out of scope for
M3; rule writers target ECS directly.
"""

from __future__ import annotations

from dataclasses import dataclass

import yaml
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError


@dataclass(frozen=True)
class CompiledSigma:
    """Result of compiling a Sigma YAML rule."""

    query: str
    title: str
    description: str | None
    rule_id: str | None  # the Sigma rule's own id field, not our DB id


class SigmaCompileError(ValueError):
    """Raised when a Sigma rule cannot be compiled to a backend query."""


def compile_yaml(body: str) -> CompiledSigma:
    """Compile a Sigma YAML body to a Lucene query string.

    Single-rule YAML only — multi-rule documents raise.
    """
    if not body or not body.strip():
        raise SigmaCompileError("empty rule body")
    try:
        collection = SigmaCollection.from_yaml(body)
    except yaml.YAMLError as exc:
        # pySigma re-raises the underlying PyYAML error from from_yaml
        # without wrapping it in a SigmaError. Surface line/column when
        # the parser provided them so the rule editor can pinpoint the
        # typo without spelunking through the server log.
        mark = getattr(exc, "problem_mark", None)
        problem = getattr(exc, "problem", None) or str(exc).split("\n", 1)[0]
        if mark is not None:
            raise SigmaCompileError(
                f"yaml parse error at line {mark.line + 1} column {mark.column + 1}: {problem}"
            ) from exc
        raise SigmaCompileError(f"yaml parse error: {problem}") from exc
    except SigmaError as exc:
        raise SigmaCompileError(f"sigma parse error: {exc}") from exc
    if len(collection.rules) != 1:
        raise SigmaCompileError(f"expected exactly one rule per body, got {len(collection.rules)}")
    rule = collection.rules[0]
    backend = OpensearchLuceneBackend()
    try:
        queries = backend.convert(collection)
    except SigmaError as exc:
        raise SigmaCompileError(f"sigma backend error: {exc}") from exc
    if not queries:
        raise SigmaCompileError("backend produced no query")
    return CompiledSigma(
        query=queries[0],
        title=str(rule.title or ""),
        description=str(rule.description) if rule.description else None,
        rule_id=str(rule.id) if rule.id else None,
    )
