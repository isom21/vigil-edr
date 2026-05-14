"""Anthropic API wrapper (Phase 4 #4.1).

A thin async surface over ``anthropic.AsyncAnthropic`` that the
summariser worker, the ``ai_suggest`` playbook step, and the NL→query
endpoint share. Three methods:

  * ``summarise_alert(alert, ecs, rule)`` — produces a 1-3 sentence
    operator-facing summary of an alert.
  * ``suggest_response(alert)`` — returns a small list of suggested
    response actions (``isolate``, ``kill``, ``quarantine``, ``ask
    analyst``, etc.) with one-sentence rationales. The shape lines up
    with the ``ai_suggest`` playbook step's output expectation.
  * ``nl_to_query(prompt, language)`` — translates English to KQL or
    Lucene. The model only sees the supported field catalogue (a
    static cached block) plus the operator's question.

Prompt caching is configured with a single ephemeral cache_control
block on the system message. The catalogue of supported rule fields
+ ECS-aligned event categories is the only thing in the prompt we
ever expect to cache; per-alert details ride in the user message
unchanged.

When ``settings.anthropic_api_key`` is empty the wrapper short-
circuits to a deterministic dev stub: no SDK import (only at top of
file), no HTTP call. This keeps `pytest -q` runnable on a machine
without an API key and matches the same opt-out shape the other
LLM-adjacent integrations use (NVD `nvd_api_key`, OpenAI-style
notebook tools, etc.).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import structlog

from app.core.config import settings

log = structlog.get_logger()


# Cached system prompt. The catalogue we ship here is the only piece
# the prompt cache helps with — operator alert envelopes ride in the
# user turn so they don't bust the cache. Keep this string stable
# between releases or every call becomes a cache miss.
_SYSTEM_PROMPT_HEADER = (
    "You are Vigil, an EDR triage assistant. You write concise, "
    "actionable summaries for SOC analysts and translate natural-"
    "language queries to KQL or Lucene targeting the Vigil telemetry "
    "indices."
)


# Vigil's supported field catalogue. Kept short so the catalogue stays
# under the Anthropic cache-write minimum threshold envelope; the
# operator can extend this on a follow-up PR if the rule pack grows.
_FIELD_CATALOGUE = """
Supported ECS-aligned fields on the `telemetry-*` indices:
- @timestamp (date)
- host.id (keyword), host.hostname (keyword), host.os.family (keyword)
- event.category (keyword: process, file, network, authentication, dns, registry)
- event.action (keyword: e.g. process_started, file_created, network_connection)
- process.pid (long), process.name (keyword), process.command_line (text)
- process.parent.pid (long), process.parent.name (keyword)
- process.executable (keyword)
- file.path (keyword), file.name (keyword), file.hash.sha256 (keyword)
- destination.ip (ip), destination.port (long)
- source.ip (ip), source.port (long)
- user.name (keyword), user.id (keyword)
- dns.question.name (keyword)

Severity levels (low → high): info, low, medium, high, critical.
Alert states: new, investigating, false_positive, true_positive.
""".strip()


_SUGGESTION_ACTION_KINDS = ("isolate", "kill", "quarantine", "ask_analyst", "monitor")


@dataclass(frozen=True)
class AiCallResult:
    """Normalised response shape every method returns. ``payload`` is
    method-specific; ``cached_input_tokens`` + ``output_tokens`` come
    straight from the Anthropic response's `usage` block."""

    payload: dict[str, Any]
    cached_input_tokens: int
    output_tokens: int
    model_id: str


class AnthropicClient:
    """Stateless wrapper. One client per worker is enough — the SDK
    is thread/coroutine-safe internally."""

    def __init__(self, *, api_key: str | None = None, model_id: str | None = None) -> None:
        self._api_key = api_key if api_key is not None else settings.anthropic_api_key
        self._model_id = model_id or settings.ai_model_id
        self._client: Any | None = None

    # ---------- dev-stub path ----------

    def _is_stub(self) -> bool:
        return not self._api_key

    def _stub_summary(self) -> AiCallResult:
        return AiCallResult(
            payload={
                "summary": "summary unavailable (no API key configured)",
                "suggested_response": [],
            },
            cached_input_tokens=0,
            output_tokens=0,
            model_id=self._model_id,
        )

    def _stub_suggestion(self) -> AiCallResult:
        return AiCallResult(
            payload={"suggested_response": []},
            cached_input_tokens=0,
            output_tokens=0,
            model_id=self._model_id,
        )

    def _stub_query(self, prompt: str, language: str) -> AiCallResult:
        return AiCallResult(
            payload={
                "query": "",
                "language": language,
                "note": "translation unavailable (no API key configured)",
            },
            cached_input_tokens=0,
            output_tokens=0,
            model_id=self._model_id,
        )

    # ---------- SDK client lazy init ----------

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        # Import lazily so the dev-stub path doesn't pay the SDK
        # import cost and tests on machines without the package
        # installed still run the no-HTTP branches.
        from anthropic import AsyncAnthropic

        self._client = AsyncAnthropic(api_key=self._api_key)
        return self._client

    # ---------- helpers ----------

    @staticmethod
    def _system_blocks() -> list[dict[str, Any]]:
        """System prompt as the cached ephemeral block. Same content
        for every call so the prompt cache hits consistently."""
        body = f"{_SYSTEM_PROMPT_HEADER}\n\n{_FIELD_CATALOGUE}"
        return [
            {
                "type": "text",
                "text": body,
                "cache_control": {"type": "ephemeral"},
            }
        ]

    @staticmethod
    def _extract_text(message: Any) -> str:
        """The SDK returns a list of content blocks. We only ask for
        text, so just concatenate the text blocks."""
        parts: list[str] = []
        for block in getattr(message, "content", []) or []:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                parts.append(text)
        return "".join(parts).strip()

    @staticmethod
    def _usage_tokens(message: Any) -> tuple[int, int]:
        usage = getattr(message, "usage", None)
        if usage is None:
            return 0, 0
        cached = getattr(usage, "cache_read_input_tokens", 0) or 0
        out = getattr(usage, "output_tokens", 0) or 0
        return int(cached), int(out)

    @staticmethod
    def _safe_json(text: str) -> dict[str, Any] | None:
        """Best-effort JSON extraction. Models sometimes wrap JSON in
        a fenced block; strip that before parsing. Returns None on
        failure so the caller can fall back to a plain-text payload."""
        if not text:
            return None
        candidate = text.strip()
        if candidate.startswith("```"):
            # Drop the opening fence (and optional language tag).
            first_newline = candidate.find("\n")
            if first_newline != -1:
                candidate = candidate[first_newline + 1 :]
            if candidate.endswith("```"):
                candidate = candidate[:-3]
        candidate = candidate.strip()
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            return None
        if isinstance(parsed, dict):
            return parsed
        return None

    # ---------- public methods ----------

    async def summarise_alert(
        self,
        alert: dict[str, Any],
        ecs: dict[str, Any] | None,
        rule: dict[str, Any] | None,
    ) -> AiCallResult:
        """Return a 1-3 sentence operator summary + a few suggested
        response actions. The dev-stub path returns the canned
        placeholder copy the frontend expects."""
        if self._is_stub():
            return self._stub_summary()

        user_msg = json.dumps(
            {
                "alert": alert,
                "ecs": ecs or {},
                "rule": rule or {},
            },
            default=str,
        )
        prompt = (
            "Given the alert envelope below, return a strict JSON object with "
            "fields:\n"
            '  - "summary": one to three concise sentences for an SOC analyst.\n'
            '  - "suggested_response": an array (length 0-4) of '
            "{kind, label, rationale} objects. kind ∈ "
            f"{list(_SUGGESTION_ACTION_KINDS)}.\n"
            "Do not include any markdown fences in the JSON.\n\n"
            f"{user_msg}"
        )

        client = self._ensure_client()
        message = await client.messages.create(
            model=self._model_id,
            max_tokens=settings.ai_max_tokens,
            system=self._system_blocks(),
            messages=[{"role": "user", "content": prompt}],
        )
        text = self._extract_text(message)
        cached, out = self._usage_tokens(message)
        parsed = self._safe_json(text) or {"summary": text, "suggested_response": []}
        summary = parsed.get("summary") or text or "summary unavailable"
        suggestions = parsed.get("suggested_response") or []
        if not isinstance(suggestions, list):
            suggestions = []
        return AiCallResult(
            payload={"summary": str(summary), "suggested_response": suggestions},
            cached_input_tokens=cached,
            output_tokens=out,
            model_id=self._model_id,
        )

    async def suggest_response(self, alert: dict[str, Any]) -> AiCallResult:
        """Return only the suggested-response array. Used by the
        playbook `ai_suggest` step where the summary itself isn't
        needed."""
        if self._is_stub():
            return self._stub_suggestion()
        result = await self.summarise_alert(alert, ecs=alert.get("details") or {}, rule=None)
        return AiCallResult(
            payload={"suggested_response": result.payload.get("suggested_response", [])},
            cached_input_tokens=result.cached_input_tokens,
            output_tokens=result.output_tokens,
            model_id=result.model_id,
        )

    async def nl_to_query(self, prompt: str, language: str) -> AiCallResult:
        """Translate natural language to a KQL or Lucene query string.
        ``language`` is the caller's claimed target — passed straight
        through so the model picks the right dialect; we don't
        validate the response is parseable on this side."""
        if self._is_stub():
            return self._stub_query(prompt, language)
        if language not in ("kql", "lucene"):
            raise ValueError(f"unsupported query language {language!r}")
        user_msg = (
            f"Translate the following request to a {language.upper()} query string "
            "against the telemetry indices described in the system prompt. "
            'Return strict JSON: {"query": "...", "language": "' + language + '"}. '
            "Do not include markdown fences.\n\n"
            f"Request: {prompt}"
        )
        client = self._ensure_client()
        message = await client.messages.create(
            model=self._model_id,
            max_tokens=settings.ai_max_tokens,
            system=self._system_blocks(),
            messages=[{"role": "user", "content": user_msg}],
        )
        text = self._extract_text(message)
        cached, out = self._usage_tokens(message)
        parsed = self._safe_json(text) or {"query": text, "language": language}
        return AiCallResult(
            payload={
                "query": str(parsed.get("query") or text or ""),
                "language": str(parsed.get("language") or language),
            },
            cached_input_tokens=cached,
            output_tokens=out,
            model_id=self._model_id,
        )


__all__ = ["AiCallResult", "AnthropicClient"]
