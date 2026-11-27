"""Provider-agnostic LiteLLM wrapper with retry backoff, RPM throttling,
strict JSON parsing, and prompt-injection delimiters.

Post-deployment debugging guide:
- 429 / RESOURCE_EXHAUSTED loops: raise LLM_THROTTLE_SECONDS (e.g., 6.0) or
  switch TRIAGE_MODEL / SYNTHESIS_MODEL via GitHub Repository Variables.
- JSON validation failures: verify the selected provider supports
  `response_format={"type": "json_object"}` in LiteLLM; some smaller models
  wrap JSON in markdown fences (handled by `_extract_json_payload`).
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import time
from typing import Any, TypeVar

import litellm
from pydantic import BaseModel

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# Suppress noisy telemetry from LiteLLM in CI logs
litellm.telemetry = False
litellm.drop_params = True

DEFAULT_TRIAGE_MODEL = "gemini/gemini-3.5-flash-lite"
DEFAULT_SYNTHESIS_MODEL = "gemini/gemini-3.8-flash"
PROMPT_VERSION = "2026.11-v2"


def wrap_untrusted_text(text: str, tag: str = "untrusted_article") -> str:
    """Wrap untrusted scraped content in explicit XML-like delimiters and
    neutralize any closing delimiter attempts embedded inside the article.

    Why: Cybersecurity articles frequently quote raw XSS/SQLi PoCs or text
    containing `</untrusted_article>`. Escaping closing tags prevents an
    attacker from breaking out of the data boundary into instruction space.
    """
    sanitized = re.sub(
        rf"</\s*{re.escape(tag)}\s*>",
        f"[/{tag}]",
        text,
        flags=re.IGNORECASE,
    )
    return f"<{tag}>\n{sanitized}\n</{tag}>"


def _extract_json_payload(raw: str) -> Any:
    """Extract JSON from an LLM response, stripping optional markdown code fences.

    Fallback safeguard for providers that ignore `response_format` and wrap
    JSON inside ```json ... ``` blocks.
    """
    cleaned = raw.strip()
    fence_match = re.search(r"```(?:json)?\s*(.*?)\s*```", cleaned, flags=re.DOTALL | re.IGNORECASE)
    if fence_match:
        cleaned = fence_match.group(1).strip()
    return json.loads(cleaned)


class LLMClient:
    """Thin, swappable LiteLLM client resilient to Free-Tier RPM/429 limits."""

    def __init__(self) -> None:
        self.triage_model = os.getenv("TRIAGE_MODEL", DEFAULT_TRIAGE_MODEL)
        self.synthesis_model = os.getenv("SYNTHESIS_MODEL", DEFAULT_SYNTHESIS_MODEL)
        self.throttle_seconds = float(os.getenv("LLM_THROTTLE_SECONDS", "4.5"))
        self.max_retries = int(os.getenv("LLM_MAX_RETRIES", "5"))
        self.timeout_seconds = int(os.getenv("LLM_TIMEOUT_SECONDS", "60"))
        # Hard output-token ceiling (OWASP LLM10 Unbounded Consumption guardrail)
        self.max_tokens = int(os.getenv("LLM_MAX_TOKENS", "2048"))
        self._last_call_ts: float = 0.0

    def _throttle(self) -> None:
        """Enforce a minimum gap between sequential LLM requests to stay below
        Free-Tier requests-per-minute (RPM) caps (e.g., 15 RPM => >= 4.0s gap).
        """
        if self.throttle_seconds <= 0:
            return
        elapsed = time.monotonic() - self._last_call_ts
        remaining = self.throttle_seconds - elapsed
        if remaining > 0:
            time.sleep(remaining)

    @staticmethod
    def _is_rate_limit_error(exc: Exception) -> bool:
        """Detect rate-limit errors across providers (Gemini returns RESOURCE_EXHAUSTED)."""
        msg = str(exc).lower()
        return (
            isinstance(exc, litellm.RateLimitError)
            or "429" in msg
            or "resource_exhausted" in msg
            or "rate limit" in msg
            or "quota" in msg
        )

    def complete_json(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[T],
        temperature: float = 0.1,
        max_tokens: int | None = None,
    ) -> T:
        """Invoke LiteLLM with exponential backoff on 429s and validate JSON via Pydantic.

        Retries transient network errors, 429 rate limits, and malformed JSON outputs,
        but fails fast on authentication/permission errors (401/403).
        """
        last_error: Exception | None = None
        token_cap = max_tokens if max_tokens is not None else self.max_tokens

        for attempt in range(1, self.max_retries + 1):
            self._throttle()
            self._last_call_ts = time.monotonic()

            try:
                response = litellm.completion(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=temperature,
                    max_tokens=token_cap,
                    timeout=self.timeout_seconds,
                    response_format={"type": "json_object"},
                )
                content = response.choices[0].message.content
                if not content:
                    raise ValueError("LLM returned empty message content")

                # Parse JSON and strictly validate field types against Pydantic schema
                parsed = _extract_json_payload(content)
                return response_model.model_validate(parsed)

            except Exception as exc:
                last_error = exc
                is_retryable = self._is_rate_limit_error(exc) or isinstance(
                    exc,
                    (
                        litellm.ServiceUnavailableError,
                        litellm.Timeout,
                        litellm.APIConnectionError,
                        json.JSONDecodeError,
                        ValueError,
                    ),
                )
                if not is_retryable or attempt == self.max_retries:
                    logger.error(
                        "LLM call failed permanently (model=%s, attempt=%d/%d): %s",
                        model,
                        attempt,
                        self.max_retries,
                        exc,
                    )
                    raise

                # Exponential backoff with jitter (especially generous on 429 RESOURCE_EXHAUSTED)
                base_wait = 6.0 if self._is_rate_limit_error(exc) else 2.0
                delay = min(base_wait * (2 ** (attempt - 1)) + random.uniform(0.5, 2.0), 90.0)
                logger.warning(
                    "LLM transient/rate-limit error (model=%s, attempt=%d/%d): %s — retrying in %.1fs",
                    model,
                    attempt,
                    self.max_retries,
                    exc,
                    delay,
                )
                time.sleep(delay)

        raise RuntimeError(f"LLM completion exhausted retries: {last_error}")
