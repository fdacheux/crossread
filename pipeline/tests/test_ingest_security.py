"""BDD step definitions for ingestion SSRF hardening and Pre-LLM Quality Gate TNR."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from ingest import (
    SSRFBlockedError,
    extract_cves,
    passes_quality_gate,
    safe_fetch_bytes,
    validate_safe_https_url,
)

pytestmark = pytest.mark.tnr

scenarios("ingest_security.feature")

BOT_MARKERS = [
    "verify you are human",
    "enable javascript",
    "access denied",
    "cloudflare",
]


@given(parsers.parse('a manual URL "{url}"'))
def given_manual_url(context: dict[str, Any], url: str) -> None:
    context["url"] = url


@when("the SSRF validator checks the URL")
def when_ssrf_validates(context: dict[str, Any]) -> None:
    try:
        validate_safe_https_url(context["url"])
        context["error"] = None
    except Exception as exc:  # noqa: BLE001
        context["error"] = exc


@given(parsers.parse('a public URL "{public_url}" that redirects to "{redirect_target}"'))
def given_redirect_url(context: dict[str, Any], public_url: str, redirect_target: str) -> None:
    context["url"] = public_url
    context["redirect_target"] = redirect_target


@when("safe_fetch_bytes retrieves the URL")
def when_safe_fetch_redirect(context: dict[str, Any]) -> None:
    # Stub DNS so the initial public host resolves to a routable public IP (93.184.216.34),
    # while the 302 redirect target points directly to the cloud metadata IP.
    fake_public_dns = [(2, 1, 6, "", ("93.184.216.34", 443))]

    fake_response = MagicMock()
    fake_response.status_code = 302
    fake_response.headers = {"location": context["redirect_target"]}

    @contextmanager
    def fake_stream(*_args: Any, **_kwargs: Any):
        yield fake_response

    fake_client = MagicMock()
    fake_client.stream.side_effect = fake_stream
    fake_client.__enter__.return_value = fake_client
    fake_client.__exit__.return_value = False
    context["fake_client"] = fake_client

    with (
        patch("ingest.socket.getaddrinfo", return_value=fake_public_dns),
        patch("ingest.httpx.Client", return_value=fake_client),
    ):
        try:
            safe_fetch_bytes(context["url"])
            context["error"] = None
        except Exception as exc:  # noqa: BLE001
            context["error"] = exc


@then("validation fails with SSRFBlockedError")
def then_ssrf_blocked(context: dict[str, Any]) -> None:
    assert isinstance(context["error"], SSRFBlockedError), f"Expected SSRFBlockedError, got {context['error']!r}"


@then("the unsafe redirect target is never requested")
def then_unsafe_redirect_not_requested(context: dict[str, Any]) -> None:
    assert context["fake_client"].stream.call_count == 1


@given(parsers.parse('extracted text "{text}"'))
def given_extracted_text(context: dict[str, Any], text: str) -> None:
    context["text"] = text


@when(parsers.parse("the Pre-LLM Quality Gate runs with minimum {min_words:d} words"))
def when_quality_gate_standard(context: dict[str, Any], min_words: int) -> None:
    context["gate_result"] = passes_quality_gate(
        context["text"],
        min_word_count=min_words,
        bot_wall_markers=BOT_MARKERS,
        is_structured_advisory=False,
    )


@when(parsers.parse("the Pre-LLM Quality Gate runs as a structured advisory with minimum {min_words:d} words"))
def when_quality_gate_advisory(context: dict[str, Any], min_words: int) -> None:
    context["gate_result"] = passes_quality_gate(
        context["text"],
        min_word_count=min_words,
        bot_wall_markers=BOT_MARKERS,
        is_structured_advisory=True,
    )


@then(parsers.parse('the quality gate rejects the article with marker "{marker}"'))
def then_quality_gate_rejects(context: dict[str, Any], marker: str) -> None:
    passed, reason = context["gate_result"]
    assert passed is False
    assert marker in reason


@then("the quality gate accepts the article")
def then_quality_gate_accepts(context: dict[str, Any]) -> None:
    passed, reason = context["gate_result"]
    assert passed is True, f"Expected quality gate to pass, got {reason!r}"


@then(parsers.parse('regex CVE extraction returns "{expected_cve}"'))
def then_regex_extracts_cve(context: dict[str, Any], expected_cve: str) -> None:
    assert expected_cve in extract_cves(context["text"])
