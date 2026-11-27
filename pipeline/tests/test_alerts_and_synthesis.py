"""BDD step definitions for Fact-Sheet synthesis constraints and owner-only Resend alerts TNR."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from alerts import dispatch_owner_daily_digest
from conftest import FakeSupabaseClient
from llm_client import LLMClient
from synthesize import (
    VALID_CATEGORIES,
    SynthesizedBriefing,
    synthesize_cluster_from_fact_sheets,
)

pytestmark = pytest.mark.tnr

scenarios("alerts_and_synthesis.feature")


@given(parsers.parse('a Fact Sheet with CVE "{cve}" and empty technical_details and remediations from the LLM'))
def given_fact_sheet_empty_fields(context: dict[str, Any], cve: str) -> None:
    context["fact_sheets"] = [
        {
            "cve_ids": [cve],
            "affected_versions": [],
            "affected_tech": ["Nginx"],
            "key_claims": ["Active exploitation reported"],
            "remediations": [],
            "source_url": "https://www.cert.ssi.gouv.fr/alerte/",
            "source_name": "CERT-FR Alertes",
        }
    ]


@given(
    parsers.parse(
        'the LLM outputs an invalid category "{bad_cat}" and hallucinated CVE "{fake_cve}"'
    )
)
def given_invalid_category(context: dict[str, Any], bad_cat: str, fake_cve: str) -> None:
    llm = MagicMock(spec=LLMClient)
    llm.synthesis_model = "gemini/gemini-3.8-flash"
    llm.complete_json.return_value = SynthesizedBriefing(
        headline="Nginx HTTP/3 Exploitation",
        tldr="Active exploitation reported against Nginx edge servers.",
        severity="Critical",
        categories=[bad_cat],
        # Deliberately omit authoritative CVE and inject hallucinated CVE
        cve_ids=[fake_cve],
        affected_tech=[],
        entities=[],
        technical_details="   ",
        remediations="",
        source_diffs="",
    )
    context["llm"] = llm


@when("synthesize_cluster_from_fact_sheets executes")
def when_synthesize_runs(context: dict[str, Any]) -> None:
    context["briefing"] = synthesize_cluster_from_fact_sheets(
        context["fact_sheets"],
        article_entities=["Nginx"],
        llm=context["llm"],
    )


@then(parsers.parse('technical_details defaults to "{expected}"'))
def then_tech_details_default(context: dict[str, Any], expected: str) -> None:
    assert context["briefing"].technical_details == expected


@then(parsers.parse('remediations defaults to "{expected}"'))
def then_remediations_default(context: dict[str, Any], expected: str) -> None:
    assert context["briefing"].remediations == expected


@then("categories falls back to a valid taxonomy value")
def then_categories_valid(context: dict[str, Any]) -> None:
    cats = context["briefing"].categories
    assert len(cats) >= 1
    assert all(c in VALID_CATEGORIES for c in cats)


@then(parsers.parse('authoritative CVE "{cve}" is preserved'))
def then_cve_preserved(context: dict[str, Any], cve: str) -> None:
    assert cve in context["briefing"].cve_ids


@then(parsers.parse('hallucinated CVE "{fake_cve}" is excluded'))
def then_hallucinated_cve_excluded(context: dict[str, Any], fake_cve: str) -> None:
    assert fake_cve not in context["briefing"].cve_ids


@given(parsers.parse("owner alert_settings.enabled is {state}"))
def given_alert_settings_enabled(context: dict[str, Any], state: str) -> None:
    enabled = state.strip().lower() == "true"
    context["sb"] = FakeSupabaseClient(
        {
            "alert_settings": [
                {
                    "id": 1,
                    "enabled": enabled,
                    "include_critical": True,
                    "include_watchlist": True,
                }
            ],
            "watchlists": [],
            "alert_logs": [],
            "clusters": [],
        }
    )
    context["touched_ids"] = []


@given(parsers.parse('a Critical cluster "{cluster_id}" was touched during the run'))
def given_critical_cluster_touched(context: dict[str, Any], cluster_id: str) -> None:
    context["sb"].store["clusters"].append(
        {
            "id": cluster_id,
            "headline": "Critical Nginx Zero-Day",
            "tldr": "Active exploitation detected.",
            "severity": "Critical",
            "cve_ids": ["CVE-2026-41892"],
            "affected_tech": ["Nginx"],
            "entities": ["Nginx"],
            "remediations": "Upgrade immediately.",
        }
    )
    context["touched_ids"].append(cluster_id)


@given(parsers.parse('watchlist keywords are "{csv}"'))
def given_watchlist_keywords(context: dict[str, Any], csv: str) -> None:
    context["sb"].store["watchlists"] = [
        {"keyword": kw.strip(), "enabled": True} for kw in csv.split(",")
    ]


@given(
    parsers.parse(
        'touched clusters include a Critical cluster with "{payload}" in the headline and a Medium cluster mentioning "{word}"'
    )
)
def given_mixed_clusters_for_digest(context: dict[str, Any], payload: str, word: str) -> None:
    context["sb"].store["clusters"].extend(
        [
            {
                "id": "clu-xss",
                "headline": f"Critical RCE {payload}",
                "tldr": "Critical flaw in Next.js middleware.",
                "severity": "Critical",
                "cve_ids": ["CVE-2026-39104"],
                "affected_tech": ["Next.js"],
                "entities": ["Next.js"],
                "remediations": "Patch Next.js.",
            },
            {
                "id": "clu-noise",
                "headline": f"General web {word} trend study",
                "tldr": f"Overview of automated {word} traffic patterns.",
                "severity": "Medium",
                "cve_ids": [],
                "affected_tech": [],
                "entities": [],
                "remediations": "Not disclosed in sources",
            },
        ]
    )
    context["touched_ids"].extend(["clu-xss", "clu-noise"])


@given(parsers.parse('cluster "{cluster_id}" was already logged as "sent" in the last 24 hours'))
def given_cluster_already_sent(context: dict[str, Any], cluster_id: str) -> None:
    context["sb"].store["alert_logs"].append(
        {
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "status": "sent",
            "cluster_ids": [cluster_id],
        }
    )


@given(parsers.parse('cluster "{cluster_id}" is touched again by a manual run'))
def given_cluster_touched_again(context: dict[str, Any], cluster_id: str) -> None:
    given_critical_cluster_touched(context, cluster_id)


@when("dispatch_owner_daily_digest executes")
def when_dispatch_digest(context: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALERTS_ENABLED", "true")
    monkeypatch.setenv("RESEND_API_KEY", "re_test_key")
    monkeypatch.setenv("ALERT_RECIPIENT_EMAIL", "owner@example.com")
    monkeypatch.setenv("DASHBOARD_URL", "https://crossread.example.com")

    sent_payloads: list[dict[str, Any]] = []

    fake_resp = MagicMock()
    fake_resp.raise_for_status.return_value = None
    fake_resp.json.return_value = {"id": "msg_test_123"}

    def fake_post(_url: str, *, headers: dict[str, str], json: dict[str, Any]) -> Any:
        sent_payloads.append(json)
        return fake_resp

    fake_client = MagicMock()
    fake_client.post.side_effect = fake_post
    fake_client.__enter__.return_value = fake_client
    fake_client.__exit__.return_value = False

    with patch("alerts.httpx.Client", return_value=fake_client):
        dispatch_owner_daily_digest(
            context["sb"],
            touched_cluster_ids=context["touched_ids"],
            fallback_watchlist=[],
        )

    context["sent_payloads"] = sent_payloads


@then("zero emails are sent via Resend")
def then_zero_emails(context: dict[str, Any]) -> None:
    assert len(context["sent_payloads"]) == 0


@then("exactly 1 email is sent via Resend")
def then_one_email(context: dict[str, Any]) -> None:
    assert len(context["sent_payloads"]) == 1


@then(parsers.parse('the HTML email body escapes "{raw_payload}"'))
def then_html_escaped(context: dict[str, Any], raw_payload: str) -> None:
    html_body: str = context["sent_payloads"][0]["html"]
    assert raw_payload not in html_body
    assert "&lt;script&gt;xss()&lt;/script&gt;" in html_body


@then("the email includes the AI-synthesized transparency notice")
def then_email_includes_ai_notice(context: dict[str, Any]) -> None:
    payload = context["sent_payloads"][0]
    assert "AI-synthesized briefing (unreviewed)" in payload["html"]
    assert "AI-synthesized briefing (unreviewed)" in payload["text"]


@then(parsers.parse('the unrelated "{word}" cluster is excluded from the digest'))
def then_unrelated_excluded(context: dict[str, Any], word: str) -> None:
    html_body: str = context["sent_payloads"][0]["html"]
    assert word not in html_body


@then(parsers.parse('alert_logs records status "{expected_status}"'))
def then_alert_log_status(context: dict[str, Any], expected_status: str) -> None:
    logs = context["sb"].store["alert_logs"]
    assert logs, "Expected at least one alert_logs record"
    assert logs[-1]["status"] == expected_status
