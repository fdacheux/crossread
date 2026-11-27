"""BDD step definitions for prompt-injection defense, CVE/entity clustering, and 429 retry TNR."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel
from pytest_bdd import given, parsers, scenarios, then, when

from cluster import BatchGroupingResponse, ClusterAssignment, PendingArticle, assign_clusters
from llm_client import LLMClient, wrap_untrusted_text

pytestmark = pytest.mark.tnr

scenarios("clustering_and_triage.feature")


class _SamplePayload(BaseModel):
    ok: bool


def _make_pending(
    temp_id: str,
    *,
    cves: list[str],
    entities: list[str],
) -> PendingArticle:
    return PendingArticle(
        temp_id=temp_id,
        url=f"https://example.com/{temp_id}",
        title=f"Advisory {temp_id}",
        source_name="The Hacker News",
        language="en",
        published_at_iso="2026-11-22T06:00:00+00:00",
        cve_ids=cves,
        entities=entities,
        fact_sheet={
            "cve_ids": cves,
            "affected_versions": [],
            "affected_tech": entities,
            "key_claims": ["Test security claim"],
            "remediations": [],
            "source_url": f"https://example.com/{temp_id}",
            "source_name": "The Hacker News",
        },
    )


@given(parsers.parse('raw article text containing "{raw}"'))
def given_raw_article(context: dict[str, Any], raw: str) -> None:
    context["raw_text"] = raw


@when("the text is wrapped for LLM input")
def when_wrapped(context: dict[str, Any]) -> None:
    context["wrapped"] = wrap_untrusted_text(context["raw_text"], tag="untrusted_article")


@then("the inner closing tag is neutralized")
def then_inner_tag_neutralized(context: dict[str, Any]) -> None:
    wrapped: str = context["wrapped"]
    assert wrapped.count("</untrusted_article>") == 1
    assert "[/untrusted_article]" in wrapped


@then("the outer untrusted_article tags remain intact")
def then_outer_tags_intact(context: dict[str, Any]) -> None:
    wrapped: str = context["wrapped"]
    assert wrapped.startswith("<untrusted_article>\n")
    assert wrapped.endswith("\n</untrusted_article>")


@given(parsers.parse('an active cluster "{cluster_id}" with CVE "{cve}" and entities "{entities}"'))
def given_active_cve_cluster(context: dict[str, Any], cluster_id: str, cve: str, entities: str) -> None:
    context["active_clusters"] = [
        {
            "id": cluster_id,
            "headline": f"Existing briefing for {cve}",
            "cve_ids": [cve],
            "entities": [e.strip() for e in entities.split(",")],
            "affected_tech": [e.strip() for e in entities.split(",")],
        }
    ]
    context["llm"] = MagicMock(spec=LLMClient)
    context["llm"].triage_model = "gemini/gemini-3.5-flash-lite"


@given(parsers.parse('an active cluster "{cluster_id}" with no CVEs and entities "{entities}"'))
def given_active_non_cve_cluster(context: dict[str, Any], cluster_id: str, entities: str) -> None:
    context["active_clusters"] = [
        {
            "id": cluster_id,
            "headline": "Existing non-CVE briefing",
            "cve_ids": [],
            "entities": [e.strip() for e in entities.split(",")],
            "affected_tech": [],
        }
    ]
    context["llm"] = MagicMock(spec=LLMClient)
    context["llm"].triage_model = "gemini/gemini-3.5-flash-lite"


@given(parsers.parse('a new English article with CVE "{cve}" and entities "{entities}"'))
def given_new_cve_article(context: dict[str, Any], cve: str, entities: str) -> None:
    context["pending"] = [
        _make_pending("new_0", cves=[cve], entities=[e.strip() for e in entities.split(",")])
    ]


@given(parsers.parse('a new non-CVE article with entities "{entities}"'))
def given_new_non_cve_article(context: dict[str, Any], entities: str) -> None:
    context["pending"] = [
        _make_pending("new_0", cves=[], entities=[e.strip() for e in entities.split(",")])
    ]


@given(parsers.parse('the LLM erroneously proposes merging the article into "{cluster_id}"'))
def given_erroneous_llm_merge(context: dict[str, Any], cluster_id: str) -> None:
    context["llm"].complete_json.return_value = BatchGroupingResponse(
        assignments=[
            ClusterAssignment(temp_id="new_0", action="existing", cluster_id=cluster_id)
        ]
    )


@when("assign_clusters executes")
def when_assign_clusters(context: dict[str, Any]) -> None:
    existing, new = assign_clusters(
        context["pending"],
        active_clusters=context["active_clusters"],
        llm=context["llm"],
    )
    context["existing_buckets"] = existing
    context["new_buckets"] = new


@then(parsers.parse('the article is assigned to existing cluster "{cluster_id}"'))
def then_assigned_existing(context: dict[str, Any], cluster_id: str) -> None:
    assert cluster_id in context["existing_buckets"]
    assert len(context["existing_buckets"][cluster_id]) == 1
    assert not context["new_buckets"]


@then("zero LLM grouping calls are made")
def then_zero_llm_calls(context: dict[str, Any]) -> None:
    context["llm"].complete_json.assert_not_called()


@then(parsers.parse('the article is placed into a new cluster instead of "{forbidden_cluster}"'))
def then_placed_in_new_cluster(context: dict[str, Any], forbidden_cluster: str) -> None:
    assert forbidden_cluster not in context["existing_buckets"]
    assert len(context["new_buckets"]) == 1


@then("the entity gate rejects the merge and creates a new cluster")
def then_entity_gate_rejects(context: dict[str, Any]) -> None:
    assert not context["existing_buckets"]
    assert len(context["new_buckets"]) == 1


@given(parsers.parse('LiteLLM fails twice with "{error_msg}" and succeeds on attempt 3'))
def given_litellm_flaky(context: dict[str, Any], error_msg: str) -> None:
    context["error_msg"] = error_msg


@when("complete_json executes")
def when_complete_json_runs(context: dict[str, Any]) -> None:
    client = LLMClient()
    client.throttle_seconds = 0.0
    client.max_retries = 4

    ok_response = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))]
    )
    side_effects = [
        RuntimeError(context["error_msg"]),
        RuntimeError(context["error_msg"]),
        ok_response,
    ]

    with (
        patch("llm_client.litellm.completion", side_effect=side_effects) as mock_call,
        patch("llm_client.time.sleep") as mock_sleep,
    ):
        context["result"] = client.complete_json(
            model="gemini/gemini-3.5-flash-lite",
            system_prompt="sys",
            user_prompt="usr",
            response_model=_SamplePayload,
        )
        context["call_count"] = mock_call.call_count
        context["sleep_count"] = mock_sleep.call_count


@then("the client retries with backoff and returns the validated JSON object")
def then_retry_succeeded(context: dict[str, Any]) -> None:
    assert context["result"].ok is True
    assert context["call_count"] == 3
    assert context["sleep_count"] == 2
