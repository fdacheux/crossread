"""Main entry point for the Bilingual Cybersecurity Cross-Reader Pipeline.

Supports:
- Scheduled daily feed ingestion (from config/feeds.json)
- Optional manual URL ingestion (via --manual-urls or MANUAL_URLS env var)
- Dry-run mode (--dry-run) to validate extraction/triage without writing to Supabase

Execution Order (critical invariants):
1. Deduplicate against the last 14 days of `articles.url` to avoid re-processing.
2. Extract Fact Sheets in memory and IMMEDIATELY wipe `cand.text = ""` (Fact-Sheet First).
3. Cluster via CVE-first hard match, then 72h entity-gated soft match.
4. For existing clusters: upsert new articles FIRST, then re-read ALL cluster Fact Sheets
   from Supabase and re-synthesize from scratch (never from a previous cluster summary).
5. Dispatch at most 1 owner Resend digest if `alert_settings.enabled = true`.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from supabase import Client, create_client

from alerts import dispatch_owner_daily_digest
from cluster import PendingArticle, assign_clusters
from ingest import fetch_manual_url, ingest_all_feeds, load_feed_config
from llm_client import LLMClient, PROMPT_VERSION
from synthesize import synthesize_cluster_from_fact_sheets
from triage import triage_and_extract

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pipeline.main")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "feeds.json"
DEFAULT_MAX_ARTICLES_PER_RUN = 40


def _get_supabase_client() -> Client:
    url = os.getenv("SUPABASE_URL", "").strip()
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    if not url or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set")
    return create_client(url, key)


def _fetch_existing_urls(sb: Client, lookback_days: int = 14) -> set[str]:
    since_iso = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).isoformat()
    resp = sb.table("articles").select("url").gte("ingested_at", since_iso).execute()
    return {row["url"] for row in (resp.data or []) if row.get("url")}


def _fetch_active_clusters_72h(sb: Client, window_hours: int) -> list[dict[str, Any]]:
    since_iso = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
    resp = (
        sb.table("clusters")
        .select("id, headline, cve_ids, entities, affected_tech, updated_at")
        .gte("updated_at", since_iso)
        .execute()
    )
    return list(resp.data or [])


def _parse_manual_urls(raw: str | None) -> list[str]:
    if not raw:
        return []
    urls: list[str] = []
    for token in raw.replace(",", "\n").splitlines():
        cleaned = token.strip()
        if cleaned:
            urls.append(cleaned)
    return urls


def _upsert_articles_with_provenance(sb: Client, rows: list[dict[str, Any]]) -> None:
    """Upsert article rows including Phase 3 AI provenance columns, falling back
    gracefully if migration 0003 has not been applied yet.
    """
    try:
        sb.table("articles").upsert(rows, on_conflict="url").execute()
    except Exception as exc:
        if "triage_model" in str(exc) or "prompt_version" in str(exc):
            stripped = [
                {k: v for k, v in row.items() if k not in {"triage_model", "prompt_version"}}
                for row in rows
            ]
            sb.table("articles").upsert(stripped, on_conflict="url").execute()
        else:
            raise


def _write_cluster_with_provenance(
    sb: Client,
    payload: dict[str, Any],
    *,
    cluster_id: str | None = None,
) -> Any:
    """Insert or update a cluster row with Phase 3 AI provenance columns, falling back
    gracefully if migration 0003 has not been applied yet.
    """
    try:
        if cluster_id:
            return sb.table("clusters").update(payload).eq("id", cluster_id).execute()
        return sb.table("clusters").insert(payload).execute()
    except Exception as exc:
        if "synthesis_model" in str(exc) or "prompt_version" in str(exc):
            stripped = {
                k: v for k, v in payload.items() if k not in {"synthesis_model", "prompt_version"}
            }
            if cluster_id:
                return sb.table("clusters").update(stripped).eq("id", cluster_id).execute()
            return sb.table("clusters").insert(stripped).execute()
        raise


def _run_retention_cleanup(sb: Client) -> None:
    """Invoke Phase 3 RGPD storage-limitation purge RPC if installed."""
    try:
        resp = sb.rpc("purge_expired_records", {}).execute()
        logger.info("RGPD retention cleanup completed: %s", resp.data)
    except Exception as exc:
        logger.debug("Skipping retention cleanup RPC (migration 0003 optional): %s", exc)


def run_pipeline(*, manual_urls: list[str], dry_run: bool, lookback_hours: int) -> None:
    load_dotenv()
    config = load_feed_config(DEFAULT_CONFIG_PATH)
    settings = config.get("settings", {})
    watchlist = config.get("watchlist_keywords", [])
    window_hours = int(settings.get("rolling_cluster_window_hours", 72))
    max_articles = max(
        1, int(os.getenv("MAX_ARTICLES_PER_RUN", str(DEFAULT_MAX_ARTICLES_PER_RUN)))
    )

    llm = LLMClient()
    sb: Client | None = None if dry_run else _get_supabase_client()

    existing_urls: set[str] = _fetch_existing_urls(sb) if sb else set()
    active_clusters: list[dict[str, Any]] = (
        _fetch_active_clusters_72h(sb, window_hours) if sb else []
    )

    # 1. Ingestion (Manual URLs OR Scheduled Feeds)
    # Note: Passing MANUAL_URLS intentionally skips scheduled feeds so ad-hoc
    # workflow_dispatch runs complete quickly and don't consume extra RPM budget.
    candidates = []
    for url in manual_urls:
        if url in existing_urls:
            logger.info("Skipping already-ingested manual URL: %s", url)
            continue
        cand = fetch_manual_url(url, settings=settings)
        if cand:
            candidates.append(cand)
            existing_urls.add(cand.url)

    if not manual_urls:
        candidates.extend(
            ingest_all_feeds(
                config,
                existing_urls=existing_urls,
                lookback_hours=lookback_hours,
            )
        )

    # Enforce per-run article ceiling (OWASP LLM10 Unbounded Consumption guardrail)
    if len(candidates) > max_articles:
        logger.warning(
            "Candidate count (%d) exceeded MAX_ARTICLES_PER_RUN (%d); capping batch.",
            len(candidates),
            max_articles,
        )
        candidates = candidates[:max_articles]

    logger.info("Total candidates passing Pre-LLM Quality Gate: %d", len(candidates))
    if not candidates:
        logger.info("No new articles to process. Exiting cleanly.")
        if sb:
            _run_retention_cleanup(sb)
        return

    # 2. Triage & Structured Fact-Sheet Extraction (raw prose discarded immediately)
    pending_articles: list[PendingArticle] = []
    for idx, cand in enumerate(candidates):
        triage_result = triage_and_extract(cand, llm=llm, watchlist_keywords=watchlist)
        # Immediately release raw scraped article text from memory (Fact-Sheet First rule)
        cand.text = ""

        if not triage_result:
            continue
        if not triage_result.relevant:
            logger.info(
                "Triage skipped [%s] %s (%s)",
                cand.source_name,
                cand.title,
                triage_result.rejection_reason,
            )
            continue

        pending_articles.append(
            PendingArticle(
                temp_id=f"art_{idx}",
                url=cand.url,
                title=cand.title,
                source_name=cand.source_name,
                language=cand.language,
                published_at_iso=cand.published_at.isoformat(),
                cve_ids=triage_result.fact_sheet.cve_ids,
                entities=triage_result.entities,
                fact_sheet=triage_result.fact_sheet.model_dump(),
            )
        )

    logger.info("Articles passing relevance triage: %d", len(pending_articles))
    if not pending_articles:
        if sb:
            _run_retention_cleanup(sb)
        return

    # 3. CVE-First, Entity-Gated Clustering
    existing_buckets, new_buckets = assign_clusters(
        pending_articles,
        active_clusters=active_clusters,
        llm=llm,
    )
    logger.info(
        "Clustering complete: %d existing clusters updated, %d new clusters created",
        len(existing_buckets),
        len(new_buckets),
    )

    if dry_run:
        for group_key, arts in new_buckets.items():
            fact_sheets = [a.fact_sheet for a in arts]
            all_entities = [e for a in arts for e in a.entities]
            briefing = synthesize_cluster_from_fact_sheets(
                fact_sheets,
                article_entities=all_entities,
                llm=llm,
            )
            logger.info("[DRY RUN] New cluster %s: [%s] %s", group_key, briefing.severity, briefing.headline)
        return

    assert sb is not None
    touched_cluster_ids: list[str] = []

    # 4a. Update existing clusters: insert new Fact Sheets, then re-synthesize from ALL Fact Sheets
    for cluster_id, new_arts in existing_buckets.items():
        rows = [
            {
                "url": a.url,
                "title": a.title,
                "source_name": a.source_name,
                "language": a.language,
                "published_at": a.published_at_iso,
                "cve_ids": a.cve_ids,
                "entities": a.entities,
                "fact_sheet": a.fact_sheet,
                "cluster_id": cluster_id,
                "triage_model": llm.triage_model,
                "prompt_version": PROMPT_VERSION,
            }
            for a in new_arts
        ]
        _upsert_articles_with_provenance(sb, rows)

        # Re-fetch ALL stored Fact Sheets for this cluster (never synthesize from previous summary!)
        all_rows = (
            sb.table("articles")
            .select("fact_sheet, entities")
            .eq("cluster_id", cluster_id)
            .execute()
            .data
            or []
        )
        all_fact_sheets = [r["fact_sheet"] for r in all_rows]
        all_entities = [e for r in all_rows for e in (r.get("entities") or [])]

        briefing = synthesize_cluster_from_fact_sheets(
            all_fact_sheets,
            article_entities=all_entities,
            llm=llm,
        )
        cluster_payload = {
            **briefing.model_dump(),
            "synthesis_model": llm.synthesis_model,
            "prompt_version": PROMPT_VERSION,
        }
        _write_cluster_with_provenance(sb, cluster_payload, cluster_id=cluster_id)
        touched_cluster_ids.append(cluster_id)
        logger.info("Re-synthesized existing cluster %s (%d sources): %s", cluster_id, len(all_fact_sheets), briefing.headline)

    # 4b. Create new clusters: synthesize strictly from their Fact Sheets, then link articles
    for group_key, arts in new_buckets.items():
        all_fact_sheets = [a.fact_sheet for a in arts]
        all_entities = [e for a in arts for e in a.entities]

        briefing = synthesize_cluster_from_fact_sheets(
            all_fact_sheets,
            article_entities=all_entities,
            llm=llm,
        )
        cluster_payload = {
            **briefing.model_dump(),
            "synthesis_model": llm.synthesis_model,
            "prompt_version": PROMPT_VERSION,
        }
        created = _write_cluster_with_provenance(sb, cluster_payload)
        cluster_id = created.data[0]["id"]

        rows = [
            {
                "url": a.url,
                "title": a.title,
                "source_name": a.source_name,
                "language": a.language,
                "published_at": a.published_at_iso,
                "cve_ids": a.cve_ids,
                "entities": a.entities,
                "fact_sheet": a.fact_sheet,
                "cluster_id": cluster_id,
                "triage_model": llm.triage_model,
                "prompt_version": PROMPT_VERSION,
            }
            for a in arts
        ]
        # Upsert articles AFTER cluster creation so the FK `articles.cluster_id` is valid
        # and the DB trigger `trg_articles_sync_cluster_count` automatically updates `source_count`.
        _upsert_articles_with_provenance(sb, rows)
        touched_cluster_ids.append(cluster_id)
        logger.info("Created cluster %s [%s] (%d sources): %s", cluster_id, briefing.severity, len(arts), briefing.headline)

    # 5. Phase 2 Owner-Only Daily Email Alert Digest (respects alert_settings.enabled)
    dispatch_owner_daily_digest(
        sb,
        touched_cluster_ids=touched_cluster_ids,
        fallback_watchlist=watchlist,
    )

    # 6. Phase 3 RGPD Storage Limitation Retention Cleanup (safe no-op if migration 0003 not applied)
    _run_retention_cleanup(sb)


def main() -> int:
    parser = argparse.ArgumentParser(description="Bilingual Cybersecurity Cross-Reader Pipeline")
    parser.add_argument("--manual-urls", default=os.getenv("MANUAL_URLS", ""), help="Newline or comma-separated HTTPS URLs")
    parser.add_argument("--dry-run", action="store_true", help="Run ingestion/triage/synthesis without writing to Supabase")
    parser.add_argument("--lookback-hours", type=int, default=36, help="Feed lookback window in hours")
    args = parser.parse_args()

    run_pipeline(
        manual_urls=_parse_manual_urls(args.manual_urls),
        dry_run=args.dry_run,
        lookback_hours=args.lookback_hours,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
