"""Phase 2 Owner-Only Daily Email Alerts via Resend Free Tier.

Sends at most ONE bundled daily HTML + plain-text email combining:
- Critical severity clusters (when include_critical=true)
- Watchlist keyword matches (when include_watchlist=true)

Respects the owner's `alert_settings.enabled` toggle in Supabase so the
dashboard can be used passively without receiving emails.

Post-deployment debugging guide:
- No email received? Check `public.alert_logs` in Supabase first:
  * `skipped_disabled` -> toggle is OFF in dashboard (`alert_settings.enabled = false`).
  * `skipped_empty`    -> no new Critical or Watchlist clusters matched in this run
                          (or they were already emailed within the last 24 hours).
  * `failed`           -> check `error_message`; on Resend Free Tier without a custom
                          verified domain, `onboarding@resend.dev` can ONLY deliver to
                          the email address registered on your Resend account.
"""

from __future__ import annotations

import html
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
from supabase import Client

logger = logging.getLogger(__name__)

RESEND_API_URL = "https://api.resend.com/emails"


def _is_safe_https(url: str) -> bool:
    try:
        return urlparse(url).scheme.lower() == "https"
    except Exception:
        return False


def _match_keywords(cluster: dict[str, Any], keywords: list[str]) -> list[str]:
    """Case-insensitive whole-word/token keyword matching across key cluster fields.

    Uses negative lookbehind/lookahead on `\\w` rather than `\\b` so keywords containing
    punctuation like `Next.js` or `Node.js` still match accurately without matching
    unrelated substrings (e.g., `CRA` inside `scraping`).
    """
    haystack = " ".join(
        [
            str(cluster.get("headline", "")),
            str(cluster.get("tldr", "")),
            " ".join(cluster.get("cve_ids") or []),
            " ".join(cluster.get("affected_tech") or []),
            " ".join(cluster.get("entities") or []),
        ]
    )
    matched: list[str] = []
    for kw in keywords:
        cleaned = kw.strip()
        if not cleaned:
            continue
        pattern = re.compile(rf"(?i)(?<!\w){re.escape(cleaned)}(?!\w)")
        if pattern.search(haystack):
            matched.append(cleaned)
    return matched


def _fetch_alert_settings(sb: Client) -> dict[str, Any] | None:
    try:
        resp = sb.table("alert_settings").select("*").eq("id", 1).limit(1).execute()
        if resp.data:
            return resp.data[0]
        return None
    except Exception as exc:
        logger.warning("alert_settings table unavailable (Phase 2 migration applied?): %s", exc)
        return None


def _fetch_watchlist_keywords(sb: Client, fallback_keywords: list[str]) -> list[str]:
    try:
        resp = sb.table("watchlists").select("keyword").eq("enabled", True).execute()
        rows = [row["keyword"] for row in (resp.data or []) if row.get("keyword")]
        return rows if rows else fallback_keywords
    except Exception:
        return fallback_keywords


def _fetch_recently_alerted_cluster_ids(sb: Client, hours: int = 24) -> set[str]:
    since_iso = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    try:
        resp = (
            sb.table("alert_logs")
            .select("cluster_ids")
            .eq("status", "sent")
            .gte("sent_at", since_iso)
            .execute()
        )
        sent_ids: set[str] = set()
        for row in resp.data or []:
            for cid in row.get("cluster_ids") or []:
                sent_ids.add(str(cid))
        return sent_ids
    except Exception:
        return set()


def _render_digest_html(
    items: list[tuple[dict[str, Any], list[str]]],
    *,
    dashboard_url: str,
) -> tuple[str, str]:
    """Build strictly escaped HTML and plain-text email bodies."""
    date_label = datetime.now(timezone.utc).strftime("%d %b %Y")
    safe_dashboard = html.escape(dashboard_url, quote=True) if _is_safe_https(dashboard_url) else ""

    html_cards: list[str] = []
    text_blocks: list[str] = [f"CrossRead Daily Cybersecurity Alert Digest ({date_label})", ""]

    for cluster, matched_kws in items:
        sev = html.escape(str(cluster.get("severity", "Medium")), quote=True)
        headline = html.escape(str(cluster.get("headline", "")), quote=True)
        tldr = html.escape(str(cluster.get("tldr", "")), quote=True)
        remediations = html.escape(
            str(cluster.get("remediations", "Not disclosed in sources")), quote=True
        )
        cves = ", ".join(html.escape(str(c), quote=True) for c in (cluster.get("cve_ids") or []))
        kw_label = ", ".join(html.escape(k, quote=True) for k in matched_kws)
        sev_color = "#b91c1c" if cluster.get("severity") == "Critical" else "#b45309"

        meta_parts = [f"<strong style='color:{sev_color}'>{sev} severity</strong>"]
        if cves:
            meta_parts.append(f"<span style='font-family:monospace'>{cves}</span>")
        if kw_label:
            meta_parts.append(f"Watchlist: {kw_label}")

        html_cards.append(
            f"""
            <div style="border:1px solid #e2e8f0;border-radius:8px;padding:18px;margin-bottom:14px;background:#ffffff;">
              <div style="font-size:12px;color:#64748b;margin-bottom:6px;">{' &middot; '.join(meta_parts)}</div>
              <h2 style="margin:0 0 8px 0;font-size:17px;line-height:1.35;color:#0f172a;">{headline}</h2>
              <p style="margin:0 0 10px 0;font-size:14px;line-height:1.6;color:#334155;">{tldr}</p>
              <div style="font-size:13px;color:#475569;border-top:1px solid #f1f5f9;padding-top:10px;">
                <strong>Remediations:</strong> {remediations}
              </div>
            </div>
            """
        )

        text_blocks.append(f"[{cluster.get('severity')}] {cluster.get('headline')}")
        if matched_kws:
            text_blocks.append(f"Watchlist matches: {', '.join(matched_kws)}")
        text_blocks.append(str(cluster.get("tldr", "")))
        text_blocks.append(f"Remediations: {cluster.get('remediations', 'Not disclosed in sources')}")
        text_blocks.append("")

    ai_notice_text = (
        "AI-synthesized briefing (unreviewed): generated from structured source Fact Sheets. "
        "Verify CVEs, affected versions, and remediation steps against the original advisories "
        "before applying production changes."
    )
    ai_notice_html = (
        f'<p style="font-size:11px;line-height:1.5;color:#64748b;margin-top:16px;'
        f'padding:10px 12px;background:#f1f5f9;border-radius:6px;">'
        f'<strong>AI Transparency Notice:</strong> {html.escape(ai_notice_text)}</p>'
    )

    footer_html = (
        f'<p style="font-size:12px;color:#64748b;margin-top:14px;">'
        f'Open the <a href="{safe_dashboard}" style="color:#0f172a;">CrossRead dashboard</a> '
        f'to read full deep-dives or turn owner email alerts off anytime.</p>'
        if safe_dashboard
        else '<p style="font-size:12px;color:#64748b;margin-top:14px;">Toggle owner email alerts off anytime in the CrossRead dashboard.</p>'
    )

    body_html = f"""<!doctype html>
<html lang="en">
  <body style="margin:0;padding:24px;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#0f172a;">
    <div style="max-width:640px;margin:0 auto;">
      <div style="margin-bottom:18px;">
        <div style="font-size:12px;color:#64748b;">CrossRead Daily Briefing &middot; {html.escape(date_label)}</div>
        <h1 style="margin:4px 0 0 0;font-size:22px;color:#0f172a;">{len(items)} Priority Security {'Alert' if len(items) == 1 else 'Alerts'}</h1>
      </div>
      {''.join(html_cards)}
      {ai_notice_html}
      {footer_html}
    </div>
  </body>
</html>"""

    text_blocks.append(f"AI Transparency Notice: {ai_notice_text}")
    if safe_dashboard:
        text_blocks.append(f"Dashboard (manage/disable alerts): {dashboard_url}")

    return body_html, "\n".join(text_blocks)


def _log_alert(
    sb: Client,
    *,
    status: str,
    cluster_ids: list[str] | None = None,
    matched_keywords: list[str] | None = None,
    provider_message_id: str | None = None,
    error_message: str | None = None,
) -> None:
    try:
        sb.table("alert_logs").insert(
            {
                "status": status,
                "cluster_ids": cluster_ids or [],
                "matched_keywords": sorted(set(matched_keywords or [])),
                "cluster_count": len(cluster_ids or []),
                "provider_message_id": provider_message_id,
                "error_message": error_message,
            }
        ).execute()
    except Exception as exc:
        logger.warning("Failed to record alert_logs entry: %s", exc)


def dispatch_owner_daily_digest(
    sb: Client,
    *,
    touched_cluster_ids: list[str],
    fallback_watchlist: list[str],
) -> None:
    """Send 1 bundled daily Resend email to the owner if alerts are enabled and matches exist."""
    if os.getenv("ALERTS_ENABLED", "true").strip().lower() == "false":
        logger.info("Alerts disabled via ALERTS_ENABLED=false; skipping digest.")
        return

    settings = _fetch_alert_settings(sb)
    if not settings or not settings.get("enabled", False):
        logger.info("Owner email alerts are OFF in alert_settings; skipping digest.")
        _log_alert(sb, status="skipped_disabled")
        return

    if not touched_cluster_ids:
        logger.info("No new or updated clusters in this run; skipping digest.")
        _log_alert(sb, status="skipped_empty")
        return

    api_key = os.getenv("RESEND_API_KEY", "").strip()
    recipient = re.sub(r"[\r\n]+", "", os.getenv("ALERT_RECIPIENT_EMAIL", "").strip())
    sender = re.sub(
        r"[\r\n]+",
        "",
        os.getenv("ALERT_FROM_EMAIL", "CrossRead Alerts <onboarding@resend.dev>").strip(),
    )
    dashboard_url = os.getenv("DASHBOARD_URL", "").strip()

    if not api_key or not recipient or "@" not in recipient:
        logger.warning("Owner alerts enabled, but RESEND_API_KEY or ALERT_RECIPIENT_EMAIL is unset or invalid.")
        _log_alert(
            sb,
            status="failed",
            error_message="Missing or invalid RESEND_API_KEY or ALERT_RECIPIENT_EMAIL secret",
        )
        return

    # Prevent duplicate alerts if a manual workflow_dispatch run touches a cluster
    # that was already emailed in the morning 07:00 CET digest.
    already_sent = _fetch_recently_alerted_cluster_ids(sb, hours=24)
    candidate_ids = [cid for cid in dict.fromkeys(touched_cluster_ids) if cid not in already_sent]
    if not candidate_ids:
        _log_alert(sb, status="skipped_empty")
        return

    clusters = (
        sb.table("clusters")
        .select("id, headline, tldr, severity, cve_ids, affected_tech, entities, remediations")
        .in_("id", candidate_ids)
        .execute()
        .data
        or []
    )

    keywords = _fetch_watchlist_keywords(sb, fallback_watchlist)
    include_critical = bool(settings.get("include_critical", True))
    include_watchlist = bool(settings.get("include_watchlist", True))

    selected: list[tuple[dict[str, Any], list[str]]] = []
    all_matched_keywords: list[str] = []

    for cluster in clusters:
        is_critical = cluster.get("severity") == "Critical"
        matched = _match_keywords(cluster, keywords) if include_watchlist else []
        if (include_critical and is_critical) or bool(matched):
            selected.append((cluster, matched))
            all_matched_keywords.extend(matched)

    if not selected:
        logger.info("No Critical or Watchlist matches in this run; skipping digest.")
        _log_alert(sb, status="skipped_empty")
        return

    # Sort Critical items first
    selected.sort(key=lambda pair: 0 if pair[0].get("severity") == "Critical" else 1)
    body_html, body_text = _render_digest_html(selected, dashboard_url=dashboard_url)

    critical_count = sum(1 for c, _ in selected if c.get("severity") == "Critical")
    subject = (
        f"[CrossRead] {critical_count} Critical + {len(selected) - critical_count} Watchlist Briefings"
        if critical_count and len(selected) > critical_count
        else f"[CrossRead] {len(selected)} Priority Security {'Briefing' if len(selected) == 1 else 'Briefings'}"
    )

    selected_ids = [str(c["id"]) for c, _ in selected]

    try:
        with httpx.Client(timeout=httpx.Timeout(15.0)) as client:
            resp = client.post(
                RESEND_API_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": sender,
                    "to": [recipient],
                    "subject": subject,
                    "html": body_html,
                    "text": body_text,
                },
            )
            resp.raise_for_status()
            msg_id = resp.json().get("id")
            logger.info("Sent owner daily alert digest (%d briefings, id=%s)", len(selected), msg_id)
            _log_alert(
                sb,
                status="sent",
                cluster_ids=selected_ids,
                matched_keywords=all_matched_keywords,
                provider_message_id=msg_id,
            )
    except Exception as exc:
        logger.error("Failed to send Resend daily digest: %s", exc)
        _log_alert(
            sb,
            status="failed",
            cluster_ids=selected_ids,
            matched_keywords=all_matched_keywords,
            error_message=str(exc)[:300],
        )
