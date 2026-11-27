"""Article ingestion, SSRF-hardened HTTPS fetching, in-memory text extraction,
CVE regex detection, and Pre-LLM Quality Gate.

Raw article text is kept strictly in memory and discarded after Fact-Sheet extraction.

Post-deployment debugging guide:
- If a feed stops producing articles, search GitHub Actions logs for
  `Feed failure [<name>]` or `Quality gate rejected [<name>]` (often caused
  by a site adding Cloudflare JS challenges or changing its RSS endpoint).
- If a valid manual URL is rejected with `SSRFBlockedError`, confirm it uses
  `https://` (not `http://`) and resolves to a public routable IP.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import feedparser
import httpx
import trafilatura
from dateutil import parser as date_parser

logger = logging.getLogger(__name__)

CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
MAX_REDIRECTS = 5
USER_AGENT = "CyberCrossReader/1.0 (+https://github.com/cyber-cross-reader)"


@dataclass
class RawArticleCandidate:
    """Ephemeral in-memory container. `text` is NEVER persisted to Supabase."""

    url: str
    title: str
    source_name: str
    language: str
    published_at: datetime
    text: str
    cve_ids: list[str] = field(default_factory=list)
    is_structured_advisory: bool = False


class SSRFBlockedError(ValueError):
    """Raised when a URL violates HTTPS-only or public-IP SSRF rules."""


def extract_cves(*texts: str) -> list[str]:
    """Extract unique, sorted, uppercase CVE identifiers via regex."""
    found: set[str] = set()
    for block in texts:
        if block:
            for match in CVE_REGEX.findall(block):
                found.add(match.upper())
    return sorted(found)


def _is_disallowed_ip(ip_str: str) -> bool:
    """Return True if an IP is NOT globally routable (blocks loopback, RFC1918
    private, link-local / cloud metadata 169.254.169.254, Carrier-Grade NAT
    100.64.0.0/10 including 100.100.100.200, multicast, reserved, or unspecified).
    """
    ip = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_and_validate_https_url(url: str) -> tuple[str, str, str]:
    """Validate that a URL is HTTPS on port 443 and resolves strictly to globally
    routable public IPs. Returns `(normalized_url, hostname, pinned_ip)`.
    """
    cleaned = url.strip()
    if len(cleaned) > 2048:
        raise SSRFBlockedError("Blocked overly long URL (>2048 chars)")

    parsed = urlparse(cleaned)
    if parsed.scheme.lower() != "https":
        raise SSRFBlockedError(f"Blocked non-HTTPS URL scheme: {parsed.scheme!r}")
    if not parsed.hostname:
        raise SSRFBlockedError("Blocked URL with missing hostname")
    if parsed.username or parsed.password:
        raise SSRFBlockedError("Blocked URL containing embedded credentials")
    if parsed.port not in (None, 443):
        raise SSRFBlockedError(f"Blocked non-standard HTTPS port: {parsed.port}")

    hostname = parsed.hostname.lower().rstrip(".")
    if "%" in hostname:
        raise SSRFBlockedError("Blocked IPv6 zone identifier in hostname")
    if hostname in {"localhost", "localhost.localdomain", "metadata.google.internal"}:
        raise SSRFBlockedError(f"Blocked disallowed hostname: {hostname}")

    # Direct IP literal check
    try:
        if _is_disallowed_ip(hostname):
            raise SSRFBlockedError(f"Blocked non-global IP literal: {hostname}")
        return cleaned, hostname, hostname
    except ValueError:
        pass

    # DNS resolution check (guards against internal hostnames, CGNAT, and metadata IPs)
    try:
        addrinfo = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"DNS resolution failed for {hostname}: {exc}") from exc

    if not addrinfo:
        raise SSRFBlockedError(f"No IP addresses resolved for {hostname}")

    validated_ips: list[str] = []
    for _, _, _, _, sockaddr in addrinfo:
        ip_str = sockaddr[0]
        if _is_disallowed_ip(ip_str):
            raise SSRFBlockedError(
                f"Blocked hostname {hostname} resolving to non-global IP {ip_str}"
            )
        validated_ips.append(ip_str)

    return cleaned, hostname, validated_ips[0]


def validate_safe_https_url(url: str) -> str:
    """Validate that a URL uses https:// on port 443 and resolves exclusively to public IPs."""
    cleaned, _, _ = _resolve_and_validate_https_url(url)
    return cleaned


def _build_pinned_ip_url(logical_url: str, pinned_ip: str) -> str:
    """Rewrite a validated HTTPS URL's netloc to the pinned IP literal so the TCP
    socket connects directly to the already-validated IP (prevents DNS rebinding).
    """
    parsed = urlparse(logical_url)
    ip_host = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"https://{ip_host}{path}{query}"


def safe_fetch_bytes(
    url: str,
    *,
    timeout_seconds: int = 15,
    max_bytes: int = 5 * 1024 * 1024,
) -> tuple[str, bytes]:
    """Fetch an HTTPS URL with manual redirect validation, pinned-IP connection
    (anti-DNS-rebinding), strict timeout, and streaming size cap.

    IMPORTANT: `follow_redirects=False` is deliberate. Every hop is re-validated
    via `_resolve_and_validate_https_url`, and the socket connects directly to the
    validated IP while preserving TLS SNI & Host verification against `hostname`.
    """
    current_url, hostname, pinned_ip = _resolve_and_validate_https_url(url)

    with httpx.Client(
        timeout=httpx.Timeout(timeout_seconds),
        follow_redirects=False,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xml,application/json;q=0.9,*/*;q=0.8",
        },
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            pinned_url = _build_pinned_ip_url(current_url, pinned_ip)
            # Stream bytes rather than calling response.content to abort early if
            # a malicious or broken server sends a huge payload without Content-Length.
            with client.stream(
                "GET",
                pinned_url,
                headers={"Host": hostname},
                extensions={"sni_hostname": hostname},
            ) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location:
                        raise ValueError(f"Redirect without Location header from {current_url}")
                    next_url = urljoin(current_url, location)
                    current_url, hostname, pinned_ip = _resolve_and_validate_https_url(next_url)
                    continue

                response.raise_for_status()
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError(
                            f"Response exceeded max size limit ({max_bytes} bytes): {current_url}"
                        )
                    chunks.append(chunk)
                return current_url, b"".join(chunks)

    raise ValueError(f"Exceeded maximum redirects ({MAX_REDIRECTS}) for {url}")


def passes_quality_gate(
    text: str,
    *,
    min_word_count: int,
    bot_wall_markers: list[str],
    is_structured_advisory: bool = False,
) -> tuple[bool, str]:
    """Pre-LLM Quality Gate: reject short extractions or bot-wall responses.

    Note: `is_structured_advisory=True` exempts concise official JSON records
    (like CISA KEV entries, which are typically 60-110 words) from the 150-word
    HTML floor while still checking for empty text and bot-wall strings.
    """
    cleaned = (text or "").strip()
    if not cleaned:
        return False, "empty_extraction"

    lowered = cleaned.lower()
    for marker in bot_wall_markers:
        if marker.lower() in lowered:
            return False, f"bot_wall_marker:{marker}"

    word_count = len(cleaned.split())
    if not is_structured_advisory and word_count < min_word_count:
        return False, f"too_short:{word_count}_words"

    return True, "ok"


def _parse_published_at(raw_value: Any) -> datetime:
    if isinstance(raw_value, datetime):
        return raw_value if raw_value.tzinfo else raw_value.replace(tzinfo=timezone.utc)
    if isinstance(raw_value, str) and raw_value.strip():
        try:
            dt = date_parser.parse(raw_value)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            pass
    return datetime.now(timezone.utc)


def load_feed_config(config_path: Path) -> dict[str, Any]:
    with config_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def fetch_manual_url(
    url: str,
    *,
    settings: dict[str, Any],
    language: str = "en",
) -> RawArticleCandidate | None:
    """Safely fetch and extract a single manually submitted HTTPS URL."""
    timeout = int(settings.get("request_timeout_seconds", 15))
    max_bytes = int(settings.get("max_response_bytes", 5 * 1024 * 1024))
    min_words = int(settings.get("min_word_count", 150))
    bot_markers = list(settings.get("bot_wall_markers", []))

    try:
        final_url, body = safe_fetch_bytes(url, timeout_seconds=timeout, max_bytes=max_bytes)
        html = body.decode("utf-8", errors="replace")
        extracted = trafilatura.extract(
            html,
            url=final_url,
            include_comments=False,
            include_tables=True,
            no_fallback=False,
        )
        metadata = trafilatura.extract_metadata(html, default_url=final_url)
        title = (metadata.title if metadata and metadata.title else urlparse(final_url).hostname or final_url).strip()
        source_name = (metadata.sitename if metadata and metadata.sitename else urlparse(final_url).hostname or "Manual URL").strip()
        published = _parse_published_at(metadata.date if metadata else None)

        ok, reason = passes_quality_gate(
            extracted or "",
            min_word_count=min_words,
            bot_wall_markers=bot_markers,
        )
        if not ok:
            logger.warning("Quality gate rejected manual URL %s (%s)", final_url, reason)
            return None

        cves = extract_cves(title, extracted or "")
        return RawArticleCandidate(
            url=final_url,
            title=title,
            source_name=source_name,
            language=language if language in {"en", "fr"} else "en",
            published_at=published,
            text=extracted or "",
            cve_ids=cves,
        )
    except Exception as exc:
        logger.warning("Failed to ingest manual URL %s: %s", url, exc)
        return None


def _ingest_cisa_kev(
    feed: dict[str, Any],
    *,
    settings: dict[str, Any],
    since: datetime,
    existing_urls: set[str],
) -> list[RawArticleCandidate]:
    """Ingest recent entries from CISA's Known Exploited Vulnerabilities JSON catalog."""
    timeout = int(settings.get("request_timeout_seconds", 15))
    max_bytes = int(settings.get("max_response_bytes", 5 * 1024 * 1024))
    candidates: list[RawArticleCandidate] = []

    try:
        _, payload = safe_fetch_bytes(feed["url"], timeout_seconds=timeout, max_bytes=max_bytes)
        data = json.loads(payload.decode("utf-8", errors="replace"))
    except Exception as exc:
        logger.error("Feed failure [%s]: %s", feed["name"], exc)
        return candidates

    for vuln in data.get("vulnerabilities", []):
        date_added = _parse_published_at(vuln.get("dateAdded"))
        if date_added < since:
            continue

        cve_id = str(vuln.get("cveID", "")).strip().upper()
        if not cve_id:
            continue

        # Stable HTTPS canonical URL per KEV entry
        entry_url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}"
        if entry_url in existing_urls:
            continue

        vendor = vuln.get("vendorProject", "Unknown vendor")
        product = vuln.get("product", "Unknown product")
        vuln_name = vuln.get("vulnerabilityName", cve_id)
        short_desc = vuln.get("shortDescription", "")
        required_action = vuln.get("requiredAction", "")
        due_date = vuln.get("dueDate", "Not disclosed in sources")
        ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")
        notes = vuln.get("notes", "")

        advisory_text = (
            f"CISA Known Exploited Vulnerability Advisory: {cve_id} — {vuln_name}.\n"
            f"Vendor: {vendor}. Product: {product}.\n"
            f"Description: {short_desc}\n"
            f"Required Remediation: {required_action} (Federal due date: {due_date}).\n"
            f"Known Ransomware Campaign Use: {ransomware}.\n"
            f"Reference Notes: {notes}"
        )

        candidates.append(
            RawArticleCandidate(
                url=entry_url,
                title=f"CISA KEV: {cve_id} — {vendor} {product} ({vuln_name})",
                source_name=feed["name"],
                language="en",
                published_at=date_added,
                text=advisory_text,
                cve_ids=extract_cves(cve_id, advisory_text),
                is_structured_advisory=True,
            )
        )

    logger.info("Feed [%s]: collected %d new KEV entries", feed["name"], len(candidates))
    return candidates


def _ingest_rss_feed(
    feed: dict[str, Any],
    *,
    settings: dict[str, Any],
    since: datetime,
    existing_urls: set[str],
    max_items_per_feed: int = 12,
) -> list[RawArticleCandidate]:
    """Fetch an RSS/Atom feed, extract full article text in memory, and apply quality gate."""
    timeout = int(settings.get("request_timeout_seconds", 15))
    max_bytes = int(settings.get("max_response_bytes", 5 * 1024 * 1024))
    min_words = int(settings.get("min_word_count", 150))
    bot_markers = list(settings.get("bot_wall_markers", []))
    candidates: list[RawArticleCandidate] = []

    try:
        _, xml_bytes = safe_fetch_bytes(feed["url"], timeout_seconds=timeout, max_bytes=max_bytes)
        parsed = feedparser.parse(xml_bytes)
    except Exception as exc:
        logger.error("Feed failure [%s]: %s", feed["name"], exc)
        return candidates

    accepted = 0
    rejected = 0

    for entry in parsed.entries[:max_items_per_feed]:
        link = str(entry.get("link", "")).strip()
        # Early dedup on feed link before paying network cost to fetch full HTML
        if not link or link in existing_urls:
            continue

        published = _parse_published_at(
            entry.get("published") or entry.get("updated") or entry.get("created")
        )
        if published < since:
            continue

        title = str(entry.get("title", "")).strip() or link
        try:
            final_url, html_bytes = safe_fetch_bytes(link, timeout_seconds=timeout, max_bytes=max_bytes)
            # Re-check after redirects (e.g., FeedBurner -> canonical article URL)
            if final_url in existing_urls:
                continue
            html = html_bytes.decode("utf-8", errors="replace")
            extracted = trafilatura.extract(
                html,
                url=final_url,
                include_comments=False,
                include_tables=True,
                no_fallback=False,
            )
        except Exception as exc:
            rejected += 1
            logger.warning("Article fetch failed [%s] %s: %s", feed["name"], link, exc)
            continue

        ok, reason = passes_quality_gate(
            extracted or "",
            min_word_count=min_words,
            bot_wall_markers=bot_markers,
        )
        if not ok:
            rejected += 1
            logger.warning("Quality gate rejected [%s] %s (%s)", feed["name"], final_url, reason)
            continue

        candidates.append(
            RawArticleCandidate(
                url=final_url,
                title=title,
                source_name=feed["name"],
                language=feed.get("language", "en"),
                published_at=published,
                text=extracted or "",
                cve_ids=extract_cves(title, extracted or ""),
            )
        )
        existing_urls.add(final_url)
        accepted += 1

    logger.info(
        "Feed [%s]: accepted=%d rejected=%d",
        feed["name"],
        accepted,
        rejected,
    )
    return candidates


def ingest_all_feeds(
    config: dict[str, Any],
    *,
    existing_urls: set[str],
    lookback_hours: int = 36,
) -> list[RawArticleCandidate]:
    """Ingest all enabled feeds from config/feeds.json within the lookback window."""
    settings = config.get("settings", {})
    since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    all_candidates: list[RawArticleCandidate] = []

    for feed in config.get("feeds", []):
        if not feed.get("enabled", True):
            continue
        feed_type = feed.get("type", "rss")
        if feed_type == "json_kev":
            all_candidates.extend(
                _ingest_cisa_kev(feed, settings=settings, since=since, existing_urls=existing_urls)
            )
        else:
            all_candidates.extend(
                _ingest_rss_feed(feed, settings=settings, since=since, existing_urls=existing_urls)
            )

    return all_candidates
