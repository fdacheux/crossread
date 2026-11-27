# Security Summary

- **Reviewed Files:** 24 files across the Python ingestion/LLM pipeline, Supabase SQL migrations, GitHub Actions workflows, Next.js dashboard, Vite preview UI, and automated test suites.
- **Dependency Audit (`bun audit`):** 0 vulnerabilities across 260 checked packages.
- **Issues Resolved:** 6

## Issues Resolved

| # | Severity | Area | Summary of Issue & Fix |
| - | -------- | ---- | ---------------------- |
| 1 | High | `pipeline/ingest.py` | **Incomplete SSRF protection (CGNAT bypass, arbitrary ports, DNS rebinding):** Python's `ip.is_private` allowed Carrier-Grade NAT addresses (`100.64.0.0/10`, including cloud metadata endpoints such as `100.100.100.200`), arbitrary HTTPS ports were accepted, and DNS was resolved twice (once during validation, again during the HTTP request). Updated IP checks to require `ip.is_global`, restricted ports strictly to `443` with a 2,048-char URL cap and IPv6 zone-ID rejection, and pinned each HTTP request and redirect hop to the validated IP using explicit `Host` and TLS `sni_hostname` headers. |
| 2 | High | `pipeline/triage.py`, `pipeline/cluster.py`, `pipeline/synthesize.py` | **First- and second-order prompt injection boundaries:** Untrusted article titles, source names, and URLs were interpolated outside the untrusted-content tags in Stage 1 triage, and Stage 2 clustering/synthesis passed untrusted Fact-Sheet JSON directly into prompts without delimiter isolation. Moved all external metadata inside `wrap_untrusted_text(...)` with length caps and added explicit delimiter-enforcement instructions to both clustering and synthesis system prompts. |
| 3 | High | `supabase/migrations/0002_phase2_owner_alerts.sql` | **Unverified email claim in `public.is_owner()` & unbounded watchlist keywords:** `public.is_owner()` trusted `auth.jwt() ->> 'email'` without checking that the address had been confirmed in `auth.users`, and `watchlists.keyword` had no upper length limit. Updated `public.is_owner()` to verify `auth.users.email_confirmed_at IS NOT NULL` for `auth.uid()` and bounded `watchlists.keyword` to 2–60 trimmed characters. |
| 4 | Medium | `.github/workflows/daily_briefing.yml` | **Workflow expression interpolated directly inside a shell script:** `${{ inputs.dry_run }}` was expanded inline inside a `run:` bash block. Moved the value into an `env:` variable (`DRY_RUN`) and compared `"$DRY_RUN"` safely in bash. |
| 5 | Medium | `web/next.config.ts` | **Missing Content-Security-Policy and HSTS headers:** The standalone Next.js dashboard lacked `Content-Security-Policy` and `Strict-Transport-Security` response headers. Added a restrictive CSP (`default-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`, `base-uri 'self'`, `form-action 'self'`, scoped `connect-src` for Supabase HTTPS endpoints) and HSTS (`max-age=63072000; includeSubDomains; preload`). |
| 6 | Low | `supabase/migrations/0001_phase1_schema.sql`, `pipeline/alerts.py` | **Unbounded Fact-Sheet JSON size/URL scheme & email header hygiene:** Added a 32 KB byte-size ceiling and `^https://` check on `fact_sheet->>'source_url'` in PostgreSQL, and stripped CR/LF characters with basic address validation on `ALERT_RECIPIENT_EMAIL` and `ALERT_FROM_EMAIL` before invoking Resend. |

## Safeguards Verified

| Control | Verification Result |
| ------- | ------------------- |
| **Row-Level Security & Least-Privilege Keys** | `public.articles`, `public.stories`, `public.story_articles`, `public.briefings`, `public.alert_settings`, and `public.watchlists` all enable RLS. Public `anon` read policies only expose published articles/stories/briefings; write access is restricted to `service_role` or the verified owner (`public.is_owner()`). `SUPABASE_SERVICE_ROLE_KEY` and `GEMINI_API_KEY` are never referenced in client-side `web/` or `src/` code. |
| **No Unsafe HTML / Script Execution** | Zero occurrences of `dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`, `document.write`, `eval`, or `shell=True` across `src/`, `web/`, and `pipeline/`. All external article URLs in the UI pass through strict `https:` validation (`toSafeHttpsUrl`) with `rel="noopener noreferrer"`. |
| **LLM Data Minimization & Schema Validation** | Raw article text stays strictly in memory and is discarded after Fact-Sheet extraction. All Gemini outputs are parsed through strict Pydantic models (`FactSheet`, `ArticleGroupingPlan`, `StorySynthesisOutput`) and checked against allowed URLs and CVE sets. |
| **Dependency Health** | `bun audit` reported 0 known vulnerabilities across 260 packages. |

---

## PoC Verification

All checks below were verified defensively against local validation functions and static configuration without targeting any external hosts.

### 1. SSRF Hardening (`pipeline/ingest.py`)
- **Prior Behavior:** `ipaddress.ip_address("100.64.0.1").is_private` and `ipaddress.ip_address("100.100.100.200").is_private` returned `False` in Python 3.12, allowing CGNAT and Alibaba-style cloud metadata IPs past `_is_disallowed_ip()`. Non-standard ports (e.g., `:8443`) were also accepted, and DNS resolution was performed separately from socket connection.
- **Patched Verification:**
  1. `_is_disallowed_ip("100.64.0.1")` and `_is_disallowed_ip("100.100.100.200")` now return `True` via `not ip.is_global`.
  2. `validate_safe_https_url("https://example.com:8443/article")` raises `SSRFBlockedError` (`Blocked non-standard HTTPS port: 8443`).
  3. `safe_fetch_bytes()` connects to `_build_pinned_ip_url(current_url, pinned_ip)` with `headers={"Host": hostname}` and `extensions={"sni_hostname": hostname}`, repeating resolution and pinning on every redirect hop (`follow_redirects=False`).
  4. Added CGNAT and non-standard port cases to `pipeline/tests/features/ingest_security.feature`.

### 2. Prompt Injection Delimiter Isolation (`pipeline/triage.py`, `pipeline/cluster.py`, `pipeline/synthesize.py`)
- **Prior Behavior:** In `triage.py`, `candidate.source_name`, `candidate.url`, and `candidate.title` were interpolated above `<untrusted_article>`, and in `cluster.py` / `synthesize.py`, serialized untrusted JSON payloads were embedded directly in user prompts without closing-tag neutralization.
- **Patched Verification:**
  1. `triage.py` now places truncated `Source Name`, `Source URL`, and `Title` inside `wrap_untrusted_text(..., tag="untrusted_article")`.
  2. `cluster.py` wraps the article list inside `wrap_untrusted_text(..., tag="untrusted_clustering_data")` and `synthesize.py` wraps Fact-Sheets inside `wrap_untrusted_text(..., tag="untrusted_fact_sheets")`.
  3. `wrap_untrusted_text()` neutralizes any embedded `</tag>` sequence so untrusted content cannot break out of the delimiter block.

### 3. Verified Owner Check (`supabase/migrations/0002_phase2_owner_alerts.sql`)
- **Prior Behavior:** `public.is_owner()` compared `auth.jwt() ->> 'email'` against `app_admins.email` without verifying email confirmation.
- **Patched Verification:** `public.is_owner()` now joins `auth.users u` on `u.id = auth.uid()` and requires `u.email_confirmed_at IS NOT NULL AND lower(coalesce(u.email, '')) = a.email`. `watchlists.keyword` now enforces `length(trim(keyword)) BETWEEN 2 AND 60`.

### 4. GitHub Actions Safe Env Binding (`.github/workflows/daily_briefing.yml`)
- **Prior Behavior:** `${{ inputs.dry_run }}` was expanded directly inside a `run:` bash block.
- **Patched Verification:** `DRY_RUN: ${{ inputs.dry_run }}` is now passed via `env:` and checked with `if [ "$DRY_RUN" = "true" ]; then`.

### 5. Dashboard Security Headers (`web/next.config.ts`)
- **Prior Behavior:** Response headers omitted `Content-Security-Policy` and `Strict-Transport-Security`.
- **Patched Verification:** Both headers are configured on `/(.*)`, with `http://127.0.0.1:4100` in `connect-src` restricted strictly to non-production or explicit local mock test environments.

### 6. Database Fact-Sheet Bounds & Email Header Hygiene (`0001_phase1_schema.sql`, `pipeline/alerts.py`)
- **Prior Behavior:** `articles.fact_sheet` lacked a byte-size upper bound and `source_url` scheme check at the DB layer; `alerts.py` passed recipient/sender env strings directly without stripping CR/LF characters.
- **Patched Verification:** `articles_fact_sheet_structure` now enforces `octet_length(fact_sheet::text) <= 32768` and `coalesce(fact_sheet ->> 'source_url', '') ~ '^https://'`, and `alerts.py` sanitizes CR/LF characters and checks for valid email structure before sending via Resend.
