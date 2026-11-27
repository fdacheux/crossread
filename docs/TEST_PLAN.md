# QA Test Plan & Automation Strategy — Bilingual Cybersecurity Cross-Reader

**Role:** Senior QA Test Manager  
**Methodology:** Behavior-Driven Development (BDD / Gherkin) + Risk-Based Test Automation  
**Target Stack:** Python Pipeline (GitHub Actions + LiteLLM) · Supabase PostgreSQL (RLS) · Next.js Dashboard (Vercel) · Resend Owner Alerts

---

## 1. Test Scope & Risk Matrix

Because this application ingests untrusted cybersecurity articles (frequently containing live XSS/SQLi payloads and PoCs) under **$0 free-tier constraints**, testing is prioritized by blast radius:

| Priority | Domain | Critical Failure Modes |
| :--- | :--- | :--- |
| **P0 — Critical** | **Security & Access Control** | SSRF via manual URLs or 302 redirects, prompt injection breaking data delimiters, frontend XSS or `javascript:` links, public/non-owner write access bypassing Supabase RLS |
| **P0 — Critical** | **Fact-Sheet & Grounding Integrity** | Raw scraped prose stored in PostgreSQL, re-synthesis from previous summary instead of all stored Fact Sheets, hallucinated remediations/versions instead of `"Not disclosed in sources"` |
| **P1 — High** | **Bilingual Clustering Precision** | Merging articles with *disjoint* explicit CVEs, failing to merge EN + FR coverage of the same CVE, merging unrelated non-CVE stories sharing zero normalized entities |
| **P1 — High** | **Free-Tier Resilience & Alerts** | Unhandled `429 RESOURCE_EXHAUSTED` crashing the daily run, Cloudflare/bot-wall HTML polluting clusters, Resend emailing while owner toggle is Off or duplicating alerts within 24h |
| **P2 — Medium** | **Dashboard UX & Readability** | Broken category/severity/search filters, stale ISR window confusion, broken source links, cross-browser styling bugs (e.g., duplicate search clear icons) |

---

## 2. Executable BDD Feature Suite

All Python BDD scenarios live in `/pipeline/tests/features/` and are executed via `pytest-bdd`:

1. **`pipeline/tests/features/ingest_security.feature`**
   - Blocks non-HTTPS URLs, loopback/private/IPv6/cloud-metadata IP literals, embedded credentials, and 302 redirects pointing to internal targets (`SSRFBlockedError`).
   - Enforces the Pre-LLM Quality Gate (< 150 words, bot-wall markers like Cloudflare / "verify you are human").
   - Exempts structured CISA KEV advisories from the 150-word floor while preserving regex CVE extraction.
2. **`pipeline/tests/features/clustering_and_triage.feature`**
   - Escapes embedded `</untrusted_article>` prompt-injection tags and preserves authoritative canonical `source_url` / `source_name`.
   - Deterministically merges bilingual EN + FR articles sharing an exact CVE-ID.
   - Strictly forbids merging articles with different explicit CVE sets.
   - Enforces the 72-hour normalized entity gate on non-CVE articles, rejecting hallucinated LLM merges with zero entity overlap.
   - Recovers from `429 RESOURCE_EXHAUSTED` with exponential backoff retries.
3. **`pipeline/tests/features/alerts_and_synthesis.feature`**
   - Verifies `"Not disclosed in sources"` fallback and DB CHECK category sanitization during cluster synthesis.
   - Verifies passive reading mode (`alert_settings.enabled = false`) skips Resend and logs `skipped_disabled`.
   - Verifies bundled single daily email when enabled, escaping HTML payloads, matching token boundaries (`Next.js` vs `CRA`), and suppressing duplicate alerts within 24 hours.

Frontend E2E regression tests live in `/web/tests/dashboard.spec.ts` (Playwright):
- Category, severity, and CVE/keyword filtering + reset.
- Single custom search clear button (no duplicate WebKit native cross).
- Deep-Dive expand/collapse, safe plain-text rendering of `<script>` strings, and omission of `javascript:` links.
- Public visitor read-only mode vs. owner-only alert controls.

---

## 3. Automation Strategy (TNR & Beyond)

### A. 100% Automated — Hard PR/Push Gate ($0, Deterministic, Zero Live LLM/Network Calls)
- **Python Unit & Security TNR (`pytest-bdd`)**: SSRF rules, redirect-hop validation, quality gate, CVE/entity clustering invariants, prompt-injection escaping, 429 retry handler, synthesis sanitization, Resend gating & HTML escaping.
- **Database & RLS Contract TNR (`supabase test db` / `pgTAP`)**: Verify `anon` is `SELECT`-only on `clusters`/`articles`, `anon` and non-owner `authenticated` cannot read/update `alert_settings` or `watchlists`, verified owner can toggle `alert_settings.enabled`, Fact-Sheet CHECK constraints enforce all 7 keys, and `sync_cluster_source_count` trigger stays accurate.
- **Frontend Functional & Security E2E TNR (`Playwright`)**: Core filtering, Deep-Dive toggle, XSS literal-text rendering, HTTPS-only links, and Owner Alerts UI states.
- **Static & Security Gates**: `tsc --noEmit`, `next build`, `py_compile` / `ruff`, `npm audit` / `pip-audit`, and secret scanning (`gitleaks`).

### B. Partially Automated — Scheduled / Pre-Release Only (NOT on Every PR)
- **LLM Golden-Dataset Evaluation (`pytest -m llm_eval` or `promptfoo`)**: Run only when modifying prompts or swapping LiteLLM models (Gemini → Mistral/Groq) against 10–15 frozen EN/FR articles (including prompt-injection traps and undisclosed-remediation cases). Avoids burning Gemini Free Tier RPD/RPM on every commit.
- **Live Feed Health Canary (Weekly cron)**: Checks all 14 endpoints in `config/feeds.json` for HTTP 200 and valid RSS/JSON parsing without blocking code merges on third-party outages.
- **Lighthouse Accessibility & Performance Check**: Run on release PRs targeting `main` (target WCAG AA >= 95, LCP < 2.5s).

### C. Manual / Exploratory QA (Do NOT Automate)
- **Editorial & Bilingual Synthesis Nuance**: Human review of EN/FR synthesis tone, CNIL/NIS2 legal accuracy, and meaningfulness of `source_diffs`.
- **Cross-Browser Visual Polish**: 5-minute Safari/Chrome/mobile layout sanity check before major UI releases.
- **Real Resend Inbox Rendering**: Inspect 1 live email in Gmail/Apple Mail/Outlook (light & dark mode + spam placement) whenever modifying the HTML digest template.
- **Adversarial Exploratory Testing**: Periodic testing of novel prompt-injection strings and redirect edge cases.

---

## 4. CI/CD Cadence & Go / No-Go Criteria

| Trigger | Suites Executed | Blocks Release? | Cost |
| :--- | :--- | :--- | :--- |
| **Every PR & Push to `main`** | Static checks + `pytest-bdd` Python TNR + Next.js build + Playwright E2E TNR | **Yes (Hard Gate)** | $0 |
| **Prompt or Model Change PR** | Above + Golden LLM Eval (`--dry-run` against frozen EN/FR fixtures) | **Yes** | $0 (Free Tier) |
| **Weekly Schedule** | Live Feed Health Canary (`config/feeds.json`) | No (alert/issue only) | $0 |
| **Major Release Sign-off** | Manual review of 1 `--dry-run` bilingual output + 1 Resend inbox check + mobile check | **Yes** | $0 |

---

## 5. Running the Automated TNR Locally

```bash
# 1. Python Pipeline BDD TNR (0 live API calls)
pip install -r pipeline/requirements.txt -r pipeline/requirements-dev.txt
pytest

# 2. Next.js Frontend E2E TNR (Playwright)
cd web
npm install
npx playwright install chromium
npm run test:e2e
```
