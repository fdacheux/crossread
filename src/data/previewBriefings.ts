import type { ClusterBriefing } from '../types/briefing';

/**
 * Representative preview clusters structured identically to the Supabase
 * `clusters` + `articles` join used by `/web/src/lib/supabase.ts`.
 * Demonstrates bilingual EN/FR cross-reading, CVE-first matching, entity-gated
 * grouping, Fact-Sheet-only synthesis, and explicit "Not disclosed in sources" handling.
 */
export const PREVIEW_BRIEFINGS: ClusterBriefing[] = [
  {
    id: 'clu-2026-001',
    created_at: '2026-11-21T07:02:00Z',
    updated_at: '2026-11-22T06:14:00Z',
    source_count: 3,
    headline:
      'Active Exploitation of Nginx HTTP/3 Header Smuggling and Memory Disclosure Flaw (CVE-2026-41892)',
    tldr:
      'CERT-FR, CISA KEV, and The Hacker News report active in-the-wild exploitation of a critical HTTP/3 header parsing flaw in Nginx edge proxies. Unauthenticated attackers can craft malformed QUIC header frames to bypass upstream ACLs and read adjacent worker memory. Emergency patches are available across mainline and stable branches.',
    severity: 'Critical',
    categories: ['Web/AppSec', 'CVEs', 'Threats'],
    cve_ids: ['CVE-2026-41892'],
    affected_tech: ['Nginx', 'HTTP/3', 'QUIC', 'Reverse Proxy'],
    entities: ['Nginx', 'CERT-FR', 'CISA', 'HTTP/3'],
    technical_details:
      'An out-of-bounds read and request-boundary desynchronization occurs inside the ngx_http_v3_parse_headers routine when dynamic QPACK table references arrive split across zero-length QUIC frames. Exploitation requires HTTP/3 (listen ... quic) to be enabled and does not require prior authentication.',
    remediations:
      'Upgrade immediately to Nginx 1.27.5 (mainline) or 1.26.4 (stable). If immediate patching is not feasible, disable QUIC/HTTP/3 listeners on internet-facing virtual hosts and enforce strict upstream header normalization. CISA mandates federal remediation within 7 days.',
    source_diffs:
      'CERT-FR Alert highlights targeted exploitation against French public-sector and hosting reverse proxies and provides an ANSSI detection checklist. CISA KEV adds the CVE to the federal catalog with an accelerated 7-day remediation deadline. The Hacker News adds observed scanning telemetry showing automated exploit probes.',
    articles: [
      {
        id: 'art-101',
        url: 'https://www.cert.ssi.gouv.fr/alerte/',
        title: 'CERTFR-2026-ALE-019 : Vulnérabilité critique activement exploitée dans Nginx HTTP/3',
        source_name: 'CERT-FR Alertes',
        language: 'fr',
        published_at: '2026-11-21T16:40:00Z',
        fact_sheet: {
          cve_ids: ['CVE-2026-41892'],
          affected_versions: ['Nginx 1.25.0 through 1.26.3', 'Nginx 1.27.0 through 1.27.4'],
          affected_tech: ['Nginx', 'HTTP/3', 'QUIC'],
          key_claims: [
            'Actively exploited against internet-facing reverse proxies in France.',
            'Allows ACL bypass and worker memory disclosure without authentication when HTTP/3 is active.',
          ],
          remediations: [
            'Apply Nginx 1.26.4 or 1.27.5 immediately.',
            'Temporarily disable QUIC listeners if patching is delayed.',
          ],
          source_url: 'https://www.cert.ssi.gouv.fr/alerte/',
          source_name: 'CERT-FR Alertes',
        },
      },
      {
        id: 'art-102',
        url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        title: 'CISA KEV: CVE-2026-41892 — Nginx HTTP/3 Header Smuggling Vulnerability',
        source_name: 'CISA KEV Catalog',
        language: 'en',
        published_at: '2026-11-21T20:15:00Z',
        fact_sheet: {
          cve_ids: ['CVE-2026-41892'],
          affected_versions: ['Nginx prior to 1.26.4 / 1.27.5'],
          affected_tech: ['Nginx', 'HTTP/3'],
          key_claims: [
            'Confirmed active exploitation in the wild; added to CISA KEV catalog.',
            'Ransomware campaign use currently marked as Unknown.',
          ],
          remediations: [
            'Apply vendor patches per FCEB deadline within 7 days or discontinue HTTP/3 exposure.',
          ],
          source_url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
          source_name: 'CISA KEV Catalog',
        },
      },
      {
        id: 'art-103',
        url: 'https://thehackernews.com/',
        title: 'Active Scans Target Critical Nginx HTTP/3 Parsing Bug (CVE-2026-41892)',
        source_name: 'The Hacker News',
        language: 'en',
        published_at: '2026-11-22T05:30:00Z',
        fact_sheet: {
          cve_ids: ['CVE-2026-41892'],
          affected_versions: ['Nginx 1.25.x – 1.27.4 with QUIC enabled'],
          affected_tech: ['Nginx', 'QUIC', 'Reverse Proxy'],
          key_claims: [
            'Mass scanning detected targeting QPACK header frame parsing on UDP/443.',
            'Bug occurs in ngx_http_v3_parse_headers during zero-length QUIC frame splitting.',
          ],
          remediations: [
            'Upgrade to Nginx 1.26.4 or 1.27.5 and audit proxy logs for anomalous QPACK resets.',
          ],
          source_url: 'https://thehackernews.com/',
          source_name: 'The Hacker News',
        },
      },
    ],
  },
  {
    id: 'clu-2026-002',
    created_at: '2026-11-21T11:20:00Z',
    updated_at: '2026-11-22T06:11:00Z',
    source_count: 2,
    headline:
      'Next.js & OIDC Middleware Cache-Key Confusion Enables Cross-Tenant Session Leakage (CVE-2026-39104)',
    tldr:
      'PortSwigger Research and Snyk detail a high-severity authorization bypass affecting Next.js applications using custom OIDC middleware with edge response caching. Attackers can manipulate internal routing headers to serve authenticated API responses to unauthenticated callers.',
    severity: 'Critical',
    categories: ['Web/AppSec', 'CVEs'],
    cve_ids: ['CVE-2026-39104'],
    affected_tech: ['Next.js', 'OIDC', 'OAuth', 'Edge Middleware'],
    entities: ['Next.js', 'Vercel', 'OIDC', 'PortSwigger', 'Snyk'],
    technical_details:
      'When self-hosted Next.js deployments sit behind a CDN that caches responses without keying on custom middleware authorization flags, supplying a crafted x-middleware-rewrite header causes downstream route handlers to skip OIDC token validation and return cached user payloads.',
    remediations:
      'Upgrade Next.js to 15.2.4 or later. Strip untrusted x-middleware-* headers at the reverse proxy/CDN edge and ensure authenticated routes emit Cache-Control: private, no-store.',
    source_diffs:
      'PortSwigger Research provides the full HTTP request smuggling chain and cache-key analysis. Snyk Security Blog adds affected package version ranges and automated lockfile scanning guidance.',
    articles: [
      {
        id: 'art-201',
        url: 'https://portswigger.net/research',
        title: 'Breaking Edge Middleware Isolation: Header Confusion in Modern SSR Routers',
        source_name: 'PortSwigger Research',
        language: 'en',
        published_at: '2026-11-21T10:55:00Z',
        fact_sheet: {
          cve_ids: ['CVE-2026-39104'],
          affected_versions: ['Next.js 14.2.0 – 15.2.3 (self-hosted with external CDN)'],
          affected_tech: ['Next.js', 'OIDC', 'Edge Middleware'],
          key_claims: [
            'Crafted x-middleware-rewrite headers can bypass OIDC middleware checks behind external CDNs.',
            'Allows cross-tenant response leakage when Vary headers omit authorization context.',
          ],
          remediations: [
            'Strip x-middleware-* headers at the CDN edge.',
            'Enforce Cache-Control: private, no-store on authenticated endpoints.',
          ],
          source_url: 'https://portswigger.net/research',
          source_name: 'PortSwigger Research',
        },
      },
      {
        id: 'art-202',
        url: 'https://snyk.io/blog/',
        title: 'Mitigating CVE-2026-39104 in Next.js Middleware Deployments',
        source_name: 'Snyk Security Blog',
        language: 'en',
        published_at: '2026-11-21T17:10:00Z',
        fact_sheet: {
          cve_ids: ['CVE-2026-39104'],
          affected_versions: ['next >= 14.2.0 < 15.2.4'],
          affected_tech: ['Next.js', 'OAuth', 'OIDC'],
          key_claims: [
            'Fixed in Next.js 15.2.4 with internal signed middleware header verification.',
            'Applications hosted with default managed edge protections were automatically shielded.',
          ],
          remediations: [
            'Upgrade next package to >= 15.2.4 and verify lockfiles.',
          ],
          source_url: 'https://snyk.io/blog/',
          source_name: 'Snyk Security Blog',
        },
      },
    ],
  },
  {
    id: 'clu-2026-003',
    created_at: '2026-11-21T08:15:00Z',
    updated_at: '2026-11-22T06:08:00Z',
    source_count: 2,
    headline:
      'CNIL Fines European SaaS Analytics Provider €4.2M Over Unauthorized Telemetry SDK & Weak API Access Controls',
    tldr:
      'France’s data protection authority (CNIL) issued a €4.2 million GDPR fine after finding that a widely embedded web analytics SDK collected session tokens without user consent and exposed customer exports via misconfigured API authorization. The ruling sets explicit security expectations for third-party JavaScript embeds.',
    severity: 'High',
    categories: ['Regulations', 'Web/AppSec'],
    cve_ids: [],
    affected_tech: ['JavaScript SDK', 'REST API', 'Browser Telemetry'],
    entities: ['CNIL', 'GDPR', 'RGPD'],
    technical_details:
      'CNIL technical auditors observed that the embedded client script captured URL query parameters containing OAuth authorization codes and transmitted them prior to consent confirmation. Separately, the vendor’s export endpoint lacked object-level authorization checks, violating GDPR Article 32 security obligations.',
    remediations:
      'Audit all third-party client-side scripts via Content Security Policy (CSP), strip sensitive tokens from URL query parameters, block telemetry initialization until explicit consent is recorded, and enforce server-side object-level authorization checks on data export APIs.',
    source_diffs:
      'CNIL Actualités publishes the official sanction summary citing GDPR Articles 6, 13, and 32. Le Monde Informatique adds industry context noting that CNIL plans follow-up sweeps targeting SaaS SDKs in Q1.',
    articles: [
      {
        id: 'art-301',
        url: 'https://www.cnil.fr/fr/actualites',
        title: 'Sanction de 4,2 millions d’euros pour collecte non consentie via SDK web et défaut de sécurité API',
        source_name: 'CNIL Actualités',
        language: 'fr',
        published_at: '2026-11-21T08:00:00Z',
        fact_sheet: {
          cve_ids: [],
          affected_versions: [],
          affected_tech: ['JavaScript SDK', 'REST API'],
          key_claims: [
            'CNIL imposed a €4.2M fine under GDPR Articles 6, 13, and 32.',
            'Embedded analytics script collected URL query parameters containing OAuth tokens before user consent.',
            'Export API lacked object-level authorization checks.',
          ],
          remediations: [
            'Gate third-party telemetry initialization behind verified consent.',
            'Enforce strict server-side authorization on export endpoints.',
          ],
          source_url: 'https://www.cnil.fr/fr/actualites',
          source_name: 'CNIL Actualités',
        },
      },
      {
        id: 'art-302',
        url: 'https://www.lemondeinformatique.fr/securite-informatique-3.html',
        title: 'RGPD : la CNIL durcit le ton sur les SDK tiers et la sécurité des API SaaS',
        source_name: 'Le Monde Informatique — Sécurité',
        language: 'fr',
        published_at: '2026-11-21T14:20:00Z',
        fact_sheet: {
          cve_ids: [],
          affected_versions: [],
          affected_tech: ['JavaScript SDK', 'Browser Telemetry'],
          key_claims: [
            'CNIL signaled additional compliance audits focused on third-party web SDKs in early next year.',
            'Security teams are urged to restrict script origins with CSP and remove secrets from URLs.',
          ],
          remediations: [
            'Audit third-party scripts with Content Security Policy (CSP) and avoid passing tokens in URL query strings.',
          ],
          source_url: 'https://www.lemondeinformatique.fr/securite-informatique-3.html',
          source_name: 'Le Monde Informatique — Sécurité',
        },
      },
    ],
  },
  {
    id: 'clu-2026-004',
    created_at: '2026-11-21T15:00:00Z',
    updated_at: '2026-11-22T06:05:00Z',
    source_count: 2,
    headline:
      'ANSSI Publishes Operational NIS2 Incident-Reporting Thresholds for French Essential and Important Entities',
    tldr:
      'French authorities released updated operational guidance clarifying the 24-hour early warning and 72-hour incident notification triggers under France’s NIS2 transposition. Organizations operating cloud, managed security, and SaaS platforms face tightened logging and supply-chain notification timelines.',
    severity: 'Medium',
    categories: ['Regulations'],
    cve_ids: [],
    affected_tech: ['Cloud Platforms', 'Managed Services', 'SIEM'],
    entities: ['NIS2', 'ANSSI', 'CERT-FR'],
    technical_details:
      'The guidance defines quantitative disruption and unauthorized-access thresholds that trigger mandatory 24-hour early warnings to ANSSI, followed by a 72-hour technical assessment and 1-month final root-cause report. Affected entities must maintain tamper-evident authentication and proxy logs.',
    remediations:
      'Verify entity classification under French NIS2 scope, integrate ANSSI’s 24h/72h escalation SLAs into incident response playbooks, and ensure web/API access logs are retained centrally.',
    source_diffs:
      'CERT-FR Avis summarizes the technical log-retention and notification workflow. Le Monde Informatique highlights compliance timelines and registration deadlines for mid-sized French tech providers.',
    articles: [
      {
        id: 'art-401',
        url: 'https://www.cert.ssi.gouv.fr/avis/',
        title: 'NIS2 : précisions opérationnelles sur les seuils de notification d’incident à 24h et 72h',
        source_name: 'CERT-FR Avis de sécurité',
        language: 'fr',
        published_at: '2026-11-21T14:50:00Z',
        fact_sheet: {
          cve_ids: [],
          affected_versions: [],
          affected_tech: ['Cloud Platforms', 'SIEM'],
          key_claims: [
            'Defines 24-hour early warning and 72-hour incident assessment thresholds under French NIS2 transposition.',
            'Requires tamper-evident authentication and reverse-proxy audit logging.',
          ],
          remediations: [
            'Update IR playbooks for 24h/72h ANSSI notifications and centralize authentication/proxy logs.',
          ],
          source_url: 'https://www.cert.ssi.gouv.fr/avis/',
          source_name: 'CERT-FR Avis de sécurité',
        },
      },
      {
        id: 'art-402',
        url: 'https://www.lemondeinformatique.fr/securite-informatique-3.html',
        title: 'Directive NIS2 en France : calendrier d’enregistrement et obligations pour les éditeurs SaaS',
        source_name: 'Le Monde Informatique — Sécurité',
        language: 'fr',
        published_at: '2026-11-21T18:10:00Z',
        fact_sheet: {
          cve_ids: [],
          affected_versions: [],
          affected_tech: ['Managed Services', 'Cloud Platforms'],
          key_claims: [
            'Clarifies registration obligations for mid-sized French SaaS and managed service providers under NIS2.',
          ],
          remediations: [
            'Confirm Essential vs. Important entity classification and designate an ANSSI reporting contact.',
          ],
          source_url: 'https://www.lemondeinformatique.fr/securite-informatique-3.html',
          source_name: 'Le Monde Informatique — Sécurité',
        },
      },
    ],
  },
  {
    id: 'clu-2026-005',
    created_at: '2026-11-22T02:30:00Z',
    updated_at: '2026-11-22T06:02:00Z',
    source_count: 1,
    headline:
      'Forensic Analysis Uncovers Steganographic Loader Targeting CI/CD Build Runners via Compromised npm Postinstall Hooks',
    tldr:
      'ZATAZ reports an ongoing supply-chain intrusion targeting European software teams through typosquatted npm utility packages that execute in CI/CD build containers. The payload harvests short-lived cloud deployment tokens from process environment variables before exfiltrating them over HTTPS.',
    severity: 'High',
    categories: ['Forensics', 'Threats', 'Web/AppSec'],
    cve_ids: [],
    affected_tech: ['Node.js', 'npm', 'GitHub Actions', 'CI/CD'],
    entities: ['npm', 'Node.js', 'ZATAZ'],
    technical_details:
      'Malicious postinstall scripts decode a second-stage JavaScript loader embedded in PNG metadata chunks and dump process.env secrets when CI environment flags are detected. The initial package-maintainer compromise vector is Not disclosed in sources.',
    remediations:
      'Pin exact dependency versions via lockfiles, run npm ci --ignore-scripts in untrusted build stages, restrict CI runner outbound egress, and rotate any cloud or registry tokens exposed in affected workflows.',
    source_diffs: 'Single source reported so far.',
    articles: [
      {
        id: 'art-501',
        url: 'https://www.zataz.com/',
        title: 'Analyse forensique : des paquets npm piégés ciblent les runners CI/CD européens',
        source_name: 'ZATAZ',
        language: 'fr',
        published_at: '2026-11-22T02:15:00Z',
        fact_sheet: {
          cve_ids: [],
          affected_versions: ['Not disclosed in sources'],
          affected_tech: ['Node.js', 'npm', 'CI/CD'],
          key_claims: [
            'Typosquatted npm packages execute postinstall loaders inside CI/CD containers.',
            'Extracts short-lived deployment tokens from process environment variables.',
            'Initial maintainer compromise vector not disclosed.',
          ],
          remediations: [
            'Use lockfile pinning and npm ci --ignore-scripts where possible.',
            'Restrict CI egress and rotate exposed workflow secrets.',
          ],
          source_url: 'https://www.zataz.com/',
          source_name: 'ZATAZ',
        },
      },
    ],
  },
  {
    id: 'clu-2026-006',
    created_at: '2026-11-20T18:00:00Z',
    updated_at: '2026-11-21T07:00:00Z',
    source_count: 1,
    headline:
      'Trail of Bits Evaluates Memory-Safe TLS Parsers and Automated Fuzzing Harnesses for Modern Web Gateways',
    tldr:
      'Trail of Bits published a comparative security engineering study evaluating memory-safe TLS and HTTP/2 parser migrations across high-throughput proxies. The research documents recurring state-machine bugs that persist even after eliminating memory corruption.',
    severity: 'Low',
    categories: ['Trends/Research', 'Web/AppSec'],
    cve_ids: [],
    affected_tech: ['TLS', 'HTTP/2', 'Rustls', 'OpenSSL'],
    entities: ['Trail of Bits', 'OpenSSL', 'Rustls'],
    technical_details:
      'Differential fuzzing across multiple TLS and HTTP/2 implementations uncovered non-memory-safety protocol state desynchronizations, including inconsistent handling of renegotiation frames and stream-reset limits. No active exploit or CVE is associated with this research.',
    remediations:
      'Adopt differential protocol fuzzing in CI for custom gateway extensions and enforce strict HTTP/2 rapid-reset rate limits at ingress proxies.',
    source_diffs: 'Single source reported so far.',
    articles: [
      {
        id: 'art-601',
        url: 'https://blog.trailofbits.com/',
        title: 'Beyond Memory Safety: Differential Fuzzing of Modern TLS and HTTP/2 Gateways',
        source_name: 'Trail of Bits Blog',
        language: 'en',
        published_at: '2026-11-20T17:45:00Z',
        fact_sheet: {
          cve_ids: [],
          affected_versions: [],
          affected_tech: ['TLS', 'HTTP/2', 'Rustls', 'OpenSSL'],
          key_claims: [
            'Differential fuzzing catches protocol state-machine mismatches missed by unit tests.',
            'Memory safety eliminates buffer overflows but not request-boundary logic flaws.',
          ],
          remediations: [
            'Integrate differential fuzzing in gateway CI pipelines and configure strict HTTP/2 reset caps.',
          ],
          source_url: 'https://blog.trailofbits.com/',
          source_name: 'Trail of Bits Blog',
        },
      },
    ],
  },
];
