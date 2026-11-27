/**
 * Lightweight offline Supabase PostgREST mock server for Playwright E2E TNR.
 * Returns deterministic bilingual briefing fixtures (including XSS and unsafe
 * URL edge cases) so CI runs with zero live Supabase keys or internet traffic.
 */
import http from 'node:http';

const PORT = Number(process.env.MOCK_SUPABASE_PORT || 4100);

const MOCK_CLUSTERS = [
  {
    id: 'e2e-clu-1',
    created_at: '2026-11-21T07:00:00Z',
    updated_at: '2026-11-22T06:14:00Z',
    source_count: 2,
    headline: 'Active Nginx HTTP/3 Header Smuggling (CVE-2026-41892)',
    tldr: 'CERT-FR and CISA KEV confirm active exploitation against edge reverse proxies.',
    severity: 'Critical',
    categories: ['Web/AppSec', 'CVEs'],
    cve_ids: ['CVE-2026-41892'],
    affected_tech: ['Nginx', 'HTTP/3'],
    entities: ['Nginx', 'CERT-FR', 'CISA'],
    technical_details: 'Payload example from advisory: <script>window.__xssFired = true</script>',
    remediations: 'Upgrade to Nginx 1.27.5 immediately.',
    source_diffs: 'CERT-FR highlights French targets; CISA KEV sets a 7-day federal deadline.',
    articles: [
      {
        id: 'e2e-art-1',
        url: 'https://www.cert.ssi.gouv.fr/alerte/',
        title: 'Alerte CERT-FR Nginx',
        source_name: 'CERT-FR Alertes',
        language: 'fr',
        published_at: '2026-11-21T16:40:00Z',
        fact_sheet: {
          cve_ids: ['CVE-2026-41892'],
          affected_versions: ['Nginx < 1.27.5'],
          affected_tech: ['Nginx'],
          key_claims: ['Actively exploited'],
          remediations: ['Upgrade to 1.27.5'],
          source_url: 'https://www.cert.ssi.gouv.fr/alerte/',
          source_name: 'CERT-FR Alertes',
        },
      },
      {
        id: 'e2e-art-2',
        // Deliberately unsafe scheme to verify BriefingCard drops it before rendering
        url: 'javascript:alert(1)',
        title: 'Malicious Scheme Source',
        source_name: 'Unsafe Source',
        language: 'en',
        published_at: '2026-11-21T18:00:00Z',
        fact_sheet: {
          cve_ids: ['CVE-2026-41892'],
          affected_versions: [],
          affected_tech: ['Nginx'],
          key_claims: [],
          remediations: [],
          source_url: 'javascript:alert(1)',
          source_name: 'Unsafe Source',
        },
      },
    ],
  },
  {
    id: 'e2e-clu-2',
    created_at: '2026-11-21T08:00:00Z',
    updated_at: '2026-11-22T06:05:00Z',
    source_count: 1,
    headline: 'CNIL Issues €4.2M GDPR Fine Over Analytics SDK',
    tldr: 'CNIL sanctioned a SaaS vendor for collecting tokens prior to user consent.',
    severity: 'High',
    categories: ['Regulations'],
    cve_ids: [],
    affected_tech: ['JavaScript SDK'],
    entities: ['CNIL', 'GDPR'],
    technical_details: 'Not disclosed in sources',
    remediations: 'Gate third-party telemetry scripts behind verified consent.',
    source_diffs: 'Single source reported so far.',
    articles: [
      {
        id: 'e2e-art-3',
        url: 'https://www.cnil.fr/fr/actualites',
        title: 'Sanction CNIL SDK',
        source_name: 'CNIL Actualités',
        language: 'fr',
        published_at: '2026-11-21T08:00:00Z',
        fact_sheet: {
          cve_ids: [],
          affected_versions: [],
          affected_tech: ['JavaScript SDK'],
          key_claims: ['€4.2M fine under GDPR'],
          remediations: ['Gate scripts behind consent'],
          source_url: 'https://www.cnil.fr/fr/actualites',
          source_name: 'CNIL Actualités',
        },
      },
    ],
  },
];

const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');
  if (req.url && req.url.startsWith('/rest/v1/clusters')) {
    res.writeHead(200);
    res.end(JSON.stringify(MOCK_CLUSTERS));
    return;
  }
  // Default empty JSON array for auth/settings probes in public visitor mode
  res.writeHead(200);
  res.end(JSON.stringify([]));
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Mock Supabase listening on http://127.0.0.1:${PORT}`);
});
