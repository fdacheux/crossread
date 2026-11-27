/**
 * Static architecture & deployment runbook views rendered in the preview tabs.
 * Keep `DEPLOY_STEPS` synchronized with `.github/workflows/daily_briefing.yml`,
 * `pipeline/.env.example`, and `web/.env.example` when adding new secrets.
 */
import { useState } from 'react';
import { Check, Copy } from 'lucide-react';

const PIPELINE_STAGES = [
  {
    step: '01. Safe Ingestion & Quality Gate',
    module: 'pipeline/ingest.py',
    summary:
      'Fetches RSS/Atom feeds, CISA KEV JSON, and manual HTTPS URLs while blocking non-HTTPS schemes and private/loopback/metadata IP ranges across every redirect hop. Extracts text in memory with trafilatura and rejects articles under 150 words or containing bot-wall markers.',
  },
  {
    step: '02. Triage & Fact-Sheet Extraction',
    module: 'pipeline/triage.py',
    summary:
      'Wraps untrusted article text inside explicit <untrusted_article> delimiters and calls LiteLLM (gemini/gemini-3.5-flash-lite) to filter for Web/AppSec and major cross-cutting events. Stores only compact structured JSON Fact Sheets and immediately discards raw prose from memory.',
  },
  {
    step: '03. CVE-First, Entity-Gated Clustering',
    module: 'pipeline/cluster.py',
    summary:
      'Deterministically merges articles sharing exact CVE-IDs via regex while forbidding merges across conflicting CVEs. Remaining non-CVE articles are grouped against active 72-hour clusters only when they share a normalized entity.',
  },
  {
    step: '04. Fact-Sheet-Only Synthesis',
    module: 'pipeline/synthesize.py',
    summary:
      'Whenever an article joins a cluster, re-fetches all stored JSON Fact Sheets for that cluster and invokes LiteLLM (gemini/gemini-3.8-flash) to produce one unified English briefing—explicitly emitting "Not disclosed in sources" for missing fields.',
  },
];

const DEPLOY_STEPS = [
  {
    id: 'supabase',
    title: '01. Provision Supabase & Apply Phase 1 Schema',
    description:
      'Create a Free Tier project in Supabase, open the SQL Editor, and run supabase/migrations/0001_phase1_schema.sql. This creates the clusters and articles tables, indexes, triggers, and strict SELECT-only Row Level Security for the anon role.',
    snippet: `# Copy Project URL, anon key (for Vercel), and service_role key (for GitHub Actions ONLY)
# File to run in Supabase SQL Editor:
supabase/migrations/0001_phase1_schema.sql`,
  },
  {
    id: 'github',
    title: '02. Configure GitHub Actions Secrets',
    description:
      'Push this repository to GitHub and add the three required secrets under Settings -> Secrets and variables -> Actions. The daily_briefing.yml workflow runs automatically at 07:00 CET and supports manual URLs via Run workflow.',
    snippet: `SUPABASE_URL=https://YOUR_PROJECT_REF.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
GEMINI_API_KEY=your_gemini_api_key

# Optional Repository Variables to swap providers via LiteLLM:
TRIAGE_MODEL=gemini/gemini-3.5-flash-lite
SYNTHESIS_MODEL=gemini/gemini-3.8-flash
LLM_THROTTLE_SECONDS=4.5`,
  },
  {
    id: 'vercel',
    title: '03. Deploy Read-Only Next.js Dashboard on Vercel Hobby',
    description:
      'Import the GitHub repository in Vercel, set the Root Directory to web, and configure only the public read-only Supabase keys. The dashboard never holds write keys or LLM credentials.',
    snippet: `# Vercel Root Directory: web
NEXT_PUBLIC_SUPABASE_URL=https://YOUR_PROJECT_REF.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_public_anon_key`,
  },
  {
    id: 'alerts',
    title: '04. Enable Owner-Only Daily Email Alerts (Optional Phase 2)',
    description:
      'Run supabase/migrations/0002_phase2_owner_alerts.sql in Supabase, register your owner email in public.admin_users, and add your Resend secrets in GitHub Actions. Alerts default to Off until you toggle them On in the dashboard.',
    snippet: `-- 1. Run supabase/migrations/0002_phase2_owner_alerts.sql, then register yourself:
INSERT INTO public.admin_users (email) VALUES ('you@example.com');

# 2. Add optional GitHub Actions Secrets & Variables:
RESEND_API_KEY=re_xxxxxxxxx
ALERT_RECIPIENT_EMAIL=you@example.com
ALERT_FROM_EMAIL=CrossRead Alerts <onboarding@resend.dev>
DASHBOARD_URL=https://your-app.vercel.app`,
  },
];

export function PipelineView() {
  return (
    <div className="space-y-8">
      <div className="space-y-1.5">
        <h1
          className="text-3xl font-bold tracking-tight text-slate-950"
          style={{ fontFamily: 'var(--font-display)', textWrap: 'balance' }}
        >
          Phase 1 Pipeline & Security Architecture
        </h1>
        <p className="text-sm text-slate-600 max-w-2xl leading-relaxed">
          All outbound scraping and LLM inference run inside an ephemeral GitHub Actions container
          using the <code className="font-mono text-xs text-slate-800">service_role</code> key,
          while the public Next.js frontend only performs read-only queries under Row Level Security.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {PIPELINE_STAGES.map((stage) => (
          <div
            key={stage.step}
            className="bg-white border border-slate-200 rounded-lg p-6 space-y-2.5"
          >
            <div className="flex items-baseline justify-between gap-4">
              <h2
                className="text-base font-semibold text-slate-950"
                style={{ fontFamily: 'var(--font-display)' }}
              >
                {stage.step}
              </h2>
              <span className="font-mono text-xs text-slate-500 whitespace-nowrap shrink-0">
                {stage.module}
              </span>
            </div>
            <p className="text-sm text-slate-600 leading-relaxed">{stage.summary}</p>
          </div>
        ))}
      </div>

      <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
        <h2
          className="text-base font-semibold text-slate-950"
          style={{ fontFamily: 'var(--font-display)' }}
        >
          Verified Engineering Safeguards
        </h2>
        <dl className="grid grid-cols-1 md:grid-cols-3 gap-6 text-sm">
          <div className="space-y-1">
            <dt className="font-medium text-slate-900">Strict Read/Write Split</dt>
            <dd className="text-slate-600 leading-relaxed">
              Supabase RLS revokes all write permissions from public keys. Public traffic cannot
              mutate records or trigger LLM API calls.
            </dd>
          </div>
          <div className="space-y-1">
            <dt className="font-medium text-slate-900">Safe Untrusted Handling</dt>
            <dd className="text-slate-600 leading-relaxed">
              Manual URLs validate HTTPS and public DNS resolution on every redirect hop; article
              text is delimited before LLM calls and escaped in React.
            </dd>
          </div>
          <div className="space-y-1">
            <dt className="font-medium text-slate-900">Free-Tier Resilience</dt>
            <dd className="text-slate-600 leading-relaxed">
              LiteLLM calls enforce sequential RPM throttling and exponential backoff on 429
              rate-limit errors, staying within $0 quotas.
            </dd>
          </div>
        </dl>
      </div>
    </div>
  );
}

export function DeployView() {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopy = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      window.setTimeout(() => setCopiedId((curr) => (curr === id ? null : curr)), 1800);
    } catch {
      setCopiedId(null);
    }
  };

  return (
    <div className="space-y-8">
      <div className="space-y-1.5">
        <h1
          className="text-3xl font-bold tracking-tight text-slate-950"
          style={{ fontFamily: 'var(--font-display)', textWrap: 'balance' }}
        >
          $0 Production Deployment Checklist
        </h1>
        <p className="text-sm text-slate-600 max-w-2xl leading-relaxed">
          Your repository contains the complete Phase 1 production files: Supabase SQL migration,
          Python pipeline + GitHub Actions workflow, and the Next.js App Router dashboard under{' '}
          <code className="font-mono text-xs text-slate-800">/web</code>.
        </p>
      </div>

      <div className="space-y-4">
        {DEPLOY_STEPS.map((step) => (
          <section
            key={step.id}
            className="bg-white border border-slate-200 rounded-lg p-6 space-y-4"
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <h2
                className="text-base font-semibold text-slate-950"
                style={{ fontFamily: 'var(--font-display)' }}
              >
                {step.title}
              </h2>
              <button
                type="button"
                onClick={() => handleCopy(step.id, step.snippet)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors self-start sm:self-auto whitespace-nowrap shrink-0 cursor-pointer"
              >
                {copiedId === step.id ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-700" aria-hidden="true" />
                    <span>Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Copy snippet</span>
                  </>
                )}
              </button>
            </div>
            <p className="text-sm text-slate-600 leading-relaxed max-w-[75ch]">
              {step.description}
            </p>
            <pre className="bg-slate-50 border border-slate-200 rounded-md p-4 font-mono text-xs text-slate-800 overflow-x-auto leading-relaxed">
              {step.snippet}
            </pre>
          </section>
        ))}
      </div>
    </div>
  );
}
