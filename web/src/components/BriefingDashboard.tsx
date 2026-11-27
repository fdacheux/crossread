'use client';

import { useMemo, useState } from 'react';
import { BriefingCard } from '@/components/BriefingCard';
import { FilterBar } from '@/components/FilterBar';
import { OwnerAlertControl } from '@/components/OwnerAlertControl';
import type { Category, ClusterBriefing, Severity } from '@/types/briefing';

interface BriefingDashboardProps {
  initialBriefings: ClusterBriefing[];
  loadError: string | null;
}

export function BriefingDashboard({
  initialBriefings,
  loadError,
}: BriefingDashboardProps) {
  const [selectedCategory, setSelectedCategory] = useState<Category | 'All'>('All');
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'All'>('All');
  const [searchQuery, setSearchQuery] = useState('');
  const [legalOpen, setLegalOpen] = useState(false);

  /**
   * Client-side filtering across the ISR-loaded briefing window (latest 60 clusters).
   * If daily volume grows beyond ~200 active clusters, move search to a Supabase
   * RPC or PostgreSQL full-text index rather than scanning client memory.
   */
  const filteredBriefings = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return initialBriefings.filter((item) => {
      if (selectedCategory !== 'All' && !item.categories.includes(selectedCategory)) {
        return false;
      }
      if (selectedSeverity !== 'All' && item.severity !== selectedSeverity) {
        return false;
      }
      if (!q) return true;

      // Concatenate searchable fields so CVE IDs, affected tech, regulations, and source names match
      const haystack = [
        item.headline,
        item.tldr,
        item.technical_details,
        item.remediations,
        ...item.cve_ids,
        ...item.affected_tech,
        ...item.entities,
        ...(item.articles ?? []).map((a) => a.source_name),
      ]
        .join(' ')
        .toLowerCase();

      return haystack.includes(q);
    });
  }, [initialBriefings, selectedCategory, selectedSeverity, searchQuery]);

  const criticalCount = useMemo(
    () => initialBriefings.filter((b) => b.severity === 'Critical').length,
    [initialBriefings]
  );

  const resetFilters = () => {
    setSelectedCategory('All');
    setSelectedSeverity('All');
    setSearchQuery('');
  };

  return (
    <div className="min-h-screen flex flex-col">
      {/* 3-Zone Top Bar */}
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between gap-8">
          <a
            href="/"
            className="text-lg font-bold tracking-tight text-slate-950 whitespace-nowrap shrink-0"
            style={{ fontFamily: 'var(--font-display)' }}
          >
            CrossRead
          </a>

          <nav
            aria-label="Quick filters"
            className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600"
          >
            <button
              type="button"
              onClick={resetFilters}
              className="hover:text-slate-950 transition-colors whitespace-nowrap shrink-0"
            >
              All Briefings
            </button>
            <button
              type="button"
              onClick={() => {
                setSelectedCategory('Web/AppSec');
                setSelectedSeverity('All');
              }}
              className="hover:text-slate-950 transition-colors whitespace-nowrap shrink-0"
            >
              Web/AppSec
            </button>
            <button
              type="button"
              onClick={() => {
                setSelectedCategory('CVEs');
                setSelectedSeverity('All');
              }}
              className="hover:text-slate-950 transition-colors whitespace-nowrap shrink-0"
            >
              CVEs
            </button>
            <button
              type="button"
              onClick={() => {
                setSelectedCategory('Regulations');
                setSelectedSeverity('All');
              }}
              className="hover:text-slate-950 transition-colors whitespace-nowrap shrink-0"
            >
              Regulations
            </button>
          </nav>

          <button
            type="button"
            onClick={() =>
              setSelectedSeverity((prev) => (prev === 'Critical' ? 'All' : 'Critical'))
            }
            className="px-4 py-2 text-xs font-medium rounded-md bg-slate-900 text-white hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 tabular-nums"
          >
            {selectedSeverity === 'Critical'
              ? 'Show All Severities'
              : `Critical (${criticalCount})`}
          </button>
        </div>
      </header>

      <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-10 space-y-8">
        <OwnerAlertControl
          headerContent={
            <div className="space-y-2">
              <h1
                className="text-3xl font-bold tracking-tight text-slate-950"
                style={{ fontFamily: 'var(--font-display)', textWrap: 'balance' }}
              >
                Bilingual Cybersecurity Briefings
              </h1>
              <p className="text-sm text-slate-600 max-w-2xl leading-relaxed">
                Unified English briefings cross-read from English and French advisories, clustered
                by exact CVE and normalized entity match, and synthesized strictly from structured
                fact sheets.
              </p>
              <p
                role="note"
                className="text-xs text-slate-500 max-w-3xl leading-relaxed"
              >
                <strong className="font-medium text-slate-700">
                  AI-synthesized briefings (unreviewed):
                </strong>{' '}
                Summaries, severity labels, and remediation notes are generated by AI from
                structured source fact sheets (EU AI Act Art. 50 notice). Always verify CVEs and
                patches against the original linked advisories before applying production changes.
              </p>
            </div>
          }
        />

        <FilterBar
          selectedCategory={selectedCategory}
          onSelectCategory={setSelectedCategory}
          selectedSeverity={selectedSeverity}
          onSelectSeverity={setSelectedSeverity}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          totalCount={initialBriefings.length}
          filteredCount={filteredBriefings.length}
          onResetFilters={resetFilters}
        />

        {loadError && (
          <div
            role="alert"
            className="bg-white border border-red-200 rounded-lg p-5 text-sm text-red-800"
          >
            {loadError}
          </div>
        )}

        {!loadError && filteredBriefings.length === 0 ? (
          <div className="bg-white border border-slate-200 rounded-lg p-12 text-center space-y-3">
            <p className="text-sm font-medium text-slate-900">No briefings match these filters</p>
            <p className="text-xs text-slate-500">
              Try broadening your category, severity, or search query, or wait for the next 07:00
              CET pipeline run.
            </p>
            <button
              type="button"
              onClick={resetFilters}
              className="mt-2 px-4 py-2 text-xs font-medium bg-slate-900 text-white rounded-md hover:bg-slate-800 transition-colors"
            >
              Reset filters
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            {filteredBriefings.map((briefing) => (
              <BriefingCard key={briefing.id} briefing={briefing} />
            ))}
          </div>
        )}
      </main>

      <footer className="border-t border-slate-200 bg-white mt-12">
        <div className="max-w-6xl mx-auto px-6 py-5 space-y-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs text-slate-500">
            <span>CrossRead — Public Read-Only Cybersecurity Briefing Desk</span>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
              <span>AI-synthesized daily at 07:00 CET</span>
              <button
                type="button"
                onClick={() => setLegalOpen((prev) => !prev)}
                aria-expanded={legalOpen}
                className="text-slate-700 hover:text-slate-950 underline decoration-slate-300 underline-offset-3 cursor-pointer"
              >
                {legalOpen ? 'Hide Privacy & AI Notice' : 'Privacy, RGPD & AI Notice'}
              </button>
            </div>
          </div>

          {legalOpen && (
            <section
              aria-label="Privacy, RGPD, and EU AI Act disclosures"
              className="border-t border-slate-100 pt-4 grid grid-cols-1 md:grid-cols-3 gap-6 text-xs text-slate-600 leading-relaxed"
            >
              <div>
                <h2 className="font-semibold text-slate-900 mb-1">
                  RGPD &amp; Zero-Tracking Privacy
                </h2>
                <p>
                  Public visitors browse anonymously with zero analytics, advertising trackers, or
                  third-party font requests. Strictly necessary authentication cookies are set only
                  if the authorized owner signs in to manage email alerts. Alert delivery logs are
                  purged after 90 days; historical briefings and audit logs follow a 12-month
                  retention limit.
                </p>
              </div>
              <div>
                <h2 className="font-semibold text-slate-900 mb-1">
                  Sub-Processors &amp; Data Rights
                </h2>
                <p>
                  Infrastructure relies on Vercel (web hosting), Supabase (PostgreSQL &amp; owner
                  Auth), GitHub Actions (scheduled batch pipeline), Google Gemini API (structured
                  synthesis), and Resend (opt-in owner digest). Raw article text is discarded in
                  memory immediately after Fact-Sheet extraction. EU residents may exercise RGPD
                  access/erasure rights or lodge a complaint with the CNIL.
                </p>
              </div>
              <div>
                <h2 className="font-semibold text-slate-900 mb-1">
                  EU AI Act Transparency (Art. 50)
                </h2>
                <p>
                  Briefings are automatically synthesized by General-Purpose AI models without
                  prior human editorial review. Severity ratings and remediation summaries are
                  informational only; verify all CVE identifiers, affected versions, and patches
                  against the primary CERT-FR, CISA, CNIL, or vendor links provided on every card.
                </p>
              </div>
            </section>
          )}
        </div>
      </footer>
    </div>
  );
}
