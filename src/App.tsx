/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useMemo, useState } from "react";
import feedConfig from "../config/feeds.json";
import { BriefingCard } from "./components/BriefingCard";
import { FilterBar, type SortMode } from "./components/FilterBar";
import { OwnerAlertControl } from "./components/OwnerAlertControl";
import { SourcesView } from "./components/SourcesView";
import { PREVIEW_BRIEFINGS } from "./data/previewBriefings";
import type { Category, Severity } from "./types/briefing";

/**
 * Interactive Preview Shell (root Vite app).
 *
 * Maintenance note:
 * - This root app mirrors the production Next.js dashboard in `/web` so the UI
 *   can be reviewed interactively without live Supabase credentials.
 * - The production Next.js dashboard lives in `/web`.
 * - Whenever you change filter/card behavior here, mirror the fix to `/web/src/components/`.
 */
type ActiveTab = "briefings" | "sources";

// Numeric rank used only when the user selects "Highest severity" sorting
const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>("briefings");
  const [selectedCategory, setSelectedCategory] = useState<Category | "All">(
    "All",
  );
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | "All">(
    "All",
  );
  const [searchQuery, setSearchQuery] = useState("");
  const [sortMode, setSortMode] = useState<SortMode>("recent");
  const [legalOpen, setLegalOpen] = useState(false);

  const criticalCount = useMemo(
    () => PREVIEW_BRIEFINGS.filter((b) => b.severity === "Critical").length,
    [],
  );

  const bilingualCount = useMemo(
    () =>
      PREVIEW_BRIEFINGS.filter((b) => {
        const langs = new Set(b.articles.map((a) => a.language));
        return langs.has("en") && langs.has("fr");
      }).length,
    [],
  );

  // Filter and sort briefings in a single memoized pass; never mutate PREVIEW_BRIEFINGS in place
  const filteredBriefings = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    const list = PREVIEW_BRIEFINGS.filter((item) => {
      if (
        selectedCategory !== "All" &&
        !item.categories.includes(selectedCategory)
      ) {
        return false;
      }
      if (selectedSeverity !== "All" && item.severity !== selectedSeverity) {
        return false;
      }
      if (!q) return true;

      // Search across briefing text, structured CVE/tech/entity arrays, and source names
      const haystack = [
        item.headline,
        item.tldr,
        item.technical_details,
        item.remediations,
        ...item.cve_ids,
        ...item.affected_tech,
        ...item.entities,
        ...item.articles.map((a) => a.source_name),
      ]
        .join(" ")
        .toLowerCase();

      return haystack.includes(q);
    });

    // Always tie-break by most recent `updated_at` so ordering stays deterministic
    return [...list].sort((a, b) => {
      if (sortMode === "severity") {
        const diff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
        if (diff !== 0) return diff;
      } else if (sortMode === "sources") {
        const diff = b.source_count - a.source_count;
        if (diff !== 0) return diff;
      }
      return (
        new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime()
      );
    });
  }, [selectedCategory, selectedSeverity, searchQuery, sortMode]);

  const resetFilters = () => {
    setSelectedCategory("All");
    setSelectedSeverity("All");
    setSearchQuery("");
    setSortMode("recent");
  };

  const toggleCriticalAction = () => {
    setActiveTab("briefings");
    setSelectedSeverity((prev) => (prev === "Critical" ? "All" : "Critical"));
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 text-slate-900">
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-20">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between gap-8">
          {/* Zone 1: Single text element wordmark */}
          <button
            type="button"
            onClick={() => {
              setActiveTab("briefings");
              resetFilters();
            }}
            className="text-lg font-bold tracking-tight text-slate-950 whitespace-nowrap shrink-0 cursor-pointer"
            style={{ fontFamily: "var(--font-display)" }}
          >
            CrossRead
          </button>

          {/* Zone 2: clean single-line navigation links */}
          <nav
            aria-label="Primary navigation"
            className="flex items-center gap-6 text-sm font-medium overflow-x-auto"
          >
            {(
              [
                { id: "briefings", label: "Briefings" },
                { id: "sources", label: "Sources" },
              ] as const
            ).map((item) => {
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveTab(item.id)}
                  aria-current={active ? "page" : undefined}
                  className={`py-1 whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                    active
                      ? "text-slate-950 underline decoration-slate-950 decoration-2 underline-offset-8"
                      : "text-slate-600 hover:text-slate-950"
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>

          {/* Zone 3: 1 primary action */}
          <button
            type="button"
            onClick={toggleCriticalAction}
            className="px-4 py-2 text-xs font-medium rounded-md bg-slate-900 text-white hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 tabular-nums cursor-pointer"
          >
            {activeTab === "briefings" && selectedSeverity === "Critical"
              ? "All Severities"
              : `Critical (${criticalCount})`}
          </button>
        </div>
      </header>

      <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-10">
        {activeTab === "briefings" && (
          <div className="space-y-8">
            {/* Editorial heading & easily accessible owner-only email alert toggle */}
            <OwnerAlertControl
              briefings={PREVIEW_BRIEFINGS}
              headerContent={
                <div className="space-y-2">
                  <h1
                    className="text-3xl sm:text-4xl font-bold tracking-tight text-slate-950"
                    style={{
                      fontFamily: "var(--font-display)",
                      textWrap: "balance",
                    }}
                  >
                    Bilingual Cybersecurity Briefings
                  </h1>
                  <p className="text-sm text-slate-600 max-w-2xl leading-relaxed">
                    {" "}
                    Unified English briefings cross-read from English and French
                    advisories, clustered by CVE and normalized entity, and
                    synthesized strictly from structured Fact Sheets.
                  </p>
                  <p
                    role="note"
                    className="text-xs text-slate-500 max-w-3xl leading-relaxed"
                  >
                    <strong className="font-medium text-slate-700">
                      AI-synthesized briefings (unreviewed):
                    </strong>{" "}
                    Summaries and severity ratings are generated by AI from
                    structured source fact sheets (EU AI Act Art. 50 notice).
                    Always verify CVEs and remediations against the original
                    linked advisories.
                  </p>
                </div>
              }
            />

            {/* Clean flat 4-column summary strip (single elevation, hairline dividers) */}
            <dl className="grid grid-cols-2 lg:grid-cols-4 bg-white border border-slate-200 rounded-lg divide-y lg:divide-y-0 lg:divide-x divide-slate-200">
              <div className="p-4">
                <dt className="text-xs text-slate-500">Preview clusters</dt>
                <dd className="mt-1 text-2xl font-semibold text-slate-950 font-mono tabular-nums">
                  {PREVIEW_BRIEFINGS.length}
                </dd>
              </div>
              <div className="p-4">
                <dt className="text-xs text-slate-500">Critical severity</dt>
                <dd className="mt-1 text-2xl font-semibold text-red-700 font-mono tabular-nums">
                  {criticalCount}
                </dd>
              </div>
              <div className="p-4">
                <dt className="text-xs text-slate-500">EN + FR cross-read</dt>
                <dd className="mt-1 text-2xl font-semibold text-slate-950 font-mono tabular-nums">
                  {bilingualCount}
                </dd>
              </div>
              <div className="p-4">
                <dt className="text-xs text-slate-500">Configured feeds</dt>
                <dd className="mt-1 text-2xl font-semibold text-slate-950 font-mono tabular-nums">
                  {feedConfig.feeds.length}
                </dd>
              </div>
            </dl>

            <FilterBar
              selectedCategory={selectedCategory}
              onSelectCategory={setSelectedCategory}
              selectedSeverity={selectedSeverity}
              onSelectSeverity={setSelectedSeverity}
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              sortMode={sortMode}
              onSortChange={setSortMode}
              totalCount={PREVIEW_BRIEFINGS.length}
              filteredCount={filteredBriefings.length}
              onResetFilters={resetFilters}
            />

            {filteredBriefings.length === 0 ? (
              <div className="bg-white border border-slate-200 rounded-lg p-12 text-center space-y-3">
                <p className="text-sm font-medium text-slate-900">
                  No briefings match these filters
                </p>
                <p className="text-xs text-slate-500">
                  Try broadening your category, severity, or keyword search.
                </p>
                <button
                  type="button"
                  onClick={resetFilters}
                  className="mt-2 px-4 py-2 text-xs font-medium bg-slate-900 text-white rounded-md hover:bg-slate-800 transition-colors cursor-pointer"
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
          </div>
        )}

        {activeTab === "sources" && <SourcesView />}
      </main>

      <footer className="border-t border-slate-200 bg-white mt-12">
        <div className="max-w-6xl mx-auto px-6 py-5 space-y-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs text-slate-500">
            <span>CrossRead — Bilingual Cybersecurity Cross-Reader</span>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
              <span>Self-hosted fonts · Zero public tracking cookies</span>
              <button
                type="button"
                onClick={() => setLegalOpen((prev) => !prev)}
                aria-expanded={legalOpen}
                className="text-slate-700 hover:text-slate-950 underline decoration-slate-300 underline-offset-3 cursor-pointer"
              >
                {legalOpen
                  ? "Hide Privacy & AI Notice"
                  : "Privacy, RGPD & AI Notice"}
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
                  Public visitors browse anonymously with zero analytics,
                  advertising trackers, or external font CDN calls. Strictly
                  necessary authentication cookies apply only when the
                  authorized owner signs in to manage alerts. Alert logs purge
                  after 90 days; briefings and admin audit logs follow a
                  12-month retention policy.
                </p>
              </div>
              <div>
                <h2 className="font-semibold text-slate-900 mb-1">
                  Data Rights &amp; Privacy
                </h2>
                <p>
                  Service providers help operate CrossRead and deliver optional
                  email alerts. Information is processed only as needed to
                  provide briefings and alerts. EU residents retain full RGPD
                  rights, including recourse to the CNIL.
                </p>
              </div>
              <div>
                <h2 className="font-semibold text-slate-900 mb-1">
                  EU AI Act Transparency (Art. 50)
                </h2>
                <p>
                  Briefings are synthesized by General-Purpose AI models without
                  prior human editorial review. Always verify CVE identifiers,
                  affected versions, and patches against the primary CERT-FR,
                  CISA, CNIL, or vendor advisories linked on each card.
                </p>
              </div>
            </section>
          )}
        </div>
      </footer>
    </div>
  );
}
