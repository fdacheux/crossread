import { useState } from 'react';
import { ChevronDown, ChevronUp, ExternalLink, FileJson } from 'lucide-react';
import {
  isSafeHttpsUrl,
  type ClusterBriefing,
  type Severity,
} from '../types/briefing';

interface BriefingCardProps {
  briefing: ClusterBriefing;
}

const SEVERITY_TEXT_STYLES: Record<Severity, string> = {
  Critical: 'text-red-700 font-semibold',
  High: 'text-amber-700 font-semibold',
  Medium: 'text-blue-700 font-medium',
  Low: 'text-slate-600 font-medium',
};

function formatUtcTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return (
    new Intl.DateTimeFormat('en-GB', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      timeZone: 'UTC',
    }).format(date) + ' UTC'
  );
}

/**
 * Layered Briefing Card (interactive preview mirror of `/web/src/components/BriefingCard.tsx`).
 *
 * Security invariants:
 * - Never render LLM-synthesized strings with `dangerouslySetInnerHTML`.
 * - Always validate external article links with `isSafeHttpsUrl()` before rendering.
 * - Includes an optional Fact-Sheet JSON inspector so developers can verify
 *   what structured data drove the cluster synthesis.
 */
export function BriefingCard({ briefing }: BriefingCardProps) {
  const [expanded, setExpanded] = useState(false);
  const [showFactSheets, setShowFactSheets] = useState(false);

  // Drop any non-HTTPS source links before rendering external anchors
  const safeArticles = briefing.articles.filter((article) =>
    isSafeHttpsUrl(article.url)
  );
  const languages = Array.from(
    new Set(safeArticles.map((a) => a.language.toUpperCase()))
  ).sort();
  const sourceCount = briefing.source_count || safeArticles.length;

  return (
    <article className="bg-white border border-slate-200 rounded-lg p-6 transition-colors hover:border-slate-300">
      {/* Unboxed quiet 1-line metadata kicker */}
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-slate-500">
        <span className={SEVERITY_TEXT_STYLES[briefing.severity]}>
          {briefing.severity} severity
        </span>
        <span aria-hidden="true">·</span>
        <span className="text-slate-700">{briefing.categories.join(', ')}</span>
        <span aria-hidden="true">·</span>
        <span className="font-mono tabular-nums">
          {sourceCount} {sourceCount === 1 ? 'source' : 'sources'}
          {languages.length > 0 ? ` (${languages.join('/')})` : ''}
        </span>
        <span aria-hidden="true">·</span>
        <time dateTime={briefing.updated_at} className="font-mono tabular-nums">
          {formatUtcTimestamp(briefing.updated_at)}
        </time>
      </div>

      {/* Headline */}
      <h2
        className="mt-2.5 text-xl font-semibold tracking-tight text-slate-950 leading-snug"
        style={{ fontFamily: 'var(--font-display)', textWrap: 'balance' }}
      >
        {briefing.headline}
      </h2>

      {/* TL;DR summary (strictly plain text) */}
      <p className="mt-3 text-[15px] leading-relaxed text-slate-700 max-w-[74ch]">
        {briefing.tldr}
      </p>

      {/* Inline structured identifiers */}
      {(briefing.cve_ids.length > 0 || briefing.affected_tech.length > 0) && (
        <dl className="mt-4 flex flex-wrap gap-x-6 gap-y-1.5 text-xs text-slate-600">
          {briefing.cve_ids.length > 0 && (
            <div className="flex items-baseline gap-2">
              <dt className="text-slate-400 font-medium">CVEs</dt>
              <dd className="font-mono tabular-nums text-slate-800">
                {briefing.cve_ids.join(', ')}
              </dd>
            </div>
          )}
          {briefing.affected_tech.length > 0 && (
            <div className="flex items-baseline gap-2">
              <dt className="text-slate-400 font-medium">Affected</dt>
              <dd className="text-slate-800">{briefing.affected_tech.join(', ')}</dd>
            </div>
          )}
        </dl>
      )}

      {/* Source links & expand toggle */}
      <div className="mt-5 pt-4 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
          <span className="text-slate-400 font-medium">Sources</span>
          {safeArticles.map((article) => (
            <a
              key={article.id}
              href={article.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-slate-700 hover:text-slate-950 underline decoration-slate-300 underline-offset-3 hover:decoration-slate-900 transition-colors"
            >
              <span>{article.source_name}</span>
              <span className="font-mono text-[11px] text-slate-400">
                [{article.language.toUpperCase()}]
              </span>
              <ExternalLink className="w-3 h-3 text-slate-400 shrink-0" aria-hidden="true" />
            </a>
          ))}
        </div>

        <button
          type="button"
          onClick={() => setExpanded((prev) => !prev)}
          aria-expanded={expanded}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-900 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors whitespace-nowrap shrink-0 self-start sm:self-auto cursor-pointer"
        >
          <span>{expanded ? 'Hide deep dive' : 'Show deep dive'}</span>
          {expanded ? (
            <ChevronUp className="w-3.5 h-3.5" aria-hidden="true" />
          ) : (
            <ChevronDown className="w-3.5 h-3.5" aria-hidden="true" />
          )}
        </button>
      </div>

      {/* Expandable Deep-Dive Section */}
      {expanded && (
        <div className="mt-5 pt-5 border-t border-slate-200 space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 text-sm">
            <div>
              <h3 className="text-xs font-semibold text-slate-900 mb-2">
                Technical details
              </h3>
              <p className="text-slate-700 leading-relaxed whitespace-pre-line">
                {briefing.technical_details || 'Not disclosed in sources'}
              </p>
            </div>

            <div>
              <h3 className="text-xs font-semibold text-slate-900 mb-2">
                Remediations
              </h3>
              <p className="text-slate-700 leading-relaxed whitespace-pre-line">
                {briefing.remediations || 'Not disclosed in sources'}
              </p>
            </div>

            <div>
              <h3 className="text-xs font-semibold text-slate-900 mb-2">
                Cross-source differences
              </h3>
              <p className="text-slate-700 leading-relaxed whitespace-pre-line">
                {briefing.source_diffs || 'Single source reported so far.'}
              </p>
            </div>
          </div>

          {/* Fact-Sheet First transparency inspector */}
          <div className="pt-4 border-t border-slate-100">
            <button
              type="button"
              onClick={() => setShowFactSheets((prev) => !prev)}
              aria-expanded={showFactSheets}
              className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-950 transition-colors cursor-pointer"
            >
              <FileJson className="w-3.5 h-3.5" aria-hidden="true" />
              <span>
                {showFactSheets
                  ? 'Hide underlying article Fact Sheets'
                  : `Inspect ${safeArticles.length} stored JSON Fact ${safeArticles.length === 1 ? 'Sheet' : 'Sheets'}`}
              </span>
            </button>

            {showFactSheets && (
              <div className="mt-4 divide-y divide-slate-200 border border-slate-200 rounded-md bg-slate-50">
                {safeArticles.map((article) => (
                  <div key={article.id} className="p-4 space-y-2">
                    <div className="flex flex-wrap items-center gap-x-2 text-xs text-slate-500">
                      <span className="font-semibold text-slate-900">
                        {article.source_name}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono">{article.language.toUpperCase()}</span>
                      <span aria-hidden="true">·</span>
                      <span className="text-slate-600">{article.title}</span>
                    </div>
                    <pre className="text-xs font-mono text-slate-700 overflow-x-auto leading-relaxed">
                      {JSON.stringify(article.fact_sheet, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </article>
  );
}
