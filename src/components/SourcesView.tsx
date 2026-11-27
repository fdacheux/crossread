import { useState } from 'react';
import { ExternalLink } from 'lucide-react';
import feedConfig from '../../config/feeds.json';
import { isSafeHttpsUrl } from '../types/briefing';

/**
 * Read-only inspector for `/config/feeds.json`.
 * Directly imports the real pipeline configuration JSON so any feed, threshold,
 * or watchlist edit made to `config/feeds.json` is immediately reflected here.
 */
export function SourcesView() {
  const [langFilter, setLangFilter] = useState<'all' | 'en' | 'fr'>('all');

  const feeds = feedConfig.feeds.filter((feed) =>
    langFilter === 'all' ? true : feed.language === langFilter
  );

  const enCount = feedConfig.feeds.filter((f) => f.language === 'en').length;
  const frCount = feedConfig.feeds.filter((f) => f.language === 'fr').length;

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div className="space-y-1.5">
          <h1
            className="text-3xl font-bold tracking-tight text-slate-950"
            style={{ fontFamily: 'var(--font-display)', textWrap: 'balance' }}
          >
            Configured Bilingual Feeds
          </h1>
          <p className="text-sm text-slate-600 max-w-2xl">
            Loaded directly from <code className="font-mono text-xs text-slate-800">config/feeds.json</code>.
            Every feed is fetched daily at 07:00 CET with HTTPS-only validation and pre-LLM quality gating.
          </p>
        </div>

        <div
          role="group"
          aria-label="Filter feeds by language"
          className="inline-flex items-center p-1 bg-slate-200/70 rounded-md gap-0.5 self-start sm:self-auto"
        >
          {(
            [
              { id: 'all', label: `All (${feedConfig.feeds.length})` },
              { id: 'en', label: `English (${enCount})` },
              { id: 'fr', label: `French (${frCount})` },
            ] as const
          ).map((opt) => (
            <button
              key={opt.id}
              type="button"
              onClick={() => setLangFilter(opt.id)}
              aria-pressed={langFilter === opt.id}
              className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 tabular-nums cursor-pointer ${
                langFilter === opt.id
                  ? 'bg-white text-slate-950 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* High-density clean table */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4">Language</th>
                <th className="py-3 px-4">Format</th>
                <th className="py-3 px-4">Focus Areas</th>
                <th className="py-3 px-4 text-right">Endpoint</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {feeds.map((feed) => (
                <tr key={feed.id} className="hover:bg-slate-50/70 transition-colors">
                  <td className="py-3 px-4 font-medium text-slate-900 whitespace-nowrap">
                    {feed.name}
                  </td>
                  <td className="py-3 px-4 font-mono text-xs text-slate-600 uppercase">
                    {feed.language}
                  </td>
                  <td className="py-3 px-4 font-mono text-xs text-slate-600">
                    {feed.type}
                  </td>
                  <td className="py-3 px-4 text-xs text-slate-600">
                    {feed.focus.join(', ')}
                  </td>
                  <td className="py-3 px-4 text-right">
                    {isSafeHttpsUrl(feed.url) ? (
                      <a
                        href={feed.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 font-mono text-xs text-slate-600 hover:text-slate-950 underline decoration-slate-300 underline-offset-2"
                      >
                        <span className="max-w-[260px] truncate">{feed.url.replace('https://', '')}</span>
                        <ExternalLink className="w-3 h-3 shrink-0" aria-hidden="true" />
                      </a>
                    ) : (
                      <span className="font-mono text-xs text-red-700">Blocked non-HTTPS URL</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Quality-gate rules & Watchlist */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
          <h2
            className="text-base font-semibold text-slate-950"
            style={{ fontFamily: 'var(--font-display)' }}
          >
            Ingestion & Quality Gate Settings
          </h2>
          <dl className="divide-y divide-slate-100 text-sm">
            <div className="py-2.5 flex items-center justify-between gap-4">
              <dt className="text-slate-500">Rolling cluster window</dt>
              <dd className="font-mono tabular-nums text-slate-900">
                {feedConfig.settings.rolling_cluster_window_hours} hours
              </dd>
            </div>
            <div className="py-2.5 flex items-center justify-between gap-4">
              <dt className="text-slate-500">Minimum article length</dt>
              <dd className="font-mono tabular-nums text-slate-900">
                {feedConfig.settings.min_word_count} words
              </dd>
            </div>
            <div className="py-2.5 flex items-center justify-between gap-4">
              <dt className="text-slate-500">Max response size</dt>
              <dd className="font-mono tabular-nums text-slate-900">
                {(feedConfig.settings.max_response_bytes / (1024 * 1024)).toFixed(0)} MB
              </dd>
            </div>
            <div className="py-2.5 flex items-center justify-between gap-4">
              <dt className="text-slate-500">HTTP request timeout</dt>
              <dd className="font-mono tabular-nums text-slate-900">
                {feedConfig.settings.request_timeout_seconds} seconds
              </dd>
            </div>
          </dl>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
          <h2
            className="text-base font-semibold text-slate-950"
            style={{ fontFamily: 'var(--font-display)' }}
          >
            Priority Watchlist Keywords ({feedConfig.watchlist_keywords.length})
          </h2>
          <p className="text-sm text-slate-600 leading-relaxed">
            Passed into the triage prompt so Web/AppSec stack advisories and EU/French regulatory updates are prioritized, and ready for Phase 2 email alerts.
          </p>
          <p className="font-mono text-xs text-slate-800 leading-loose">
            {feedConfig.watchlist_keywords.join(' · ')}
          </p>
        </div>
      </div>
    </div>
  );
}
