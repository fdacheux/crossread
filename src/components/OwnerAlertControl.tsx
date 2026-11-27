import { useMemo, useState, type FormEvent, type ReactNode } from 'react';
import { Bell, BellOff, Plus, Settings2, X } from 'lucide-react';
import feedConfig from '../../config/feeds.json';
import type { ClusterBriefing } from '../types/briefing';

interface OwnerAlertControlProps {
  briefings: ClusterBriefing[];
  headerContent: ReactNode;
}

function matchKeywords(cluster: ClusterBriefing, keywords: string[]): string[] {
  const haystack = [
    cluster.headline,
    cluster.tldr,
    ...cluster.cve_ids,
    ...cluster.affected_tech,
    ...cluster.entities,
  ]
    .join(' ')
    .toLowerCase();

  return keywords.filter((kw) => {
    const cleaned = kw.trim().toLowerCase();
    return cleaned.length >= 2 && haystack.includes(cleaned);
  });
}

/**
 * Interactive preview of the Phase 2 Owner-Only Email Alerts control.
 *
 * Note: State here is local to the browser preview so you can test toggling
 * alerts On/Off, switching between Owner and Public Visitor views, and previewing
 * digest matches. The production Supabase Auth + RLS implementation lives in
 * `/web/src/components/OwnerAlertControl.tsx`.
 */
export function OwnerAlertControl({
  briefings,
  headerContent,
}: OwnerAlertControlProps) {
  // Default OFF so the dashboard can be read passively without receiving email alerts
  const [ownerSignedIn, setOwnerSignedIn] = useState(true);
  const [alertsEnabled, setAlertsEnabled] = useState(false);
  const [includeCritical, setIncludeCritical] = useState(true);
  const [includeWatchlist, setIncludeWatchlist] = useState(true);
  const [keywords, setKeywords] = useState<string[]>(
    feedConfig.watchlist_keywords.slice(0, 12)
  );
  const [newKeyword, setNewKeyword] = useState('');
  const [panelOpen, setPanelOpen] = useState(false);

  const digestMatches = useMemo(() => {
    return briefings
      .map((briefing) => {
        const isCritical = briefing.severity === 'Critical';
        const matchedKeywords = includeWatchlist ? matchKeywords(briefing, keywords) : [];
        const included = (includeCritical && isCritical) || matchedKeywords.length > 0;
        return included ? { briefing, matchedKeywords } : null;
      })
      .filter(
        (entry): entry is { briefing: ClusterBriefing; matchedKeywords: string[] } =>
          entry !== null
      );
  }, [briefings, includeCritical, includeWatchlist, keywords]);

  const handleAddKeyword = (e: FormEvent) => {
    e.preventDefault();
    const cleaned = newKeyword.trim();
    if (cleaned.length < 2) return;
    if (keywords.some((k) => k.toLowerCase() === cleaned.toLowerCase())) {
      setNewKeyword('');
      return;
    }
    setKeywords((prev) => [...prev, cleaned]);
    setNewKeyword('');
  };

  const handleRemoveKeyword = (target: string) => {
    setKeywords((prev) => prev.filter((k) => k !== target));
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        {headerContent}
        {/* Compact, easily accessible toggle row */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
        {ownerSignedIn ? (
          <>
            <button
              type="button"
              onClick={() => setAlertsEnabled((prev) => !prev)}
              aria-pressed={alertsEnabled}
              className={`inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium rounded-md border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                alertsEnabled
                  ? 'bg-slate-900 text-white border-slate-900 hover:bg-slate-800'
                  : 'bg-white text-slate-700 border-slate-200 hover:border-slate-400 hover:text-slate-950'
              }`}
            >
              {alertsEnabled ? (
                <Bell className="w-3.5 h-3.5" aria-hidden="true" />
              ) : (
                <BellOff className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
              )}
              <span>{alertsEnabled ? 'Email alerts: On' : 'Email alerts: Off'}</span>
            </button>

            <button
              type="button"
              onClick={() => setPanelOpen((prev) => !prev)}
              aria-expanded={panelOpen}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-md hover:border-slate-400 hover:text-slate-950 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Settings2 className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Alert settings</span>
            </button>
          </>
        ) : (
          <button
            type="button"
            onClick={() => setPanelOpen((prev) => !prev)}
            aria-expanded={panelOpen}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-md hover:border-slate-400 hover:text-slate-950 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <BellOff className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
            <span>Owner alerts</span>
          </button>
        )}
        </div>
      </div>

      {/* Collapsible owner-only alert drawer */}
      {panelOpen && (
        <section
          aria-label="Owner email alert configuration"
          className="bg-white border border-slate-200 rounded-lg p-6 space-y-5"
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-100">
            <div>
              <h2
                className="text-sm font-semibold text-slate-950"
                style={{ fontFamily: 'var(--font-display)' }}
              >
                Owner-Only Daily Email Alerts (Resend)
              </h2>
              <p className="text-xs text-slate-600 mt-0.5">
                Protected by Supabase Auth and owner-only Row Level Security. Off by default so the
                dashboard can be read passively.
              </p>
            </div>

            <div className="flex items-center gap-2 self-start sm:self-auto">
              <div
                role="group"
                aria-label="Preview access role"
                className="inline-flex items-center p-0.5 bg-slate-100 rounded-md text-xs"
              >
                <button
                  type="button"
                  onClick={() => setOwnerSignedIn(true)}
                  aria-pressed={ownerSignedIn}
                  className={`px-2.5 py-1 rounded font-medium transition-colors whitespace-nowrap cursor-pointer ${
                    ownerSignedIn ? 'bg-white text-slate-950 shadow-xs' : 'text-slate-600'
                  }`}
                >
                  Owner view
                </button>
                <button
                  type="button"
                  onClick={() => setOwnerSignedIn(false)}
                  aria-pressed={!ownerSignedIn}
                  className={`px-2.5 py-1 rounded font-medium transition-colors whitespace-nowrap cursor-pointer ${
                    !ownerSignedIn ? 'bg-white text-slate-950 shadow-xs' : 'text-slate-600'
                  }`}
                >
                  Public visitor
                </button>
              </div>

              <button
                type="button"
                onClick={() => setPanelOpen(false)}
                aria-label="Close alert settings"
                className="p-1.5 text-slate-400 hover:text-slate-700 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {!ownerSignedIn ? (
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-sm">
              <p className="text-slate-600 max-w-xl leading-relaxed">
                Public visitors read briefings freely with zero email prompts or database write
                access. Only an account listed in{' '}
                <code className="font-mono text-xs text-slate-800">public.admin_users</code> can
                toggle alerts or view delivery logs.
              </p>
              <button
                type="button"
                onClick={() => setOwnerSignedIn(true)}
                className="px-4 py-2 text-xs font-medium bg-slate-900 text-white rounded-md hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 self-start sm:self-auto cursor-pointer"
              >
                Switch back to Owner view
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Left column: trigger rules & watchlist */}
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-5 text-xs text-slate-700">
                  <label className="inline-flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={includeCritical}
                      onChange={(e) => setIncludeCritical(e.target.checked)}
                      className="rounded border-slate-300 text-slate-900"
                    />
                    <span>Include Critical briefings</span>
                  </label>

                  <label className="inline-flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={includeWatchlist}
                      onChange={(e) => setIncludeWatchlist(e.target.checked)}
                      className="rounded border-slate-300 text-slate-900"
                    />
                    <span>Include Watchlist matches</span>
                  </label>
                </div>

                <form onSubmit={handleAddKeyword} className="flex gap-2">
                  <input
                    type="text"
                    value={newKeyword}
                    onChange={(e) => setNewKeyword(e.target.value)}
                    placeholder="Add watchlist keyword (e.g., Kubernetes, DORA)"
                    aria-label="Add watchlist keyword"
                    className="flex-1 px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-md text-slate-900 placeholder:text-slate-400 focus:outline-none focus:bg-white focus:border-slate-900"
                  />
                  <button
                    type="submit"
                    disabled={newKeyword.trim().length < 2}
                    className="inline-flex items-center gap-1 px-3 py-2 text-xs font-medium bg-slate-900 text-white rounded-md hover:bg-slate-800 disabled:opacity-40 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Plus className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Add</span>
                  </button>
                </form>

                <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-slate-700">
                  {keywords.map((kw) => (
                    <span key={kw} className="inline-flex items-center gap-1 font-mono">
                      <span>{kw}</span>
                      <button
                        type="button"
                        onClick={() => handleRemoveKeyword(kw)}
                        aria-label={`Remove ${kw}`}
                        className="text-slate-400 hover:text-red-700 cursor-pointer"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </span>
                  ))}
                </div>
              </div>

              {/* Right column: Live preview of today's bundled Resend digest */}
              <div className="bg-slate-50 border border-slate-200 rounded-md p-4 space-y-3">
                <div className="flex items-center justify-between gap-2 text-xs">
                  <span className="font-semibold text-slate-900">
                    Next 07:00 CET Bundled Digest Preview
                  </span>
                  <span
                    className={`font-mono tabular-nums ${
                      alertsEnabled ? 'text-slate-900 font-medium' : 'text-slate-500'
                    }`}
                  >
                    {alertsEnabled
                      ? `${digestMatches.length} queued`
                      : 'Paused (alerts off)'}
                  </span>
                </div>

                {!alertsEnabled ? (
                  <p className="text-xs text-slate-600 leading-relaxed">
                    Daily email alerts are turned off. Briefings will continue to appear on the
                    dashboard. No email is sent while alerts are off.
                  </p>
                ) : digestMatches.length === 0 ? (
                  <p className="text-xs text-slate-600 leading-relaxed">
                    No briefings currently match your active Critical or Watchlist rules. No email
                    will be sent.
                  </p>
                ) : (
                  <ul className="divide-y divide-slate-200 text-xs">
                    {digestMatches.map(({ briefing, matchedKeywords }) => (
                      <li key={briefing.id} className="py-2 first:pt-0 last:pb-0 space-y-0.5">
                        <div className="text-slate-500">
                          <span
                            className={
                              briefing.severity === 'Critical'
                                ? 'text-red-700 font-semibold'
                                : 'text-amber-700 font-medium'
                            }
                          >
                            {briefing.severity}
                          </span>
                          {matchedKeywords.length > 0 && (
                            <>
                              <span aria-hidden="true"> · </span>
                              <span className="font-mono text-slate-700">
                                {matchedKeywords.join(', ')}
                              </span>
                            </>
                          )}
                        </div>
                        <p className="text-slate-900 font-medium leading-snug">
                          {briefing.headline}
                        </p>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
