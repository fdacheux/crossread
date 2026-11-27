'use client';

import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { Bell, BellOff, LogOut, Plus, Settings2, X } from 'lucide-react';
import { getSupabaseBrowserClient } from '@/lib/supabase-browser';

interface OwnerAlertControlProps {
  headerContent: ReactNode;
}

interface AlertSettings {
  id: number;
  enabled: boolean;
  include_critical: boolean;
  include_watchlist: boolean;
  updated_at: string;
}

interface WatchlistRow {
  id: string;
  keyword: string;
  enabled: boolean;
}

interface AlertLogRow {
  id: string;
  sent_at: string;
  cluster_count: number;
  status: string;
}

/**
 * Owner-only email alert toggle and watchlist editor (Phase 2).
 *
 * How authorization works:
 * - Public visitors never need to sign in and never query `alert_settings`
 *   until they authenticate.
 * - After Supabase Auth sign-in, we probe `alert_settings` (id = 1). If the
 *   signed-in email is NOT in `public.admin_users`, PostgreSQL RLS returns
 *   zero rows (`settingsRow === null`) and the UI stays in read-only mode.
 *
 * Post-deployment debugging guide:
 * - Magic link redirects to localhost or fails? Add your Vercel production URL
 *   under Supabase Dashboard -> Authentication -> URL Configuration -> Redirect URLs.
 * - Owner signed in but sees "not registered in admin_users"? Run:
 *   `INSERT INTO public.admin_users (email) VALUES ('your-email@example.com');`
 */
export function OwnerAlertControl({ headerContent }: OwnerAlertControlProps) {
  const [userEmail, setUserEmail] = useState<string | null>(null);
  const [isOwner, setIsOwner] = useState(false);
  const [settings, setSettings] = useState<AlertSettings | null>(null);
  const [watchlists, setWatchlists] = useState<WatchlistRow[]>([]);
  const [latestLog, setLatestLog] = useState<AlertLogRow | null>(null);

  const [panelOpen, setPanelOpen] = useState(false);
  const [emailInput, setEmailInput] = useState('');
  const [newKeyword, setNewKeyword] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const loadOwnerState = useCallback(async () => {
    const supabase = getSupabaseBrowserClient();
    if (!supabase) return;

    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user?.email) {
      setUserEmail(null);
      setIsOwner(false);
      setSettings(null);
      setWatchlists([]);
      setLatestLog(null);
      return;
    }

    setUserEmail(user.email);

    // Owner-only RLS enforces authorization on alert_settings, watchlists, and alert_logs.
    // Use `maybeSingle()` (not `single()`) so a non-owner returns `data: null` cleanly
    // instead of throwing a PostgREST 406 PGRST116 error.
    const { data: settingsRow, error: settingsErr } = await supabase
      .from('alert_settings')
      .select('id, enabled, include_critical, include_watchlist, updated_at')
      .eq('id', 1)
      .maybeSingle();

    if (settingsErr || !settingsRow) {
      setIsOwner(false);
      setSettings(null);
      return;
    }

    setIsOwner(true);
    setSettings(settingsRow as AlertSettings);

    const [{ data: kwRows }, { data: logRows }] = await Promise.all([
      supabase.from('watchlists').select('id, keyword, enabled').order('keyword'),
      supabase
        .from('alert_logs')
        .select('id, sent_at, cluster_count, status')
        .order('sent_at', { ascending: false })
        .limit(1),
    ]);

    setWatchlists((kwRows ?? []) as WatchlistRow[]);
    setLatestLog((logRows?.[0] as AlertLogRow) ?? null);
  }, []);

  useEffect(() => {
    const supabase = getSupabaseBrowserClient();
    if (!supabase) return;

    void loadOwnerState();
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange(() => {
      void loadOwnerState();
    });

    return () => subscription.unsubscribe();
  }, [loadOwnerState]);

  const handleToggleEnabled = async () => {
    const supabase = getSupabaseBrowserClient();
    if (!supabase || !settings || busy) return;

    const nextEnabled = !settings.enabled;
    setBusy(true);
    setNotice(null);

    const { data, error } = await supabase
      .from('alert_settings')
      .update({ enabled: nextEnabled })
      .eq('id', 1)
      .select('id, enabled, include_critical, include_watchlist, updated_at')
      .single();

    setBusy(false);
    if (error || !data) {
      setNotice('Could not update alert status. Confirm owner permissions.');
      return;
    }
    setSettings(data as AlertSettings);
  };

  const handleUpdateFlag = async (
    field: 'include_critical' | 'include_watchlist',
    value: boolean
  ) => {
    const supabase = getSupabaseBrowserClient();
    if (!supabase || !settings || busy) return;

    setBusy(true);
    const { data, error } = await supabase
      .from('alert_settings')
      .update({ [field]: value })
      .eq('id', 1)
      .select('id, enabled, include_critical, include_watchlist, updated_at')
      .single();

    setBusy(false);
    if (!error && data) {
      setSettings(data as AlertSettings);
    }
  };

  const handleAddKeyword = async (e: FormEvent) => {
    e.preventDefault();
    const supabase = getSupabaseBrowserClient();
    const cleaned = newKeyword.trim();
    if (!supabase || cleaned.length < 2 || busy) return;

    setBusy(true);
    setNotice(null);
    const { data, error } = await supabase
      .from('watchlists')
      .insert({ keyword: cleaned, enabled: true })
      .select('id, keyword, enabled')
      .single();
    setBusy(false);

    if (error || !data) {
      setNotice('Keyword already exists or could not be added.');
      return;
    }
    setWatchlists((prev) =>
      [...prev, data as WatchlistRow].sort((a, b) => a.keyword.localeCompare(b.keyword))
    );
    setNewKeyword('');
  };

  const handleDeleteKeyword = async (id: string) => {
    const supabase = getSupabaseBrowserClient();
    if (!supabase || busy) return;

    setBusy(true);
    const { error } = await supabase.from('watchlists').delete().eq('id', id);
    setBusy(false);
    if (!error) {
      setWatchlists((prev) => prev.filter((item) => item.id !== id));
    }
  };

  const handleMagicLinkSignIn = async (e: FormEvent) => {
    e.preventDefault();
    const supabase = getSupabaseBrowserClient();
    const email = emailInput.trim().toLowerCase();
    if (!supabase || !email || busy) return;

    setBusy(true);
    setNotice(null);
    const { error } = await supabase.auth.signInWithOtp({
      email,
      options: {
        emailRedirectTo: window.location.origin,
        // Prevent unauthenticated visitors from registering new accounts via the owner login box
        shouldCreateUser: false,
      },
    });
    setBusy(false);

    if (error) {
      setNotice('Unable to send sign-in link. Only pre-registered owner accounts can sign in.');
      return;
    }
    setNotice('If this email is registered as an owner, a sign-in link has been sent.');
    setEmailInput('');
  };

  const handleSignOut = async () => {
    const supabase = getSupabaseBrowserClient();
    if (!supabase) return;
    await supabase.auth.signOut();
    setPanelOpen(false);
    setNotice(null);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        {headerContent}
        <div className="flex items-center gap-2 shrink-0">
          {isOwner && settings ? (
            <>
              <button
                type="button"
                onClick={handleToggleEnabled}
                disabled={busy}
                aria-pressed={settings.enabled}
                className={`inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium rounded-md border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  settings.enabled
                    ? 'bg-slate-900 text-white border-slate-900 hover:bg-slate-800'
                    : 'bg-white text-slate-700 border-slate-200 hover:border-slate-400 hover:text-slate-950'
                }`}
              >
                {settings.enabled ? (
                  <Bell className="w-3.5 h-3.5" aria-hidden="true" />
                ) : (
                  <BellOff className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
                )}
                <span>{settings.enabled ? 'Email alerts: On' : 'Email alerts: Off'}</span>
              </button>

              <button
                type="button"
                onClick={() => setPanelOpen((prev) => !prev)}
                aria-expanded={panelOpen}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-md hover:border-slate-400 hover:text-slate-950 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Settings2 className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Settings</span>
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

      {panelOpen && (
        <section
          aria-label="Owner email alert controls"
          className="bg-white border border-slate-200 rounded-lg p-5 space-y-4"
        >
          {!userEmail ? (
            <div className="space-y-3">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h2 className="text-sm font-semibold text-slate-950">
                    Owner-only daily email alerts
                  </h2>
                  <p className="text-xs text-slate-600 mt-0.5">
                    Sign in with your authorized owner email to pause or resume the daily Resend
                    digest and edit watchlist keywords. Public visitors can read briefings without
                    signing in.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setPanelOpen(false)}
                  aria-label="Close owner alert panel"
                  className="p-1 text-slate-400 hover:text-slate-700"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <form onSubmit={handleMagicLinkSignIn} className="flex flex-col sm:flex-row gap-2.5">
                <input
                  type="email"
                  required
                  value={emailInput}
                  onChange={(e) => setEmailInput(e.target.value)}
                  placeholder="owner@example.com"
                  aria-label="Owner email address"
                  className="flex-1 max-w-sm px-3 py-2 text-sm bg-slate-50 border border-slate-200 rounded-md text-slate-900 focus:outline-none focus:bg-white focus:border-slate-900"
                />
                <button
                  type="submit"
                  disabled={busy}
                  className="px-4 py-2 text-xs font-medium bg-slate-900 text-white rounded-md hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
                >
                  {busy ? 'Sending...' : 'Send sign-in link'}
                </button>
              </form>
              {notice && <p className="text-xs text-slate-700">{notice}</p>}
            </div>
          ) : !isOwner || !settings ? (
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-slate-700">
              <span>
                Signed in as <strong className="font-mono">{userEmail}</strong>, which is not
                registered in <code className="font-mono">admin_users</code>. Read-only access
                remains active.
              </span>
              <button
                type="button"
                onClick={handleSignOut}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 font-medium text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-md self-start sm:self-auto"
              >
                <LogOut className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Sign out</span>
              </button>
            </div>
          ) : (
            <div className="space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
                <div>
                  <h2 className="text-sm font-semibold text-slate-950">
                    Daily Resend Digest Settings
                  </h2>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Signed in as <span className="font-mono text-slate-700">{userEmail}</span>
                    {latestLog && (
                      <>
                        {' · '}Last run: <span className="font-mono">{latestLog.status}</span> (
                        {latestLog.cluster_count} briefings)
                      </>
                    )}
                  </p>
                </div>

                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={handleSignOut}
                    className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-950"
                  >
                    <LogOut className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Sign out</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setPanelOpen(false)}
                    aria-label="Close settings"
                    className="p-1 text-slate-400 hover:text-slate-700"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-6 text-xs text-slate-700">
                <label className="inline-flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={settings.include_critical}
                    onChange={(e) => handleUpdateFlag('include_critical', e.target.checked)}
                    disabled={busy}
                    className="rounded border-slate-300 text-slate-900 focus:ring-slate-900"
                  />
                  <span>Include Critical severity briefings</span>
                </label>

                <label className="inline-flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={settings.include_watchlist}
                    onChange={(e) => handleUpdateFlag('include_watchlist', e.target.checked)}
                    disabled={busy}
                    className="rounded border-slate-300 text-slate-900 focus:ring-slate-900"
                  />
                  <span>Include Watchlist keyword matches</span>
                </label>
              </div>

              <div className="space-y-3 pt-2 border-t border-slate-100">
                <form onSubmit={handleAddKeyword} className="flex flex-col sm:flex-row gap-2">
                  <input
                    type="text"
                    value={newKeyword}
                    onChange={(e) => setNewKeyword(e.target.value)}
                    placeholder="Add watchlist keyword (e.g., Kubernetes, DORA, Nginx)"
                    aria-label="Add watchlist keyword"
                    className="flex-1 max-w-md px-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-md text-slate-900 focus:outline-none focus:bg-white focus:border-slate-900"
                  />
                  <button
                    type="submit"
                    disabled={busy || newKeyword.trim().length < 2}
                    className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium bg-slate-900 text-white rounded-md hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0"
                  >
                    <Plus className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Add keyword</span>
                  </button>
                </form>

                {notice && <p className="text-xs text-red-700">{notice}</p>}

                <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-slate-700">
                  {watchlists.map((item) => (
                    <span key={item.id} className="inline-flex items-center gap-1 font-mono">
                      <span>{item.keyword}</span>
                      <button
                        type="button"
                        onClick={() => handleDeleteKeyword(item.id)}
                        aria-label={`Remove ${item.keyword}`}
                        className="text-slate-400 hover:text-red-700"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
