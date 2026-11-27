'use client';

import { createBrowserClient } from '@supabase/ssr';
import type { SupabaseClient } from '@supabase/supabase-js';

let browserClient: SupabaseClient | null = null;

/**
 * Browser-side Supabase client used ONLY when the owner signs in to toggle
 * alert_settings or edit watchlists (protected by owner-only RLS policies).
 *
 * Security (OWASP A02 / ANSSI): Uses `@supabase/ssr` cookie-backed session
 * storage (`SameSite=Lax; Secure` in HTTPS) instead of `localStorage` so
 * owner tokens are never persisted in Web Storage.
 */
export function getSupabaseBrowserClient(): SupabaseClient | null {
  if (browserClient) return browserClient;

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !anonKey) return null;

  browserClient = createBrowserClient(url, anonKey);
  return browserClient;
}
