/**
 * Read-only server-side Supabase query helpers for the Next.js dashboard.
 *
 * Security boundary: Uses ONLY `NEXT_PUBLIC_SUPABASE_ANON_KEY`, which is
 * limited to SELECT queries on `clusters` and `articles` by Phase 1 RLS.
 *
 * Post-deployment debugging guide:
 * - Empty feed with no error: confirm the GitHub Action has run at least once
 *   and `0001_phase1_schema.sql` SELECT policies exist for the `anon` role.
 * - Missing `articles` array on cards: verify the foreign key `articles.cluster_id`
 *   exists so PostgREST can resolve the embedded `articles (...)` relationship.
 */

import { createClient } from '@supabase/supabase-js';
import type { ClusterBriefing } from '@/types/briefing';

/**
 * Strictly validates that an external article URL uses HTTPS before rendering
 * in an anchor href, blocking javascript:, data:, or http: schemes.
 */
export function isSafeHttpsUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    return parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

export async function fetchBriefings(limit = 60): Promise<{
  briefings: ClusterBriefing[];
  error: string | null;
}> {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseAnonKey) {
    return {
      briefings: [],
      error:
        'Supabase environment variables are not configured. Set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY.',
    };
  }

  const supabase = createClient(supabaseUrl, supabaseAnonKey, {
    auth: { persistSession: false },
  });

  const { data, error } = await supabase
    .from('clusters')
    .select(
      `
      id,
      created_at,
      updated_at,
      source_count,
      headline,
      tldr,
      severity,
      categories,
      cve_ids,
      affected_tech,
      entities,
      technical_details,
      remediations,
      source_diffs,
      articles (
        id,
        url,
        title,
        source_name,
        language,
        published_at,
        fact_sheet
      )
    `
    )
    .order('updated_at', { ascending: false })
    .limit(limit);

  if (error) {
    // Log raw PostgREST/network error on server logs only; return a generic user message
    // so internal table names or schema details never leak into browser HTML.
    console.error('Supabase read error:', error.message);
    return {
      briefings: [],
      error: 'Unable to load briefings right now. Please try again shortly.',
    };
  }

  return {
    briefings: (data ?? []) as unknown as ClusterBriefing[],
    error: null,
  };
}
