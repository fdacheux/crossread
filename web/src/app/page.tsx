import { BriefingDashboard } from '@/components/BriefingDashboard';
import { fetchBriefings } from '@/lib/supabase';

/**
 * Incremental Static Regeneration (ISR) window in seconds (5 minutes).
 * Keeps Vercel Hobby fast and protects Supabase Free Tier read quotas.
 * Debug note: After a manual pipeline run, new clusters appear on the live
 * site within 5 minutes (or immediately after a Vercel redeploy).
 */
export const revalidate = 300;

export default async function HomePage() {
  // Fetch the 60 most recently updated clusters along with their linked source articles.
  const { briefings, error } = await fetchBriefings(60);

  return <BriefingDashboard initialBriefings={briefings} loadError={error} />;
}
