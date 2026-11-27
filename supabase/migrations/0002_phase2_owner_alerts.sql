-- ============================================================================
-- Phase 2 Migration: Owner-Only Email Alerts (Resend), Watchlists & Alert Logs
-- Target: Supabase PostgreSQL (Free Tier)
-- Security: Strictly owner-only RLS verified via public.admin_users + auth.jwt().
--           Public (anon) visitors have ZERO access to alert settings, watchlists,
--           or delivery logs.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Authorized Owner Registry (managed strictly via SQL Editor / service_role)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.admin_users (
  email      text PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT admin_users_email_lowercase CHECK (email = lower(email))
);

ALTER TABLE public.admin_users ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.admin_users FROM anon, authenticated;

COMMENT ON TABLE public.admin_users IS
  'Owner email allowlist for Phase 2 admin/alert controls. Insert your owner email via Supabase SQL Editor.';

-- Helper function: returns true ONLY when the signed-in Supabase user email
-- matches an entry in public.admin_users.
--
-- Why SECURITY DEFINER + search_path = '':
-- `authenticated` has zero direct SELECT privileges on `public.admin_users` so
-- visitors cannot enumerate owner emails. SECURITY DEFINER lets this function
-- perform the boolean check without exposing the table; pinning search_path = ''
-- prevents search-path hijacking and satisfies Supabase Security Advisor checks.
--
-- Debug tip: If the owner signs in and still sees "not registered in admin_users",
-- verify `SELECT * FROM public.admin_users;` contains their exact lowercase email.
CREATE OR REPLACE FUNCTION public.is_owner()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.admin_users a
    JOIN auth.users u ON u.id = auth.uid()
    WHERE u.email_confirmed_at IS NOT NULL
      AND lower(coalesce(u.email, '')) = a.email
  );
$$;

REVOKE ALL ON FUNCTION public.is_owner() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.is_owner() TO authenticated;

-- ----------------------------------------------------------------------------
-- 2. Singleton Owner Alert Settings (defaults to disabled = passive reading)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.alert_settings (
  id                integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  enabled           boolean NOT NULL DEFAULT false,
  include_critical  boolean NOT NULL DEFAULT true,
  include_watchlist boolean NOT NULL DEFAULT true,
  updated_at        timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.alert_settings (id, enabled, include_critical, include_watchlist)
VALUES (1, false, true, true)
ON CONFLICT (id) DO NOTHING;

DROP TRIGGER IF EXISTS trg_alert_settings_set_updated_at ON public.alert_settings;
CREATE TRIGGER trg_alert_settings_set_updated_at
  BEFORE UPDATE ON public.alert_settings
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

ALTER TABLE public.alert_settings ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.alert_settings FROM anon, authenticated;
GRANT SELECT, UPDATE ON TABLE public.alert_settings TO authenticated;

DROP POLICY IF EXISTS "Owner can read alert settings" ON public.alert_settings;
CREATE POLICY "Owner can read alert settings"
  ON public.alert_settings
  FOR SELECT
  TO authenticated
  USING (public.is_owner());

DROP POLICY IF EXISTS "Owner can update alert settings" ON public.alert_settings;
CREATE POLICY "Owner can update alert settings"
  ON public.alert_settings
  FOR UPDATE
  TO authenticated
  USING (public.is_owner())
  WITH CHECK (public.is_owner());

-- ----------------------------------------------------------------------------
-- 3. Owner Watchlist Keywords
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.watchlists (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  keyword    text NOT NULL UNIQUE,
  enabled    boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT watchlists_keyword_not_blank CHECK (length(trim(keyword)) BETWEEN 2 AND 60)
);

ALTER TABLE public.watchlists ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.watchlists FROM anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.watchlists TO authenticated;

DROP POLICY IF EXISTS "Owner manages watchlists" ON public.watchlists;
CREATE POLICY "Owner manages watchlists"
  ON public.watchlists
  FOR ALL
  TO authenticated
  USING (public.is_owner())
  WITH CHECK (public.is_owner());

-- Seed starter watchlist keywords (matches config/feeds.json)
INSERT INTO public.watchlists (keyword)
VALUES
  ('Next.js'), ('React'), ('Node.js'), ('Nginx'), ('OpenSSL'),
  ('PostgreSQL'), ('Supabase'), ('OAuth'), ('OIDC'), ('JWT'),
  ('NIS2'), ('GDPR'), ('CNIL'), ('ANSSI')
ON CONFLICT (keyword) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 4. Alert Delivery Logs (Owner read-only; pipeline service_role writes)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.alert_logs (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sent_at             timestamptz NOT NULL DEFAULT now(),
  cluster_ids         uuid[] NOT NULL DEFAULT '{}'::uuid[],
  matched_keywords    text[] NOT NULL DEFAULT '{}'::text[],
  cluster_count       integer NOT NULL DEFAULT 0 CHECK (cluster_count >= 0),
  status              text NOT NULL CHECK (status IN ('sent', 'skipped_disabled', 'skipped_empty', 'failed')),
  provider_message_id text,
  error_message       text
);

CREATE INDEX IF NOT EXISTS idx_alert_logs_sent_at_desc
  ON public.alert_logs (sent_at DESC);

ALTER TABLE public.alert_logs ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.alert_logs FROM anon, authenticated;
GRANT SELECT ON TABLE public.alert_logs TO authenticated;

DROP POLICY IF EXISTS "Owner can read alert logs" ON public.alert_logs;
CREATE POLICY "Owner can read alert logs"
  ON public.alert_logs
  FOR SELECT
  TO authenticated
  USING (public.is_owner());

-- ----------------------------------------------------------------------------
-- SETUP REMINDER (run once in Supabase SQL Editor with your owner email):
--   INSERT INTO public.admin_users (email) VALUES ('you@example.com');
-- ----------------------------------------------------------------------------
