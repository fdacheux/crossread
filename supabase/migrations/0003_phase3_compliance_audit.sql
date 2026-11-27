-- ============================================================================
-- Phase 3 Migration: Compliance, AI Provenance, Admin Audit Logging & Retention
-- Target: Supabase PostgreSQL (Free Tier)
-- Aligns with:
--   - EU AI Act Art. 50 & Traceability: model & prompt provenance columns
--   - ANSSI Logging / NIST CSF DE.CM: append-only trigger-driven admin_audit_logs
--   - RGPD Art. 5(1)(e) Storage Limitation: automated retention cleanup RPC
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. EU AI Act Traceability: Model & Prompt Provenance Columns
-- ----------------------------------------------------------------------------
ALTER TABLE public.articles
  ADD COLUMN IF NOT EXISTS triage_model text,
  ADD COLUMN IF NOT EXISTS prompt_version text;

ALTER TABLE public.clusters
  ADD COLUMN IF NOT EXISTS synthesis_model text,
  ADD COLUMN IF NOT EXISTS prompt_version text;

COMMENT ON COLUMN public.articles.triage_model IS
  'Model identifier used during Stage 1 Fact-Sheet extraction (EU AI Act traceability).';
COMMENT ON COLUMN public.clusters.synthesis_model IS
  'Model identifier used during Stage 3 cluster briefing synthesis (EU AI Act traceability).';
COMMENT ON COLUMN public.clusters.prompt_version IS
  'Pipeline prompt specification version used to generate this briefing.';

-- ----------------------------------------------------------------------------
-- 2. ANSSI Logging / NIST DE.CM: Append-Only Owner Admin Audit Log
-- Populated strictly via SECURITY DEFINER triggers on alert_settings & watchlists.
-- Authenticated owners have read-only access; zero direct write privileges.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.admin_audit_logs (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  actor_id    uuid,
  actor_email text,
  table_name  text NOT NULL,
  operation   text NOT NULL CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),
  record_id   text NOT NULL,
  old_data    jsonb,
  new_data    jsonb
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_occurred_at_desc
  ON public.admin_audit_logs (occurred_at DESC);

ALTER TABLE public.admin_audit_logs ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.admin_audit_logs FROM anon, authenticated;
GRANT SELECT ON TABLE public.admin_audit_logs TO authenticated;

DROP POLICY IF EXISTS "Owner can read admin audit logs" ON public.admin_audit_logs;
CREATE POLICY "Owner can read admin audit logs"
  ON public.admin_audit_logs
  FOR SELECT
  TO authenticated
  USING (public.is_owner());

CREATE OR REPLACE FUNCTION public.record_admin_audit()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_actor_id    uuid := auth.uid();
  v_actor_email text := NULL;
  v_record_id   text;
BEGIN
  IF v_actor_id IS NOT NULL THEN
    SELECT lower(u.email)
      INTO v_actor_email
      FROM auth.users u
     WHERE u.id = v_actor_id;
  END IF;

  IF TG_OP = 'DELETE' THEN
    v_record_id := COALESCE(to_jsonb(OLD) ->> 'id', 'unknown');
    INSERT INTO public.admin_audit_logs (
      actor_id, actor_email, table_name, operation, record_id, old_data, new_data
    )
    VALUES (
      v_actor_id, v_actor_email, TG_TABLE_NAME, TG_OP, v_record_id, to_jsonb(OLD), NULL
    );
    RETURN OLD;
  ELSIF TG_OP = 'INSERT' THEN
    v_record_id := COALESCE(to_jsonb(NEW) ->> 'id', 'unknown');
    INSERT INTO public.admin_audit_logs (
      actor_id, actor_email, table_name, operation, record_id, old_data, new_data
    )
    VALUES (
      v_actor_id, v_actor_email, TG_TABLE_NAME, TG_OP, v_record_id, NULL, to_jsonb(NEW)
    );
    RETURN NEW;
  ELSE
    v_record_id := COALESCE(to_jsonb(NEW) ->> 'id', 'unknown');
    INSERT INTO public.admin_audit_logs (
      actor_id, actor_email, table_name, operation, record_id, old_data, new_data
    )
    VALUES (
      v_actor_id, v_actor_email, TG_TABLE_NAME, TG_OP, v_record_id, to_jsonb(OLD), to_jsonb(NEW)
    );
    RETURN NEW;
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.record_admin_audit() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_audit_alert_settings ON public.alert_settings;
CREATE TRIGGER trg_audit_alert_settings
  AFTER INSERT OR UPDATE OR DELETE ON public.alert_settings
  FOR EACH ROW
  EXECUTE FUNCTION public.record_admin_audit();

DROP TRIGGER IF EXISTS trg_audit_watchlists ON public.watchlists;
CREATE TRIGGER trg_audit_watchlists
  AFTER INSERT OR UPDATE OR DELETE ON public.watchlists
  FOR EACH ROW
  EXECUTE FUNCTION public.record_admin_audit();

-- ----------------------------------------------------------------------------
-- 3. RGPD Art. 5(1)(e) Storage Limitation & 500 MB Free-Tier Retention Cleanup
-- Invoked daily by the batch pipeline using service_role.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.purge_expired_records(
  alert_log_days integer DEFAULT 90,
  audit_log_days integer DEFAULT 365,
  content_days   integer DEFAULT 365
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_deleted_alert_logs integer := 0;
  v_deleted_audit_logs integer := 0;
  v_deleted_articles   integer := 0;
  v_deleted_clusters   integer := 0;
BEGIN
  DELETE FROM public.alert_logs
   WHERE sent_at < now() - make_interval(days => GREATEST(alert_log_days, 7));
  GET DIAGNOSTICS v_deleted_alert_logs = ROW_COUNT;

  DELETE FROM public.admin_audit_logs
   WHERE occurred_at < now() - make_interval(days => GREATEST(audit_log_days, 30));
  GET DIAGNOSTICS v_deleted_audit_logs = ROW_COUNT;

  DELETE FROM public.articles
   WHERE ingested_at < now() - make_interval(days => GREATEST(content_days, 30));
  GET DIAGNOSTICS v_deleted_articles = ROW_COUNT;

  DELETE FROM public.clusters c
   WHERE c.updated_at < now() - make_interval(days => GREATEST(content_days, 30))
     AND NOT EXISTS (
       SELECT 1 FROM public.articles a WHERE a.cluster_id = c.id
     );
  GET DIAGNOSTICS v_deleted_clusters = ROW_COUNT;

  RETURN jsonb_build_object(
    'deleted_alert_logs', v_deleted_alert_logs,
    'deleted_audit_logs', v_deleted_audit_logs,
    'deleted_articles',   v_deleted_articles,
    'deleted_clusters',   v_deleted_clusters
  );
END;
$$;

REVOKE ALL ON FUNCTION public.purge_expired_records(integer, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.purge_expired_records(integer, integer, integer) TO service_role;
