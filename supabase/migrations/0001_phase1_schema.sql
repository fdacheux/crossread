-- ============================================================================
-- Phase 1 (Lean v1) Schema Migration: Bilingual Cybersecurity Cross-Reader
-- Target: Supabase PostgreSQL (Free Tier, 500 MB storage cap)
-- Security: Row Level Security (RLS) enabled on both tables; public SELECT
--           only for anon/authenticated; writes restricted to service_role.
--
-- Post-deployment maintenance notes:
-- - This script is idempotent (IF NOT EXISTS / DROP IF EXISTS) so it can be
--   re-run safely during recovery.
-- - Keep CHECK constraints in sync with `pipeline/synthesize.py` (categories &
--   severity) and `pipeline/triage.py` (fact_sheet required JSON keys).
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ----------------------------------------------------------------------------
-- 1. Table: public.clusters
-- One unified, layered English briefing per story cluster.
-- Always synthesized strictly from all linked articles' JSON Fact Sheets.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.clusters (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  source_count      integer NOT NULL DEFAULT 0,
  headline          text NOT NULL,
  tldr              text NOT NULL,
  severity          text NOT NULL,
  categories        text[] NOT NULL DEFAULT '{}'::text[],
  cve_ids           text[] NOT NULL DEFAULT '{}'::text[],
  affected_tech     text[] NOT NULL DEFAULT '{}'::text[],
  entities          text[] NOT NULL DEFAULT '{}'::text[],
  technical_details text NOT NULL DEFAULT 'Not disclosed in sources',
  remediations      text NOT NULL DEFAULT 'Not disclosed in sources',
  source_diffs      text NOT NULL DEFAULT '',

  CONSTRAINT clusters_source_count_non_negative
    CHECK (source_count >= 0),

  CONSTRAINT clusters_severity_valid
    CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),

  CONSTRAINT clusters_categories_valid
    CHECK (
      categories <@ ARRAY[
        'Web/AppSec',
        'CVEs',
        'Regulations',
        'Forensics',
        'Threats',
        'Trends/Research'
      ]::text[]
    )
);

COMMENT ON TABLE public.clusters IS
  'Unified English cybersecurity briefings synthesized strictly from structured article Fact Sheets.';
COMMENT ON COLUMN public.clusters.entities IS
  'Normalized vendor/product/regulation entities aggregated across cluster articles to support 72-hour non-CVE entity-gated clustering.';

-- ----------------------------------------------------------------------------
-- 2. Table: public.articles
-- Stores ONLY article metadata and compact structured JSON Fact Sheets.
-- Raw scraped article prose is NEVER persisted (Fact-Sheet First rule).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.articles (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  url          text NOT NULL UNIQUE,
  title        text NOT NULL,
  source_name  text NOT NULL,
  language     text NOT NULL,
  published_at timestamptz NOT NULL,
  ingested_at  timestamptz NOT NULL DEFAULT now(),
  cve_ids      text[] NOT NULL DEFAULT '{}'::text[],
  entities     text[] NOT NULL DEFAULT '{}'::text[],
  fact_sheet   jsonb NOT NULL,
  cluster_id   uuid REFERENCES public.clusters(id) ON DELETE SET NULL,

  CONSTRAINT articles_url_https_only
    CHECK (url ~ '^https://'),

  CONSTRAINT articles_language_valid
    CHECK (language IN ('en', 'fr')),

  CONSTRAINT articles_fact_sheet_structure
    CHECK (
      jsonb_typeof(fact_sheet) = 'object'
      AND octet_length(fact_sheet::text) <= 32768
      AND coalesce(fact_sheet ->> 'source_url', '') ~ '^https://'
      AND fact_sheet ?& ARRAY[
        'cve_ids',
        'affected_versions',
        'affected_tech',
        'key_claims',
        'remediations',
        'source_url',
        'source_name'
      ]
    )
);

COMMENT ON TABLE public.articles IS
  'Ingested English/French cybersecurity articles storing structured JSON Fact Sheets only (no raw article prose).';

-- ----------------------------------------------------------------------------
-- 3. Indexes (Dashboard filtering, CVE-first hard match, 72h entity lookup)
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_clusters_updated_at_desc
  ON public.clusters (updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_clusters_severity
  ON public.clusters (severity);

CREATE INDEX IF NOT EXISTS idx_clusters_categories_gin
  ON public.clusters USING GIN (categories);

CREATE INDEX IF NOT EXISTS idx_clusters_cve_ids_gin
  ON public.clusters USING GIN (cve_ids);

CREATE INDEX IF NOT EXISTS idx_clusters_affected_tech_gin
  ON public.clusters USING GIN (affected_tech);

CREATE INDEX IF NOT EXISTS idx_clusters_entities_gin
  ON public.clusters USING GIN (entities);

CREATE INDEX IF NOT EXISTS idx_articles_cluster_id
  ON public.articles (cluster_id);

CREATE INDEX IF NOT EXISTS idx_articles_published_at_desc
  ON public.articles (published_at DESC);

CREATE INDEX IF NOT EXISTS idx_articles_cve_ids_gin
  ON public.articles USING GIN (cve_ids);

CREATE INDEX IF NOT EXISTS idx_articles_entities_gin
  ON public.articles USING GIN (entities);

-- ----------------------------------------------------------------------------
-- 4. Triggers: Automatic updated_at & Cluster source_count Maintenance
-- Functions pin search_path = '' per PostgreSQL / Supabase security guidelines.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_clusters_set_updated_at ON public.clusters;
CREATE TRIGGER trg_clusters_set_updated_at
  BEFORE UPDATE ON public.clusters
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- Automatically recalculates `clusters.source_count` whenever articles are linked,
-- moved between clusters, or deleted, preventing drift between pipeline runs.
CREATE OR REPLACE FUNCTION public.sync_cluster_source_count()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.cluster_id IS NOT NULL THEN
      UPDATE public.clusters
      SET source_count = (
        SELECT count(*)::integer FROM public.articles WHERE cluster_id = NEW.cluster_id
      )
      WHERE id = NEW.cluster_id;
    END IF;
    RETURN NEW;

  ELSIF TG_OP = 'DELETE' THEN
    IF OLD.cluster_id IS NOT NULL THEN
      UPDATE public.clusters
      SET source_count = (
        SELECT count(*)::integer FROM public.articles WHERE cluster_id = OLD.cluster_id
      )
      WHERE id = OLD.cluster_id;
    END IF;
    RETURN OLD;

  ELSIF TG_OP = 'UPDATE' AND OLD.cluster_id IS DISTINCT FROM NEW.cluster_id THEN
    IF OLD.cluster_id IS NOT NULL THEN
      UPDATE public.clusters
      SET source_count = (
        SELECT count(*)::integer FROM public.articles WHERE cluster_id = OLD.cluster_id
      )
      WHERE id = OLD.cluster_id;
    END IF;
    IF NEW.cluster_id IS NOT NULL THEN
      UPDATE public.clusters
      SET source_count = (
        SELECT count(*)::integer FROM public.articles WHERE cluster_id = NEW.cluster_id
      )
      WHERE id = NEW.cluster_id;
    END IF;
    RETURN NEW;
  END IF;

  RETURN COALESCE(NEW, OLD);
END;
$$;

DROP TRIGGER IF EXISTS trg_articles_sync_cluster_count ON public.articles;
CREATE TRIGGER trg_articles_sync_cluster_count
  AFTER INSERT OR UPDATE OF cluster_id OR DELETE ON public.articles
  FOR EACH ROW
  EXECUTE FUNCTION public.sync_cluster_source_count();

-- ----------------------------------------------------------------------------
-- 5. Phase 1 Row Level Security (RLS) & Least-Privilege Grants
-- Public dashboard reads via Supabase anon key (SELECT only).
-- GitHub Actions pipeline writes via Supabase service_role key (BYPASSRLS).
-- ----------------------------------------------------------------------------
ALTER TABLE public.clusters ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.articles ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.clusters FROM anon, authenticated;
REVOKE ALL ON TABLE public.articles FROM anon, authenticated;

GRANT SELECT ON TABLE public.clusters TO anon, authenticated;
GRANT SELECT ON TABLE public.articles TO anon, authenticated;

DROP POLICY IF EXISTS "Public read-only access to clusters" ON public.clusters;
CREATE POLICY "Public read-only access to clusters"
  ON public.clusters
  FOR SELECT
  TO anon, authenticated
  USING (true);

DROP POLICY IF EXISTS "Public read-only access to articles" ON public.articles;
CREATE POLICY "Public read-only access to articles"
  ON public.articles
  FOR SELECT
  TO anon, authenticated
  USING (true);
