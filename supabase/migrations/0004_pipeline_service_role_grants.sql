-- The pipeline uses service_role, which bypasses RLS but still requires SQL
-- privileges on each table accessed through the Supabase REST API.
GRANT USAGE ON SCHEMA public TO service_role;

GRANT SELECT, INSERT, UPDATE ON TABLE public.articles, public.clusters TO service_role;
GRANT SELECT ON TABLE public.alert_settings, public.watchlists TO service_role;
GRANT SELECT, INSERT ON TABLE public.alert_logs TO service_role;
