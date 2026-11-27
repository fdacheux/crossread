Feature: Fact-Sheet synthesis and owner-only daily Resend email alerts
  As the application owner
  I want briefings strictly grounded in Fact Sheets and daily emails gated by my On/Off toggle
  So that passive dashboard reading sends zero emails and active alerts are safe and deduplicated

  Scenario: Enforce explicit unknowns and sanitize out-of-taxonomy categories during synthesis
    Given a Fact Sheet with CVE "CVE-2026-41892" and empty technical_details and remediations from the LLM
    And the LLM outputs an invalid category "RandomBuzzword" and hallucinated CVE "CVE-2099-99999"
    When synthesize_cluster_from_fact_sheets executes
    Then technical_details defaults to "Not disclosed in sources"
    And remediations defaults to "Not disclosed in sources"
    And categories falls back to a valid taxonomy value
    And authoritative CVE "CVE-2026-41892" is preserved
    And hallucinated CVE "CVE-2099-99999" is excluded

  Scenario: Skip Resend when owner alerts are turned Off
    Given owner alert_settings.enabled is false
    And a Critical cluster "clu-crit-1" was touched during the run
    When dispatch_owner_daily_digest executes
    Then zero emails are sent via Resend
    And alert_logs records status "skipped_disabled"

  Scenario: Send one escaped bundled digest email when owner alerts are On
    Given owner alert_settings.enabled is true
    And watchlist keywords are "Next.js,CRA"
    And touched clusters include a Critical cluster with "<script>xss()</script>" in the headline and a Medium cluster mentioning "scraping"
    When dispatch_owner_daily_digest executes
    Then exactly 1 email is sent via Resend
    And the HTML email body escapes "<script>xss()</script>"
    And the email includes the AI-synthesized transparency notice
    And the unrelated "scraping" cluster is excluded from the digest
    And alert_logs records status "sent"

  Scenario: Prevent duplicate Resend emails for clusters already alerted within 24 hours
    Given owner alert_settings.enabled is true
    And cluster "clu-crit-1" was already logged as "sent" in the last 24 hours
    And cluster "clu-crit-1" is touched again by a manual run
    When dispatch_owner_daily_digest executes
    Then zero emails are sent via Resend
    And alert_logs records status "skipped_empty"
