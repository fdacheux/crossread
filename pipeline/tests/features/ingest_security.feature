Feature: Safe URL ingestion and pre-LLM quality filtering
  As the pipeline operator
  I want untrusted URLs and feeds validated before LLM processing
  So that internal infrastructure is protected and bot-walls never enter the database

  Scenario Outline: Block unsafe or internal manual URLs
    Given a manual URL "<url>"
    When the SSRF validator checks the URL
    Then validation fails with SSRFBlockedError

    Examples:
      | url                                        |
      | http://thehackernews.com/article           |
      | https://127.0.0.1/admin                    |
      | https://169.254.169.254/latest/meta-data/  |
      | https://10.0.0.12/internal                 |
      | https://172.16.0.5/status                  |
      | https://192.168.1.1/router                 |
      | https://[::1]/secret                       |
      | https://user:pass@example.com/article      |
      | https://localhost/health                   |
      | https://100.64.0.1/internal                |
      | https://100.100.100.200/latest/meta-data/  |
      | https://example.com:8443/article           |

  Scenario: Block SSRF hidden behind an HTTP 302 redirect
    Given a public URL "https://public.example/go" that redirects to "https://169.254.169.254/latest/meta-data/"
    When safe_fetch_bytes retrieves the URL
    Then validation fails with SSRFBlockedError

  Scenario: Reject bot-wall pages at the Pre-LLM Quality Gate
    Given extracted text "Just a moment... Verify you are human - Cloudflare security check"
    When the Pre-LLM Quality Gate runs with minimum 150 words
    Then the quality gate rejects the article with marker "bot_wall_marker"

  Scenario: Reject short HTML extractions below 150 words
    Given extracted text "Short snippet about a security patch released today."
    When the Pre-LLM Quality Gate runs with minimum 150 words
    Then the quality gate rejects the article with marker "too_short"

  Scenario: Exempt concise CISA KEV structured advisories from the 150-word floor
    Given extracted text "CISA KEV Advisory: CVE-2026-41892 affects Nginx HTTP/3. Apply patch immediately."
    When the Pre-LLM Quality Gate runs as a structured advisory with minimum 150 words
    Then the quality gate accepts the article
    And regex CVE extraction returns "CVE-2026-41892"
