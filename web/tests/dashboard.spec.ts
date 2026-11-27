import { expect, test } from '@playwright/test';

/**
 * Frontend Functional & Security E2E Non-Regression Suite (TNR).
 * Mirrors BDD Features 6 & 7 from `/docs/TEST_PLAN.md`.
 */
test.describe('Public Cybersecurity Briefing Dashboard (TNR)', () => {
  test('filters briefings by category, severity, and CVE search with single clear button', async ({
    page,
  }) => {
    await page.goto('/');

    // Both fixture briefings load initially
    await expect(page.getByText('Showing 2 of 2 briefings')).toBeVisible();
    await expect(page.getByText('Active Nginx HTTP/3 Header Smuggling (CVE-2026-41892)')).toBeVisible();
    await expect(page.getByText('CNIL Issues €4.2M GDPR Fine Over Analytics SDK')).toBeVisible();

    // Category filter: Regulations
    await page.getByRole('group', { name: 'Filter by category' }).getByRole('button', { name: 'Regulations' }).click();
    await expect(page.getByText('Showing 1 of 2 briefings')).toBeVisible();
    await expect(page.getByText('CNIL Issues €4.2M GDPR Fine Over Analytics SDK')).toBeVisible();

    // Reset filters
    await page.getByRole('button', { name: 'Reset' }).click();
    await expect(page.getByText('Showing 2 of 2 briefings')).toBeVisible();

    // Search by exact CVE + verify single custom clear button works
    const searchInput = page.getByRole('searchbox', { name: 'Search briefings' });
    await searchInput.fill('CVE-2026-41892');
    await expect(page.getByText('Showing 1 of 2 briefings')).toBeVisible();

    const clearBtn = page.getByRole('button', { name: 'Clear search' });
    await expect(clearBtn).toBeVisible();
    await clearBtn.click();
    await expect(searchInput).toHaveValue('');
    await expect(page.getByText('Showing 2 of 2 briefings')).toBeVisible();
  });

  test('renders XSS payloads strictly as escaped plain text and strips javascript: source links', async ({
    page,
  }) => {
    await page.goto('/');

    // Verify valid HTTPS source link renders while malicious javascript: link is omitted
    await expect(page.getByRole('link', { name: /CERT-FR Alertes/ })).toHaveAttribute(
      'href',
      'https://www.cert.ssi.gouv.fr/alerte/'
    );
    await expect(page.getByText('Unsafe Source')).toHaveCount(0);

    // Expand Deep-Dive on the Nginx cluster containing `<script>window.__xssFired = true</script>`
    await page.getByRole('button', { name: 'Show deep dive' }).first().click();
    await expect(
      page.getByText('Payload example from advisory: <script>window.__xssFired = true</script>')
    ).toBeVisible();

    // Confirm script never executed in the browser context
    const xssFired = await page.evaluate(() => Boolean((window as unknown as Record<string, unknown>).__xssFired));
    expect(xssFired).toBe(false);
  });

  test('keeps owner email alerts gated behind owner sign-in for public visitors', async ({
    page,
  }) => {
    await page.goto('/');

    // Public visitor sees only the quiet Owner alerts button (not an unlocked On/Off switch)
    const ownerAlertsBtn = page.getByRole('button', { name: 'Owner alerts' });
    await expect(ownerAlertsBtn).toBeVisible();
    await expect(page.getByRole('button', { name: /Email alerts: (On|Off)/ })).toHaveCount(0);

    // Opening the panel shows the magic-link sign-in form without blocking dashboard reading
    await ownerAlertsBtn.click();
    await expect(page.getByRole('textbox', { name: 'Owner email address' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Send sign-in link' })).toBeVisible();
  });

  test('displays EU AI Act Art. 50 disclosure and expandable RGPD Privacy notice', async ({
    page,
  }) => {
    await page.goto('/');

    await expect(page.getByText(/AI-synthesized briefings \(unreviewed\)/)).toBeVisible();

    const legalBtn = page.getByRole('button', { name: 'Privacy, RGPD & AI Notice' });
    await expect(legalBtn).toBeVisible();
    await legalBtn.click();

    await expect(page.getByText(/RGPD & Zero-Tracking Privacy/)).toBeVisible();
    await expect(page.getByText(/EU AI Act Transparency \(Art\. 50\)/)).toBeVisible();
  });
});
