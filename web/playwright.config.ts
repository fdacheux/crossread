import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright E2E TNR configuration for `/web` (Next.js App Router).
 * Starts both an offline mock Supabase server and Next.js so tests run
 * deterministically in CI with zero external credentials or live API usage.
 */
export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://127.0.0.1:3005',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: [
    {
      command: 'node tests/mock-supabase.mjs',
      url: 'http://127.0.0.1:4100/rest/v1/clusters',
      reuseExistingServer: !process.env.CI,
      timeout: 15_000,
    },
    {
      command: 'npx next dev --port 3005 --hostname 127.0.0.1',
      url: 'http://127.0.0.1:3005',
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
      env: {
        NEXT_PUBLIC_SUPABASE_URL: 'http://127.0.0.1:4100',
        NEXT_PUBLIC_SUPABASE_ANON_KEY: 'test-anon-key',
      },
    },
  ],
});
