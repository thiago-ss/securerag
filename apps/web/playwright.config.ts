import { defineConfig } from '@playwright/test';

/**
 * Playwright config for the SecureRAG console. The webServer boots the REAL
 * API (Testcontainers PostgreSQL + fake OIDC provider) plus the vite dev
 * server proxying /api — browser tests assert real behavior, not mocks.
 * First run needs `npx playwright install chromium`.
 */
const PORT = process.env['WEB_TEST_PORT'] ?? '5173';

export default defineConfig({
  testDir: 'test',
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  retries: 0,
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'npx tsx test/server.ts',
    url: `http://127.0.0.1:${PORT}/__control/ready`,
    reuseExistingServer: false,
    timeout: 180_000,
    env: { WEB_TEST_PORT: PORT },
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
