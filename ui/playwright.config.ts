import { defineConfig, devices } from '@playwright/test';

// Runs against a live stack (`make dev` + `make demo-fleet` by default), so
// nginx, the /api proxy, CSP and ui-config.json are part of what is tested.
export default defineConfig({
  testDir: './e2e',
  // The gateway rate-limits to 100 req/10s per IP; parallel workers trip it.
  workers: 1,
  forbidOnly: !!process.env['CI'],
  retries: process.env['CI'] ? 1 : 0,
  reporter: process.env['CI'] ? [['github'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: process.env['E2E_BASE_URL'] ?? 'http://localhost:8090',
    trace: 'retain-on-failure',
  },
  // Static host for the web-components demo (e2e/elements-demo.spec.ts); needs `npm run build:elements` first.
  webServer: {
    command: 'python3 -m http.server 8099 --directory packages/elements',
    url: 'http://localhost:8099/demo.html',
    reuseExistingServer: true,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
