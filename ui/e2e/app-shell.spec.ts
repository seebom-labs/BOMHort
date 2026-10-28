import { test, expect } from './fixtures';

test.describe('App shell', () => {
  test('dark mode toggles, persists across reload and respects OS preference', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto('/');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');

    await page.locator('.theme-toggle').click();
    await expect(page.locator('html')).not.toHaveAttribute('data-theme', 'dark');
    expect(await page.evaluate(() => localStorage.getItem('bomhort-theme'))).toBe('light');

    await page.reload();
    await expect(page.locator('html')).not.toHaveAttribute('data-theme', 'dark');
  });

  test('serves ui-config.json and custom-theme.css under the CSP', async ({ page }) => {
    const [cfg, css, index] = await Promise.all([
      page.request.get('/ui-config.json'),
      page.request.get('/custom-theme.css'),
      page.request.get('/'),
    ]);
    expect(cfg.ok()).toBeTruthy();
    expect((await cfg.json()).brandName).toBeTruthy();
    expect(css.ok(), 'custom-theme.css must resolve even when not mounted').toBeTruthy();
    const h = index.headers();
    expect(h['content-security-policy']).toContain("default-src 'self'");
    expect(h['x-content-type-options']).toBe('nosniff');
    expect(h['x-frame-options']).toBe('DENY');
  });

  test('navbar reflects ui-config brand and links every top-level route', async ({ page }) => {
    await page.goto('/');
    const nav = page.getByRole('navigation');
    await expect(nav.locator('.brand img')).toHaveAttribute('alt', /.+/);
    for (const name of [
      'Dashboard',
      'Projects',
      'SBOMs',
      'Vulnerabilities',
      'CVE Impact',
      'Licenses',
      'Compliance',
      'Dependencies',
      'Pkg Search',
      'Version Skew',
    ]) {
      await expect(nav.getByRole('link', { name, exact: true })).toBeVisible();
    }
  });
});

test.describe('API unavailable', () => {
  test.use({ expectApiErrors: true });
  test('dashboard shows its error state instead of a blank page', async ({ page }) => {
    await page.route('**/api/v1/**', (r) => r.fulfill({ status: 503, body: 'down' }));
    await page.goto('/');
    await expect(page.locator('.error-state')).toContainText('Unable to load dashboard data');
  });
});
