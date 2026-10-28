import { test, expect } from './fixtures';

test.describe('Dashboard /', () => {
  test('renders configured title, stats and charts', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveTitle(/BOMHort/);
    await expect(page.getByRole('heading', { level: 1, name: 'Dashboard' })).toBeVisible();
    await expect(page.locator('.loading-state')).toHaveCount(0);
    await expect(page.locator('.error-state')).toHaveCount(0);
    await expect(page.locator('.kpi-card').first()).toBeVisible();
    await expect(page.locator('svg').first()).toBeVisible();
    // ui-config.json description is sanitized, not bypassed: formatting kept, no scripts.
    await expect(page.locator('main strong').first()).toBeVisible();
    await expect(page.locator('main script')).toHaveCount(0);
  });

  test('unknown routes redirect to the dashboard', async ({ page }) => {
    await page.goto('/does-not-exist');
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Dashboard' })).toBeVisible();
  });
});
