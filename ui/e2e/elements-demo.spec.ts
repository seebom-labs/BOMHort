import { test, expect } from '@playwright/test';

test('elements render against the API and route inside the host page', async ({ page }) => {
  const errors: string[] = [];
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('http://localhost:8099/demo.html');
  await expect(page.locator('bomhort-donut-chart svg')).toBeVisible();
  await expect(page.locator('bomhort-scope-badge').first()).toContainText(/direct/i);
  await expect(page.locator('bomhort-scope-matrix .scope-card').first()).toBeVisible();

  const vulnRow = page.locator('bomhort-page .vuln-id').first();
  await expect(vulnRow).toBeVisible({ timeout: 15000 });
  // Internal links route inside the element and report the new URL to the host.
  await vulnRow.click();
  await expect(page.locator('bomhort-page h1')).toContainText(/CVE Impact/i);
  await expect(page.locator('#current')).toContainText('/cve-impact?vuln=');
  await page.getByRole('button', { name: 'Projects' }).click();
  await expect(page.locator('bomhort-page h1')).toContainText(/Projects/i);
  expect(errors).toEqual([]);
});
