import { test, expect, first, api } from './fixtures';

type Vuln = { vuln_id: string; cve_id: string; severity: string };

test.describe('Vulnerabilities', () => {
  test('/vulnerabilities renders a virtual list, filters by id and scope, exports a report', async ({
    page,
  }) => {
    const { total } = await api<{ total: number }>(page, '/vulnerabilities?page_size=1');
    const vuln = await first<Vuln>(page, '/vulnerabilities?page_size=1');

    await page.goto('/vulnerabilities');
    await expect(page.getByRole('heading', { level: 1, name: 'Vulnerabilities' })).toBeVisible();
    const rows = page.locator('.vuln-row');
    await expect(rows.first()).toBeVisible();
    // Virtual scroll: the DOM must hold a window of rows, never the whole result set.
    expect(await rows.count()).toBeLessThanOrEqual(Math.min(total, 60));

    await page.getByPlaceholder(/Filter by CVE/).fill(vuln.vuln_id);
    await expect(rows.first()).toContainText(vuln.cve_id || vuln.vuln_id);
    await page.getByPlaceholder(/Filter by CVE/).fill('CVE-1900-0000');
    await expect(page.locator('.state')).toContainText('No vulnerability matches');
    await page.getByPlaceholder(/Filter by CVE/).fill('');

    await page.getByLabel('Dependency scope filter').selectOption('direct');
    await expect(page.locator('.export-btn')).toHaveAttribute('href', /scope=direct/);
    await expect(page.locator('.viewport')).not.toHaveClass(/stale/);
    await page.getByLabel('Dependency scope filter').selectOption('');

    const href = await page.locator('.export-btn').getAttribute('href');
    expect(href).toContain('/api/v1/');
    expect((await page.request.get(href!)).ok()).toBeTruthy();

    await rows.first().locator('.vuln-id').click();
    await expect(page).toHaveURL(/\/cve-impact\?vuln=/);
  });

  test('/cve-impact searches by id, groups by project and links to versions', async ({ page }) => {
    const vuln = await first<Vuln>(page, '/vulnerabilities?page_size=1');

    await page.goto('/cve-impact');
    await expect(page.getByRole('heading', { level: 1, name: 'CVE Impact Search' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Search' })).toBeDisabled();

    await page.getByPlaceholder(/Enter any id/).fill(vuln.vuln_id);
    await page.getByRole('button', { name: 'Search' }).click();
    await expect(page.locator('.result-count')).toBeVisible();
    const card = page.locator('.project-card').first();
    await expect(card).toBeVisible();

    await card.locator('.project-header').click();
    await expect(card.locator('.project-details')).toBeVisible();
    await page.locator('.sort-btn', { hasText: /name/i }).click();
    await expect(page.locator('.sort-btn.active')).toContainText(/name/i);

    await card.locator('.version-tag').first().click();
    await expect(page).toHaveURL(/\/sboms\/[0-9a-f-]{36}$/);
  });

  test('/cve-impact?cve= deep link searches immediately and also accepts an alias', async ({
    page,
  }) => {
    const vuln = await first<Vuln & { aliases: string[] }>(page, '/vulnerabilities?page_size=1');
    const alias = vuln.aliases?.find((a) => a !== vuln.vuln_id) ?? vuln.vuln_id;
    await page.goto(`/cve-impact?cve=${alias}`);
    await expect(page.locator('.project-card').first()).toBeVisible();
  });
});
