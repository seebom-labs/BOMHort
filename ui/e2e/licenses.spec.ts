import { test, expect, api } from './fixtures';

type License = { license_id: string; category: string; package_count: number };
type Violation = { document_name: string; source_file: string };

test.describe('Licenses', () => {
  test('/licenses shows category cards, resolution sources and an expandable license list', async ({
    page,
  }) => {
    const licenses = await api<License[]>(page, '/licenses/compliance');
    expect(licenses.length).toBeGreaterThan(0);

    await page.goto('/licenses');
    await expect(page.getByRole('heading', { level: 1, name: 'License Compliance' })).toBeVisible();
    for (const h of ['Permissive', 'Copyleft', 'Not Approved', 'Unknown', 'Exempted']) {
      await expect(page.getByRole('heading', { level: 3, name: h })).toBeVisible();
    }
    await expect(page.getByRole('heading', { level: 2, name: 'License Resolution' })).toBeVisible();
    await expect(page.locator('.source-row').first()).toBeVisible();

    await expect(page.locator('.license-card')).toHaveCount(licenses.length);
    await page.locator('.sort-btn', { hasText: 'Most Usages' }).click();
    const top = licenses.reduce((a, b) => (b.package_count > a.package_count ? b : a));
    await expect(page.locator('.license-card .license-id').first()).toHaveText(top.license_id);

    const card = page.locator('.license-card').first();
    await card.locator('.card-header').click();
    await expect(card.locator('.card-body')).toBeVisible();
  });

  test('/license-compliance lists violations with filter and the configured exceptions', async ({
    page,
  }) => {
    const violations = await api<Violation[]>(page, '/projects/license-compliance');

    await page.goto('/license-compliance');
    await expect(page.getByRole('heading', { level: 1, name: 'License Compliance' })).toBeVisible();
    await expect(page.locator('.tabs button.active')).toContainText(
      `Non-Compliant (${violations.length})`,
    );

    if (violations.length) {
      const v = violations[0];
      await expect(page.locator('.violation-card').first()).toBeVisible();
      await page.getByPlaceholder(/Filter by project/).fill(v.document_name || v.source_file);
      await expect(page).toHaveURL(/search=/);
      await expect(page.locator('.violation-card .project-name').first()).toContainText(
        v.document_name || v.source_file,
      );
    } else {
      await expect(page.locator('.empty')).toBeVisible();
    }

    await page.locator('.tabs button', { hasText: 'Configured Exceptions' }).click();
    await expect(page.locator('.exception-card, .empty-hint').first()).toBeVisible();
  });
});
