import { test, expect, first } from './fixtures';

type Sbom = {
  sbom_id: string;
  document_name: string;
  source_file: string;
  package_count: number;
  vuln_count: number;
};

test.describe('SBOM Explorer', () => {
  test('/sboms lists documents, toggles grouping, filters and links', async ({ page }) => {
    const sbom = await first<Sbom>(page, '/sboms?page_size=1');

    await page.goto('/sboms');
    await expect(page.getByRole('heading', { level: 1, name: 'SBOM Explorer' })).toBeVisible();
    await expect(page.locator('.sbom-link').first()).toBeVisible();

    await page.getByRole('button', { name: 'By project' }).click();
    await expect(page).toHaveURL(/view=grouped/);
    await expect(page.locator('.group-list')).toBeVisible();
    await page.getByRole('button', { name: 'Documents' }).click();
    await expect(page).not.toHaveURL(/view=grouped/);

    await page.locator('main .search-input').fill(sbom.document_name);
    await expect(page.locator('.sbom-link').first()).toContainText(sbom.document_name);
    await page.locator('main .search-input').fill('no-such-sbom-xyz');
    await expect(page.locator('.empty-search')).toBeVisible();
    await page.locator('main .search-input').fill('');

    await page.locator('.sbom-link').first().click();
    await expect(page).toHaveURL(/\/sboms\/[0-9a-f-]{36}$/);
  });

  test('/sboms/:id shows all four tabs and offers the original download', async ({ page }) => {
    const sbom = await first<Sbom>(page, '/sboms?page_size=1');
    await page.goto(`/sboms/${sbom.sbom_id}`);
    await expect(page.getByRole('heading', { level: 1 })).toContainText(
      sbom.document_name || sbom.source_file,
    );
    await expect(page.locator('.tabs button.active')).toContainText('Vulnerabilities');

    for (const tab of ['Licenses', 'VEX', 'Dependencies']) {
      await page.locator('.tabs button', { hasText: tab }).click();
      await expect(page.locator('.tab-content')).toBeVisible();
    }
    await expect(page.locator('.tabs button', { hasText: 'Dependencies' })).toContainText(
      `(${sbom.package_count})`,
    );
    await expect(page.locator('.dep-row').first()).toBeVisible();

    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: /Download/ }).click();
    expect((await download).suggestedFilename()).toMatch(/\.json$/);
  });
});

test.describe('not found', () => {
  test.use({ expectApiErrors: true });
  test('/sboms/:id for an unknown id stays on the loading state', async ({ page }) => {
    // shortcut: the page has no not-found state yet, it keeps "Loading"; tighten when one exists.
    await page.goto('/sboms/00000000-0000-0000-0000-000000000000');
    await expect(page.locator('.loading')).toContainText('Loading SBOM details');
  });
});
