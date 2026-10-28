import { test, expect, api } from './fixtures';

type DepStats = {
  total_unique_deps: number;
  top_dependencies: { package_name: string; project_count: number }[];
};
type Skew = {
  total_skewed_packages: number;
  items: { package_name: string; version_count: number }[];
};
type Global = {
  packages: { package_name: string }[];
  projects: unknown[];
  vulnerabilities: unknown[];
  licenses: unknown[];
};

test.describe('Search & statistics', () => {
  test('/dependencies shows unique count and a sortable virtual list', async ({ page }) => {
    const stats = await api<DepStats>(page, '/stats/dependencies');

    await page.goto('/dependencies');
    await expect(
      page.getByRole('heading', { level: 1, name: 'Dependency Statistics' }),
    ).toBeVisible();
    await expect(page.locator('.summary-card .big-number').first()).toHaveText(
      String(stats.total_unique_deps),
    );
    await expect(page.locator('.dep-row').first()).toBeVisible();

    await page.locator('.table-header .col-name').click();
    await expect(page.locator('.table-header .col-name')).toHaveClass(/active/);
    const names = [...stats.top_dependencies.map((d) => d.package_name)].sort((a, b) =>
      a.localeCompare(b),
    );
    await expect(page.locator('.dep-row .pkg-name').first()).toHaveText(names[0]);
  });

  test('/package-search searches, expands and opens package detail', async ({ page }) => {
    const dep = (await api<DepStats>(page, '/stats/dependencies')).top_dependencies[0];

    await page.goto('/package-search');
    await expect(page.getByRole('heading', { level: 1, name: 'Package Search' })).toBeVisible();
    await expect(page.locator('.empty-state')).toBeVisible();

    await page.getByPlaceholder(/Search package name/).fill(dep.package_name);
    await expect(page.locator('.result-count')).toContainText('packages found');
    const card = page.locator('.result-card', { hasText: dep.package_name }).first();
    await card.click();
    await expect(card.locator('.project-link').first()).toBeVisible();

    // "View all" only renders above 5 projects; the detail route is covered directly.
    await page.goto(`/package-search/${encodeURIComponent(dep.package_name)}`);
    await expect(page.getByRole('heading', { level: 1 })).toContainText(dep.package_name);
    await expect(page.locator('.project-link').first()).toBeVisible();
    await page.getByRole('link', { name: '← Package Search' }).click();
    await expect(page).toHaveURL(/\/package-search$/);
  });

  test('/version-skew lists skewed packages, filters and expands versions', async ({ page }) => {
    const skew = await api<Skew>(page, '/stats/version-skew?page_size=1');
    const item = skew.items[0];

    await page.goto('/version-skew');
    await expect(
      page.getByRole('heading', { level: 1, name: 'Version Consistency' }),
    ).toBeVisible();
    await expect(page.locator('.skew-row').first()).toBeVisible();

    await page.getByPlaceholder('Search packages...').fill(item.package_name);
    const row = page.locator('.skew-row').first();
    await expect(row).toContainText(item.package_name);
    await expect(row.locator('.version-badge')).toHaveText(String(item.version_count));

    await row.click();
    await expect(page.locator('.version-breakdown')).toBeVisible();
    await expect(page.locator('.version-entry')).toHaveCount(item.version_count);
    await page.locator('.version-entry a').first().click();
    await expect(page).toHaveURL(/\/sboms\?search=/);
  });

  test('/archived-packages renders list or empty state', async ({ page }) => {
    const archived = await api<unknown[]>(page, '/packages/archived');
    await page.goto('/archived-packages');
    await expect(
      page.getByRole('heading', { level: 1, name: /Archived Repositories/ }),
    ).toBeVisible();
    if (archived.length) await expect(page.locator('.archived-badge').first()).toBeVisible();
    else await expect(page.locator('.empty-state')).toBeVisible();
  });

  test('navbar global search opens dropdown; /search?q= renders all sections', async ({ page }) => {
    const data = await api<Global>(page, '/search?q=go');
    const pkg = data.packages[0];

    await page.goto('/');
    const input = page.getByPlaceholder('Search packages, projects, CVEs...');
    await input.fill(pkg.package_name);
    await expect(page.locator('.dropdown-panel')).toBeVisible();
    await expect(page.locator('.dropdown-panel .result-item').first()).toContainText(
      pkg.package_name,
    );
    await input.press('Enter');
    await expect(page).toHaveURL(/\/(search\?q=|package-search\/)/);

    await page.goto(`/search?q=${encodeURIComponent(pkg.package_name)}`);
    await expect(page.getByRole('heading', { level: 1, name: 'Global Search' })).toBeVisible();
    const expected = (['packages', 'projects', 'vulnerabilities', 'licenses'] as const).filter(
      (k) => data[k].length,
    );
    await expect(page.locator('.facet-section h2')).toHaveCount(expected.length);
    for (const k of expected) {
      await expect(
        page.getByRole('heading', { level: 2, name: new RegExp(`^${k} \\(`, 'i') }),
      ).toBeVisible();
    }
  });
});
