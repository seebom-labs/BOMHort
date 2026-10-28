import { test, expect, first } from './fixtures';

type Project = { project_name: string; sbom_count: number };

test.describe('Projects', () => {
  test('/projects lists, filters and links to a project', async ({ page }) => {
    const project = await first<Project>(page, '/projects?page_size=1');

    await page.goto('/projects');
    await expect(page.getByRole('heading', { level: 1, name: 'Projects' })).toBeVisible();
    await expect(page.locator('.project-link').first()).toBeVisible();

    await page.getByPlaceholder('Search projects…').fill(project.project_name);
    await expect(page.locator('.search-hint')).toContainText(project.project_name);
    const links = page.locator('.project-link');
    await expect(links.first()).toContainText(project.project_name);

    await page.getByPlaceholder('Search projects…').fill('no-such-project-xyz');
    await expect(page.locator('.empty-search')).toBeVisible();
    await page.locator('.clear-btn').click();
    await expect(page.locator('.empty-search')).toHaveCount(0);

    await links.first().click();
    await expect(page).toHaveURL(/\/projects\/.+/);
  });

  test('/projects/:name shows every tab with virtual-scrolled rows', async ({ page }) => {
    const project = await first<Project>(page, '/projects?page_size=1');
    await page.goto(`/projects/${encodeURIComponent(project.project_name)}`);
    await expect(page.getByRole('heading', { level: 1, name: project.project_name })).toBeVisible();
    await expect(page.locator('.tabs button.active')).toHaveText('Overview');

    await page.locator('.tabs button', { hasText: 'Versions' }).click();
    await expect(page.locator('cdk-virtual-scroll-viewport .row')).toHaveCount(project.sbom_count);

    await page.locator('.tabs button', { hasText: 'Vulnerabilities' }).click();
    await expect(page.locator('.tab-content')).toBeVisible();

    await page.locator('.tabs button', { hasText: 'Packages' }).click();
    await expect(page.getByPlaceholder('Filter components by name or PURL…')).toBeVisible();
    await expect(page.locator('.pkg-row').first()).toBeVisible();

    await page.locator('.tabs button', { hasText: 'Versions' }).click();
    await page.locator('cdk-virtual-scroll-viewport .row-link').first().click();
    await expect(page).toHaveURL(/\/sboms\/[0-9a-f-]{36}$/);
  });
});

test.describe('not found', () => {
  test.use({ expectApiErrors: true });
  test('/projects/:name for an unknown project shows not-found', async ({ page }) => {
    await page.goto('/projects/definitely-not-a-project');
    await expect(page.getByRole('heading', { level: 1, name: 'Project not found' })).toBeVisible();
  });
});
