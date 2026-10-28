import { test, expect, api } from './fixtures';

type Cluster = { name: string; namespaces: { name: string; projects: { name: string }[] }[] };

test.describe('Fleet /fleet', () => {
  // selectCluster() treats a 404 from /clusters/{name}/stats as "no stats", by design.
  test.use({ expectApiErrors: true });
  test('nav shows Fleet only when clusters exist, tree drills cluster → namespace → project', async ({
    page,
  }) => {
    const fleet = await api<Cluster[]>(page, '/fleet');
    const cluster = fleet.find((c) => c.name)!;
    expect(cluster, 'demo fleet has at least one named cluster').toBeTruthy();

    await page.goto('/');
    await page.getByRole('navigation').getByRole('link', { name: 'Fleet' }).click();
    await expect(page).toHaveURL(/\/fleet$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Fleet' })).toBeVisible();

    const clusterNode = page.locator('.cluster-node', { hasText: cluster.name });
    await clusterNode.click();
    await expect(clusterNode).toHaveClass(/selected/);
    await expect(page.locator('aside.detail')).toContainText('Cluster:');
    await expect(page.locator('aside.detail dl.stats').first()).toContainText('SBOMs');

    const ns = cluster.namespaces.find((n) => n.name)!;
    const nsNode = page.locator('.namespace-node', { hasText: ns.name }).first();
    await nsNode.click();
    await expect(nsNode).toHaveClass(/selected/);
    await expect(page.locator('aside.detail')).toContainText(`in cluster ${cluster.name}`);

    const project = ns.projects.find((p) => p.name)!;
    await page.locator('.project-node', { hasText: project.name }).first().click();
    await expect(page).toHaveURL(new RegExp(`/sboms\\?search=${encodeURIComponent(project.name)}`));
  });
});
