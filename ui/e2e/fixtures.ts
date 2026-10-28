import { test as base, expect, Page } from '@playwright/test';

// Every page test fails on a browser console error or a failed /api request:
// a route that renders its shell but never gets data is not "working".
export const test = base.extend<{ page: Page; expectApiErrors: boolean }>({
  // Opt-in for not-found tests, where a 4xx from the API is the point.
  expectApiErrors: [false, { option: true }],
  page: async ({ page, expectApiErrors }, use) => {
    const problems: string[] = [];
    page.on('console', (m) => {
      if (
        m.type() === 'error' &&
        !(expectApiErrors && /HTTP Error|Failed to load resource|Http failure/.test(m.text()))
      ) {
        problems.push(`console: ${m.text()}`);
      }
    });
    page.on('response', (r) => {
      if (!expectApiErrors && r.url().includes('/api/') && r.status() >= 400)
        problems.push(`${r.status()} ${r.url()}`);
    });
    await use(page);
    expect(problems, 'browser errors / failed API calls').toEqual([]);
  },
});

export { expect };

export async function api<T>(page: Page, path: string): Promise<T> {
  const res = await page.request.get(`/api/v1${path}`);
  expect(res.ok(), `GET /api/v1${path}`).toBeTruthy();
  return (await res.json()) as T;
}

export const first = async <T>(page: Page, path: string): Promise<T> => {
  const item = (await api<{ data: T[] }>(page, path)).data?.[0];
  expect(item, `${path} returned no rows – run \`make demo-fleet\` first`).toBeTruthy();
  return item;
};
