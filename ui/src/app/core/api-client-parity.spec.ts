import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { describe, it, expect, beforeEach } from 'vitest';
import { ApiService } from './api.service';
import { BomhortApiClient } from '@bomhort/api-client';

// The fetch client is the published contract; the Angular service is one
// consumer. This test proves every method issues the identical request so
// a component ported to another framework hits the same endpoints.
const calls: Record<string, unknown[]> = {
  getDashboardStats: [],
  getSboms: [2, 25, 'gin', 'payment-api'],
  getSbomDetail: ['id-1'],
  getSbomDependencies: ['id-1'],
  getSbomVulnerabilities: ['id-1', 'direct'],
  getSbomVex: ['id-1'],
  getSbomLicenses: ['id-1'],
  getVulnerabilities: [3, 10, 'transitive'],
  getAffectedProjectsByCVE: ['CVE-2024-1'],
  getLicenseCompliance: ['GPL-3.0-only'],
  getLicenseSources: [],
  getProjectsWithLicenseViolations: [],
  getProjectLicenseViolationSummaries: ['pay'],
  getDependencyStats: [0], // 0 is a real value and must not be dropped like '' / undefined
  getVersionSkew: [1, 20, 'lodash'],
  getVEXStatements: [1, 50],
  getLicenseExceptions: [],
  getArchivedPackages: [],
  searchPackages: ['net', 2, 10],
  getPackageDetail: ['golang.org/x/net', 1, 50],
  getProjects: [1, 50, '', 'sandbox'],
  getProjectGroups: [1, 50, 'api', ''],
  getTags: [],
  getProjectDetail: ['org/project'],
  getProjectSboms: ['org/project', 1, 50],
  getProjectVulnerabilities: ['org/project', 'root'],
  getProjectPackages: ['org/project', 1, 50, 'x'],
  globalSearch: ['go', 5],
  getFleet: [],
  getClusters: [],
  getClusterStats: ['prod-eu'],
  getClusterSboms: ['prod-eu', 1, 50],
  getNamespaces: ['prod-eu'],
  getNamespaceStats: ['payments', 'prod-eu'],
  getNamespaceSboms: ['payments', 'prod-eu', 2, 50],
};

describe('ApiService ↔ @bomhort/api-client parity', () => {
  let service: ApiService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    service = TestBed.inject(ApiService);
    http = TestBed.inject(HttpTestingController);
  });

  for (const [method, args] of Object.entries(calls)) {
    it(`${method} requests the same URL`, async () => {
      let fetched = '';
      const client = new BomhortApiClient({
        fetch: async (input) => {
          fetched = String(input);
          return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
        },
      });
      const svc = service as unknown as Record<string, (...a: unknown[]) => { subscribe(): void }>;
      const cli = client as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;

      svc[method](...args).subscribe();
      const req = http.expectOne(() => true);
      req.flush({});
      await cli[method](...args);

      // Same path and same decoded params; HttpParams leaves "/" unencoded and
      // orders keys differently, both irrelevant to the server.
      const a = new URL(fetched, 'http://h');
      const b = new URL(req.request.urlWithParams, 'http://h');
      expect(a.pathname).toBe(b.pathname);
      expect([...a.searchParams.entries()].sort()).toEqual([...b.searchParams.entries()].sort());
      http.verify();
    });
  }

  it('download and report URLs match', () => {
    const client = new BomhortApiClient();
    expect(client.getSbomDownloadUrl('abc')).toBe(service.getSbomDownloadUrl('abc'));
    expect(client.vulnerabilityReportUrl('direct')).toBe(service.vulnerabilityReportUrl('direct'));
    expect(client.vulnerabilityReportUrl()).toBe(service.vulnerabilityReportUrl());
  });

  it('every ApiService method has a counterpart', () => {
    const own = Object.getOwnPropertyNames(ApiService.prototype).filter((n) => n !== 'constructor');
    const covered = new Set([...Object.keys(calls), 'getSbomDownloadUrl', 'vulnerabilityReportUrl']);
    expect(own.filter((n) => !covered.has(n))).toEqual([]);
    for (const n of own) expect(typeof (BomhortApiClient.prototype as never)[n]).toBe('function');
  });

  it('throws ApiError with status and body on non-2xx', async () => {
    const client = new BomhortApiClient({
      baseUrl: 'https://x/api/v1/',
      apiKey: 'k',
      fetch: async (_i, init) => {
        expect((init?.headers as Record<string, string>)['X-API-Key']).toBe('k');
        return new Response('nope', { status: 404 });
      },
    });
    await expect(client.getTags()).rejects.toMatchObject({ name: 'ApiError', status: 404, body: 'nope', url: 'https://x/api/v1/tags' });
  });
});
