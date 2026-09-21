import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { describe, it, expect, beforeEach } from 'vitest';
import { FleetViewComponent } from './fleet-view.component';
import { FleetCluster } from '../../core/api.models';

const FLEET: FleetCluster[] = [
  {
    name: 'prod-eu',
    sbom_count: 4,
    vuln_count: 7,
    namespaces: [
      { name: 'payments', sbom_count: 2, vuln_count: 5, projects: [
        { name: 'payment-api', sbom_count: 1, vuln_count: 4 },
        { name: 'ledger', sbom_count: 1, vuln_count: 1 },
      ] },
      { name: 'search', sbom_count: 1, vuln_count: 2, projects: [
        { name: 'query-service', sbom_count: 1, vuln_count: 2 },
      ] },
    ],
  },
  // An unlabelled cluster: everything ingested before the layout was configured.
  { name: '', sbom_count: 1, vuln_count: 0, namespaces: [
    { name: '', sbom_count: 1, vuln_count: 0, projects: [{ name: '', sbom_count: 1, vuln_count: 0 }] },
  ] },
];

describe('FleetViewComponent', () => {
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [FleetViewComponent],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
    http = TestBed.inject(HttpTestingController);
  });

  it('loads the whole tree with a single request and auto-selects the first cluster', () => {
    const fixture = TestBed.createComponent(FleetViewComponent);
    fixture.detectChanges();

    http.expectOne('/api/v1/fleet').flush(FLEET);
    // Auto-selection must scope stats to the first cluster, not the fleet.
    http.expectOne('/api/v1/clusters/prod-eu/stats').flush({
      cluster: 'prod-eu', total_sboms: 4, total_packages: 12, total_vulnerabilities: 7,
      critical_vulns: 1, high_vulns: 2, medium_vulns: 3, low_vulns: 1,
      license_breakdown: { permissive: 12 },
    });

    const c = fixture.componentInstance;
    expect(c.clusters.length).toBe(2);
    expect(c.namespaceCount).toBe(3);
    expect(c.selected?.cluster).toBe('prod-eu');
    expect(c.stats?.total_sboms).toBe(4);
    http.verify();
  });

  it('scopes namespace stats to the owning cluster', () => {
    const fixture = TestBed.createComponent(FleetViewComponent);
    fixture.detectChanges();
    http.expectOne('/api/v1/fleet').flush(FLEET);
    http.expectOne('/api/v1/clusters/prod-eu/stats').flush({
      cluster: 'prod-eu', total_sboms: 4, total_packages: 12, total_vulnerabilities: 7,
      critical_vulns: 0, high_vulns: 0, medium_vulns: 0, low_vulns: 0, license_breakdown: {},
    });

    const c = fixture.componentInstance;
    c.selectNamespace(FLEET[0], FLEET[0].namespaces[0]);

    // Without the cluster query param, `payments` from other clusters would
    // silently be merged into these numbers.
    const req = http.expectOne('/api/v1/namespaces/payments/stats?cluster=prod-eu');
    req.flush({
      namespace: 'payments', cluster: 'prod-eu', clusters: ['prod-eu'],
      total_sboms: 2, total_packages: 7, total_vulnerabilities: 5,
      critical_vulns: 1, high_vulns: 1, medium_vulns: 2, low_vulns: 1,
      license_breakdown: { permissive: 7 },
    });

    expect(c.selected?.kind).toBe('namespace');
    expect(c.selectedLabel).toBe('payments');
    expect(c.stats?.total_sboms).toBe(2);
    http.verify();
  });

  it('renders unassigned dimensions instead of hiding them', () => {
    const fixture = TestBed.createComponent(FleetViewComponent);
    fixture.detectChanges();
    http.expectOne('/api/v1/fleet').flush(FLEET);
    http.expectOne('/api/v1/clusters/prod-eu/stats').flush({
      cluster: 'prod-eu', total_sboms: 4, total_packages: 0, total_vulnerabilities: 0,
      critical_vulns: 0, high_vulns: 0, medium_vulns: 0, low_vulns: 0, license_breakdown: {},
    });
    fixture.detectChanges();

    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('(unassigned)');
    // A mixed fleet is configured, so the misconfiguration hint stays hidden.
    expect(fixture.componentInstance.onlyUnassigned).toBe(false);
    http.verify();
  });
});

