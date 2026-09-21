import { TestBed } from '@angular/core/testing';
import { RouterModule } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { App } from './app';

describe('App', () => {
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    // Ensure localStorage is available in test env
    if (typeof localStorage === 'undefined' || !localStorage.getItem) {
      Object.defineProperty(globalThis, 'localStorage', {
        value: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
        writable: true,
      });
    }
    // Ensure matchMedia is available in test env
    if (typeof window !== 'undefined' && !window.matchMedia) {
      window.matchMedia = () => ({ matches: false, addEventListener: () => {}, removeEventListener: () => {} } as any);
    }

    await TestBed.configureTestingModule({
      imports: [App, RouterModule.forRoot([])],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  /**
   * The navbar asks the API whether this instance has deployment semantics.
   * Every test has to answer that call or verify() fails on it.
   *
   * `clusters` are the raw API rows: '' is the bucket unassigned SBOMs land
   * in and does not make an instance a fleet.
   */
  const flushClusters = (names: string[]) => {
    httpMock.expectOne((r) => r.url.includes('/api/v1/clusters')).flush(
      names.map((name) => ({
        name, sbom_count: 1, package_count: 1, vuln_count: 0,
        last_ingested: '2026-05-01T12:00:00Z',
      })),
    );
  };

  const navLinks = (fixture: { nativeElement: unknown }) =>
    (fixture.nativeElement as HTMLElement).querySelectorAll('.nav-links a');

  it('should create the app', () => {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    expect(fixture.componentInstance).toBeTruthy();
    flushClusters([]);
  });

  it('should render the navbar with brand', () => {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    flushClusters([]);
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.brand')?.textContent).toContain('BOMHort');
  });

  /**
   * Catalogue mode: nothing runs in a cluster, so the API reports only the
   * unnamed bucket. The Fleet tab must not be offered — it would lead to a
   * tree whose single root has no name.
   */
  it('should hide the Fleet tab when no cluster is named', async () => {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    flushClusters(['']);
    await fixture.whenStable();
    fixture.detectChanges();

    const links = navLinks(fixture);
    expect(links.length).toBe(10);
    expect(Array.from(links).map((a) => a.textContent)).not.toContain('Fleet');
    expect(links[0].textContent).toContain('Dashboard');
    expect(links[1].textContent).toContain('Projects');
  });

  /**
   * Fleet mode: as soon as one SBOM carries a cluster label the tab appears,
   * without any configuration change.
   */
  it('should show the Fleet tab once a cluster is named', async () => {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    flushClusters(['prod-eu', '']);
    await fixture.whenStable();
    fixture.detectChanges();

    const links = navLinks(fixture);
    expect(links.length).toBe(11);
    expect(links[1].textContent).toContain('Fleet');
  });

  /** A failing call must not offer a tab that cannot work. */
  it('should hide the Fleet tab when the clusters call fails', async () => {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    httpMock.expectOne((r) => r.url.includes('/api/v1/clusters'))
      .flush('boom', { status: 500, statusText: 'Server Error' });
    await fixture.whenStable();
    fixture.detectChanges();

    expect(fixture.componentInstance.hasFleet).toBe(false);
    expect(navLinks(fixture).length).toBe(10);
  });

  it('should have navigation links', async () => {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    flushClusters(['prod-eu']);
    await fixture.whenStable();
    fixture.detectChanges();

    const links = navLinks(fixture);
    expect(links.length).toBe(11);
    expect(links[0].textContent).toContain('Dashboard');
    expect(links[1].textContent).toContain('Fleet');
    expect(links[2].textContent).toContain('Projects');
    expect(links[3].textContent).toContain('SBOMs');
    expect(links[4].textContent).toContain('Vulnerabilities');
    expect(links[5].textContent).toContain('CVE Impact');
    expect(links[6].textContent).toContain('Licenses');
    expect(links[7].textContent).toContain('Compliance');
    expect(links[8].textContent).toContain('Dependencies');
    expect(links[9].textContent).toContain('Pkg Search');
    expect(links[10].textContent).toContain('Version Skew');
  });
});

