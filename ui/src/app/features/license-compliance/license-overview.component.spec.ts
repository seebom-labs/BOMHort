import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { LicenseOverviewComponent } from './license-overview.component';

describe('LicenseOverviewComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [LicenseOverviewComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    }).compileComponents();
  });

  it('should create', () => {
    const fixture = TestBed.createComponent(LicenseOverviewComponent);
    const component = fixture.componentInstance;
    expect(component).toBeTruthy();
  });

  it('should show category cards', () => {
    const fixture = TestBed.createComponent(LicenseOverviewComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    const cards = compiled.querySelectorAll('.category-card');
    // permissive, copyleft, not approved, unknown, exempted
    expect(cards.length).toBe(5);
    expect(compiled.querySelector('.category-card.unapproved h3')?.textContent).toContain('Not Approved');
  });

  it('splits license sources into resolved, open and excluded', () => {
    const fixture = TestBed.createComponent(LicenseOverviewComponent);
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/licenses/compliance').flush([]);
    http.expectOne('/api/v1/licenses/sources').flush([
      { source: 'declared', origin: 'declared', modifiers: [], resolved: true, package_count: 10, sbom_count: 2, examples: ['a'] },
      { source: 'declared+normalized', origin: 'declared', modifiers: ['normalized'], resolved: true, package_count: 2, sbom_count: 1, examples: ['n'] },
      { source: 'pypi+latest', origin: 'pypi', modifiers: ['latest'], resolved: true, package_count: 3, sbom_count: 1, examples: ['b'] },
      { source: 'npm', origin: 'npm', modifiers: [], resolved: true, package_count: 3, sbom_count: 1, examples: ['d'] },
      { source: 'not-published', origin: 'not-published', modifiers: [], resolved: false, package_count: 2, sbom_count: 1, examples: ['c', 'e'] },
      { source: 'first-party', origin: 'first-party', modifiers: [], resolved: false, package_count: 7, sbom_count: 3, examples: ['self'] },
    ]);
    fixture.detectChanges();
    const c = fixture.componentInstance;
    expect(c.resolvedTotal).toBe(18);
    expect(c.openTotal).toBe(2);
    // Declared licenses are not a gap; first-party is not counted.
    expect(c.registryResolvedTotal).toBe(6);
    expect(c.gapTotal).toBe(8);
    expect(c.resolvedShare).toBe('75.0%');

    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('.resolution-headline')?.textContent).toContain('75.0%');
    const rows = el.querySelectorAll('.reason-row');
    expect(rows.length).toBe(1);
    expect(rows[0].querySelector('.reason-label')?.textContent).toContain('Not published');
    expect(rows[0].querySelector('.reason-examples')?.textContent).toContain('c, e');
    expect(rows[0].querySelector('.reason-hint')?.textContent).toContain('license exception');
    expect(el.querySelector('.resolution-excluded')?.textContent).toContain('7 first-party components');
  });

  it('shows no gap headline when every dependency has a license', () => {
    const fixture = TestBed.createComponent(LicenseOverviewComponent);
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/licenses/compliance').flush([]);
    http.expectOne('/api/v1/licenses/sources').flush([
      { source: 'declared', origin: 'declared', modifiers: [], resolved: true, package_count: 10, sbom_count: 2, examples: ['a'] },
    ]);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('.resolution-headline')).toBeNull();
    expect(el.querySelector('.resolution-empty')?.textContent).toContain('Every dependency has a license');

    fixture.componentInstance.toggleResolution();
    fixture.detectChanges();
    expect(el.querySelector('.resolution-content')).toBeNull();
  });
});
