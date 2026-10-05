import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { ActivatedRoute } from '@angular/router';
import { SbomDetailComponent } from './sbom-detail.component';

describe('SbomDetailComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SbomDetailComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: {
              paramMap: {
                get: (key: string) => key === 'id' ? 'test-sbom-123' : null,
              },
            },
          },
        },
      ],
    }).compileComponents();
  });

  it('should create', () => {
    const fixture = TestBed.createComponent(SbomDetailComponent);
    const component = fixture.componentInstance;
    expect(component).toBeTruthy();
  });

  it('should show loading initially', () => {
    const fixture = TestBed.createComponent(SbomDetailComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.loading')?.textContent).toContain('Loading');
  });

  it('should default to vulns tab', () => {
    const fixture = TestBed.createComponent(SbomDetailComponent);
    const component = fixture.componentInstance;
    expect(component.activeTab).toBe('vulns');
  });

  it('should detect copyleft licenses', () => {
    const fixture = TestBed.createComponent(SbomDetailComponent);
    const component = fixture.componentInstance;
    expect(component.isCopyleft('GPL-3.0-only')).toBe(true);
    expect(component.isCopyleft('AGPL-3.0')).toBe(true);
    expect(component.isCopyleft('MIT')).toBe(false);
    expect(component.isCopyleft('Apache-2.0')).toBe(false);
  });

  it('should explain where a dependency license came from', () => {
    const fixture = TestBed.createComponent(SbomDetailComponent);
    const component = fixture.componentInstance as unknown as {
      flattenTree(nodes: unknown[]): { licenseTitle: string }[];
    };
    const flat = component.flattenTree([
      { index: 0, spdx_id: 'a', name: 'a', version: '1', purl: '', license: 'MIT', license_source: 'npm+latest', children: [] },
      { index: 1, spdx_id: 'b', name: 'b', version: '1', purl: '', license: 'NOASSERTION', license_source: 'not-published', children: [] },
      { index: 2, spdx_id: 'c', name: 'c', version: '1', purl: '', license: 'MIT', children: [] },
    ]);
    expect(flat[0].licenseTitle).toContain('Source: npm registry (taken from the latest release');
    expect(flat[1].licenseTitle).toContain('Unknown: Not published');
    expect(flat[2].licenseTitle).toBe('');
  });

  it('should render every package of an expanded license as a non-shrinking row', () => {
    const fixture = TestBed.createComponent(SbomDetailComponent);
    const component = fixture.componentInstance;
    const packages = Array.from({ length: 85 }, (_, i) => `pkg-${i}`);

    component.detail = {
      sbom_id: 'test-sbom-123',
      source_file: 'test.spdx.json',
      document_name: 'test',
    } as any;
    component.licenses = [
      { license_id: 'NOASSERTION', category: 'unknown', package_count: packages.length, packages },
    ];
    component.activeTab = 'licenses';
    component.expandedLicense = 'NOASSERTION';
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    const items = compiled.querySelectorAll<HTMLElement>('.lic-pkg-item');
    expect(items.length).toBe(85);

    // The list is a column flex container with max-height + overflow-y: auto.
    // Items must not shrink, otherwise all rows get squashed into the
    // container height instead of scrolling (regression: overlapping rows).
    const style = getComputedStyle(items[0]);
    expect(style.flexShrink).toBe('0');
  });

  it('should render the VEX statements scoped to this SBOM (#350)', () => {
    const fixture = TestBed.createComponent(SbomDetailComponent);
    const component = fixture.componentInstance;

    component.detail = {
      sbom_id: 'test-sbom-123',
      source_file: 'test.spdx.json',
      document_name: 'test',
    } as any;
    component.vexStatements = [
      {
        vex_id: 'v1', document_id: 'd', source_file: 'a.openvex.json',
        sbom_id: 'test-sbom-123', product_purl: 'pkg:golang/x@1',
        vuln_id: 'CVE-2026-1', status: 'not_affected',
        justification: 'vulnerable_code_not_in_execute_path',
        vex_timestamp: '2026-09-01T12:00:00Z', ingested_at: '2026-09-02T12:00:00Z',
        tooling: 'VEXViper/0.1.0',
      },
      {
        vex_id: 'v2', document_id: 'd', source_file: 'b.openvex.json',
        sbom_id: 'test-sbom-123', product_purl: 'pkg:golang/y@2',
        vuln_id: 'CVE-2026-2', status: 'affected',
        justification: '',
        vex_timestamp: '2026-09-01T12:00:00Z', ingested_at: '2026-09-02T12:00:00Z',
      },
    ];
    component.activeTab = 'vex';
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    const rows = compiled.querySelectorAll('.vex-row');
    expect(rows.length).toBe(2);

    // Tooling set -> automated badge; no scope badge, every listed
    // statement is scoped to this SBOM (#350).
    expect(rows[0].querySelector('.vex-origin-badge')?.textContent?.trim()).toBe('automated');
    expect(rows[0].querySelector('.vex-scope-badge')).toBeNull();
    expect(rows[1].querySelector('.vex-origin-badge')).toBeNull();
  });

  it('should detect automated statements from role or tooling (#334)', () => {
    const fixture = TestBed.createComponent(SbomDetailComponent);
    const component = fixture.componentInstance;
    expect(component.isAutomated({ tooling: 'VEXViper/0.1.0' } as any)).toBe(true);
    expect(component.isAutomated({ role: 'Automated triage bot' } as any)).toBe(true);
    expect(component.isAutomated({ author: 'Alice' } as any)).toBe(false);
  });
});

