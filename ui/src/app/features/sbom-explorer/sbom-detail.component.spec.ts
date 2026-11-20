import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { ActivatedRoute } from '@angular/router';
import { afterEach, beforeEach as beforeEachVi, vi } from 'vitest';
import { By } from '@angular/platform-browser';
import { SbomDetailComponent } from './sbom-detail.component';
import { DependencyTreeComponent } from './dependency-tree.component';
import { CdkVirtualScrollViewport } from '@angular/cdk/scrolling';

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

// Dependency tree (#56): the page loads its data through the real requests,
// the test answers them.
describe('SbomDetailComponent dependency tree', () => {
  const dep = (index: number, name: string, children: number[], scope: string) => ({
    index, spdx_id: name, name, version: '1.0.0', purl: `pkg:npm/${name}@1.0.0`,
    license: 'MIT', children, dependency_scope: scope,
  });
  const graph = [
    dep(0, 'app', [1, 2], 'root'),
    dep(1, 'express', [3], 'direct'),
    dep(2, 'lodash', [], 'direct'),
    dep(3, 'debug', [], 'transitive'),
  ];

  async function load(deps: object[], vulns: object[] = []) {
    await TestBed.configureTestingModule({
      imports: [SbomDetailComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: ActivatedRoute, useValue: { snapshot: { paramMap: { get: () => 's1' } } } },
      ],
    }).compileComponents();
    const fixture = TestBed.createComponent(SbomDetailComponent);
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    const answers: [string, object][] = [
      ['/detail', { sbom_id: 's1', source_file: 'a.spdx.json', document_name: 'app', package_count: deps.length }],
      ['/vulnerabilities', vulns],
      ['/licenses', []],
      ['/dependencies', deps],
      ['/vex', []],
      ['/packages/archived', []],
    ];
    for (const [suffix, body] of answers) {
      http.expectOne((r) => r.url.endsWith(suffix)).flush(body);
    }
    fixture.componentInstance.activeTab = 'deps';
    await settle(fixture);
    return fixture;
  }

  // cdk-virtual-scroll renders the rows that fit its measured height, which
  // is 0 without a layout engine. Give the viewport one so rows render.
  beforeEachVi(() => {
    vi.spyOn(Element.prototype, 'clientHeight', 'get').mockReturnValue(600);
    vi.spyOn(Element.prototype, 'clientWidth', 'get').mockReturnValue(1000);
  });
  afterEach(() => vi.restoreAllMocks());

  async function settle(fixture: { detectChanges(): void; whenStable(): Promise<unknown> }) {
    for (let i = 0; i < 3; i++) {
      fixture.detectChanges();
      await fixture.whenStable();
      await new Promise((r) => setTimeout(r, 20));
    }
    fixture.detectChanges();
  }

  const treeOf = (fixture: ComponentFixture<SbomDetailComponent>) =>
    fixture.debugElement.query(By.directive(DependencyTreeComponent)).componentInstance as DependencyTreeComponent;

  const rowNames = (el: HTMLElement) =>
    [...el.querySelectorAll('.dep-row .dep-name')].map((n) => n.firstChild?.textContent?.trim());

  it('opens on the tree with the product expanded', async () => {
    const fixture = await load(graph);
    const c = treeOf(fixture);
    expect(c.view).toBe('tree');
    expect(c.treeRows.map((r) => r.index)).toEqual([0, 1, 2]);
    // The tab still counts every package, not the visible rows.
    const tab = [...(fixture.nativeElement as HTMLElement).querySelectorAll('.tabs button')]
      .find((b) => b.textContent?.includes('Dependencies'));
    expect(tab?.textContent).toContain('(4)');
  });

  it('expands and collapses a package', async () => {
    const fixture = await load(graph);
    const c = treeOf(fixture);
    c.toggleRow(c.treeRows[1]);
    expect(c.treeRows.map((r) => r.index)).toEqual([0, 1, 3, 2]);
    expect(c.treeRows[1].expanded).toBe(true);
    c.toggleRow(c.treeRows[1]);
    expect(c.treeRows.map((r) => r.index)).toEqual([0, 1, 2]);
    c.toggleRow(c.treeRows[1]);
    c.collapseAll();
    expect(c.treeRows.map((r) => r.index)).toEqual([0, 1, 2]);
  });

  it('marks tree rows for assistive technology', async () => {
    const fixture = await load(graph);
    const el = fixture.nativeElement as HTMLElement;
    const items = el.querySelectorAll('[role="treeitem"]');
    expect(items.length).toBeGreaterThan(0);
    expect(items[0].getAttribute('aria-level')).toBe('1');
    expect(items[0].getAttribute('aria-expanded')).toBe('true');
    expect(el.querySelector('[role="tree"]')).not.toBeNull();
  });

  it('searches the tree down to the match, and the list', async () => {
    const fixture = await load(graph);
    const c = treeOf(fixture);
    c.onSearch('debug');
    expect(c.treeRows.map((r) => r.index)).toEqual([0, 1, 3]);
    expect(c.treeRows[2].match).toBe(true);
    expect(c.listDeps.map((d) => d.name)).toEqual(['debug']);
    const search = (fixture.nativeElement as HTMLElement).querySelector<HTMLInputElement>('.dep-search')!;
    search.value = 'debug';
    search.dispatchEvent(new Event('input'));
    await settle(fixture);
    // While searching, manual expansion is ignored: no toggle is offered.
    expect((fixture.nativeElement as HTMLElement).querySelectorAll('.tree-toggle').length).toBe(0);
    expect(rowNames(fixture.nativeElement)).toEqual(['app', 'express', 'debug']);
    search.value = 'zzz';
    search.dispatchEvent(new Event('input'));
    await settle(fixture);
    expect((fixture.nativeElement as HTMLElement).querySelector('.dep-hint')?.textContent).toContain('No dependencies match');
  });

  it('falls back to the list when the SBOM has no relationships', async () => {
    const fixture = await load([dep(0, 'a', [], 'unknown'), dep(1, 'b', [], 'unknown')]);
    const c = treeOf(fixture);
    expect(c.view).toBe('list');
    c.setView('tree');
    expect(c.view).toBe('list');
    const treeBtn = [...(fixture.nativeElement as HTMLElement).querySelectorAll<HTMLButtonElement>('.toggle-btn')]
      .find((b) => b.textContent?.trim() === 'Tree');
    expect(treeBtn?.disabled).toBe(true);
    expect(rowNames(fixture.nativeElement)).toEqual(['a', 'b']);
  });

  it('shows open findings per package, without the ones VEX resolved', async () => {
    const fixture = await load(graph, [
      { vuln_id: 'V1', severity: 'MEDIUM', purl: 'pkg:npm/express@1.0.0' },
      { vuln_id: 'V2', severity: 'CRITICAL', purl: 'pkg:npm/express@1.0.0' },
      { vuln_id: 'V3', severity: 'HIGH', purl: 'pkg:npm/lodash@1.0.0', vex_status: 'not_affected' },
    ]);
    const c = treeOf(fixture);
    expect(c.vulnSummary('pkg:npm/express@1.0.0')).toEqual({ count: 2, worst: 'CRITICAL' });
    expect(c.vulnSummary('pkg:npm/lodash@1.0.0')).toBeNull();
    const badge = (fixture.nativeElement as HTMLElement).querySelector('.dep-vulns');
    expect(badge?.textContent?.trim()).toBe('2');
    expect(badge?.classList.contains('sev-critical')).toBe(true);
  });
  // WAI-ARIA tree pattern (#56 review): the rows themselves take the
  // keyboard, with a single tab stop that follows focus.
  describe('keyboard', () => {
    const items = (el: HTMLElement) => [...el.querySelectorAll<HTMLElement>('[role="treeitem"]')];
    const name = (el: Element | null) => el?.querySelector('.dep-name')?.firstChild?.textContent?.trim();
    async function press(fixture: ComponentFixture<SbomDetailComponent>, key: string) {
      (document.activeElement as HTMLElement).dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true }));
      await settle(fixture);
      return document.activeElement;
    }

    it('is a single tab stop; the toggles are not in the tab order', async () => {
      const fixture = await load(graph);
      const el = fixture.nativeElement as HTMLElement;
      const stops = items(el).filter((i) => i.getAttribute('tabindex') === '0');
      expect(stops.map(name)).toEqual(['app']);
      expect(items(el).filter((i) => i.getAttribute('tabindex') === '-1').length).toBe(items(el).length - 1);
      expect([...el.querySelectorAll('.tree-toggle')].every((b) => b.getAttribute('tabindex') === '-1')).toBe(true);
      expect(items(el).map((i) => [i.getAttribute('aria-posinset'), i.getAttribute('aria-setsize')]))
        .toEqual([['1', '1'], ['1', '2'], ['2', '2']]);
    });

    it('moves between rows, into children, to leaves and back to parents', async () => {
      const fixture = await load(graph);
      const el = fixture.nativeElement as HTMLElement;
      items(el)[0].focus();
      expect(name(await press(fixture, 'ArrowDown'))).toBe('express');
      expect(name(await press(fixture, 'ArrowDown'))).toBe('lodash');
      expect(name(await press(fixture, 'ArrowDown'))).toBe('lodash'); // last row: stays
      expect(name(await press(fixture, 'ArrowUp'))).toBe('express');

      // Right on a collapsed parent expands it and keeps focus there ...
      let focused = await press(fixture, 'ArrowRight');
      expect(name(focused)).toBe('express');
      expect(focused?.getAttribute('aria-expanded')).toBe('true');
      // ... a second Right moves to its first child, a leaf.
      focused = await press(fixture, 'ArrowRight');
      expect(name(focused)).toBe('debug');
      expect(focused?.getAttribute('aria-level')).toBe('3');
      // Left on a leaf goes to the parent, then collapses it, then goes up.
      expect(name(await press(fixture, 'ArrowLeft'))).toBe('express');
      focused = await press(fixture, 'ArrowLeft');
      expect(name(focused)).toBe('express');
      expect(focused?.getAttribute('aria-expanded')).toBe('false');
      expect(name(await press(fixture, 'ArrowLeft'))).toBe('app');

      expect(name(await press(fixture, 'End'))).toBe('lodash');
      expect(name(await press(fixture, 'Home'))).toBe('app');
      // Enter and Space toggle; the tab stop follows focus.
      focused = await press(fixture, 'Enter');
      expect(focused?.getAttribute('aria-expanded')).toBe('false');
      expect(items(el).map(name)).toEqual(['app']);
      focused = await press(fixture, ' ');
      expect(focused?.getAttribute('aria-expanded')).toBe('true');
      expect(focused?.getAttribute('tabindex')).toBe('0');
    });

    it('scrolls a row that virtual scrolling has not rendered into view', async () => {
      const many = [dep(0, 'app', Array.from({ length: 300 }, (_, i) => i + 1), 'root'),
        ...Array.from({ length: 300 }, (_, i) => dep(i + 1, `pkg-${i + 1}`, [], 'direct'))];
      const fixture = await load(many);
      const viewport = fixture.debugElement.query(By.directive(CdkVirtualScrollViewport))
        .componentInstance as CdkVirtualScrollViewport;
      expect(viewport.getRenderedRange().end).toBeLessThan(301); // only part of the tree is rendered
      const scroll = vi.spyOn(viewport, 'scrollToIndex').mockImplementation(() => {});
      items(fixture.nativeElement)[0].focus();
      await press(fixture, 'End');
      expect(scroll).toHaveBeenCalledWith(300);
      expect(treeOf(fixture).activeKey).toBe('0/300');
    });
  });

  it('treats a whitespace-only search as no search', async () => {
    const fixture = await load(graph);
    const el = fixture.nativeElement as HTMLElement;
    const toggles = el.querySelectorAll('.tree-toggle').length;
    const search = el.querySelector<HTMLInputElement>('.dep-search')!;
    search.value = '   ';
    search.dispatchEvent(new Event('input'));
    await settle(fixture);
    expect(el.querySelectorAll('.tree-toggle').length).toBe(toggles);
    expect(treeOf(fixture).treeRows.map((r) => r.index)).toEqual([0, 1, 2]);
    expect(el.querySelector('.dep-hint')).toBeNull();
    expect(el.querySelector('.dep-collapse')).not.toBeNull();
  });
});

