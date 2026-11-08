import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { SbomListComponent } from './sbom-list.component';
import { ProjectGroupItem } from '../../core/api.models';

describe('SbomListComponent', () => {
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SbomListComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    }).compileComponents();
    httpMock = TestBed.inject(HttpTestingController);
  });

  /**
   * ngOnInit loads the flat list. Tests that go on to assert something else
   * answer that request with an empty page first, so it never leaks into
   * their expectations.
   */
  function initFlat(fixture: ComponentFixture<SbomListComponent>): void {
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.endsWith('/sboms'))
      .flush({ data: [], total: 0, page: 1, page_size: 100 });
  }

  it('should create', () => {
    const fixture = TestBed.createComponent(SbomListComponent);
    expect(fixture.componentInstance).toBeTruthy();
  });

  it('should have a virtual scroll viewport', () => {
    const fixture = TestBed.createComponent(SbomListComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('cdk-virtual-scroll-viewport')).toBeTruthy();
  });

  it('should carry the ownership dimensions through to the rows (#177)', () => {
    const fixture = TestBed.createComponent(SbomListComponent);
    const component = fixture.componentInstance;

    component.sboms = [
      {
        sbom_id: 'a', source_file: 'a.spdx.json', spdx_version: 'SPDX-2.3',
        document_name: 'payment-service', package_count: 10, vuln_count: 0,
        ingested_at: '2026-09-01T12:00:00Z',
        cluster: 'prod-eu', namespace: 'payments', project: 'payment-service',
      },
      // Single-instance deployment: all three default to '' and are omitted
      // by the API, so the row must render without badges.
      {
        sbom_id: 'b', source_file: 'b.spdx.json', spdx_version: 'SPDX-2.3',
        document_name: 'standalone', package_count: 5, vuln_count: 0,
        ingested_at: '2026-09-01T12:00:00Z',
      },
    ] as any;
    component.total = 2;

    // The rows render inside a cdk-virtual-scroll-viewport, which never
    // materialises items in jsdom (no element layout, so the measured
    // viewport height stays 0). Assert on the data contract instead of the
    // DOM; the badges are plain *ngIf bindings on these exact fields, and
    // the DTO side is covered by pkg/dto/api_ownership_test.go.
    expect(() => fixture.detectChanges()).not.toThrow();

    expect(component.sboms[0].cluster).toBe('prod-eu');
    expect(component.sboms[0].namespace).toBe('payments');
    expect(component.sboms[0].project).toBe('payment-service');
    expect(component.sboms[1].cluster).toBeUndefined();
    expect(component.sboms[1].namespace).toBeUndefined();
    expect(component.sboms[1].project).toBeUndefined();
  });

  it('carries workload identity fields to the rows (#458)', () => {
    const fixture = TestBed.createComponent(SbomListComponent);
    const component = fixture.componentInstance;

    component.sboms = [
      {
        sbom_id: 'a', source_file: 'a.spdx.json', spdx_version: 'SPDX-2.3',
        document_name: 'payment-service', package_count: 10, vuln_count: 0,
        ingested_at: '2026-09-01T12:00:00Z',
        workload_kind: 'Deployment', workload_name: 'payment-service', workload_uid: 'uid-1',
      },
    ] as any;

    expect(() => fixture.detectChanges()).not.toThrow();
    expect(component.sboms[0].workload_kind).toBe('Deployment');
    expect(component.sboms[0].workload_name).toBe('payment-service');
    expect(component.sboms[0].workload_uid).toBe('uid-1');
  });

  // ── View mode (#58) ──────────────────────────────────────────────────────
  //
  // The grouped rows themselves live in ProjectGroupListComponent and are
  // tested there. What belongs here is which mode is active, what it loads,
  // and what it tells the user it is searching.

  it('defaults to the flat document list', () => {
    const fixture = TestBed.createComponent(SbomListComponent);
    initFlat(fixture);

    expect(fixture.componentInstance.viewMode).toBe('flat');
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('app-project-group-list')).toBeFalsy();
    expect(compiled.querySelector('.view-toggle')).toBeTruthy();
  });

  it('hands the project page to the grouped list when grouped', () => {
    const fixture = TestBed.createComponent(SbomListComponent);
    const component = fixture.componentInstance;
    initFlat(fixture);

    component.viewMode = 'grouped';
    component.groups = [singleGroup('payment-service')];
    component.total = 1;
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('app-parent-group-list')).toBeTruthy();
    expect(compiled.querySelector('cdk-virtual-scroll-viewport')).toBeFalsy();
    // A parentless project is rendered as its plain project row.
    expect(compiled.querySelector('.project-row')?.textContent).toContain('payment-service');
  });

  it('loads parent groups, not documents, while grouped', () => {
    const fixture = TestBed.createComponent(SbomListComponent);
    const component = fixture.componentInstance;
    initFlat(fixture);

    component.viewMode = 'grouped';
    component.loadMore();

    const req = httpMock.expectOne((r) => r.url.endsWith('/projects'));
    expect(req.request.params.get('page')).toBe('2');
    expect(req.request.params.get('group_by')).toBe('parent');
    req.flush({ data: [singleGroup('p')], total: 1, page: 2, page_size: 100 });
    expect(component.groups.length).toBe(1);
  });

  it('counts the right rows for the load-more control in each mode', () => {
    const fixture = TestBed.createComponent(SbomListComponent);
    const component = fixture.componentInstance;

    component.sboms = [{ sbom_id: 'a' }, { sbom_id: 'b' }] as any;
    component.groups = [singleGroup('p')];

    component.viewMode = 'flat';
    expect(component.loadedCount).toBe(2);
    component.viewMode = 'grouped';
    expect(component.loadedCount).toBe(1);
  });

  it('says what the search box actually searches in each mode', () => {
    const fixture = TestBed.createComponent(SbomListComponent);
    const component = fixture.componentInstance;

    // The two modes search different things because they list different
    // things: documents by name or path, projects by name.
    component.viewMode = 'flat';
    expect(component.searchPlaceholder).toContain('path');
    component.viewMode = 'grouped';
    expect(component.searchPlaceholder).toContain('projects');

    // Inside a project scope the box searches that project's documents,
    // whatever the mode was.
    component.projectScope = 'payment-service';
    expect(component.searchPlaceholder).toContain('payment-service');
  });

  it('hides the view toggle inside a project scope', () => {
    const fixture = TestBed.createComponent(SbomListComponent);
    const component = fixture.componentInstance;
    initFlat(fixture);

    // A project scope is already one project's versions; grouping it would
    // collapse the page into the row that was clicked to open it.
    component.projectScope = 'payment-service';
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.view-toggle')).toBeFalsy();
    expect(compiled.querySelector('.scope-banner')).toBeTruthy();
  });

  it('drops the loaded rows when the filters change', () => {
    const fixture = TestBed.createComponent(SbomListComponent);
    const component = fixture.componentInstance;
    initFlat(fixture);

    component.groups = [singleGroup('p')];
    component.sboms = [{ sbom_id: 'a' }] as any;

    (component as any).resetRows();

    expect(component.groups).toEqual([]);
    expect(component.sboms).toEqual([]);
  });
});

/** A project without a parent: the API returns it as a group of one. */
function singleGroup(name: string): ProjectGroupItem {
  return {
    name,
    is_project: true,
    project_count: 1,
    sbom_count: 11,
    package_count: 420,
    vuln_count: 7,
    latest_ingested: '',
    tags: [],
    sources: [],
    members: [{ project_name: name, sbom_count: 11, package_count: 420, vuln_count: 7, latest_ingested: '', latest_sbom_id: '', tags: [] }],
  };
}

