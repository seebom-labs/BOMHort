import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { provideLocationMocks } from '@angular/common/testing';
import { ProjectListComponent } from './project-list.component';
import { TagListItem } from '../../core/api.models';

describe('ProjectListComponent', () => {
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    // RouterTestingHarness instantiates the module, and an instantiated
    // module cannot be reconfigured — so it is reset explicitly rather than
    // relying on the automatic teardown between tests.
    TestBed.resetTestingModule();

    await TestBed.configureTestingModule({
      imports: [ProjectListComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        // A real router, not a stub: the filter state lives in the URL, so
        // stubbing ActivatedRoute would test a mock instead of the wiring
        // that makes a grouping shareable.
        provideRouter([{ path: 'projects', component: ProjectListComponent }]),
        provideLocationMocks(),
      ],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  /** Navigates to the route and returns the component under test. */
  const open = async (url = '/projects') => {
    const harness = await RouterTestingHarness.create(url);
    const component = harness.routeDebugElement!.componentInstance as ProjectListComponent;
    return { harness, component };
  };

  /**
   * The component issues two independent requests on init. Tests that only
   * care about the listing still have to answer the tags call, or verify()
   * fails on an outstanding request.
   */
  const flushTags = (tags: TagListItem[] = []) => {
    httpMock.expectOne((r) => r.url.includes('/api/v1/tags')).flush(tags);
  };

  const flushProjects = (body: Partial<{ data: unknown[]; total: number }> = {}) => {
    httpMock.expectOne((r) => r.url.includes('/api/v1/projects')).flush({
      data: [], total: 0, page: 1, page_size: 100, ...body,
    });
  };

  const k2s = {
    project_name: 'k2s',
    sbom_count: 3,
    package_count: 10,
    vuln_count: 0,
    latest_ingested: '2026-05-01T12:00:00Z',
    latest_sbom_id: 'k2s-1',
    tags: ['sandbox-applications'],
  };

  it('should create', async () => {
    const { component } = await open();
    expect(component).toBeTruthy();

    flushProjects();
    flushTags();
  });

  it('should load projects on init', async () => {
    const { harness, component } = await open();

    const req = httpMock.expectOne((r) => r.url.includes('/api/v1/projects'));
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('page_size')).toBe('100');

    req.flush({
      data: [{ ...k2s, project_name: 'containerd', tags: [] }],
      total: 1, page: 1, page_size: 100,
    });
    flushTags();
    harness.detectChanges();

    expect(component.projects.length).toBe(1);
    expect(component.projects[0].project_name).toBe('containerd');
    expect(component.total).toBe(1);
  });

  it('should search projects with debounce', async () => {
    const { component } = await open();
    flushProjects();
    flushTags();

    component.searchTerm = 'kube';
    component.onSearchChange('kube');

    await new Promise((resolve) => setTimeout(resolve, 350));

    httpMock.expectOne((r) =>
      r.url.includes('/api/v1/projects') && r.params.get('search') === 'kube'
    ).flush({ data: [], total: 0, page: 1, page_size: 100 });
  });

  /**
   * An untagged instance must not send a tag parameter at all. An empty one
   * would read as deliberate to the API and is the kind of difference that
   * quietly changes a query plan.
   */
  it('should omit the tag parameter when no grouping is selected', async () => {
    await open();

    const req = httpMock.expectOne((r) => r.url.includes('/api/v1/projects'));
    expect(req.request.params.has('tag')).toBe(false);

    req.flush({ data: [], total: 0, page: 1, page_size: 100 });
    flushTags();
  });

  it('should filter by tag and reset paging', async () => {
    const { harness, component } = await open();
    flushProjects();
    flushTags([{ tag: 'sandbox-applications', sbom_count: 312, project_count: 41 }]);
    harness.detectChanges();

    expect(component.tags.length).toBe(1);

    component.selectTag('sandbox-applications');
    await harness.fixture.whenStable();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/v1/projects') && r.params.get('tag') === 'sandbox-applications'
    );
    // Paging must restart: keeping a page number from the previous, wider
    // result set would skip the first page of the narrowed one.
    expect(req.request.params.get('page')).toBe('1');

    req.flush({ data: [k2s], total: 1, page: 1, page_size: 100 });
    harness.detectChanges();

    // The tagged project keeps its own identity and version count: a tag
    // groups projects, it never merges them into one row.
    expect(component.projects[0].project_name).toBe('k2s');
    expect(component.projects[0].sbom_count).toBe(3);
  });

  it('should clear the filter when the active tag is clicked again', async () => {
    const { harness, component } = await open();
    flushProjects();
    flushTags([{ tag: 'graduated', sbom_count: 89, project_count: 12 }]);

    component.selectTag('graduated');
    await harness.fixture.whenStable();
    httpMock.expectOne((r) => r.params.get('tag') === 'graduated')
      .flush({ data: [], total: 0, page: 1, page_size: 100 });

    component.selectTag('graduated');
    await harness.fixture.whenStable();
    expect(component.activeTag).toBe('');

    const req = httpMock.expectOne((r) => r.url.includes('/api/v1/projects'));
    expect(req.request.params.has('tag')).toBe(false);
    req.flush({ data: [], total: 0, page: 1, page_size: 100 });
  });

  /**
   * The grouping bar is data-driven, so a failing tags call must degrade to
   * "this instance groups nothing" rather than taking the project listing
   * down with it.
   */
  it('should still show projects when the tags call fails', async () => {
    const { harness, component } = await open();

    flushProjects({ data: [{ ...k2s, project_name: 'containerd', tags: [] }], total: 1 });
    httpMock.expectOne((r) => r.url.includes('/api/v1/tags'))
      .flush('boom', { status: 500, statusText: 'Server Error' });
    harness.detectChanges();

    expect(component.tags.length).toBe(0);
    expect(component.projects.length).toBe(1);
  });

  it('should not repeat the active tag on each row', async () => {
    const { component } = await open();
    flushProjects();
    flushTags();

    component.activeTag = 'sandbox-applications';

    expect(component.otherTags({
      ...k2s, tags: ['sandbox-applications', 'observability'],
    })).toEqual(['observability']);
  });

  // ── Deep linking ────────────────────────────────────────────────────────
  // The whole point of putting the filter in the URL: a grouping is something
  // you can send to someone. These cover the entry path a shared link takes.

  it('should apply a grouping from the URL on load', async () => {
    const { component } = await open('/projects?tag=sandbox-applications');

    const req = httpMock.expectOne((r) => r.url.includes('/api/v1/projects'));
    expect(req.request.params.get('tag')).toBe('sandbox-applications');
    req.flush({ data: [k2s], total: 1, page: 1, page_size: 100 });
    flushTags([{ tag: 'sandbox-applications', sbom_count: 312, project_count: 41 }]);

    // The chip must come up pre-selected, otherwise the link shows filtered
    // data while the UI claims nothing is filtered.
    expect(component.activeTag).toBe('sandbox-applications');
  });

  it('should apply both grouping and search from the URL', async () => {
    const { component } = await open('/projects?tag=graduated&search=prom');

    const req = httpMock.expectOne((r) => r.url.includes('/api/v1/projects'));
    expect(req.request.params.get('tag')).toBe('graduated');
    expect(req.request.params.get('search')).toBe('prom');
    req.flush({ data: [], total: 0, page: 1, page_size: 100 });
    flushTags();

    expect(component.activeTag).toBe('graduated');
    expect(component.searchTerm).toBe('prom');
  });

  it('should write the grouping to the URL when a chip is clicked', async () => {
    const { harness, component } = await open();
    flushProjects();
    flushTags([{ tag: 'incubating', sbom_count: 5, project_count: 2 }]);

    component.selectTag('incubating');
    await harness.fixture.whenStable();
    httpMock.expectOne((r) => r.params.get('tag') === 'incubating')
      .flush({ data: [], total: 0, page: 1, page_size: 100 });

    // Shareable: the state a colleague would receive is in the address bar.
    expect(TestBed.inject(Router).url).toContain('tag=incubating');
  });

  /**
   * Clearing the filter must remove the parameter rather than leave `tag=`
   * behind — a URL carrying an empty filter reads as a deliberate one.
   */
  it('should drop the parameter from the URL when the grouping is cleared', async () => {
    const { harness, component } = await open('/projects?tag=incubating');
    flushProjects();
    flushTags([{ tag: 'incubating', sbom_count: 5, project_count: 2 }]);

    component.selectTag('incubating');
    await harness.fixture.whenStable();
    flushProjects();

    expect(TestBed.inject(Router).url).not.toContain('tag=');
  });

  /**
   * A navigation that does not change the filter must not refetch: the
   * queryParams stream also fires for unrelated parameter changes, and a
   * reload there would throw away rows the user already paged in.
   */
  it('should not reload when the filter state is unchanged', async () => {
    const { harness } = await open('/projects?tag=incubating');
    flushProjects();
    flushTags([{ tag: 'incubating', sbom_count: 5, project_count: 2 }]);

    await TestBed.inject(Router).navigate([], {
      queryParams: { tag: 'incubating', unrelated: '1' },
    });
    await harness.fixture.whenStable();

    // verify() in afterEach fails if this triggered another /projects call.
    expect(true).toBe(true);
  });
});


