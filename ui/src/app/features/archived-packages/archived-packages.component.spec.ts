import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { ArchivedPackagesComponent } from './archived-packages.component';
import { ArchivedRepoGroup, ArchivedRepoSBOM, PaginatedResponse } from '../../core/api.models';

function sbom(over: Partial<ArchivedRepoSBOM> = {}): ArchivedRepoSBOM {
  return { sbom_id: 'sbom-1', project_name: 'k2s', project_version: '0.3.0', ...over };
}

function repo(over: Partial<ArchivedRepoGroup> = {}): ArchivedRepoGroup {
  return { repo: 'go-yaml/yaml', stars: 7019, last_pushed: '2025-04-01T17:00:11Z', sboms: [sbom()], ...over };
}

function page(data: ArchivedRepoGroup[], total = data.length): PaginatedResponse<ArchivedRepoGroup> {
  return { data, total, page: 1, page_size: 20 };
}

describe('ArchivedPackagesComponent', () => {
  let http: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ArchivedPackagesComponent],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  const isRepos = (r: { url: string }) => r.url.endsWith('/packages/archived/repos');

  /** Creates the component and answers the one request it fires. */
  function renderWith(body: PaginatedResponse<ArchivedRepoGroup> | null) {
    const fixture = TestBed.createComponent(ArchivedPackagesComponent);
    fixture.detectChanges();
    http.expectOne(isRepos).flush(body);
    fixture.detectChanges();
    return fixture;
  }

  it('should show loading initially', () => {
    const fixture = TestBed.createComponent(ArchivedPackagesComponent);
    expect(fixture.componentInstance.loading).toBe(true);
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).querySelector('.loading')?.textContent).toContain('Loading');
    http.expectOne(isRepos).flush(page([]));
  });

  it('asks for the first page of grouped repos, not the flat package list', () => {
    const fixture = TestBed.createComponent(ArchivedPackagesComponent);
    fixture.detectChanges();
    const req = http.expectOne(isRepos);
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('page_size')).toBe('20');
    req.flush(page([]));
  });

  it('renders the empty state when nothing is affected', () => {
    const fixture = renderWith(page([]));
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('No archived repositories detected');
    expect(fixture.componentInstance.loading).toBe(false);
  });

  it('survives a null body instead of rendering nothing at all', () => {
    const fixture = renderWith(null);
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('No archived repositories detected');
    expect(fixture.componentInstance.grouped).toEqual([]);
  });

  it('lists the affected projects with one entry per project and a tag per version', () => {
    const fixture = renderWith(page([repo({ sboms: [
      sbom({ sbom_id: 'a', project_name: 'k2s', project_version: '0.3.0' }),
      sbom({ sbom_id: 'b', project_name: 'k2s', project_version: '0.4.0' }),
      sbom({ sbom_id: 'c', project_name: 'prometheus', project_version: '2.51.0' }),
    ] })]));

    const grouped = fixture.componentInstance.grouped;
    expect(grouped.length).toBe(1);
    expect(grouped[0].repo).toBe('go-yaml/yaml');
    expect(grouped[0].projects.map(p => p.projectName)).toEqual(['k2s', 'prometheus']);
    expect(fixture.componentInstance.totalProjects).toBe(2);
    const k2s = grouped[0].projects.find(p => p.projectName === 'k2s')!;
    expect(k2s.versions.map(v => v.version).sort()).toEqual(['0.3.0', '0.4.0']);
  });

  it('uses the reported product version rather than guessing from the name', () => {
    const fixture = renderWith(page([repo()]));
    expect(fixture.componentInstance.grouped[0].projects[0].versions[0].version).toBe('0.3.0');
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('0.3.0');
    expect(text).not.toContain('latest');
  });

  it('falls back to the name heuristic for pre-021 SBOMs', () => {
    const fixture = renderWith(page([repo({ sboms: [sbom({ project_name: 'Cilium - cilium v1.17.13', project_version: '' })] })]));
    const project = fixture.componentInstance.grouped[0].projects[0];
    expect(project.projectName).toBe('Cilium - cilium');
    expect(project.versions[0].version).toBe('1.17.13');
  });

  it('shows the server total and loads the next page on demand', () => {
    const fixture = renderWith(page([repo({ repo: 'a/one' })], 2));
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('.summary-count')?.textContent).toContain('2 archived repo');
    const btn = el.querySelector<HTMLButtonElement>('.load-more-btn')!;
    expect(btn.textContent).toContain('1 / 2');

    btn.click();
    const req = http.expectOne(isRepos);
    expect(req.request.params.get('page')).toBe('2');
    req.flush({ ...page([repo({ repo: 'b/two' })], 2), page: 2 });
    fixture.detectChanges();

    expect(fixture.componentInstance.grouped.map(g => g.repo)).toEqual(['a/one', 'b/two']);
    expect(el.querySelector('.load-more-btn')).toBeNull();
  });

  it('stops loading when the request fails', () => {
    const fixture = TestBed.createComponent(ArchivedPackagesComponent);
    fixture.detectChanges();
    http.expectOne(isRepos).flush('boom', { status: 500, statusText: 'Server Error' });
    fixture.detectChanges();
    expect(fixture.componentInstance.loading).toBe(false);
    expect((fixture.nativeElement as HTMLElement).querySelector('.loading')).toBeNull();
  });
});
