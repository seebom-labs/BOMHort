import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { ArchivedPackagesComponent } from './archived-packages.component';
import { ArchivedPackageInfo } from '../../core/api.models';

/** One API row, overridable per test. */
function row(over: Partial<ArchivedPackageInfo> = {}): ArchivedPackageInfo {
  return {
    sbom_id: 'sbom-1',
    source_file: 'k2s/k2s-0.3.0.spdx.json',
    project_name: 'k2s',
    project_version: '0.3.0',
    package_name: 'gopkg.in/yaml.v3',
    package_purl: 'pkg:golang/gopkg.in/yaml.v3@v3.0.1',
    repo: 'go-yaml/yaml',
    last_pushed: '2025-04-01T17:00:11Z',
    stars: 7019,
    ...over,
  };
}

describe('ArchivedPackagesComponent', () => {
  let http: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ArchivedPackagesComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  /** Creates the component and answers the one request it fires. */
  function renderWith(body: ArchivedPackageInfo[] | null) {
    const fixture = TestBed.createComponent(ArchivedPackagesComponent);
    fixture.detectChanges();
    http.expectOne(r => r.url.endsWith('/packages/archived')).flush(body);
    fixture.detectChanges();
    return fixture;
  }

  it('should create', () => {
    const fixture = TestBed.createComponent(ArchivedPackagesComponent);
    expect(fixture.componentInstance).toBeTruthy();
  });

  it('should show loading initially', () => {
    const fixture = TestBed.createComponent(ArchivedPackagesComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.loading')?.textContent).toContain('Loading');
    http.expectOne(r => r.url.endsWith('/packages/archived')).flush([]);
  });

  it('should have loading state as true initially', () => {
    const fixture = TestBed.createComponent(ArchivedPackagesComponent);
    expect(fixture.componentInstance.loading).toBe(true);
    fixture.detectChanges();
    http.expectOne(r => r.url.endsWith('/packages/archived')).flush([]);
  });

  // The page the dashboard banner links to. It rendered empty while the
  // banner promised three repositories, so the states below are the ones
  // that actually matter.

  it('renders the empty state when nothing is affected', () => {
    const fixture = renderWith([]);
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('No archived repositories detected');
    expect(fixture.componentInstance.loading).toBe(false);
  });

  it('survives a null body instead of rendering nothing at all', () => {
    // The endpoint used to serialise an empty result as null; a template
    // iterating over null would leave a blank page with no explanation.
    const fixture = renderWith(null);
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('No archived repositories detected');
    expect(fixture.componentInstance.grouped).toEqual([]);
  });

  it('groups packages by repository and lists the affected projects', () => {
    const fixture = renderWith([
      row({ sbom_id: 'a', project_name: 'k2s', project_version: '0.3.0' }),
      row({ sbom_id: 'b', project_name: 'k2s', project_version: '0.4.0' }),
      row({ sbom_id: 'c', project_name: 'prometheus', project_version: '2.51.0' }),
    ]);

    const grouped = fixture.componentInstance.grouped;
    expect(grouped.length).toBe(1);
    expect(grouped[0].repo).toBe('go-yaml/yaml');
    // k2s appears once with two versions, not twice.
    expect(grouped[0].projects.map(p => p.projectName)).toEqual(['k2s', 'prometheus']);
    expect(fixture.componentInstance.totalProjects).toBe(2);

    const k2s = grouped[0].projects.find(p => p.projectName === 'k2s')!;
    expect(k2s.versions.map(v => v.version).sort()).toEqual(['0.3.0', '0.4.0']);
  });

  it('uses the reported product version rather than guessing from the name', () => {
    // Regression guard: "k2s" carries no version in its name, so the name
    // heuristic returned '' and the UI rendered "latest" for a project whose
    // SBOM plainly states 0.3.0.
    const fixture = renderWith([row({ project_name: 'k2s', project_version: '0.3.0' })]);

    const version = fixture.componentInstance.grouped[0].projects[0].versions[0].version;
    expect(version).toBe('0.3.0');

    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('0.3.0');
    expect(text).not.toContain('latest');
  });

  it('falls back to the name heuristic for pre-021 SBOMs', () => {
    const fixture = renderWith([
      row({ project_name: 'Cilium - cilium v1.17.13', project_version: '' }),
    ]);

    const project = fixture.componentInstance.grouped[0].projects[0];
    expect(project.projectName).toBe('Cilium - cilium');
    expect(project.versions[0].version).toBe('1.17.13');
  });

  it('sorts repositories by stars so the most depended-on comes first', () => {
    const fixture = renderWith([
      row({ sbom_id: 'a', repo: 'small/lib', stars: 12 }),
      row({ sbom_id: 'b', repo: 'go-yaml/yaml', stars: 7019 }),
    ]);

    expect(fixture.componentInstance.grouped.map(g => g.repo)).toEqual([
      'go-yaml/yaml',
      'small/lib',
    ]);
  });

  it('stops loading when the request fails', () => {
    const fixture = TestBed.createComponent(ArchivedPackagesComponent);
    fixture.detectChanges();
    http.expectOne(r => r.url.endsWith('/packages/archived'))
      .flush('boom', { status: 500, statusText: 'Server Error' });
    fixture.detectChanges();

    expect(fixture.componentInstance.loading).toBe(false);
    expect((fixture.nativeElement as HTMLElement).querySelector('.loading')).toBeNull();
  });
});

