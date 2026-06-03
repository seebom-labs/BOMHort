import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { ProjectListComponent } from './project-list.component';

describe('ProjectListComponent', () => {
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ProjectListComponent],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create', () => {
    const fixture = TestBed.createComponent(ProjectListComponent);
    fixture.detectChanges();
    const component = fixture.componentInstance;
    expect(component).toBeTruthy();

    // Flush initial load request.
    const req = httpMock.expectOne((r) => r.url.includes('/api/v1/projects'));
    req.flush({ data: [], total: 0, page: 1, page_size: 100 });
  });

  it('should load projects on init', () => {
    const fixture = TestBed.createComponent(ProjectListComponent);
    fixture.detectChanges();

    const req = httpMock.expectOne((r) => r.url.includes('/api/v1/projects'));
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('page_size')).toBe('100');

    req.flush({
      data: [
        {
          project_name: 'containerd',
          sbom_count: 5,
          package_count: 120,
          vuln_count: 3,
          latest_ingested: '2026-05-01T12:00:00Z',
          latest_sbom_id: 'abc-123',
        },
      ],
      total: 1,
      page: 1,
      page_size: 100,
    });

    fixture.detectChanges();
    expect(fixture.componentInstance.projects.length).toBe(1);
    expect(fixture.componentInstance.projects[0].project_name).toBe('containerd');
    expect(fixture.componentInstance.total).toBe(1);
  });

  it('should search projects with debounce', async () => {
    const fixture = TestBed.createComponent(ProjectListComponent);
    fixture.detectChanges();

    // Flush initial load.
    const initReq = httpMock.expectOne((r) => r.url.includes('/api/v1/projects'));
    initReq.flush({ data: [], total: 0, page: 1, page_size: 100 });

    // Trigger search.
    fixture.componentInstance.searchTerm = 'kube';
    fixture.componentInstance.onSearchChange('kube');

    // Wait for debounce (300ms).
    await new Promise((resolve) => setTimeout(resolve, 350));

    const searchReq = httpMock.expectOne((r) =>
      r.url.includes('/api/v1/projects') && r.params.get('search') === 'kube'
    );
    searchReq.flush({ data: [], total: 0, page: 1, page_size: 100 });
  });
});



