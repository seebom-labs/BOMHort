import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { ApiService } from './api.service';
import {
  DashboardStats,
  PaginatedResponse,
  SBOMListItem,
  VulnerabilityListItem,
  SBOMDetail,
  ArchivedPackageInfo,
  SBOMLicenseBreakdownItem,
  ProjectLicenseViolation,
  AffectedProject,
  DependencyStatsResponse,
  VEXStatementItem,
  LicenseExceptionsFile,
} from './api.models';

describe('ApiService', () => {
  let service: ApiService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    });
    service = TestBed.inject(ApiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should fetch dashboard stats', () => {
    const mockStats: DashboardStats = {
      total_sboms: 100,
      total_packages: 5000,
      total_vulnerabilities: 42,
      effective_vulnerabilities: 35,
      suppressed_by_vex: 7,
      critical_vulns: 5,
      high_vulns: 10,
      medium_vulns: 15,
      low_vulns: 12,
      license_breakdown: { permissive: 80, copyleft: 15, unknown: 5 },
      exempted_packages: 3,
      total_vex_statements: 10,
    };

    service.getDashboardStats().subscribe((stats) => {
      expect(stats.total_sboms).toBe(100);
      expect(stats.total_vulnerabilities).toBe(42);
    });

    const req = httpMock.expectOne('/api/v1/stats/dashboard');
    expect(req.request.method).toBe('GET');
    req.flush(mockStats);
  });

  it('should fetch SBOMs with pagination', () => {
    const mockResp: PaginatedResponse<SBOMListItem> = {
      data: [{ sbom_id: '123', source_file: 'test.spdx.json', spdx_version: 'SPDX-2.3', document_name: 'test', package_count: 10, vuln_count: 2, ingested_at: '2025-01-01' }],
      total: 1,
      page: 1,
      page_size: 50,
    };

    service.getSboms(1, 50).subscribe((resp) => {
      expect(resp.data.length).toBe(1);
      expect(resp.data[0].sbom_id).toBe('123');
    });

    const req = httpMock.expectOne((r) => r.url === '/api/v1/sboms');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    req.flush(mockResp);
  });

  it('should fetch vulnerabilities with pagination', () => {
    const mockResp: PaginatedResponse<VulnerabilityListItem> = {
      data: [],
      total: 0,
      page: 1,
      page_size: 50,
    };

    service.getVulnerabilities(1, 50).subscribe((resp) => {
      expect(resp.data.length).toBe(0);
    });

    const req = httpMock.expectOne((r) => r.url === '/api/v1/vulnerabilities');
    expect(req.request.method).toBe('GET');
    req.flush(mockResp);
  });

  it('should fetch SBOM dependencies', () => {
    service.getSbomDependencies('abc-123').subscribe((nodes) => {
      expect(nodes).toEqual([]);
    });

    const req = httpMock.expectOne('/api/v1/sboms/abc-123/dependencies');
    expect(req.request.method).toBe('GET');
    req.flush([]);
  });

  it('should fetch license compliance', () => {
    service.getLicenseCompliance().subscribe((items) => {
      expect(items).toEqual([]);
    });

    const req = httpMock.expectOne('/api/v1/licenses/compliance');
    expect(req.request.method).toBe('GET');
    req.flush([]);
  });

  it('should fetch SBOM detail', () => {
    const mockDetail: SBOMDetail = {
      sbom_id: 'abc-123',
      source_file: 'test.spdx.json',
      spdx_version: 'SPDX-2.3',
      document_name: 'test',
      package_count: 50,
      vuln_count: 3,
      ingested_at: '2025-01-01',
      critical_vulns: 1,
      high_vulns: 1,
      medium_vulns: 1,
      low_vulns: 0,
    };

    service.getSbomDetail('abc-123').subscribe((detail) => {
      expect(detail.sbom_id).toBe('abc-123');
      expect(detail.package_count).toBe(50);
    });

    const req = httpMock.expectOne('/api/v1/sboms/abc-123/detail');
    expect(req.request.method).toBe('GET');
    req.flush(mockDetail);
  });

  it('should fetch SBOM vulnerabilities', () => {
    service.getSbomVulnerabilities('abc-123').subscribe((vulns) => {
      expect(vulns).toEqual([]);
    });

    const req = httpMock.expectOne('/api/v1/sboms/abc-123/vulnerabilities');
    expect(req.request.method).toBe('GET');
    req.flush([]);
  });

  it('should fetch SBOM licenses', () => {
    service.getSbomLicenses('abc-123').subscribe((licenses) => {
      expect(licenses).toEqual([]);
    });

    const req = httpMock.expectOne('/api/v1/sboms/abc-123/licenses');
    expect(req.request.method).toBe('GET');
    req.flush([]);
  });

  it('should fetch projects with license compliance issues', () => {
    service.getProjectsWithLicenseViolations().subscribe((violations) => {
      expect(violations).toEqual([]);
    });

    const req = httpMock.expectOne('/api/v1/projects/license-compliance');
    expect(req.request.method).toBe('GET');
    req.flush([]);
  });

  it('should fetch affected projects by CVE', () => {
    service.getAffectedProjectsByCVE('CVE-2024-1234').subscribe((projects) => {
      expect(projects).toEqual([]);
    });

    const req = httpMock.expectOne('/api/v1/vulnerabilities/CVE-2024-1234/affected-projects');
    expect(req.request.method).toBe('GET');
    req.flush([]);
  });

  it('should fetch dependency stats with limit', () => {
    const mockResp: DependencyStatsResponse = {
      total_unique_deps: 100,
      top_dependencies: [],
    };

    service.getDependencyStats(25).subscribe((resp) => {
      expect(resp.total_unique_deps).toBe(100);
    });

    const req = httpMock.expectOne((r) => r.url === '/api/v1/stats/dependencies');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('limit')).toBe('25');
    req.flush(mockResp);
  });

  it('should fetch VEX statements with pagination', () => {
    const mockResp: PaginatedResponse<VEXStatementItem> = {
      data: [],
      total: 0,
      page: 1,
      page_size: 50,
    };

    service.getVEXStatements(1, 50).subscribe((resp) => {
      expect(resp.data).toEqual([]);
    });

    const req = httpMock.expectOne((r) => r.url === '/api/v1/vex/statements');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    req.flush(mockResp);
  });

  it('should fetch license exceptions', () => {
    const mockExceptions: LicenseExceptionsFile = {
      version: '1.0.0',
      lastUpdated: '2026-03-01',
      blanketExceptions: [],
      exceptions: [],
    };

    service.getLicenseExceptions().subscribe((exc) => {
      expect(exc.version).toBe('1.0.0');
    });

    const req = httpMock.expectOne('/api/v1/license-exceptions');
    expect(req.request.method).toBe('GET');
    req.flush(mockExceptions);
  });

  it('should fetch archived packages', () => {
    service.getArchivedPackages().subscribe((packages) => {
      expect(packages).toEqual([]);
    });

    const req = httpMock.expectOne('/api/v1/packages/archived');
    expect(req.request.method).toBe('GET');
    req.flush([]);
  });

  it('should return correct SBOM download URL', () => {
    const sbomId = '550e8400-e29b-41d4-a716-446655440000';
    const url = service.getSbomDownloadUrl(sbomId);
    expect(url).toBe(`/api/v1/sboms/${sbomId}/download`);
  });

  it('should fetch global search results', () => {
    const mockResp = {
      query: 'test',
      packages: [],
      total_packages: 0,
      projects: [],
      total_projects: 0,
      vulnerabilities: [],
      total_vulnerabilities: 0,
      licenses: [],
      total_licenses: 0
    };

    service.globalSearch('test', 5).subscribe((resp) => {
      expect(resp.query).toBe('test');
    });

    const req = httpMock.expectOne((r) => r.url === '/api/v1/search');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('q')).toBe('test');
    expect(req.request.params.get('limit')).toBe('5');
    req.flush(mockResp);
  });
});

