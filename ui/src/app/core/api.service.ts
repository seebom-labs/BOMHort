import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
  DashboardStats,
  PaginatedResponse,
  SBOMListItem,
  SBOMDetail,
  SBOMLicenseBreakdownItem,
  VulnerabilityListItem,
  DependencyNode,
  LicenseComplianceItem,
  VEXStatementItem,
  ProjectLicenseViolation,
  AffectedProject,
  DependencyStatsResponse,
  DependencySearchResponse,
  PackageDetailResponse,
  VersionSkewResponse,
  LicenseExceptionsFile,
  ArchivedPackageInfo,
} from './api.models';

@Injectable({
  providedIn: 'root',
})
export class ApiService {
  private readonly baseUrl = '/api/v1';

  constructor(private readonly http: HttpClient) {}

  getDashboardStats(): Observable<DashboardStats> {
    return this.http.get<DashboardStats>(`${this.baseUrl}/stats/dashboard`);
  }

  getSboms(page = 1, pageSize = 50, search = ''): Observable<PaginatedResponse<SBOMListItem>> {
    let params = new HttpParams()
      .set('page', page.toString())
      .set('page_size', pageSize.toString());
    if (search) {
      params = params.set('search', search);
    }
    return this.http.get<PaginatedResponse<SBOMListItem>>(`${this.baseUrl}/sboms`, { params });
  }

  getSbomDetail(sbomId: string): Observable<SBOMDetail> {
    return this.http.get<SBOMDetail>(`${this.baseUrl}/sboms/${sbomId}/detail`);
  }

  getSbomDependencies(sbomId: string): Observable<DependencyNode[]> {
    return this.http.get<DependencyNode[]>(`${this.baseUrl}/sboms/${sbomId}/dependencies`);
  }

  getSbomVulnerabilities(sbomId: string): Observable<VulnerabilityListItem[]> {
    return this.http.get<VulnerabilityListItem[]>(`${this.baseUrl}/sboms/${sbomId}/vulnerabilities`);
  }

  getSbomLicenses(sbomId: string): Observable<SBOMLicenseBreakdownItem[]> {
    return this.http.get<SBOMLicenseBreakdownItem[]>(`${this.baseUrl}/sboms/${sbomId}/licenses`);
  }

  getVulnerabilities(page = 1, pageSize = 50, vexFilter?: string): Observable<PaginatedResponse<VulnerabilityListItem>> {
    let params = new HttpParams()
      .set('page', page.toString())
      .set('page_size', pageSize.toString());
    if (vexFilter) {
      params = params.set('vex_filter', vexFilter);
    }
    return this.http.get<PaginatedResponse<VulnerabilityListItem>>(
      `${this.baseUrl}/vulnerabilities`,
      { params }
    );
  }

  getAffectedProjectsByCVE(vulnId: string): Observable<AffectedProject[]> {
    return this.http.get<AffectedProject[]>(`${this.baseUrl}/vulnerabilities/${vulnId}/affected-projects`);
  }

  getLicenseCompliance(): Observable<LicenseComplianceItem[]> {
    return this.http.get<LicenseComplianceItem[]>(`${this.baseUrl}/licenses/compliance`);
  }

  getProjectsWithLicenseViolations(): Observable<ProjectLicenseViolation[]> {
    return this.http.get<ProjectLicenseViolation[]>(`${this.baseUrl}/projects/license-compliance`);
  }

  getDependencyStats(limit = 50): Observable<DependencyStatsResponse> {
    const params = new HttpParams().set('limit', limit.toString());
    return this.http.get<DependencyStatsResponse>(`${this.baseUrl}/stats/dependencies`, { params });
  }

  getVersionSkew(page = 1, pageSize = 50, search = ''): Observable<VersionSkewResponse> {
    let params = new HttpParams()
      .set('page', page.toString())
      .set('page_size', pageSize.toString());
    if (search) {
      params = params.set('search', search);
    }
    return this.http.get<VersionSkewResponse>(`${this.baseUrl}/stats/version-skew`, { params });
  }

  getVEXStatements(page = 1, pageSize = 50): Observable<PaginatedResponse<VEXStatementItem>> {
    const params = new HttpParams()
      .set('page', page.toString())
      .set('page_size', pageSize.toString());
    return this.http.get<PaginatedResponse<VEXStatementItem>>(`${this.baseUrl}/vex/statements`, { params });
  }

  getLicenseExceptions(): Observable<LicenseExceptionsFile> {
    return this.http.get<LicenseExceptionsFile>(`${this.baseUrl}/license-exceptions`);
  }

  getArchivedPackages(): Observable<ArchivedPackageInfo[]> {
    return this.http.get<ArchivedPackageInfo[]>(`${this.baseUrl}/packages/archived`);
  }

  searchPackages(query: string, page = 1, pageSize = 50): Observable<DependencySearchResponse> {
    let params = new HttpParams()
      .set('q', query)
      .set('page', page.toString())
      .set('page_size', pageSize.toString());
    return this.http.get<DependencySearchResponse>(`${this.baseUrl}/packages/search`, { params });
  }

  getPackageDetail(name: string, page = 1, pageSize = 50): Observable<PackageDetailResponse> {
    const params = new HttpParams()
      .set('name', name)
      .set('page', page.toString())
      .set('page_size', pageSize.toString());
    return this.http.get<PackageDetailResponse>(`${this.baseUrl}/packages/detail`, { params });
  }
}

