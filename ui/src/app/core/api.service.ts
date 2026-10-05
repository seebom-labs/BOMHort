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
  LicenseSourceItem,
  VEXStatementItem,
  ProjectLicenseViolation,
  AffectedProject,
  DependencyStatsResponse,
  DependencySearchResponse,
  PackageDetailResponse,
  VersionSkewResponse,
  LicenseExceptionsFile,
  ArchivedPackageInfo,
  ProjectListItem,
  ProjectGroupItem,
  ProjectDetail,
  ProjectPackageItem,
  TagListItem,
  GlobalSearchResponse,
  FleetCluster,
  ClusterListItem,
  ClusterStats,
  NamespaceListItem,
  NamespaceStats,
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

  /**
   * SBOM list. `search` is a substring match on document name / source path;
   * `project` (#398) is the exact project identity and scopes the list to
   * one project's versions. They compose.
   */
  getSboms(page = 1, pageSize = 50, search = '', project = ''): Observable<PaginatedResponse<SBOMListItem>> {
    let params = new HttpParams()
      .set('page', page.toString())
      .set('page_size', pageSize.toString());
    if (search) {
      params = params.set('search', search);
    }
    if (project) {
      params = params.set('project', project);
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

  /** VEX statements affecting one SBOM (#350): scoped first, then global. */
  getSbomVex(sbomId: string): Observable<VEXStatementItem[]> {
    return this.http.get<VEXStatementItem[]>(`${this.baseUrl}/sboms/${sbomId}/vex`);
  }

  getSbomLicenses(sbomId: string): Observable<SBOMLicenseBreakdownItem[]> {
    return this.http.get<SBOMLicenseBreakdownItem[]>(`${this.baseUrl}/sboms/${sbomId}/licenses`);
  }

  /**
   * Paginated vulnerabilities. Every finding is returned with its VEX status
   * attached for display - there is no "effective only" mode.
   */
  getVulnerabilities(page = 1, pageSize = 50): Observable<PaginatedResponse<VulnerabilityListItem>> {
    const params = new HttpParams()
      .set('page', page.toString())
      .set('page_size', pageSize.toString());
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

  getLicenseSources(): Observable<LicenseSourceItem[]> {
    return this.http.get<LicenseSourceItem[]>(`${this.baseUrl}/licenses/sources`);
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

  /**
   * Returns the download URL for a given SBOM.
   * The browser can navigate to this URL directly to trigger a file download.
   */
  getSbomDownloadUrl(sbomId: string): string {
    return `${this.baseUrl}/sboms/${sbomId}/download`;
  }

  getProjects(page = 1, pageSize = 50, search = '', tag = ''): Observable<PaginatedResponse<ProjectListItem>> {
    let params = new HttpParams()
      .set('page', page.toString())
      .set('page_size', pageSize.toString());
    if (search) {
      params = params.set('search', search);
    }
    // A tag narrows which projects are listed; it never merges them, so the
    // response shape is unchanged and paging still counts projects.
    if (tag) {
      params = params.set('tag', tag);
    }
    return this.http.get<PaginatedResponse<ProjectListItem>>(`${this.baseUrl}/projects`, { params });
  }

  /**
   * Projects grouped by their resolved parent (product), paged by group.
   * search matches the group or any member; tag restricts the members.
   */
  getProjectGroups(page = 1, pageSize = 50, search = '', tag = ''): Observable<PaginatedResponse<ProjectGroupItem>> {
    let params = new HttpParams()
      .set('group_by', 'parent')
      .set('page', page.toString())
      .set('page_size', pageSize.toString());
    if (search) {
      params = params.set('search', search);
    }
    if (tag) {
      params = params.set('tag', tag);
    }
    return this.http.get<PaginatedResponse<ProjectGroupItem>>(`${this.baseUrl}/projects`, { params });
  }
  /**
   * Grouping labels in use on this instance.
   *
   * Returns [] when nothing is tagged, which callers should treat as "this
   * deployment does not group projects" and hide the filter entirely rather
   * than showing an empty control.
   */
  getTags(): Observable<TagListItem[]> {
    return this.http.get<TagListItem[]>(`${this.baseUrl}/tags`);
  }

  // ── Project read model (#398) ──
  //
  // Names are percent-encoded because the org/project fallback shape
  // contains "/" — unencoded it would route to /projects/{org}/{project},
  // which is not a path the API has.

  getProjectDetail(name: string): Observable<ProjectDetail> {
    return this.http.get<ProjectDetail>(`${this.baseUrl}/projects/${encodeURIComponent(name)}`);
  }

  getProjectSboms(name: string, page = 1, pageSize = 50): Observable<PaginatedResponse<SBOMListItem>> {
    const params = new HttpParams()
      .set('page', page.toString())
      .set('page_size', pageSize.toString());
    return this.http.get<PaginatedResponse<SBOMListItem>>(
      `${this.baseUrl}/projects/${encodeURIComponent(name)}/sboms`, { params });
  }

  /** One row per distinct (vuln_id, purl) across the project's SBOMs. */
  getProjectVulnerabilities(name: string): Observable<VulnerabilityListItem[]> {
    return this.http.get<VulnerabilityListItem[]>(
      `${this.baseUrl}/projects/${encodeURIComponent(name)}/vulnerabilities`);
  }

  getProjectPackages(
    name: string, page = 1, pageSize = 50, search = '',
  ): Observable<PaginatedResponse<ProjectPackageItem>> {
    let params = new HttpParams()
      .set('page', page.toString())
      .set('page_size', pageSize.toString());
    if (search) {
      params = params.set('search', search);
    }
    return this.http.get<PaginatedResponse<ProjectPackageItem>>(
      `${this.baseUrl}/projects/${encodeURIComponent(name)}/packages`, { params });
  }

  globalSearch(q: string, limit?: number): Observable<GlobalSearchResponse> {
    let params = new HttpParams().set('q', q);
    if (limit !== undefined) {
      params = params.set('limit', limit.toString());
    }
    return this.http.get<GlobalSearchResponse>(`${this.baseUrl}/search`, { params });
  }

  // ── Ownership dimensions (#131 cluster, #138 namespace, #57 project) ──

  /** Full cluster → namespace → project tree in one request. */
  getFleet(): Observable<FleetCluster[]> {
    return this.http.get<FleetCluster[]>(`${this.baseUrl}/fleet`);
  }

  getClusters(): Observable<ClusterListItem[]> {
    return this.http.get<ClusterListItem[]>(`${this.baseUrl}/clusters`);
  }

  getClusterStats(cluster: string): Observable<ClusterStats> {
    return this.http.get<ClusterStats>(`${this.baseUrl}/clusters/${encodeURIComponent(cluster)}/stats`);
  }

  getClusterSboms(cluster: string, page = 1, pageSize = 50): Observable<PaginatedResponse<SBOMListItem>> {
    const params = new HttpParams()
      .set('page', page.toString())
      .set('page_size', pageSize.toString());
    return this.http.get<PaginatedResponse<SBOMListItem>>(
      `${this.baseUrl}/clusters/${encodeURIComponent(cluster)}/sboms`, { params });
  }

  /**
   * Namespace endpoints take an optional cluster scope, because a namespace
   * name is only unique inside a cluster — `payments` in prod-eu and
   * `payments` in staging are different things and must not be merged.
   */
  getNamespaces(cluster = ''): Observable<NamespaceListItem[]> {
    let params = new HttpParams();
    if (cluster) {
      params = params.set('cluster', cluster);
    }
    return this.http.get<NamespaceListItem[]>(`${this.baseUrl}/namespaces`, { params });
  }

  getNamespaceStats(namespace: string, cluster = ''): Observable<NamespaceStats> {
    let params = new HttpParams();
    if (cluster) {
      params = params.set('cluster', cluster);
    }
    return this.http.get<NamespaceStats>(
      `${this.baseUrl}/namespaces/${encodeURIComponent(namespace)}/stats`, { params });
  }

  getNamespaceSboms(
    namespace: string, cluster = '', page = 1, pageSize = 50,
  ): Observable<PaginatedResponse<SBOMListItem>> {
    let params = new HttpParams()
      .set('page', page.toString())
      .set('page_size', pageSize.toString());
    if (cluster) {
      params = params.set('cluster', cluster);
    }
    return this.http.get<PaginatedResponse<SBOMListItem>>(
      `${this.baseUrl}/namespaces/${encodeURIComponent(namespace)}/sboms`, { params });
  }
}

