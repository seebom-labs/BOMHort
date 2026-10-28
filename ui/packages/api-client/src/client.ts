import type {
  AffectedProject,
  ArchivedPackageInfo,
  ClusterListItem,
  ClusterStats,
  DashboardStats,
  DependencyNode,
  DependencySearchResponse,
  DependencyStatsResponse,
  FleetCluster,
  GlobalSearchResponse,
  LicenseComplianceItem,
  LicenseExceptionsFile,
  LicenseSourceItem,
  NamespaceListItem,
  NamespaceStats,
  PackageDetailResponse,
  PaginatedResponse,
  ProjectDetail,
  ProjectGroupItem,
  ProjectLicenseViolation,
  ProjectLicenseViolationSummary,
  ProjectListItem,
  ProjectPackageItem,
  SBOMDetail,
  SBOMLicenseBreakdownItem,
  SBOMListItem,
  TagListItem,
  VEXStatementItem,
  VersionSkewResponse,
  VulnerabilityListItem,
} from './models';

export interface ApiClientOptions {
  /** Base URL of the API, e.g. `https://bomhort.example.com/api/v1`. Default `/api/v1`. */
  baseUrl?: string;
  /** Sent as `X-API-Key` on every request (AUTH_ENABLED instances). */
  apiKey?: string;
  /** Sent as `Authorization: Bearer …` on every request. */
  token?: string;
  /** Defaults to `globalThis.fetch`; inject for tests or custom transports. */
  fetch?: typeof fetch;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly url: string,
    readonly body: string,
  ) {
    super(`${status} ${url}`);
    this.name = 'ApiError';
  }
}

type Params = Record<string, string | number | undefined>;

/** Query string from the given params; empty strings and undefined are omitted, like the Angular service. */
export function query(params: Params): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

/**
 * Framework-free, read-only client for the BOMHort REST API. One method per
 * endpoint, same names and defaults as the Angular `ApiService`, so a
 * component ported to another framework needs no call-site changes.
 */
export class BomhortApiClient {
  readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly fetchFn: typeof fetch;

  constructor(opts: ApiClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? '/api/v1').replace(/\/$/, '');
    this.headers = {};
    if (opts.apiKey) this.headers['X-API-Key'] = opts.apiKey;
    if (opts.token) this.headers['Authorization'] = `Bearer ${opts.token}`;
    this.fetchFn = opts.fetch ?? ((input, init) => fetch(input, init));
  }

  private async get<T>(path: string, signal?: AbortSignal): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const res = await this.fetchFn(url, { headers: { Accept: 'application/json', ...this.headers }, signal });
    if (!res.ok) throw new ApiError(res.status, url, await res.text());
    return (await res.json()) as T;
  }

  getDashboardStats(signal?: AbortSignal): Promise<DashboardStats> {
    return this.get('/stats/dashboard', signal);
  }

  getSboms(page = 1, pageSize = 50, search = '', project = '', signal?: AbortSignal): Promise<PaginatedResponse<SBOMListItem>> {
    return this.get(`/sboms${query({ page, page_size: pageSize, search, project })}`, signal);
  }

  getSbomDetail(sbomId: string, signal?: AbortSignal): Promise<SBOMDetail> {
    return this.get(`/sboms/${sbomId}/detail`, signal);
  }

  getSbomDependencies(sbomId: string, signal?: AbortSignal): Promise<DependencyNode[]> {
    return this.get(`/sboms/${sbomId}/dependencies`, signal);
  }

  getSbomVulnerabilities(sbomId: string, scope = '', signal?: AbortSignal): Promise<VulnerabilityListItem[]> {
    return this.get(`/sboms/${sbomId}/vulnerabilities${query({ scope })}`, signal);
  }

  getSbomVex(sbomId: string, signal?: AbortSignal): Promise<VEXStatementItem[]> {
    return this.get(`/sboms/${sbomId}/vex`, signal);
  }

  getSbomLicenses(sbomId: string, signal?: AbortSignal): Promise<SBOMLicenseBreakdownItem[]> {
    return this.get(`/sboms/${sbomId}/licenses`, signal);
  }

  getSbomDownloadUrl(sbomId: string): string {
    return `${this.baseUrl}/sboms/${sbomId}/download`;
  }

  vulnerabilityReportUrl(scope = ''): string {
    return `${this.baseUrl}/reports/vulnerabilities${query({ format: 'csv', scope })}`;
  }

  getVulnerabilities(page = 1, pageSize = 50, scope = '', signal?: AbortSignal): Promise<PaginatedResponse<VulnerabilityListItem>> {
    return this.get(`/vulnerabilities${query({ page, page_size: pageSize, scope })}`, signal);
  }

  getAffectedProjectsByCVE(vulnId: string, signal?: AbortSignal): Promise<AffectedProject[]> {
    return this.get(`/vulnerabilities/${vulnId}/affected-projects`, signal);
  }

  getLicenseCompliance(license?: string, signal?: AbortSignal): Promise<LicenseComplianceItem[]> {
    return this.get(`/licenses/compliance${query({ license })}`, signal);
  }

  getLicenseSources(signal?: AbortSignal): Promise<LicenseSourceItem[]> {
    return this.get('/licenses/sources', signal);
  }

  getProjectsWithLicenseViolations(signal?: AbortSignal): Promise<ProjectLicenseViolation[]> {
    return this.get('/projects/license-compliance', signal);
  }

  getProjectLicenseViolationSummaries(search = '', signal?: AbortSignal): Promise<ProjectLicenseViolationSummary[]> {
    return this.get(`/projects/license-compliance${query({ summary: 'true', search })}`, signal);
  }

  getDependencyStats(limit = 50, signal?: AbortSignal): Promise<DependencyStatsResponse> {
    return this.get(`/stats/dependencies${query({ limit })}`, signal);
  }

  getVersionSkew(page = 1, pageSize = 50, search = '', signal?: AbortSignal): Promise<VersionSkewResponse> {
    return this.get(`/stats/version-skew${query({ page, page_size: pageSize, search })}`, signal);
  }

  getVEXStatements(page = 1, pageSize = 50, signal?: AbortSignal): Promise<PaginatedResponse<VEXStatementItem>> {
    return this.get(`/vex/statements${query({ page, page_size: pageSize })}`, signal);
  }

  getLicenseExceptions(signal?: AbortSignal): Promise<LicenseExceptionsFile> {
    return this.get('/license-exceptions', signal);
  }

  getArchivedPackages(signal?: AbortSignal): Promise<ArchivedPackageInfo[]> {
    return this.get('/packages/archived', signal);
  }

  searchPackages(q: string, page = 1, pageSize = 50, signal?: AbortSignal): Promise<DependencySearchResponse> {
    return this.get(`/packages/search${query({ q, page, page_size: pageSize })}`, signal);
  }

  getPackageDetail(name: string, page = 1, pageSize = 50, signal?: AbortSignal): Promise<PackageDetailResponse> {
    return this.get(`/packages/detail${query({ name, page, page_size: pageSize })}`, signal);
  }

  getProjects(page = 1, pageSize = 50, search = '', tag = '', signal?: AbortSignal): Promise<PaginatedResponse<ProjectListItem>> {
    return this.get(`/projects${query({ page, page_size: pageSize, search, tag })}`, signal);
  }

  getProjectGroups(page = 1, pageSize = 50, search = '', tag = '', signal?: AbortSignal): Promise<PaginatedResponse<ProjectGroupItem>> {
    return this.get(`/projects${query({ group_by: 'parent', page, page_size: pageSize, search, tag })}`, signal);
  }

  getTags(signal?: AbortSignal): Promise<TagListItem[]> {
    return this.get('/tags', signal);
  }

  getProjectDetail(name: string, signal?: AbortSignal): Promise<ProjectDetail> {
    return this.get(`/projects/${encodeURIComponent(name)}`, signal);
  }

  getProjectSboms(name: string, page = 1, pageSize = 50, signal?: AbortSignal): Promise<PaginatedResponse<SBOMListItem>> {
    return this.get(`/projects/${encodeURIComponent(name)}/sboms${query({ page, page_size: pageSize })}`, signal);
  }

  getProjectVulnerabilities(name: string, scope = '', signal?: AbortSignal): Promise<VulnerabilityListItem[]> {
    return this.get(`/projects/${encodeURIComponent(name)}/vulnerabilities${query({ scope })}`, signal);
  }

  getProjectPackages(name: string, page = 1, pageSize = 50, search = '', signal?: AbortSignal): Promise<PaginatedResponse<ProjectPackageItem>> {
    return this.get(`/projects/${encodeURIComponent(name)}/packages${query({ page, page_size: pageSize, search })}`, signal);
  }

  globalSearch(q: string, limit?: number, signal?: AbortSignal): Promise<GlobalSearchResponse> {
    return this.get(`/search${query({ q, limit })}`, signal);
  }

  getFleet(signal?: AbortSignal): Promise<FleetCluster[]> {
    return this.get('/fleet', signal);
  }

  getClusters(signal?: AbortSignal): Promise<ClusterListItem[]> {
    return this.get('/clusters', signal);
  }

  getClusterStats(cluster: string, signal?: AbortSignal): Promise<ClusterStats> {
    return this.get(`/clusters/${encodeURIComponent(cluster)}/stats`, signal);
  }

  getClusterSboms(cluster: string, page = 1, pageSize = 50, signal?: AbortSignal): Promise<PaginatedResponse<SBOMListItem>> {
    return this.get(`/clusters/${encodeURIComponent(cluster)}/sboms${query({ page, page_size: pageSize })}`, signal);
  }

  getNamespaces(cluster = '', signal?: AbortSignal): Promise<NamespaceListItem[]> {
    return this.get(`/namespaces${query({ cluster })}`, signal);
  }

  getNamespaceStats(namespace: string, cluster = '', signal?: AbortSignal): Promise<NamespaceStats> {
    return this.get(`/namespaces/${encodeURIComponent(namespace)}/stats${query({ cluster })}`, signal);
  }

  getNamespaceSboms(namespace: string, cluster = '', page = 1, pageSize = 50, signal?: AbortSignal): Promise<PaginatedResponse<SBOMListItem>> {
    return this.get(`/namespaces/${encodeURIComponent(namespace)}/sboms${query({ cluster, page, page_size: pageSize })}`, signal);
  }
}
