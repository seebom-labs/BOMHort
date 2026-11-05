import type {
  OwnerFilter,
  AffectedProject,
  ArchivedPackageInfo,
  ArchivedRepoGroup,
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
  OriginItem,
  PackageDetailResponse,
  PaginatedResponse,
  ProjectDetail,
  ProjectGroupItem,
  ProjectLicenseViolation,
  ProjectLicenseViolationSummary,
  ProjectListItem,
  ProjectPackageItem,
  QualityStatsResponse,
  SBOMDetail,
  SBOMLicenseBreakdownItem,
  SBOMListItem,
  TagListItem,
  ToolQualitySummary,
  VEXStatementItem,
  VersionSkewResponse,
  VulnerabilityListItem,
  ReachabilitySummary,
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

function isSignal(val: unknown): val is AbortSignal {
  return typeof val === 'object' && val !== null && 'aborted' in val;
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

  private async post<T>(path: string, body: string, signal?: AbortSignal): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const res = await this.fetchFn(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...this.headers },
      body,
      signal,
    });
    if (!res.ok) throw new ApiError(res.status, url, await res.text());
    return (await res.json()) as T;
  }

  getDashboardStats(signal?: AbortSignal): Promise<DashboardStats>;
  getDashboardStats(owner?: OwnerFilter, signal?: AbortSignal): Promise<DashboardStats>;
  getDashboardStats(ownerOrSignal?: OwnerFilter | AbortSignal, maybeSignal?: AbortSignal): Promise<DashboardStats> {
    const owner = isSignal(ownerOrSignal) ? {} : (ownerOrSignal ?? {});
    const signal = isSignal(ownerOrSignal) ? ownerOrSignal : maybeSignal;
    return this.get(`/stats/dashboard${query({ ...owner })}`, signal);
  }

  getQualityStats(signal?: AbortSignal): Promise<QualityStatsResponse> {
    return this.get('/stats/quality', signal);
  }

  getSboms(page?: number, pageSize?: number, search?: string, project?: string, signal?: AbortSignal): Promise<PaginatedResponse<SBOMListItem>>;
  getSboms(page?: number, pageSize?: number, search?: string, project?: string, minQuality?: number, signal?: AbortSignal): Promise<PaginatedResponse<SBOMListItem>>;
  getSboms(page?: number, pageSize?: number, search?: string, project?: string, origin?: string, signal?: AbortSignal): Promise<PaginatedResponse<SBOMListItem>>;
  getSboms(page?: number, pageSize?: number, search?: string, project?: string, origin?: string, minQuality?: number, signal?: AbortSignal): Promise<PaginatedResponse<SBOMListItem>>;
  getSboms(
    page = 1,
    pageSize = 50,
    search = '',
    project = '',
    originOrQualityOrSignal?: string | number | AbortSignal,
    minQualityOrSignal?: number | AbortSignal,
    maybeSignal?: AbortSignal,
  ): Promise<PaginatedResponse<SBOMListItem>> {
    const origin = typeof originOrQualityOrSignal === 'string' ? originOrQualityOrSignal : '';
    const minQuality = typeof originOrQualityOrSignal === 'number'
      ? originOrQualityOrSignal
      : typeof minQualityOrSignal === 'number'
        ? minQualityOrSignal
        : 0;
    const signal = isSignal(originOrQualityOrSignal)
      ? originOrQualityOrSignal
      : isSignal(minQualityOrSignal)
        ? minQualityOrSignal
        : maybeSignal;
    return this.get(
      `/sboms${query({ page, page_size: pageSize, search, project, origin, min_quality: minQuality > 0 ? minQuality : undefined })}`,
      signal,
    );
  }

  getSbomDetail(sbomId: string, signal?: AbortSignal): Promise<SBOMDetail> {
    return this.get(`/sboms/${sbomId}/detail`, signal);
  }

  getSbomDependencies(sbomId: string, signal?: AbortSignal): Promise<DependencyNode[]> {
    return this.get(`/sboms/${sbomId}/dependencies`, signal);
  }

  getSbomVulnerabilities(sbomId: string, scope = '', reachability = '', signal?: AbortSignal): Promise<VulnerabilityListItem[]> {
    return this.get(`/sboms/${sbomId}/vulnerabilities${query({ scope, reachability })}`, signal);
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

  vulnerabilityReportUrl(scope = '', owner: OwnerFilter = {}, reachability = ''): string {
    return `${this.baseUrl}/reports/vulnerabilities${query({ format: 'csv', scope, reachability, ...owner })}`;
  }

  getVulnerabilities(page?: number, pageSize?: number, scope?: string, signal?: AbortSignal): Promise<PaginatedResponse<VulnerabilityListItem>>;
  getVulnerabilities(page?: number, pageSize?: number, scope?: string, origin?: string, signal?: AbortSignal): Promise<PaginatedResponse<VulnerabilityListItem>>;
  getVulnerabilities(page?: number, pageSize?: number, scope?: string, owner?: OwnerFilter, signal?: AbortSignal): Promise<PaginatedResponse<VulnerabilityListItem>>;
  getVulnerabilities(page?: number, pageSize?: number, scope?: string, owner?: OwnerFilter, reachability?: string, signal?: AbortSignal): Promise<PaginatedResponse<VulnerabilityListItem>>;
  getVulnerabilities(
    page = 1,
    pageSize = 50,
    scope = '',
    ownerOrOriginOrSignal?: OwnerFilter | string | AbortSignal,
    reachabilityOrSignal?: string | AbortSignal,
    maybeSignal?: AbortSignal,
  ): Promise<PaginatedResponse<VulnerabilityListItem>> {
    let owner: OwnerFilter = {};
    let reachability = '';
    let signal: AbortSignal | undefined = maybeSignal;
    if (isSignal(ownerOrOriginOrSignal)) {
      signal = ownerOrOriginOrSignal;
    } else if (typeof ownerOrOriginOrSignal === 'string') {
      owner = { origin: ownerOrOriginOrSignal };
    } else if (ownerOrOriginOrSignal && typeof ownerOrOriginOrSignal === 'object') {
      owner = ownerOrOriginOrSignal;
    }
    if (isSignal(reachabilityOrSignal)) {
      signal = reachabilityOrSignal;
    } else if (typeof reachabilityOrSignal === 'string') {
      reachability = reachabilityOrSignal;
    }
    return this.get(`/vulnerabilities${query({ page, page_size: pageSize, scope, reachability, ...owner })}`, signal);
  }

  uploadEvidence(sbomId: string, evidenceJson: string | object, ref = '', signal?: AbortSignal): Promise<ReachabilitySummary> {
    const body = typeof evidenceJson === 'string' ? evidenceJson : JSON.stringify(evidenceJson);
    return this.post(`/sboms/${encodeURIComponent(sbomId)}/evidence${query({ ref })}`, body, signal);
  }

  getAffectedProjectsByCVE(vulnId: string, signal?: AbortSignal): Promise<AffectedProject[]>;
  getAffectedProjectsByCVE(vulnId: string, owner?: OwnerFilter, signal?: AbortSignal): Promise<AffectedProject[]>;
  getAffectedProjectsByCVE(vulnId: string, ownerOrSignal?: OwnerFilter | AbortSignal, maybeSignal?: AbortSignal): Promise<AffectedProject[]> {
    const owner = isSignal(ownerOrSignal) ? {} : (ownerOrSignal ?? {});
    const signal = isSignal(ownerOrSignal) ? ownerOrSignal : maybeSignal;
    return this.get(`/vulnerabilities/${vulnId}/affected-projects${query({ ...owner })}`, signal);
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

  getArchivedPackages(sbomId?: string, signal?: AbortSignal): Promise<ArchivedPackageInfo[]> {
    return this.get(`/packages/archived${query({ sbom_id: sbomId })}`, signal);
  }

  getArchivedRepos(page = 1, pageSize = 20, signal?: AbortSignal): Promise<PaginatedResponse<ArchivedRepoGroup>> {
    return this.get(`/packages/archived/repos${query({ page, page_size: pageSize })}`, signal);
  }

  searchPackages(q: string, page = 1, pageSize = 50, signal?: AbortSignal): Promise<DependencySearchResponse> {
    return this.get(`/packages/search${query({ q, page, page_size: pageSize })}`, signal);
  }

  getPackageDetail(name: string, page = 1, pageSize = 50, signal?: AbortSignal): Promise<PackageDetailResponse> {
    return this.get(`/packages/detail${query({ name, page, page_size: pageSize })}`, signal);
  }

  getProjects(page?: number, pageSize?: number, search?: string, tag?: string, signal?: AbortSignal): Promise<PaginatedResponse<ProjectListItem>>;
  getProjects(page?: number, pageSize?: number, search?: string, tag?: string, origin?: string, signal?: AbortSignal): Promise<PaginatedResponse<ProjectListItem>>;
  getProjects(
    page = 1,
    pageSize = 50,
    search = '',
    tag = '',
    originOrSignal?: string | AbortSignal,
    maybeSignal?: AbortSignal,
  ): Promise<PaginatedResponse<ProjectListItem>> {
    const origin = typeof originOrSignal === 'string' ? originOrSignal : '';
    const signal = isSignal(originOrSignal) ? originOrSignal : maybeSignal;
    return this.get(`/projects${query({ page, page_size: pageSize, search, tag, origin })}`, signal);
  }

  getProjectGroups(page?: number, pageSize?: number, search?: string, tag?: string, signal?: AbortSignal): Promise<PaginatedResponse<ProjectGroupItem>>;
  getProjectGroups(page?: number, pageSize?: number, search?: string, tag?: string, origin?: string, signal?: AbortSignal): Promise<PaginatedResponse<ProjectGroupItem>>;
  getProjectGroups(
    page = 1,
    pageSize = 50,
    search = '',
    tag = '',
    originOrSignal?: string | AbortSignal,
    maybeSignal?: AbortSignal,
  ): Promise<PaginatedResponse<ProjectGroupItem>> {
    const origin = typeof originOrSignal === 'string' ? originOrSignal : '';
    const signal = isSignal(originOrSignal) ? originOrSignal : maybeSignal;
    return this.get(`/projects${query({ group_by: 'parent', page, page_size: pageSize, search, tag, origin })}`, signal);
  }

  getTags(signal?: AbortSignal): Promise<TagListItem[]> {
    return this.get('/tags', signal);
  }

  getOrigins(signal?: AbortSignal): Promise<OriginItem[]> {
    return this.get('/origins', signal);
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

  getFleet(signal?: AbortSignal): Promise<FleetCluster[]>;
  getFleet(origin?: string, signal?: AbortSignal): Promise<FleetCluster[]>;
  getFleet(originOrSignal?: string | AbortSignal, maybeSignal?: AbortSignal): Promise<FleetCluster[]> {
    const origin = typeof originOrSignal === 'string' ? originOrSignal : '';
    const signal = isSignal(originOrSignal) ? originOrSignal : maybeSignal;
    return this.get(`/fleet${query({ origin })}`, signal);
  }

  getClusters(signal?: AbortSignal): Promise<ClusterListItem[]> {
    return this.get('/clusters', signal);
  }

  getClusterStats(cluster: string, signal?: AbortSignal): Promise<ClusterStats> {
    return this.get(`/clusters/${encodeURIComponent(cluster)}/stats`, signal);
  }

  getClusterSboms(cluster: string, page?: number, pageSize?: number, signal?: AbortSignal): Promise<PaginatedResponse<SBOMListItem>>;
  getClusterSboms(cluster: string, page?: number, pageSize?: number, origin?: string, signal?: AbortSignal): Promise<PaginatedResponse<SBOMListItem>>;
  getClusterSboms(
    cluster: string,
    page = 1,
    pageSize = 50,
    originOrSignal?: string | AbortSignal,
    maybeSignal?: AbortSignal,
  ): Promise<PaginatedResponse<SBOMListItem>> {
    const origin = typeof originOrSignal === 'string' ? originOrSignal : '';
    const signal = isSignal(originOrSignal) ? originOrSignal : maybeSignal;
    return this.get(`/clusters/${encodeURIComponent(cluster)}/sboms${query({ page, page_size: pageSize, origin })}`, signal);
  }

  getNamespaces(cluster = '', signal?: AbortSignal): Promise<NamespaceListItem[]> {
    return this.get(`/namespaces${query({ cluster })}`, signal);
  }

  getNamespaceStats(namespace: string, cluster = '', signal?: AbortSignal): Promise<NamespaceStats> {
    return this.get(`/namespaces/${encodeURIComponent(namespace)}/stats${query({ cluster })}`, signal);
  }

  getNamespaceSboms(namespace: string, cluster?: string, page?: number, pageSize?: number, signal?: AbortSignal): Promise<PaginatedResponse<SBOMListItem>>;
  getNamespaceSboms(namespace: string, cluster?: string, page?: number, pageSize?: number, origin?: string, signal?: AbortSignal): Promise<PaginatedResponse<SBOMListItem>>;
  getNamespaceSboms(
    namespace: string,
    cluster = '',
    page = 1,
    pageSize = 50,
    originOrSignal?: string | AbortSignal,
    maybeSignal?: AbortSignal,
  ): Promise<PaginatedResponse<SBOMListItem>> {
    const origin = typeof originOrSignal === 'string' ? originOrSignal : '';
    const signal = isSignal(originOrSignal) ? originOrSignal : maybeSignal;
    return this.get(`/namespaces/${encodeURIComponent(namespace)}/sboms${query({ cluster, page, page_size: pageSize, origin })}`, signal);
  }
}
