export interface DashboardStats {
  total_sboms: number;
  total_packages: number;
  total_vulnerabilities: number;
  effective_vulnerabilities: number;
  suppressed_by_vex: number;
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
  license_breakdown: Record<string, number>;
  exempted_packages: number;
  total_vex_statements: number;
  last_cve_refresh?: string;
  new_vulns_since_refresh?: number;
  archived_repos_count?: number;
}

export interface ArchivedPackageInfo {
  sbom_id: string;
  source_file: string;
  project_name: string;
  project_version: string;
  package_name: string;
  package_purl: string;
  repo: string;
  last_pushed: string;
  stars: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface SBOMListItem {
  sbom_id: string;
  source_file: string;
  spdx_version: string;
  document_name: string;
  /** Version of the described product; omitted when the document states none. */
  document_version?: string;
  package_count: number;
  vuln_count: number;
  ingested_at: string;
  /** Source attribution (#332); omitted by the API when unknown. */
  source_repo?: string;
  source_ref?: string;
  /** Ownership dimensions (#177); omitted when unset. */
  cluster?: string;
  namespace?: string;
  project?: string;
}

export interface VulnerabilityListItem {
  vuln_id: string;
  severity: string;
  purl: string;
  summary: string;
  fixed_version: string;
  source_file: string;
  discovered_at: string;
  vex_status?: string;
  /**
   * Effective VEX statement detail (#335): the API returns exactly one row
   * per (vuln_id, purl); the newest statement wins. Omitted when no VEX
   * statement covers the pair.
   */
  vex_justification?: string;
  vex_timestamp?: string;
  vex_statement_id?: string;
  vex_author?: string;
  vex_tooling?: string;
  /** "sbom": the winning statement is scoped to this SBOM; unscoped
   *  statements never apply, so this is the only value (#350). */
  vex_scope?: 'sbom';
  /**
   * On project-level listings only (#398): how many of the project's SBOMs
   * carry this (vuln_id, purl) pair. Absent on per-SBOM listings.
   */
  affected_sboms?: number;
}

export interface DependencyNode {
  index: number;
  spdx_id: string;
  name: string;
  version: string;
  purl: string;
  license: string;
  /** Where `license` came from, or why it is unknown (see shared/license-source.ts). */
  license_source?: string;
  children: number[];
}

export interface LicenseSourceItem {
  source: string;
  origin: string;
  modifiers: string[];
  resolved: boolean;
  package_count: number;
  sbom_count: number;
  examples: string[];
}

export interface LicenseComplianceItem {
  license_id: string;
  category: string;
  package_count: number;
  sbom_count: number;
  non_compliant_packages?: string[];
  exempted_packages?: string[];
  exemption_reason?: string;
  affected_sboms?: LicenseAffectedSBOM[];
}

export interface LicenseAffectedSBOM {
  sbom_id: string;
  document_name: string;
}

export interface VEXStatementItem {
  vex_id: string;
  document_id: string;
  source_file: string;
  /** SBOM the statement is scoped to (#350); absent = global. */
  sbom_id?: string;
  product_purl: string;
  vuln_id: string;
  status: string;
  justification: string;
  impact_statement?: string;
  action_statement?: string;
  vex_timestamp: string;
  ingested_at: string;
  /** Provenance (#334); omitted by the API when the document has none. */
  author?: string;
  role?: string;
  tooling?: string;
  status_notes?: string;
  affected_sboms?: VEXAffectedSBOM[];
}

export interface VEXAffectedSBOM {
  sbom_id: string;
  document_name: string;
}

export interface SBOMDetail {
  sbom_id: string;
  source_file: string;
  spdx_version: string;
  document_name: string;
  /** Version of the described product; omitted when the document states none. */
  document_version?: string;
  package_count: number;
  vuln_count: number;
  ingested_at: string;
  /** Source attribution (#332); omitted by the API when unknown. */
  source_repo?: string;
  source_ref?: string;
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
}

export interface SBOMLicenseBreakdownItem {
  license_id: string;
  category: string;
  package_count: number;
  packages: string[];
  exempted_packages?: string[];
  exemption_reason?: string;
}

export interface ProjectLicenseViolation {
  sbom_id: string;
  source_file: string;
  document_name: string;
  copyleft_count: number;
  /** Declared licenses that are not on the policy allow-list. */
  unapproved_count: number;
  unknown_count: number;
  violating_licenses: string[];
  non_compliant_packages: string[];
}

export interface AffectedProject {
  sbom_id: string;
  source_file: string;
  document_name: string;
  purl: string;
  package_name: string;
  version: string;
  severity: string;
  vex_status?: string;
  is_direct: boolean;
}

export interface DependencyStatsItem {
  package_name: string;
  purl: string;
  project_count: number;
  versions: string[];
  vuln_count: number;
}

export interface DependencyStatsResponse {
  total_unique_deps: number;
  top_dependencies: DependencyStatsItem[];
}

export interface VersionSkewDetail {
  version: string;
  project_count: number;
  projects: string[];
}

export interface VersionSkewItem {
  package_name: string;
  purl: string;
  version_count: number;
  project_count: number;
  is_direct_in_count: number;
  versions: VersionSkewDetail[];
}

export interface VersionSkewResponse {
  total_skewed_packages: number;
  items: VersionSkewItem[];
  page: number;
  page_size: number;
}

export interface LicenseExceptionsFile {
  version: string;
  lastUpdated: string;
  description?: string;
  blanketExceptions: BlanketException[];
  exceptions: LicenseException[];
}

export interface BlanketException {
  id: string;
  license: string;
  status: string;
  approvedDate: string;
  scope?: string;
  comment?: string;
}

export interface LicenseException {
  id: string;
  package: string;
  license: string;
  project?: string;
  status: string;
  approvedDate: string;
  scope?: string;
  results?: string;
  comment?: string;
}

export interface DependencySearchProject {
  project_name: string;
  version: string;
  sbom_id: string;
}

export interface DependencySearchResult {
  package_name: string;
  purl: string;
  project_count: number;
  versions: string[];
  projects: DependencySearchProject[];
}

export interface DependencySearchResponse {
  total_results: number;
  items: DependencySearchResult[];
  page: number;
  page_size: number;
  query: string;
}

export interface PackageDetailResponse {
  package_name: string;
  total_projects: number;
  projects: DependencySearchProject[];
  page: number;
  page_size: number;
}

export interface ProjectListItem {
  project_name: string;
  sbom_count: number;
  /**
   * De-duplicated across the project's SBOMs (#398): a component shipped in
   * every version counts once, as does a (vuln_id, purl) pair. These are the
   * project's numbers, not the sum of its versions' numbers.
   */
  package_count: number;
  vuln_count: number;
  latest_ingested: string;
  latest_sbom_id: string;
  /**
   * Grouping labels across this project's SBOMs (#357).
   *
   * A tag labels a project, it does not stand in for one: a project with
   * three SBOMs is still listed once under its own name and merely carries
   * the groupings those SBOMs arrived with.
   */
  tags: string[];
  /**
   * The product this project belongs to, resolved by the API (explicit
   * config first, then repository owner, document name, purl, supplier).
   * Omitted when it has none.
   */
  parent?: string;
  /** How parent was resolved: config, explicit, tag, repo, document, purl, supplier. */
  parent_source?: ParentSource;
}

export type ParentSource = 'config' | 'explicit' | 'tag' | 'repo' | 'document' | 'purl' | 'supplier';

/**
 * One row of GET /api/v1/projects?group_by=parent: a parent with its member
 * projects, or a project that belongs to no parent (a group of one).
 *
 * package_count and vuln_count are de-duplicated across all SBOMs of all
 * members, so they are not the sum of the members' counts.
 */
export interface ProjectGroupItem {
  name: string;
  /** The parent is itself a project (has its own SBOMs), not only a label. */
  is_project: boolean;
  project_count: number;
  sbom_count: number;
  package_count: number;
  vuln_count: number;
  latest_ingested: string;
  tags: string[];
  /** Distinct parent_source values of the members: why they were grouped. */
  sources: ParentSource[];
  /** The owner the automatic grouping used, e.g. "argoproj". */
  owner?: string;
  /** The parent project first when it is one, then the others by name. */
  members: ProjectListItem[];
}

/**
 * One project as a unit, from GET /api/v1/projects/{name} (#398). Mirrors
 * ClusterStats / NamespaceStats so the drill-downs share components.
 */
export interface ProjectDetail {
  project_name: string;
  tags: string[];
  /**
   * Tags that are themselves project names — the parents. A bucket laid out
   * {parent}/{subproject}/… with INGEST_PATH_LAYOUT="tag/project" gives every
   * sub-project its parent as a tag; these render as links up the tree.
   */
  parents: string[];
  /** Other projects tagged with this project's name — its sub-projects. */
  related_project_count: number;

  sbom_count: number;
  package_count: number;
  vuln_count: number;
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;

  latest_ingested?: string;
  latest_version?: string;
  latest_sbom_id?: string;
  source_repo?: string;

  /** Where the project is deployed; empty on a catalogue instance. */
  clusters: string[];
  namespaces: string[];
  license_breakdown: Record<string, number>;

  /** The resolved parent (product) of this project; see ProjectListItem. */
  parent?: string;
  parent_source?: ParentSource;
  /** The owner the automatic grouping used, e.g. "argoproj". */
  parent_owner?: string;
  /** Projects whose resolved parent is this project. */
  children: string[];
}

/** One distinct component across a project's SBOMs (#398). */
export interface ProjectPackageItem {
  name: string;
  version: string;
  purl?: string;
  /** How many of the project's SBOMs ship this component. */
  sbom_count: number;
  /** Distinct vulnerability ids known against it within the project. */
  vuln_count: number;
}

/**
 * One grouping label and its reach, from GET /api/v1/tags.
 *
 * Fetched rather than hard-coded so the UI renders whichever groupings an
 * instance actually uses — a fixed list would be wrong everywhere but the one
 * deployment it was written for.
 */
export interface TagListItem {
  tag: string;
  sbom_count: number;
  /** Distinct projects carrying the tag; the number a grouping is really about. */
  project_count: number;
  /**
   * The tag is also a project name (#398) — a parent whose children carry
   * it. Rendered as a link to the parent rather than as a plain filter chip.
   */
  is_project: boolean;
}

export interface GlobalSearchPackage {
  package_name: string;
  purl: string;
  project_count: number;
}

export interface GlobalSearchProject {
  project_name: string;
  sbom_count: number;
  latest_sbom_id: string;
}

export interface GlobalSearchVulnerability {
  vuln_id: string;
  severity: string;
  summary: string;
  affected_sboms: number;
}

export interface GlobalSearchLicense {
  license_id: string;
  category: string;
  sbom_count: number;
}

export interface GlobalSearchResponse {
  query: string;
  packages: GlobalSearchPackage[];
  total_packages: number;
  projects: GlobalSearchProject[];
  total_projects: number;
  vulnerabilities: GlobalSearchVulnerability[];
  total_vulnerabilities: number;
  licenses: GlobalSearchLicense[];
  total_licenses: number;
}

/**
 * Ownership views (#131 cluster, #138 namespace, #57 project).
 *
 * An empty `name` is not missing data — it is the column DEFAULT '' for an SBOM
 * that was ingested without that dimension configured. The UI renders it as
 * "(unassigned)".
 */
export interface FleetProject {
  name: string;
  sbom_count: number;
  vuln_count: number;
  last_ingested?: string;
}

export interface FleetNamespace {
  name: string;
  sbom_count: number;
  vuln_count: number;
  projects: FleetProject[];
}

export interface FleetCluster {
  name: string;
  sbom_count: number;
  vuln_count: number;
  namespaces: FleetNamespace[];
}

export interface ClusterListItem {
  name: string;
  sbom_count: number;
  package_count: number;
  vuln_count: number;
  last_ingested?: string;
}

export interface ClusterStats {
  cluster: string;
  total_sboms: number;
  total_packages: number;
  total_vulnerabilities: number;
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
  license_breakdown: Record<string, number>;
  last_ingested?: string;
}

export interface NamespaceListItem {
  name: string;
  cluster?: string;
  cluster_count: number;
  sbom_count: number;
  package_count: number;
  vuln_count: number;
  last_ingested?: string;
}

export interface NamespaceStats {
  namespace: string;
  cluster?: string;
  clusters: string[];
  total_sboms: number;
  total_packages: number;
  total_vulnerabilities: number;
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
  license_breakdown: Record<string, number>;
  last_ingested?: string;
}
