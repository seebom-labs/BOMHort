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
  package_count: number;
  vuln_count: number;
  ingested_at: string;
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
}

export interface DependencyNode {
  index: number;
  spdx_id: string;
  name: string;
  version: string;
  purl: string;
  license: string;
  children: number[];
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
  product_purl: string;
  vuln_id: string;
  status: string;
  justification: string;
  impact_statement?: string;
  action_statement?: string;
  vex_timestamp: string;
  ingested_at: string;
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
  package_count: number;
  vuln_count: number;
  ingested_at: string;
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

