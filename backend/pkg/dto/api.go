package dto

// DashboardStats is the response DTO for the /api/v1/stats/dashboard endpoint.
type DashboardStats struct {
	TotalSBOMs               uint64            `json:"total_sboms"`
	TotalPackages            uint64            `json:"total_packages"`
	TotalVulnerabilities     uint64            `json:"total_vulnerabilities"`
	EffectiveVulnerabilities uint64            `json:"effective_vulnerabilities"`
	SuppressedByVEX          uint64            `json:"suppressed_by_vex"`
	CriticalVulns            uint64            `json:"critical_vulns"`
	HighVulns                uint64            `json:"high_vulns"`
	MediumVulns              uint64            `json:"medium_vulns"`
	LowVulns                 uint64            `json:"low_vulns"`
	LicenseBreakdown         map[string]uint64 `json:"license_breakdown"`
	ExemptedPackages         uint64            `json:"exempted_packages"`
	TotalVEXStatements       uint64            `json:"total_vex_statements"`
	LastCVERefresh           string            `json:"last_cve_refresh,omitempty"`
	NewVulnsSinceRefresh     uint64            `json:"new_vulns_since_refresh"`
	ArchivedReposCount       uint64            `json:"archived_repos_count"`
}

// SBOMListItem is the response DTO for listing SBOMs.
type SBOMListItem struct {
	SBOMID       string `json:"sbom_id"`
	SourceFile   string `json:"source_file"`
	SPDXVersion  string `json:"spdx_version"`
	DocumentName string `json:"document_name"`
	// DocumentVersion is the described product's version ('' = unknown).
	DocumentVersion string `json:"document_version,omitempty"`
	PackageCount    uint64 `json:"package_count"`
	VulnCount       uint64 `json:"vuln_count"`
	IngestedAt      string `json:"ingested_at"`
	SourceRepo      string `json:"source_repo,omitempty"`
	SourceRef       string `json:"source_ref,omitempty"`
	// Ownership dimensions (#177). Completes the list contract before the
	// v1.0 freeze: the detail view and the cluster endpoints already expose
	// these, so a client could not tell which cluster/namespace/project a
	// listed SBOM belongs to without a second request per row. All three
	// default to '' and are omitted when unset (single-instance deployments).
	Cluster   string `json:"cluster,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Project   string `json:"project,omitempty"`
}

// PaginatedResponse wraps any list response with pagination metadata.
type PaginatedResponse[T any] struct {
	Data     []T    `json:"data"`
	Total    uint64 `json:"total"`
	Page     uint64 `json:"page"`
	PageSize uint64 `json:"page_size"`
}

// VulnerabilityListItem is the response DTO for listing vulnerabilities.
type VulnerabilityListItem struct {
	VulnID       string `json:"vuln_id"`
	Severity     string `json:"severity"`
	PURL         string `json:"purl"`
	Summary      string `json:"summary"`
	FixedVersion string `json:"fixed_version"`
	SourceFile   string `json:"source_file"`
	DiscoveredAt string `json:"discovered_at"`
	VEXStatus    string `json:"vex_status,omitempty"`
	// Effective VEX statement detail (#335): exactly one row per
	// (vuln_id, purl) is returned; the statement with the newest
	// vex_timestamp wins (OpenVEX conflict rule). All fields are omitted
	// when no VEX statement covers the pair.
	VEXJustification string `json:"vex_justification,omitempty"`
	VEXTimestamp     string `json:"vex_timestamp,omitempty"`
	VEXStatementID   string `json:"vex_statement_id,omitempty"`
	VEXAuthor        string `json:"vex_author,omitempty"`
	VEXTooling       string `json:"vex_tooling,omitempty"`
	// VEXScope (#350): "sbom" when the winning statement is scoped to this
	// SBOM, "global" for unscoped legacy statements. Omitted without VEX.
	VEXScope string `json:"vex_scope,omitempty"`
}

// DependencyNode represents a single node in the dependency tree for the UI.
type DependencyNode struct {
	Index    uint32   `json:"index"`
	SPDXID   string   `json:"spdx_id"`
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	PURL     string   `json:"purl"`
	License  string   `json:"license"`
	Children []uint32 `json:"children"`
}

// LicenseComplianceItem is the response DTO for license compliance overview.
type LicenseComplianceItem struct {
	LicenseID            string                `json:"license_id"`
	Category             string                `json:"category"`
	PackageCount         uint64                `json:"package_count"`
	SBOMCount            int                   `json:"sbom_count"`
	NonCompliantPackages []string              `json:"non_compliant_packages,omitempty"`
	ExemptedPackages     []string              `json:"exempted_packages,omitempty"`
	ExemptionReason      string                `json:"exemption_reason,omitempty"`
	AffectedSBOMs        []LicenseAffectedSBOM `json:"affected_sboms,omitempty"`
}

// LicenseAffectedSBOM links a license back to the SBOMs that contain it.
type LicenseAffectedSBOM struct {
	SBOMID       string `json:"sbom_id"`
	DocumentName string `json:"document_name"`
}

// VEXStatementItem is the response DTO for listing VEX statements.
type VEXStatementItem struct {
	VEXID      string `json:"vex_id"`
	DocumentID string `json:"document_id"`
	SourceFile string `json:"source_file"`
	// SBOMID scopes the statement to one SBOM (#350); empty = global.
	SBOMID          string `json:"sbom_id,omitempty"`
	ProductPURL     string `json:"product_purl"`
	VulnID          string `json:"vuln_id"`
	Status          string `json:"status"`
	Justification   string `json:"justification"`
	ImpactStatement string `json:"impact_statement,omitempty"`
	ActionStatement string `json:"action_statement,omitempty"`
	VEXTimestamp    string `json:"vex_timestamp"`
	IngestedAt      string `json:"ingested_at"`
	// Provenance (#334); omitted when the source document has none.
	Author        string            `json:"author,omitempty"`
	Role          string            `json:"role,omitempty"`
	Tooling       string            `json:"tooling,omitempty"`
	StatusNotes   string            `json:"status_notes,omitempty"`
	AffectedSBOMs []VEXAffectedSBOM `json:"affected_sboms,omitempty"`
}

// VEXAffectedSBOM links a VEX statement to an SBOM that uses the affected PURL.
type VEXAffectedSBOM struct {
	SBOMID       string `json:"sbom_id"`
	DocumentName string `json:"document_name"`
}

// SBOMDetail is the response DTO for detailed SBOM view with vulns and licenses.
type SBOMDetail struct {
	SBOMID       string `json:"sbom_id"`
	SourceFile   string `json:"source_file"`
	SPDXVersion  string `json:"spdx_version"`
	DocumentName string `json:"document_name"`
	// DocumentVersion is the described product's version ('' = unknown).
	DocumentVersion string `json:"document_version,omitempty"`
	PackageCount    uint64 `json:"package_count"`
	VulnCount       uint64 `json:"vuln_count"`
	IngestedAt      string `json:"ingested_at"`
	SourceRepo      string `json:"source_repo,omitempty"`
	SourceRef       string `json:"source_ref,omitempty"`
	CriticalVulns   uint64 `json:"critical_vulns"`
	HighVulns       uint64 `json:"high_vulns"`
	MediumVulns     uint64 `json:"medium_vulns"`
	LowVulns        uint64 `json:"low_vulns"`
}

// SBOMLicenseBreakdownItem is a per-SBOM license summary.
type SBOMLicenseBreakdownItem struct {
	LicenseID        string   `json:"license_id"`
	Category         string   `json:"category"`
	PackageCount     uint32   `json:"package_count"`
	Packages         []string `json:"packages"`
	ExemptedPackages []string `json:"exempted_packages,omitempty"`
	ExemptionReason  string   `json:"exemption_reason,omitempty"`
}

// ProjectLicenseViolation represents a project that has license compliance issues.
type ProjectLicenseViolation struct {
	SBOMID               string   `json:"sbom_id"`
	SourceFile           string   `json:"source_file"`
	DocumentName         string   `json:"document_name"`
	CopyleftCount        uint64   `json:"copyleft_count"`
	UnknownCount         uint64   `json:"unknown_count"`
	ViolatingLicenses    []string `json:"violating_licenses"`
	NonCompliantPackages []string `json:"non_compliant_packages"`
}

// AffectedProject represents a project affected by a specific CVE.
type AffectedProject struct {
	SBOMID       string `json:"sbom_id"`
	SourceFile   string `json:"source_file"`
	DocumentName string `json:"document_name"`
	PURL         string `json:"purl"`
	PackageName  string `json:"package_name"`
	Version      string `json:"version"`
	Severity     string `json:"severity"`
	VEXStatus    string `json:"vex_status,omitempty"`
	IsDirect     bool   `json:"is_direct"`
}

// DependencyStatsItem is a cross-project dependency usage statistic.
type DependencyStatsItem struct {
	PackageName  string   `json:"package_name"`
	PURL         string   `json:"purl"`
	ProjectCount uint64   `json:"project_count"`
	Versions     []string `json:"versions"`
	VulnCount    uint64   `json:"vuln_count"`
}

// DependencyStatsResponse wraps the dependency statistics response.
type DependencyStatsResponse struct {
	TotalUniqueDeps uint64                `json:"total_unique_deps"`
	TopDependencies []DependencyStatsItem `json:"top_dependencies"`
}

// VersionSkewItem represents a package with inconsistent versions across projects.
type VersionSkewItem struct {
	PackageName     string              `json:"package_name"`
	PURL            string              `json:"purl"`
	VersionCount    uint64              `json:"version_count"`
	ProjectCount    uint64              `json:"project_count"`
	IsDirectInCount uint64              `json:"is_direct_in_count"`
	Versions        []VersionSkewDetail `json:"versions"`
}

// VersionSkewDetail shows per-version breakdown for a skewed package.
type VersionSkewDetail struct {
	Version      string   `json:"version"`
	ProjectCount uint64   `json:"project_count"`
	Projects     []string `json:"projects"`
}

// VersionSkewResponse wraps the version skew statistics response.
type VersionSkewResponse struct {
	TotalSkewedPackages uint64            `json:"total_skewed_packages"`
	Items               []VersionSkewItem `json:"items"`
	Page                uint64            `json:"page"`
	PageSize            uint64            `json:"page_size"`
}

// DependencySearchProject represents a project using a specific package.
type DependencySearchProject struct {
	ProjectName string `json:"project_name"`
	Version     string `json:"version"`
	SBOMID      string `json:"sbom_id"`
}

// DependencySearchResult represents a package found by search.
type DependencySearchResult struct {
	PackageName  string                    `json:"package_name"`
	PURL         string                    `json:"purl"`
	ProjectCount uint64                    `json:"project_count"`
	Versions     []string                  `json:"versions"`
	Projects     []DependencySearchProject `json:"projects"`
}

// DependencySearchResponse wraps the package search response.
type DependencySearchResponse struct {
	TotalResults uint64                   `json:"total_results"`
	Items        []DependencySearchResult `json:"items"`
	Page         uint64                   `json:"page"`
	PageSize     uint64                   `json:"page_size"`
	Query        string                   `json:"query"`
}

// PackageDetailResponse returns all projects using a specific package (paginated).
type PackageDetailResponse struct {
	PackageName   string                    `json:"package_name"`
	TotalProjects uint64                    `json:"total_projects"`
	Projects      []DependencySearchProject `json:"projects"`
	Page          uint64                    `json:"page"`
	PageSize      uint64                    `json:"page_size"`
}

// GlobalSearchPackage is a package hit in the global search response.
type GlobalSearchPackage struct {
	PackageName  string `json:"package_name"`
	PURL         string `json:"purl"`
	ProjectCount uint64 `json:"project_count"`
}

// GlobalSearchProject is a project hit in the global search response.
type GlobalSearchProject struct {
	ProjectName  string `json:"project_name"`
	SBOMCount    uint64 `json:"sbom_count"`
	LatestSBOMID string `json:"latest_sbom_id"`
}

// GlobalSearchVulnerability is a vulnerability hit in the global search response.
type GlobalSearchVulnerability struct {
	VulnID        string `json:"vuln_id"`
	Severity      string `json:"severity"`
	Summary       string `json:"summary"`
	AffectedSBOMs uint64 `json:"affected_sboms"`
}

// GlobalSearchLicense is a license hit in the global search response.
type GlobalSearchLicense struct {
	LicenseID string `json:"license_id"`
	Category  string `json:"category"`
	SBOMCount uint64 `json:"sbom_count"`
}

// GlobalSearchResponse is the faceted response for /api/v1/search.
// Each facet returns up to `limit` items plus the total match count.
type GlobalSearchResponse struct {
	Query                string                      `json:"query"`
	Packages             []GlobalSearchPackage       `json:"packages"`
	TotalPackages        uint64                      `json:"total_packages"`
	Projects             []GlobalSearchProject       `json:"projects"`
	TotalProjects        uint64                      `json:"total_projects"`
	Vulnerabilities      []GlobalSearchVulnerability `json:"vulnerabilities"`
	TotalVulnerabilities uint64                      `json:"total_vulnerabilities"`
	Licenses             []GlobalSearchLicense       `json:"licenses"`
	TotalLicenses        uint64                      `json:"total_licenses"`
}

// ClusterListItem represents a cluster in the cluster listing.
type ClusterListItem struct {
	Name         string `json:"name"`
	SBOMCount    uint64 `json:"sbom_count"`
	PackageCount uint64 `json:"package_count"`
	VulnCount    uint64 `json:"vuln_count"`
	LastIngested string `json:"last_ingested,omitempty"`
}

// ClusterStats is the response DTO for per-cluster statistics.
type ClusterStats struct {
	Cluster              string            `json:"cluster"`
	TotalSBOMs           uint64            `json:"total_sboms"`
	TotalPackages        uint64            `json:"total_packages"`
	TotalVulnerabilities uint64            `json:"total_vulnerabilities"`
	CriticalVulns        uint64            `json:"critical_vulns"`
	HighVulns            uint64            `json:"high_vulns"`
	MediumVulns          uint64            `json:"medium_vulns"`
	LowVulns             uint64            `json:"low_vulns"`
	LicenseBreakdown     map[string]uint64 `json:"license_breakdown"`
	LastIngested         string            `json:"last_ingested,omitempty"`
}

// NamespaceListItem represents a namespace in the namespace listing (#138).
// A namespace name is only unique within a cluster, so ClusterCount tells the
// caller whether `payments` here means one team or the same name reused in
// several clusters. Cluster is set only when the listing was filtered.
type NamespaceListItem struct {
	Name         string `json:"name"`
	Cluster      string `json:"cluster,omitempty"`
	ClusterCount uint64 `json:"cluster_count"`
	SBOMCount    uint64 `json:"sbom_count"`
	PackageCount uint64 `json:"package_count"`
	VulnCount    uint64 `json:"vuln_count"`
	LastIngested string `json:"last_ingested,omitempty"`
}

// NamespaceStats is the response DTO for per-namespace statistics. It mirrors
// ClusterStats so both drill-downs render with the same UI components.
type NamespaceStats struct {
	Namespace            string            `json:"namespace"`
	Cluster              string            `json:"cluster,omitempty"`
	Clusters             []string          `json:"clusters"`
	TotalSBOMs           uint64            `json:"total_sboms"`
	TotalPackages        uint64            `json:"total_packages"`
	TotalVulnerabilities uint64            `json:"total_vulnerabilities"`
	CriticalVulns        uint64            `json:"critical_vulns"`
	HighVulns            uint64            `json:"high_vulns"`
	MediumVulns          uint64            `json:"medium_vulns"`
	LowVulns             uint64            `json:"low_vulns"`
	LicenseBreakdown     map[string]uint64 `json:"license_breakdown"`
	LastIngested         string            `json:"last_ingested,omitempty"`
}

// FleetProject is a leaf of the ownership tree.
type FleetProject struct {
	Name         string `json:"name"`
	SBOMCount    uint64 `json:"sbom_count"`
	VulnCount    uint64 `json:"vuln_count"`
	LastIngested string `json:"last_ingested,omitempty"`
}

// FleetNamespace groups projects inside one cluster.
type FleetNamespace struct {
	Name      string         `json:"name"`
	SBOMCount uint64         `json:"sbom_count"`
	VulnCount uint64         `json:"vuln_count"`
	Projects  []FleetProject `json:"projects"`
}

// FleetCluster is the root of the ownership tree returned by
// GET /api/v1/fleet. Unassigned dimensions appear as an empty name.
type FleetCluster struct {
	Name       string           `json:"name"`
	SBOMCount  uint64           `json:"sbom_count"`
	VulnCount  uint64           `json:"vuln_count"`
	Namespaces []FleetNamespace `json:"namespaces"`
}

// ProjectListItem is the response DTO for the project list view.
type ProjectListItem struct {
	ProjectName    string `json:"project_name"`
	SBOMCount      uint64 `json:"sbom_count"`
	PackageCount   uint64 `json:"package_count"`
	VulnCount      uint64 `json:"vuln_count"`
	LatestIngested string `json:"latest_ingested"`
	LatestSBOMID   string `json:"latest_sbom_id"`
	// Tags (#357) are the union of the grouping labels across this project's
	// SBOMs. A project keeps its identity here — the tag is a label on it, not
	// a replacement for it — so a project with three SBOMs stays one row and
	// merely carries the groupings those SBOMs were ingested with.
	Tags []string `json:"tags"`
}

// TagListItem describes one grouping label and its reach, powering a
// data-driven grouping UI: the frontend renders whatever tags an instance
// actually uses rather than a hard-coded list.
type TagListItem struct {
	Tag string `json:"tag"`
	// SBOMCount counts documents; ProjectCount counts the distinct projects
	// behind them. The latter is what a grouping is really about — 300 SBOMs
	// across 40 sandbox applications should read as "40 projects", not "300".
	SBOMCount    uint64 `json:"sbom_count"`
	ProjectCount uint64 `json:"project_count"`
}
