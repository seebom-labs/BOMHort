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
	PackageCount uint64 `json:"package_count"`
	VulnCount    uint64 `json:"vuln_count"`
	IngestedAt   string `json:"ingested_at"`
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
	VEXID           string            `json:"vex_id"`
	DocumentID      string            `json:"document_id"`
	SourceFile      string            `json:"source_file"`
	ProductPURL     string            `json:"product_purl"`
	VulnID          string            `json:"vuln_id"`
	Status          string            `json:"status"`
	Justification   string            `json:"justification"`
	ImpactStatement string            `json:"impact_statement,omitempty"`
	ActionStatement string            `json:"action_statement,omitempty"`
	VEXTimestamp    string            `json:"vex_timestamp"`
	IngestedAt      string            `json:"ingested_at"`
	AffectedSBOMs   []VEXAffectedSBOM `json:"affected_sboms,omitempty"`
}

// VEXAffectedSBOM links a VEX statement to an SBOM that uses the affected PURL.
type VEXAffectedSBOM struct {
	SBOMID       string `json:"sbom_id"`
	DocumentName string `json:"document_name"`
}

// SBOMDetail is the response DTO for detailed SBOM view with vulns and licenses.
type SBOMDetail struct {
	SBOMID        string `json:"sbom_id"`
	SourceFile    string `json:"source_file"`
	SPDXVersion   string `json:"spdx_version"`
	DocumentName  string `json:"document_name"`
	PackageCount  uint64 `json:"package_count"`
	VulnCount     uint64 `json:"vuln_count"`
	IngestedAt    string `json:"ingested_at"`
	CriticalVulns uint64 `json:"critical_vulns"`
	HighVulns     uint64 `json:"high_vulns"`
	MediumVulns   uint64 `json:"medium_vulns"`
	LowVulns      uint64 `json:"low_vulns"`
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
	PackageName     string                `json:"package_name"`
	PURL            string                `json:"purl"`
	VersionCount    uint64                `json:"version_count"`
	ProjectCount    uint64                `json:"project_count"`
	IsDirectInCount uint64                `json:"is_direct_in_count"`
	Versions        []VersionSkewDetail   `json:"versions"`
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

