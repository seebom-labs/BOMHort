package models

import (
	"time"

	"github.com/google/uuid"
)

// SBOM represents the metadata of a single SPDX document.
type SBOM struct {
	IngestedAt        time.Time `json:"ingested_at"`
	SBOMID            uuid.UUID `json:"sbom_id"`
	SourceFile        string    `json:"source_file"`
	SPDXVersion       string    `json:"spdx_version"`
	DocumentName      string    `json:"document_name"`
	DocumentNamespace string    `json:"document_namespace"`
	SHA256Hash        string    `json:"sha256_hash"`
	CreationDate      time.Time `json:"creation_date"`
	CreatorTools      []string  `json:"creator_tools"`
	Cluster           string    `json:"cluster,omitempty"`
}

// SBOMPackages stores the full dependency tree of an SBOM as parallel arrays.
// One row per SBOM – ClickHouse compresses columnar arrays extremely well.
type SBOMPackages struct {
	IngestedAt       time.Time `json:"ingested_at"`
	SBOMID           uuid.UUID `json:"sbom_id"`
	SourceFile       string    `json:"source_file"`
	PackageSPDXIDs   []string  `json:"package_spdx_ids"`
	PackageNames     []string  `json:"package_names"`
	PackageVersions  []string  `json:"package_versions"`
	PackagePURLs     []string  `json:"package_purls"`
	PackageLicenses  []string  `json:"package_licenses"`
	RelSourceIndices []uint32  `json:"rel_source_indices"`
	RelTargetIndices []uint32  `json:"rel_target_indices"`
	RelTypes         []string  `json:"rel_types"`
	Cluster          string    `json:"cluster,omitempty"`
}

// Vulnerability represents a single vulnerability discovered via the OSV API.
type Vulnerability struct {
	DiscoveredAt     time.Time `json:"discovered_at"`
	SBOMID           uuid.UUID `json:"sbom_id"`
	SourceFile       string    `json:"source_file"`
	PURL             string    `json:"purl"`
	VulnID           string    `json:"vuln_id"`
	Severity         string    `json:"severity"`
	Summary          string    `json:"summary"`
	AffectedVersions []string  `json:"affected_versions"`
	FixedVersion     string    `json:"fixed_version"`
	OSVJSON          string    `json:"osv_json"`
	Cluster          string    `json:"cluster,omitempty"`
}

// LicenseCompliance represents the compliance status for a license within an SBOM.
type LicenseCompliance struct {
	CheckedAt            time.Time `json:"checked_at"`
	SBOMID               uuid.UUID `json:"sbom_id"`
	SourceFile           string    `json:"source_file"`
	LicenseID            string    `json:"license_id"`
	Category             string    `json:"category"` // permissive, copyleft, unknown
	PackageCount         uint32    `json:"package_count"`
	NonCompliantPackages []string  `json:"non_compliant_packages"`
	ExemptedPackages     []string  `json:"exempted_packages"`
	ExemptionReason      string    `json:"exemption_reason"`
	Cluster              string    `json:"cluster,omitempty"`
}

// IngestionJob represents a job in the ClickHouse-based queue.
type IngestionJob struct {
	CreatedAt    time.Time  `json:"created_at"`
	JobID        uuid.UUID  `json:"job_id"`
	SourceFile   string     `json:"source_file"`
	SHA256Hash   string     `json:"sha256_hash"`
	Status       string     `json:"status"`   // pending, processing, done, failed
	JobType      string     `json:"job_type"` // sbom, vex
	ClaimedBy    string     `json:"claimed_by"`
	ClaimedAt    *time.Time `json:"claimed_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	ErrorMessage string     `json:"error_message,omitempty"`
	Cluster      string     `json:"cluster,omitempty"`
}

// Job status constants.
const (
	JobStatusPending    = "pending"
	JobStatusProcessing = "processing"
	JobStatusDone       = "done"
	JobStatusFailed     = "failed"
)

// Job type constants.
const (
	JobTypeSBOM = "sbom"
	JobTypeVEX  = "vex"
)

// VEXStatement represents a single VEX statement linking a product to a vulnerability status.
type VEXStatement struct {
	IngestedAt      time.Time `json:"ingested_at"`
	VEXID           uuid.UUID `json:"vex_id"`
	DocumentID      string    `json:"document_id"`
	SourceFile      string    `json:"source_file"`
	ProductPURL     string    `json:"product_purl"`
	VulnID          string    `json:"vuln_id"`
	Status          string    `json:"status"`        // not_affected, affected, fixed, under_investigation
	Justification   string    `json:"justification"` // component_not_present, vulnerable_code_not_present, etc.
	ImpactStatement string    `json:"impact_statement"`
	ActionStatement string    `json:"action_statement"`
	VEXTimestamp    time.Time `json:"vex_timestamp"`
	Cluster         string    `json:"cluster,omitempty"`
}

// VEX status constants (OpenVEX spec).
const (
	VEXStatusNotAffected        = "not_affected"
	VEXStatusAffected           = "affected"
	VEXStatusFixed              = "fixed"
	VEXStatusUnderInvestigation = "under_investigation"
)
