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
	// Namespace (#138) and Project (#57) are the two ownership dimensions
	// orthogonal to Cluster. Note that Namespace is the *deployment* namespace
	// (Kubernetes tenant boundary) and has nothing to do with
	// DocumentNamespace above, which is the SPDX document's URI identifier.
	Namespace string `json:"namespace,omitempty"`
	Project   string `json:"project,omitempty"`
	// SourceRepo/SourceRef (#332) name where the product's source lives:
	// a normalised https repository URL and the commit/tag/branch the SBOM
	// was generated from. Extracted from the document at parse time
	// (internal/sourcerepo), overridable via X-Source-Repo/X-Source-Ref
	// upload headers and PATCH /api/v1/sboms/{id}. '' = unknown.
	SourceRepo string `json:"source_repo,omitempty"`
	SourceRef  string `json:"source_ref,omitempty"`
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
	Namespace        string    `json:"namespace,omitempty"`
	Project          string    `json:"project,omitempty"`
	// RootIndices marks the package(s) the SBOM DESCRIBES – the product itself,
	// not a dependency. Kept in the arrays (index 0 is the dependency-tree root)
	// but excluded from license compliance. Not persisted to ClickHouse.
	RootIndices []uint32 `json:"-"`
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
	// Aliases are the other identifiers OSV lists for the same flaw
	// (GHSA-… ↔ CVE-… ↔ GO-…). VEX matching accepts any of them: a
	// statement written about the CVE must hit the finding stored under
	// its GHSA id.
	Aliases      []string `json:"aliases,omitempty"`
	FixedVersion string   `json:"fixed_version"`
	OSVJSON      string   `json:"osv_json"`
	Cluster      string   `json:"cluster,omitempty"`
	Namespace    string   `json:"namespace,omitempty"`
	Project      string   `json:"project,omitempty"`
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
	Namespace            string    `json:"namespace,omitempty"`
	Project              string    `json:"project,omitempty"`
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
	Namespace    string     `json:"namespace,omitempty"`
	Project      string     `json:"project,omitempty"`
	// SourceRepo/SourceRef (#332) carry an explicit X-Source-Repo /
	// X-Source-Ref upload override from the gateway to the parsing worker.
	// Empty for watcher-enqueued jobs — the worker then keeps whatever the
	// document itself yields.
	SourceRepo string `json:"source_repo,omitempty"`
	SourceRef  string `json:"source_ref,omitempty"`
	// TargetSBOMID (#350) carries an explicit ?sbom_id= VEX-upload mapping
	// from the gateway to the parsing worker. Empty for SBOM jobs and for
	// watcher-enqueued VEX jobs (the worker then auto-resolves per product).
	TargetSBOMID string `json:"target_sbom_id,omitempty"`
}

// StoredDocument is a row in document_store (#256): the reference to the
// original SBOM bytes captured at ingest, plus integrity metadata. The bytes
// themselves live in the blob store addressed by StorageRef.
type StoredDocument struct {
	StoredAt        time.Time `json:"stored_at"`
	SBOMID          uuid.UUID `json:"sbom_id"`
	Cluster         string    `json:"cluster,omitempty"`
	Namespace       string    `json:"namespace,omitempty"`
	Project         string    `json:"project,omitempty"`
	SourceFile      string    `json:"source_file"`
	StorageBackend  string    `json:"storage_backend"` // s3 | fs
	StorageRef      string    `json:"storage_ref"`     // s3://bucket/key or fs://relative/path
	SHA256Hash      string    `json:"sha256_hash"`     // of the original (decoded) bytes
	SizeBytes       uint64    `json:"size_bytes"`      // of the original (decoded) bytes
	ContentType     string    `json:"content_type"`
	ContentEncoding string    `json:"content_encoding"`  // "" (identity) | gzip — how the blob is stored
	StoredSizeBytes uint64    `json:"stored_size_bytes"` // bytes actually occupied in the blob store
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

// VEXProductWide is the sentinel stored in vex_statements.product_purl for a
// statement that applies to the product as a whole rather than to one of its
// components.
//
// OpenVEX allows a statement to name only products[] with no subcomponents[],
// which asserts the status for the entire product — "this application is not
// affected by CVE-X", regardless of which library carries the vulnerable code.
// Such a statement has no component purl to match against
// vulnerabilities.purl, so suppression joins test for this sentinel in
// addition to an exact purl match. '*' can never collide with a real purl,
// which always starts with "pkg:".
const VEXProductWide = "*"

// VEXStatement represents a single VEX statement linking a product to a vulnerability status.
type VEXStatement struct {
	IngestedAt time.Time `json:"ingested_at"`
	VEXID      uuid.UUID `json:"vex_id"`
	DocumentID string    `json:"document_id"`
	SourceFile string    `json:"source_file"`
	// SBOMID scopes the statement to one SBOM (#350). Empty = global/legacy:
	// the statement matches every SBOM, but a scoped statement always beats
	// a global one. Stored as String in ClickHouse so '' can mean "global".
	SBOMID string `json:"sbom_id,omitempty"`
	// ProductRef is the OpenVEX product @id (or purl identifier) this
	// statement was made about. Persisted (migration 020) so statements
	// whose product SBOM had not been ingested yet can be re-resolved
	// later — without the ref an unscoped statement was inert forever.
	ProductRef string `json:"product_ref,omitempty"`
	// ProductWide reports that the document named a product with no
	// subcomponents, i.e. the status covers every component of the product.
	// Not persisted: once ProductRef resolves to an SBOM the parsing worker
	// rewrites ProductPURL to VEXProductWide, which is what the suppression
	// joins read.
	ProductWide     bool      `json:"-"`
	ProductPURL     string    `json:"product_purl"`
	VulnID          string    `json:"vuln_id"`
	Status          string    `json:"status"`        // not_affected, affected, fixed, under_investigation
	Justification   string    `json:"justification"` // component_not_present, vulnerable_code_not_present, etc.
	ImpactStatement string    `json:"impact_statement"`
	ActionStatement string    `json:"action_statement"`
	VEXTimestamp    time.Time `json:"vex_timestamp"`
	// Provenance (#334): who (or what) issued the statement. Author, Role
	// and Tooling come from the OpenVEX document; StatusNotes from the
	// statement (automated producers write confidence + reasoning there).
	Author      string `json:"author,omitempty"`
	Role        string `json:"role,omitempty"`
	Tooling     string `json:"tooling,omitempty"`
	StatusNotes string `json:"status_notes,omitempty"`
	Cluster     string `json:"cluster,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Project     string `json:"project,omitempty"`
}

// VEX status constants (OpenVEX spec).
const (
	VEXStatusNotAffected        = "not_affected"
	VEXStatusAffected           = "affected"
	VEXStatusFixed              = "fixed"
	VEXStatusUnderInvestigation = "under_investigation"
)
