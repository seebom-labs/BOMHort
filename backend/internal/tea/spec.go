package tea

// Pinned TEA specification constants.
//
// Target: Transparency Exchange API (TEA, ECMA TC54 / CycloneDX, Beta 2).
// Pinned version 1.0.0; any future Beta 3 or 1.1 changes require a dedicated issue.
const (
	// SpecVersion is the SemVer 2.0.0 string advertised in discovery and headers.
	SpecVersion = "1.0.0"

	// WellKnownSchemaVersion is the schemaVersion for /.well-known/tea payload.
	WellKnownSchemaVersion = 1

	// EndpointPriorityDefault is the default priority for TEA endpoints (0.0 to 1.0).
	EndpointPriorityDefault = 1.0
)

// Artifact types as specified in the TEA specification (components/schemas/artifact-type).
const (
	ArtifactTypeBOM             = "BOM"
	ArtifactTypeVulnerabilities = "VULNERABILITIES"
	ArtifactTypeAttestation     = "ATTESTATION"
	ArtifactTypeCertification   = "CERTIFICATION"
	ArtifactTypeLicense         = "LICENSE"
	ArtifactTypeReleaseNotes    = "RELEASE_NOTES"
	ArtifactTypeOther           = "OTHER"
)

// Collection belongs-to types (components/schemas/collection-belongs-to-type).
const (
	BelongsToProductRelease   = "PRODUCT_RELEASE"
	BelongsToComponentRelease = "COMPONENT_RELEASE"
)

// Collection update reason types (components/schemas/collection-update-reason-type).
const (
	UpdateReasonInitialRelease  = "INITIAL_RELEASE"
	UpdateReasonVEXUpdated      = "VEX_UPDATED"
	UpdateReasonArtifactUpdated = "ARTIFACT_UPDATED"
	UpdateReasonArtifactAdded   = "ARTIFACT_ADDED"
	UpdateReasonArtifactRemoved = "ARTIFACT_REMOVED"
)

// Checksum algorithm types (components/schemas/checksum-type).
const (
	ChecksumAlgSHA256 = "SHA-256"
	ChecksumAlgSHA1   = "SHA-1"
	ChecksumAlgSHA512 = "SHA-512"
)

// Error codes matching TEA unknown-error-type schema.
const (
	ErrCodeObjectUnknown      = "OBJECT_UNKNOWN"
	ErrCodeNotImplemented     = "NOT_IMPLEMENTED"
	ErrCodeNoAcceptableFormat = "NO_ACCEPTABLE_FORMAT"
	ErrCodeSignatureNotFound  = "SIGNATURE_NOT_FOUND"
	ErrCodeInvalidRequest     = "INVALID_REQUEST"
	ErrCodeInvalidPageToken   = "INVALID_PAGE_TOKEN"
)

// Standard Media Types for supply chain documents in TEA.
const (
	MediaTypeSPDXJSON      = "application/spdx+json"
	MediaTypeCycloneDXJSON = "application/vnd.cyclonedx+json"
	MediaTypeOpenVEXJSON   = "application/vnd.openvex+json"
	MediaTypeInTotoJSON    = "application/vnd.in-toto+json"
	MediaTypeJSON          = "application/json"
	MediaTypeOctetStream   = "application/octet-stream"
)
