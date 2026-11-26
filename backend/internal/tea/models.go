package tea

// WellKnownDocument represents the JSON payload served at /.well-known/tea.
type WellKnownDocument struct {
	SchemaVersion int        `json:"schemaVersion"`
	Endpoints     []Endpoint `json:"endpoints"`
}

// Endpoint represents a single TEA API endpoint entry in /.well-known/tea.
type Endpoint struct {
	URL      string   `json:"url"`
	Versions []string `json:"versions"`
	Priority float64  `json:"priority,omitempty"`
}

// DiscoveryInfo represents one product release matched during discovery.
type DiscoveryInfo struct {
	ProductReleaseUUID string       `json:"productReleaseUuid"`
	Servers            []ServerInfo `json:"servers"`
}

// ServerInfo contains connection and version metadata for a TEA server.
type ServerInfo struct {
	RootURL  string   `json:"rootUrl"`
	Versions []string `json:"versions"`
	Priority float64  `json:"priority,omitempty"`
}

// Identifier describes a product, component or release identifier.
type Identifier struct {
	IDType  string `json:"idType"`  // CPE, TEI, PURL
	IDValue string `json:"idValue"` // e.g. pkg:golang/github.com/org/repo@v1.0.0
}

// Product represents a TEA Product entity (maps to BOMHort project + parent).
type Product struct {
	UUID        string       `json:"uuid"`
	Name        string       `json:"name"`
	Identifiers []Identifier `json:"identifiers,omitempty"`
}

// ProductRelease represents a specific release of a TEA Product.
type ProductRelease struct {
	UUID        string         `json:"uuid"`
	Product     string         `json:"product"`
	ProductName string         `json:"productName,omitempty"`
	Version     string         `json:"version"`
	CreatedDate string         `json:"createdDate"`
	ReleaseDate string         `json:"releaseDate,omitempty"`
	PreRelease  bool           `json:"preRelease,omitempty"`
	Identifiers []Identifier   `json:"identifiers,omitempty"`
	Components  []ComponentRef `json:"components"`
}

// ComponentRef references a component within a product release.
type ComponentRef struct {
	UUID    string `json:"uuid"`
	Release string `json:"release,omitempty"`
}

// Component represents a TEA Component entity (maps to SBOM root / root_purl).
type Component struct {
	UUID        string       `json:"uuid"`
	Name        string       `json:"name"`
	Identifiers []Identifier `json:"identifiers,omitempty"`
}

// ComponentRelease represents a specific release of a TEA Component.
type ComponentRelease struct {
	UUID        string       `json:"uuid"`
	Component   string       `json:"component"`
	Version     string       `json:"version"`
	CreatedDate string       `json:"createdDate"`
	ReleaseDate string       `json:"releaseDate,omitempty"`
	Identifiers []Identifier `json:"identifiers,omitempty"`
}

// Collection represents a versioned collection of artifacts for a release.
type Collection struct {
	UUID         string                 `json:"uuid"`
	Version      int                    `json:"version"`
	CreatedDate  string                 `json:"createdDate"`
	BelongsTo    string                 `json:"belongsTo"` // PRODUCT_RELEASE or COMPONENT_RELEASE
	UpdateReason CollectionUpdateReason `json:"updateReason"`
	Artifacts    []Artifact             `json:"artifacts"`
}

// CollectionUpdateReason explains the reason for the collection creation or update.
type CollectionUpdateReason struct {
	Type    string `json:"type"`              // INITIAL_RELEASE, VEX_UPDATED, ARTIFACT_UPDATED, etc.
	Comment string `json:"comment,omitempty"` // Optional human-readable description
}

// Artifact represents a security or supply chain document (SBOM, VEX, attestation).
type Artifact struct {
	UUID            string           `json:"uuid"`
	Version         int              `json:"version"`
	Name            string           `json:"name"`
	Type            string           `json:"type"` // BOM, VULNERABILITIES, ATTESTATION
	CreatedDate     string           `json:"createdDate"`
	DistributionIDs []string         `json:"distributionIds,omitempty"`
	Formats         []ArtifactFormat `json:"formats"`
}

// ArtifactFormat represents a specific representation format of an artifact.
type ArtifactFormat struct {
	MediaType    string     `json:"mediaType"`
	Description  string     `json:"description,omitempty"`
	URL          string     `json:"url,omitempty"`
	SignatureURL string     `json:"signatureUrl,omitempty"`
	Checksums    []Checksum `json:"checksums,omitempty"`
}

// Checksum contains integrity digests for artifact content bytes.
type Checksum struct {
	AlgType  string `json:"algType"`  // SHA-256, SHA-1, SHA-512
	AlgValue string `json:"algValue"` // Lowercase hexadecimal digest
}

// ErrorResponse represents the standard TEA error body.
type ErrorResponse struct {
	Error   string `json:"error"`             // Unknown error code from TEA schema
	Message string `json:"message,omitempty"` // Diagnostic explanation
}

// PaginatedResponse wraps a slice of items with TEA pagination metadata.
type PaginatedResponse[T any] struct {
	HasNext       bool   `json:"hasNext"`
	NextPageToken string `json:"nextPageToken,omitempty"`
	Results       []T    `json:"results"`
}
