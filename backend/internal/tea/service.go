package tea

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

var (
	// ErrNotFound is returned when a requested TEA resource is not found.
	ErrNotFound = errors.New("tea resource not found")

	// ErrInvalidRequest is returned on malformed input query or parameters.
	ErrInvalidRequest = errors.New("invalid tea request")
)

// Service implements the core business logic of the Transparency Exchange API.
type Service struct {
	store Store
}

// NewService creates a new TEA service backed by the provided Store.
func NewService(store Store) *Service {
	return &Service{store: store}
}

// ProductUUID returns a deterministic UUID for a product based on its project name.
func ProductUUID(projectName string) string {
	return uuid.NewSHA1(uuid.NameSpaceDNS, []byte("bomhort:tea:product:"+projectName)).String()
}

// ComponentUUID returns a deterministic UUID for a component based on its root PURL or name.
func ComponentUUID(purl, fallbackName string) string {
	if purl != "" {
		return uuid.NewSHA1(uuid.NameSpaceDNS, []byte("bomhort:tea:component:"+purl)).String()
	}
	return uuid.NewSHA1(uuid.NameSpaceDNS, []byte("bomhort:tea:component:name:"+fallbackName)).String()
}

// ComponentReleaseUUID returns a deterministic UUID for a component release distinct
// from product release UUIDs per the disjoint namespace requirement in doc/tea-uuid-scope.md.
func ComponentReleaseUUID(sbomID string) string {
	return uuid.NewSHA1(uuid.NameSpaceDNS, []byte("bomhort:tea:component-release:"+sbomID)).String()
}

// ArtifactVEXUUID returns a deterministic UUID for an SBOM's consolidated VEX artifact.
func ArtifactVEXUUID(sbomID string) string {
	return uuid.NewSHA1(uuid.NameSpaceDNS, []byte("bomhort:tea:artifact:vex:"+sbomID)).String()
}

// ArtifactAttestationUUID returns a deterministic UUID for an SBOM's attestation artifact.
func ArtifactAttestationUUID(sbomID string) string {
	return uuid.NewSHA1(uuid.NameSpaceDNS, []byte("bomhort:tea:artifact:attestation:"+sbomID)).String()
}

// ArtifactBOMDerivedUUID returns the derived UUID for an SBOM BOM artifact.
func ArtifactBOMDerivedUUID(sbomID string) string {
	return uuid.NewSHA1(uuid.NameSpaceDNS, []byte("bomhort:tea:artifact:bom:"+sbomID)).String()
}

// GetWellKnown constructs the discovery document for /.well-known/tea.
func (s *Service) GetWellKnown(baseURL string) WellKnownDocument {
	baseURL = strings.TrimRight(baseURL, "/")
	return WellKnownDocument{
		SchemaVersion: WellKnownSchemaVersion,
		Endpoints: []Endpoint{
			{
				URL:      baseURL,
				Versions: []string{SpecVersion},
				Priority: EndpointPriorityDefault,
			},
		},
	}
}

// Discover resolves a TEI or PURL query into matching Product Release discovery-info.
func (s *Service) Discover(ctx context.Context, teiRaw, purlRaw, baseURL string) ([]DiscoveryInfo, error) {
	hasTEI := strings.TrimSpace(teiRaw) != ""
	hasPURL := strings.TrimSpace(purlRaw) != ""

	if (!hasTEI && !hasPURL) || (hasTEI && hasPURL) {
		return nil, fmt.Errorf("%w: exactly one of 'tei' or 'purl' parameter must be provided", ErrInvalidRequest)
	}

	var targetPURL string
	var targetUUID string

	if hasPURL {
		targetPURL = CleanPURL(purlRaw)
	} else {
		parsed, err := ParseTEI(teiRaw)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
		}
		if parsed.Type == "purl" {
			targetPURL = parsed.PURL
		} else if parsed.Type == "uuid" {
			targetUUID = parsed.UUID
		} else {
			targetPURL = parsed.RawValue
		}
	}

	var matchingReleases []models.SBOM

	if targetUUID != "" {
		rel, err := s.store.QueryReleaseBySBOMID(ctx, targetUUID)
		if err == nil && rel != nil {
			matchingReleases = append(matchingReleases, *rel)
		}
	} else if targetPURL != "" {
		rels, err := s.store.QueryReleasesByPURL(ctx, targetPURL)
		if err != nil {
			return nil, err
		}
		matchingReleases = rels
	}

	if len(matchingReleases) == 0 {
		return nil, ErrNotFound
	}

	baseURL = strings.TrimRight(baseURL, "/")
	serverInfo := ServerInfo{
		RootURL:  baseURL,
		Versions: []string{SpecVersion},
		Priority: EndpointPriorityDefault,
	}

	out := make([]DiscoveryInfo, 0, len(matchingReleases))
	for _, rel := range matchingReleases {
		out = append(out, DiscoveryInfo{
			ProductReleaseUUID: rel.SBOMID.String(),
			Servers:            []ServerInfo{serverInfo},
		})
	}

	return out, nil
}

// ListProducts returns a paginated list of TEA products mapped from BOMHort projects.
func (s *Service) ListProducts(ctx context.Context, page, pageSize uint64) (*PaginatedResponse[Product], error) {
	summaries, total, err := s.store.QueryProducts(ctx, page, pageSize)
	if err != nil {
		return nil, err
	}

	results := make([]Product, 0, len(summaries))
	for _, sum := range summaries {
		results = append(results, toProduct(sum))
	}

	hasNext := (page * pageSize) < total
	var nextPageToken string
	if hasNext {
		nextPageToken = fmt.Sprintf("%d", page+1)
	}

	return &PaginatedResponse[Product]{
		HasNext:       hasNext,
		NextPageToken: nextPageToken,
		Results:       results,
	}, nil
}

// GetProduct retrieves a single TEA product by UUID or project name.
func (s *Service) GetProduct(ctx context.Context, idOrUUID string) (*Product, error) {
	sum, err := s.findProduct(ctx, idOrUUID)
	if err != nil {
		return nil, err
	}
	p := toProduct(*sum)
	return &p, nil
}

// ListProductReleases lists the releases belonging to a specific product.
func (s *Service) ListProductReleases(ctx context.Context, idOrUUID string, page, pageSize uint64) (*PaginatedResponse[ProductRelease], error) {
	sum, err := s.findProduct(ctx, idOrUUID)
	if err != nil {
		return nil, err
	}

	releases, total, err := s.store.QueryReleasesByProject(ctx, sum.ProjectName, page, pageSize)
	if err != nil {
		return nil, err
	}

	results := make([]ProductRelease, 0, len(releases))
	for _, r := range releases {
		results = append(results, toProductRelease(r, sum.ProjectName))
	}

	hasNext := (page * pageSize) < total
	var nextPageToken string
	if hasNext {
		nextPageToken = fmt.Sprintf("%d", page+1)
	}

	return &PaginatedResponse[ProductRelease]{
		HasNext:       hasNext,
		NextPageToken: nextPageToken,
		Results:       results,
	}, nil
}

// ListAllProductReleases lists all product releases across all projects.
func (s *Service) ListAllProductReleases(ctx context.Context, page, pageSize uint64) (*PaginatedResponse[ProductRelease], error) {
	releases, total, err := s.store.QueryAllReleases(ctx, page, pageSize)
	if err != nil {
		return nil, err
	}

	results := make([]ProductRelease, 0, len(releases))
	for _, r := range releases {
		results = append(results, toProductRelease(r, r.Project))
	}

	hasNext := (page * pageSize) < total
	var nextPageToken string
	if hasNext {
		nextPageToken = fmt.Sprintf("%d", page+1)
	}

	return &PaginatedResponse[ProductRelease]{
		HasNext:       hasNext,
		NextPageToken: nextPageToken,
		Results:       results,
	}, nil
}

// GetProductRelease retrieves a single product release by SBOM ID / release UUID.
func (s *Service) GetProductRelease(ctx context.Context, releaseUUID string) (*ProductRelease, error) {
	r, err := s.store.QueryReleaseBySBOMID(ctx, releaseUUID)
	if err != nil || r == nil {
		return nil, ErrNotFound
	}
	pr := toProductRelease(*r, r.Project)
	return &pr, nil
}

// GetCollection returns the artifact collection for a product release.
// Per doc/tea-uuid-scope.md, a Collection uses the same UUID as its parent Product Release.
func (s *Service) GetCollection(ctx context.Context, releaseUUID string, _ int) (*Collection, error) {
	rel, err := s.store.QueryReleaseBySBOMID(ctx, releaseUUID)
	if err != nil || rel == nil {
		return nil, ErrNotFound
	}

	vexCount, _ := s.store.QueryVEXStatementsCount(ctx, releaseUUID)

	// Format mediaType from source file extension
	mediaType := MediaTypeSPDXJSON
	lowerFile := strings.ToLower(rel.SourceFile)
	if strings.HasSuffix(lowerFile, ".cdx.json") || strings.Contains(lowerFile, "cyclonedx") {
		mediaType = MediaTypeCycloneDXJSON
	}

	// 1. Original SBOM artifact
	bomArtifact := Artifact{
		UUID:        rel.SBOMID.String(),
		Version:     1,
		Name:        filepath.Base(rel.SourceFile),
		Type:        ArtifactTypeBOM,
		CreatedDate: formatTime(rel.CreationDate, rel.IngestedAt),
		Formats: []ArtifactFormat{
			{
				MediaType:   mediaType,
				Description: "Original SBOM",
				Checksums: []Checksum{
					{
						AlgType:  ChecksumAlgSHA256,
						AlgValue: rel.SHA256Hash,
					},
				},
			},
		},
	}

	artifacts := []Artifact{bomArtifact}
	updateReasonType := UpdateReasonInitialRelease

	// 2. OpenVEX artifact if VEX statements exist
	if vexCount > 0 {
		updateReasonType = UpdateReasonVEXUpdated
		vexArtifact := Artifact{
			UUID:        ArtifactVEXUUID(releaseUUID),
			Version:     1,
			Name:        "Consolidated OpenVEX",
			Type:        ArtifactTypeVulnerabilities,
			CreatedDate: formatTime(rel.IngestedAt, time.Now()),
			Formats: []ArtifactFormat{
				{
					MediaType:   MediaTypeOpenVEXJSON,
					Description: "Consolidated OpenVEX Vulnerability Exploitability eXchange",
				},
			},
		}
		artifacts = append(artifacts, vexArtifact)
	}

	col := &Collection{
		UUID:        rel.SBOMID.String(),
		Version:     1,
		CreatedDate: formatTime(rel.IngestedAt, time.Now()),
		BelongsTo:   BelongsToProductRelease,
		UpdateReason: CollectionUpdateReason{
			Type: updateReasonType,
		},
		Artifacts: artifacts,
	}

	return col, nil
}

// ListComponents returns a paginated list of TEA components.
func (s *Service) ListComponents(ctx context.Context, page, pageSize uint64) (*PaginatedResponse[Component], error) {
	summaries, total, err := s.store.QueryProducts(ctx, page, pageSize)
	if err != nil {
		return nil, err
	}

	results := make([]Component, 0, len(summaries))
	for _, sum := range summaries {
		results = append(results, toComponent(sum))
	}

	hasNext := (page * pageSize) < total
	var nextPageToken string
	if hasNext {
		nextPageToken = fmt.Sprintf("%d", page+1)
	}

	return &PaginatedResponse[Component]{
		HasNext:       hasNext,
		NextPageToken: nextPageToken,
		Results:       results,
	}, nil
}

// GetComponent returns a single TEA component by UUID or name.
func (s *Service) GetComponent(ctx context.Context, idOrUUID string) (*Component, error) {
	sum, err := s.findProduct(ctx, idOrUUID)
	if err != nil {
		return nil, err
	}
	c := toComponent(*sum)
	return &c, nil
}

// ListComponentReleases lists the releases of a component.
func (s *Service) ListComponentReleases(ctx context.Context, idOrUUID string, page, pageSize uint64) (*PaginatedResponse[ComponentRelease], error) {
	sum, err := s.findProduct(ctx, idOrUUID)
	if err != nil {
		return nil, err
	}

	releases, total, err := s.store.QueryReleasesByProject(ctx, sum.ProjectName, page, pageSize)
	if err != nil {
		return nil, err
	}

	results := make([]ComponentRelease, 0, len(releases))
	compUUID := ComponentUUID(sum.RootPURL, sum.ProjectName)
	for _, r := range releases {
		results = append(results, toComponentRelease(r, compUUID))
	}

	hasNext := (page * pageSize) < total
	var nextPageToken string
	if hasNext {
		nextPageToken = fmt.Sprintf("%d", page+1)
	}

	return &PaginatedResponse[ComponentRelease]{
		HasNext:       hasNext,
		NextPageToken: nextPageToken,
		Results:       results,
	}, nil
}

// GetComponentRelease retrieves a single component release by UUID.
func (s *Service) GetComponentRelease(ctx context.Context, releaseUUID string) (*ComponentRelease, error) {
	rel, err := s.findReleaseByComponentReleaseUUID(ctx, releaseUUID)
	if err != nil || rel == nil {
		return nil, ErrNotFound
	}
	compUUID := ComponentUUID(rel.RootPURL, rel.Project)
	cr := toComponentRelease(*rel, compUUID)
	return &cr, nil
}

// GetArtifact retrieves artifact metadata.
func (s *Service) GetArtifact(ctx context.Context, artifactUUID string, version int) (*Artifact, error) {
	rel, isVEX, err := s.resolveArtifactTarget(ctx, artifactUUID)
	if err != nil || rel == nil {
		return nil, ErrNotFound
	}

	col, err := s.GetCollection(ctx, rel.SBOMID.String(), version)
	if err != nil {
		return nil, err
	}

	for _, a := range col.Artifacts {
		if isVEX && a.Type == ArtifactTypeVulnerabilities {
			return &a, nil
		}
		if !isVEX && a.Type == ArtifactTypeBOM {
			return &a, nil
		}
	}

	return nil, ErrNotFound
}

// GetArtifactData retrieves the raw bytes and metadata for artifact download.
func (s *Service) GetArtifactData(ctx context.Context, artifactUUID string, _ int) (*ArtifactData, error) {
	rel, isVEX, err := s.resolveArtifactTarget(ctx, artifactUUID)
	if err != nil || rel == nil {
		return nil, ErrNotFound
	}

	if isVEX {
		stmts, err := s.store.QueryVEXStatements(ctx, rel.SBOMID.String())
		if err != nil {
			return nil, err
		}
		return buildOpenVEXArtifactData(rel.SBOMID.String(), stmts)
	}

	return s.store.GetArtifactData(ctx, rel.SBOMID.String())
}

// Helper methods

func (s *Service) findProduct(ctx context.Context, idOrUUID string) (*ProductSummary, error) {
	idOrUUID = strings.TrimSpace(idOrUUID)
	// Try direct project name query
	if sum, err := s.store.QueryProductByName(ctx, idOrUUID); err == nil && sum != nil {
		return sum, nil
	}

	// Try matching by UUID across all products
	summaries, _, err := s.store.QueryProducts(ctx, 1, 1000)
	if err != nil {
		return nil, err
	}
	for _, sum := range summaries {
		if ProductUUID(sum.ProjectName) == idOrUUID || ComponentUUID(sum.RootPURL, sum.ProjectName) == idOrUUID {
			return &sum, nil
		}
	}

	return nil, ErrNotFound
}

func (s *Service) findReleaseByComponentReleaseUUID(ctx context.Context, targetUUID string) (*models.SBOM, error) {
	// 1. Direct sbom_id match
	if rel, err := s.store.QueryReleaseBySBOMID(ctx, targetUUID); err == nil && rel != nil {
		return rel, nil
	}

	// 2. Derived component-release UUID match
	releases, _, err := s.store.QueryAllReleases(ctx, 1, 1000)
	if err != nil {
		return nil, err
	}
	for _, r := range releases {
		if ComponentReleaseUUID(r.SBOMID.String()) == targetUUID {
			return &r, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Service) resolveArtifactTarget(ctx context.Context, artifactUUID string) (*models.SBOM, bool, error) {
	// 1. Try direct SBOM ID
	if rel, err := s.store.QueryReleaseBySBOMID(ctx, artifactUUID); err == nil && rel != nil {
		return rel, false, nil
	}

	// 2. Check all recent releases to resolve derived BOM or VEX UUIDs
	releases, _, err := s.store.QueryAllReleases(ctx, 1, 1000)
	if err != nil {
		return nil, false, err
	}
	for _, r := range releases {
		idStr := r.SBOMID.String()
		if ArtifactBOMDerivedUUID(idStr) == artifactUUID {
			return &r, false, nil
		}
		if ArtifactVEXUUID(idStr) == artifactUUID {
			return &r, true, nil
		}
	}

	return nil, false, ErrNotFound
}

func toProduct(sum ProductSummary) Product {
	name := sum.ProjectName
	if sum.Parent != "" && sum.Parent != sum.ProjectName {
		name = sum.Parent + " / " + sum.ProjectName
	}
	var idents []Identifier
	if sum.RootPURL != "" {
		idents = append(idents, Identifier{IDType: "PURL", IDValue: sum.RootPURL})
	}
	return Product{
		UUID:        ProductUUID(sum.ProjectName),
		Name:        name,
		Identifiers: idents,
	}
}

func toProductRelease(r models.SBOM, projectName string) ProductRelease {
	compUUID := ComponentUUID(r.RootPURL, projectName)
	compRelUUID := ComponentReleaseUUID(r.SBOMID.String())

	var idents []Identifier
	if r.RootPURL != "" {
		idents = append(idents, Identifier{IDType: "PURL", IDValue: r.RootPURL})
		idents = append(idents, Identifier{IDType: "TEI", IDValue: EncodePURLTEI("bomhort.local", r.RootPURL)})
	}

	version := r.DocumentVersion
	if version == "" {
		version = "latest"
	}

	return ProductRelease{
		UUID:        r.SBOMID.String(),
		Product:     ProductUUID(projectName),
		ProductName: projectName,
		Version:     version,
		CreatedDate: formatTime(r.CreationDate, r.IngestedAt),
		ReleaseDate: formatTime(r.CreationDate, r.IngestedAt),
		Identifiers: idents,
		Components: []ComponentRef{
			{
				UUID:    compUUID,
				Release: compRelUUID,
			},
		},
	}
}

func toComponent(sum ProductSummary) Component {
	var idents []Identifier
	if sum.RootPURL != "" {
		idents = append(idents, Identifier{IDType: "PURL", IDValue: sum.RootPURL})
	}
	return Component{
		UUID:        ComponentUUID(sum.RootPURL, sum.ProjectName),
		Name:        sum.ProjectName,
		Identifiers: idents,
	}
}

func toComponentRelease(r models.SBOM, compUUID string) ComponentRelease {
	var idents []Identifier
	if r.RootPURL != "" {
		idents = append(idents, Identifier{IDType: "PURL", IDValue: r.RootPURL})
	}

	version := r.DocumentVersion
	if version == "" {
		version = "latest"
	}

	return ComponentRelease{
		UUID:        ComponentReleaseUUID(r.SBOMID.String()),
		Component:   compUUID,
		Version:     version,
		CreatedDate: formatTime(r.CreationDate, r.IngestedAt),
		ReleaseDate: formatTime(r.CreationDate, r.IngestedAt),
		Identifiers: idents,
	}
}

func formatTime(t, fallback time.Time) string {
	if !t.IsZero() {
		return t.UTC().Format(time.RFC3339)
	}
	if !fallback.IsZero() {
		return fallback.UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}
