package tea

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

var (
	// ErrNotFound is returned when a requested TEA resource is not found.
	ErrNotFound = errors.New("tea resource not found")

	// ErrInvalidRequest is returned on malformed input query or parameters.
	ErrInvalidRequest      = errors.New("invalid tea request")
	ErrSnapshotUnavailable = errors.New("TEA snapshot storage unavailable")
)

// Salt masks for reversible disjoint UUID derivation from sbom_id.
// These salts preserve RFC 4122 version 4 and variant bits (salt[6] & 0xf0 == 0, salt[8] & 0xc0 == 0).
var (
	saltComponentRelease = [16]byte{
		0x1a, 0x2b, 0x3c, 0x4d,
		0x5e, 0x6f, 0x07, 0x89,
		0x12, 0x34, 0x56, 0x78,
		0x9a, 0xbc, 0xde, 0xf0,
	}
	saltVEXArtifact = [16]byte{
		0xfe, 0xdc, 0xba, 0x98,
		0x76, 0x54, 0x03, 0x21,
		0x23, 0x45, 0x67, 0x89,
		0xab, 0xcd, 0xef, 0x01,
	}
	saltAttestationArtifact = [16]byte{
		0x45, 0x67, 0x89, 0xab,
		0xcd, 0xef, 0x01, 0x23,
		0x34, 0x56, 0x78, 0x9a,
		0xbc, 0xde, 0xf0, 0x12,
	}
)

// Service implements the core business logic of the Transparency Exchange API.
type Service struct {
	store        Store
	baseURL      string
	mu           sync.RWMutex
	projectIndex map[string]string // UUID -> projectName
}

// NewService creates a new TEA service backed by the provided Store and optional baseURL.
func NewService(store Store, baseURL ...string) *Service {
	var b string
	if len(baseURL) > 0 {
		b = baseURL[0]
	}
	return &Service{
		store:        store,
		baseURL:      b,
		projectIndex: make(map[string]string),
	}
}

// Authority returns the host authority extracted from the configured baseURL.
func (s *Service) Authority() string {
	return ExtractAuthority(s.baseURL)
}

// ProductUUID returns a deterministic UUID for a product based on its project name.
func ProductUUID(projectName string) string {
	return uuid.NewSHA1(uuid.NameSpaceDNS, []byte("bomhort:tea:product:"+projectName)).String()
}

// ComponentUUID returns a deterministic UUID for a component based on its canonical
// unversioned root PURL or fallback project name.
func ComponentUUID(purl, fallbackName string) string {
	unversioned := UnversionedPURL(purl)
	if unversioned != "" {
		return uuid.NewSHA1(uuid.NameSpaceDNS, []byte("bomhort:tea:component:"+unversioned)).String()
	}
	return uuid.NewSHA1(uuid.NameSpaceDNS, []byte("bomhort:tea:component:name:"+fallbackName)).String()
}

// ComponentReleaseUUID returns a deterministic, disjoint, reversible UUID for a component release.
func ComponentReleaseUUID(sbomID string) string {
	u, err := uuid.Parse(sbomID)
	if err != nil {
		return uuid.NewSHA1(uuid.NameSpaceDNS, []byte("bomhort:tea:component-release:"+sbomID)).String()
	}
	var derived [16]byte
	for i := 0; i < 16; i++ {
		derived[i] = u[i] ^ saltComponentRelease[i]
	}
	return uuid.UUID(derived).String()
}

// ReverseComponentReleaseUUID recovers the original sbomID from a derived component-release UUID.
func ReverseComponentReleaseUUID(derivedUUID string) (string, bool) {
	u, err := uuid.Parse(derivedUUID)
	if err != nil {
		return "", false
	}
	var orig [16]byte
	for i := 0; i < 16; i++ {
		orig[i] = u[i] ^ saltComponentRelease[i]
	}
	return uuid.UUID(orig).String(), true
}

// ArtifactVEXUUID returns a deterministic, disjoint, reversible UUID for an SBOM's consolidated VEX artifact.
func ArtifactVEXUUID(sbomID string) string {
	u, err := uuid.Parse(sbomID)
	if err != nil {
		return uuid.NewSHA1(uuid.NameSpaceDNS, []byte("bomhort:tea:artifact:vex:"+sbomID)).String()
	}
	var derived [16]byte
	for i := 0; i < 16; i++ {
		derived[i] = u[i] ^ saltVEXArtifact[i]
	}
	return uuid.UUID(derived).String()
}

// ReverseArtifactVEXUUID recovers the original sbomID from a derived VEX artifact UUID.
func ReverseArtifactVEXUUID(derivedUUID string) (string, bool) {
	u, err := uuid.Parse(derivedUUID)
	if err != nil {
		return "", false
	}
	var orig [16]byte
	for i := 0; i < 16; i++ {
		orig[i] = u[i] ^ saltVEXArtifact[i]
	}
	return uuid.UUID(orig).String(), true
}

// ArtifactAttestationUUID returns a deterministic, disjoint, reversible UUID for an SBOM's attestation artifact.
func ArtifactAttestationUUID(sbomID string) string {
	u, err := uuid.Parse(sbomID)
	if err != nil {
		return uuid.NewSHA1(uuid.NameSpaceDNS, []byte("bomhort:tea:artifact:attestation:"+sbomID)).String()
	}
	var derived [16]byte
	for i := 0; i < 16; i++ {
		derived[i] = u[i] ^ saltAttestationArtifact[i]
	}
	return uuid.UUID(derived).String()
}

// ReverseArtifactAttestationUUID recovers the original sbomID from a derived attestation artifact UUID.
func ReverseArtifactAttestationUUID(derivedUUID string) (string, bool) {
	u, err := uuid.Parse(derivedUUID)
	if err != nil {
		return "", false
	}
	var orig [16]byte
	for i := 0; i < 16; i++ {
		orig[i] = u[i] ^ saltAttestationArtifact[i]
	}
	return uuid.UUID(orig).String(), true
}

// ArtifactBOMDerivedUUID returns the derived UUID for an SBOM BOM artifact.
func ArtifactBOMDerivedUUID(sbomID string) string {
	return sbomID
}

// ProbeFormat inspects raw document bytes and filename to determine its media type
// and whether it represents an in-toto attestation envelope (#534).
func ProbeFormat(data []byte, filename string) (mediaType string, isInToto bool) {
	type formatProbe struct {
		BomFormat     string `json:"bomFormat"`
		SPDXVersion   string `json:"spdxVersion"`
		PredicateType string `json:"predicateType"`
	}

	var probe formatProbe
	_ = jsonUnmarshal(data, &probe)

	if probe.PredicateType != "" {
		return MediaTypeInTotoJSON, true
	}
	if probe.BomFormat == "CycloneDX" {
		return MediaTypeCycloneDXJSON, false
	}
	if probe.SPDXVersion != "" {
		return MediaTypeSPDXJSON, false
	}

	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".cdx.json") || strings.Contains(lower, "cyclonedx") {
		return MediaTypeCycloneDXJSON, false
	}
	return MediaTypeSPDXJSON, false
}

func jsonUnmarshal(data []byte, v interface{}) error {
	if len(data) == 0 {
		return errors.New("empty data")
	}
	return json.Unmarshal(data, v)
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

	authority := s.Authority()
	results := make([]ProductRelease, 0, len(releases))
	for _, r := range releases {
		results = append(results, toProductRelease(r, sum.ProjectName, authority))
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

	authority := s.Authority()
	results := make([]ProductRelease, 0, len(releases))
	for _, r := range releases {
		results = append(results, toProductRelease(r, r.Project, authority))
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
	pr := toProductRelease(*r, r.Project, s.Authority())
	return &pr, nil
}

// GetCollection returns the artifact collection for a product release.
// Per doc/tea-uuid-scope.md, a Collection uses the same UUID as its parent Product Release.
func (s *Service) GetCollection(ctx context.Context, releaseUUID string, version int, isLatest bool) (*Collection, error) {
	rel, err := s.store.QueryReleaseBySBOMID(ctx, releaseUUID)
	if errors.Is(err, ErrNotFound) || (err == nil && rel == nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !isLatest {
		snapshot, err := s.store.GetSnapshot(ctx, releaseUUID, version, 0)
		if err == nil {
			return &snapshot.Collection, nil
		}
		if !errors.Is(err, ErrNotFound) || version != 1 {
			return nil, err
		}
	}
	snapshot, err := s.publishLatest(ctx, rel)
	if err != nil {
		return nil, err
	}
	if !isLatest && version != snapshot.Collection.Version {
		snapshot, err = s.store.GetSnapshot(ctx, releaseUUID, version, 0)
		if err != nil {
			return nil, err
		}
	}
	return &snapshot.Collection, nil
}

func (s *Service) ListCollections(ctx context.Context, releaseUUID string, page, pageSize uint64) (*PaginatedResponse[Collection], error) {
	latest, err := s.GetCollection(ctx, releaseUUID, 1, true)
	if err != nil {
		return nil, err
	}
	results := make([]Collection, 0)
	total := uint64(latest.Version)
	if page == 0 || pageSize == 0 {
		return nil, ErrInvalidRequest
	}
	if page-1 < (total+pageSize-1)/pageSize {
		offset := (page - 1) * pageSize
		snapshots, err := s.store.ListSnapshots(ctx, releaseUUID, total, pageSize, offset)
		if err != nil {
			return nil, err
		}
		expected := min(pageSize, total-offset)
		if uint64(len(snapshots)) != expected {
			return nil, errors.New("TEA snapshot index has missing or conflicting revisions")
		}
		for _, snapshot := range snapshots {
			results = append(results, snapshot.Collection)
		}
		hasNext := offset+uint64(len(results)) < total
		var next string
		if hasNext {
			next = fmt.Sprintf("%d", page+1)
		}
		return &PaginatedResponse[Collection]{HasNext: hasNext, NextPageToken: next, Results: results}, nil
	}
	return &PaginatedResponse[Collection]{Results: results}, nil
}

func (s *Service) publishLatest(ctx context.Context, rel *models.SBOM) (*Snapshot, error) {
	sbomID := rel.SBOMID.String()
	for {
		previous, err := s.store.LatestSnapshot(ctx, rel)
		if err != nil {
			return nil, err
		}
		stmts, err := s.store.QueryVEXStatements(ctx, sbomID)
		if err != nil {
			return nil, fmt.Errorf("querying vex statements: %w", err)
		}
		col, err := s.buildCollection(ctx, rel, len(stmts))
		if err != nil {
			return nil, err
		}
		next := &Snapshot{Collection: *col}
		if previous != nil {
			next.Collection.Version = previous.Collection.Version
			next.LastVEXVersion = previous.LastVEXVersion
			next.LastVEXFingerprint = previous.LastVEXFingerprint
		}
		if len(stmts) != 0 {
			data, err := buildOpenVEXArtifactData(sbomID, stmts, s.Authority(), 1)
			if err != nil {
				return nil, err
			}
			fingerprint := data.SHA256Hash
			_ = data.Body.Close()
			if next.LastVEXVersion == 0 || fingerprint != next.LastVEXFingerprint {
				next.LastVEXVersion++
			}
			next.LastVEXFingerprint = fingerprint
			data, err = buildOpenVEXArtifactData(sbomID, stmts, s.Authority(), next.LastVEXVersion)
			if err != nil {
				return nil, err
			}
			next.VEXBytes, err = io.ReadAll(data.Body)
			_ = data.Body.Close()
			if err != nil {
				return nil, err
			}
			for i := range next.Collection.Artifacts {
				if next.Collection.Artifacts[i].Type == ArtifactTypeVulnerabilities {
					next.Collection.Artifacts[i].Version = next.LastVEXVersion
				}
			}
		}
		if previous != nil && reflect.DeepEqual(next.Collection, previous.Collection) &&
			next.LastVEXVersion == previous.LastVEXVersion &&
			next.LastVEXFingerprint == previous.LastVEXFingerprint &&
			bytes.Equal(next.VEXBytes, previous.VEXBytes) {
			return previous, nil
		}
		if previous == nil {
			next.Collection.Version = 1
		} else {
			next.Collection.Version = previous.Collection.Version + 1
		}
		created, err := s.store.PublishSnapshot(ctx, rel, previous, next)
		if err != nil {
			return nil, err
		}
		if created {
			return next, nil
		}
	}
}

func (s *Service) buildCollection(ctx context.Context, rel *models.SBOM, vexCount int) (*Collection, error) {
	releaseUUID := rel.SBOMID.String()
	if rel.IngestedAt.IsZero() && rel.CreationDate.IsZero() {
		return nil, errors.New("TEA collection has no stable creation date")
	}
	// Retrieve real 64-char document sha256 and content-based format probe
	sha256Hex := rel.SHA256Hash
	mediaType := MediaTypeSPDXJSON
	isInToto := false
	docName := filepath.Base(rel.SourceFile)

	if docInfo, dErr := s.store.QueryStoredDocumentInfo(ctx, releaseUUID); dErr == nil && docInfo != nil {
		if docInfo.SHA256Hash != "" {
			sha256Hex = docInfo.SHA256Hash
		}
		if docInfo.ContentType != "" {
			mediaType = docInfo.ContentType
		}
		isInToto = docInfo.IsInToto
		if docInfo.Filename != "" {
			docName = docInfo.Filename
		}
	} else if dErr == nil || errors.Is(dErr, ErrNotFound) {
		// Fallback detection from file extension
		lowerFile := strings.ToLower(rel.SourceFile)
		if strings.HasSuffix(lowerFile, ".cdx.json") || strings.Contains(lowerFile, "cyclonedx") {
			mediaType = MediaTypeCycloneDXJSON
		}
	} else {
		return nil, fmt.Errorf("querying stored document info: %w", dErr)
	}

	// 1. Original SBOM artifact
	bomArtifact := Artifact{
		UUID:        rel.SBOMID.String(),
		Version:     1,
		Name:        docName,
		Type:        ArtifactTypeBOM,
		CreatedDate: formatTime(rel.CreationDate, rel.IngestedAt),
		Formats: []ArtifactFormat{
			{
				MediaType:   mediaType,
				Description: "Original SBOM",
				Checksums: []Checksum{
					{
						AlgType:  ChecksumAlgSHA256,
						AlgValue: sha256Hex,
					},
				},
			},
		},
	}

	artifacts := []Artifact{bomArtifact}
	updateReasonType := UpdateReasonInitialRelease

	// 2. In-toto attestation envelope artifact if captured
	if isInToto {
		attestationArtifact := Artifact{
			UUID:        ArtifactAttestationUUID(releaseUUID),
			Version:     1,
			Name:        docName,
			Type:        ArtifactTypeAttestation,
			CreatedDate: formatTime(rel.CreationDate, rel.IngestedAt),
			Formats: []ArtifactFormat{
				{
					MediaType:   MediaTypeInTotoJSON,
					Description: "In-toto Attestation Envelope",
					Checksums: []Checksum{
						{
							AlgType:  ChecksumAlgSHA256,
							AlgValue: sha256Hex,
						},
					},
				},
			},
		}
		artifacts = append(artifacts, attestationArtifact)
	}

	// 3. OpenVEX artifact if VEX statements exist
	if vexCount > 0 {
		updateReasonType = UpdateReasonVEXUpdated
		vexArtifact := Artifact{
			UUID:        ArtifactVEXUUID(releaseUUID),
			Version:     1,
			Name:        "Consolidated OpenVEX",
			Type:        ArtifactTypeVulnerabilities,
			CreatedDate: formatTime(rel.IngestedAt, rel.CreationDate),
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
		CreatedDate: formatTime(rel.IngestedAt, rel.CreationDate),
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
func (s *Service) GetArtifact(ctx context.Context, artifactUUID string, version int, isLatest bool) (*Artifact, error) {
	rel, isVEX, isAttestation, err := s.resolveArtifactTarget(ctx, artifactUUID)
	if err != nil || rel == nil {
		return nil, ErrNotFound
	}

	if !isVEX && !isLatest && version != 1 {
		return nil, ErrNotFound
	}
	sbomID := rel.SBOMID.String()
	if isVEX {
		var snapshot *Snapshot
		if isLatest {
			latest, err := s.publishLatest(ctx, rel)
			if err != nil {
				return nil, err
			}
			if latest.LastVEXVersion == 0 {
				return nil, ErrNotFound
			}
			version = latest.LastVEXVersion
		}
		snapshot, err = s.store.GetSnapshot(ctx, sbomID, 0, version)
		if errors.Is(err, ErrNotFound) && !isLatest && version == 1 {
			if _, err = s.publishLatest(ctx, rel); err == nil {
				snapshot, err = s.store.GetSnapshot(ctx, sbomID, 0, version)
			}
		}
		if err != nil {
			return nil, err
		}
		for _, artifact := range snapshot.Collection.Artifacts {
			if artifact.Type == ArtifactTypeVulnerabilities && artifact.Version == version {
				return &artifact, nil
			}
		}
		return nil, ErrNotFound
	}

	col, err := s.GetCollection(ctx, sbomID, 1, true)
	if err != nil {
		return nil, err
	}
	for _, a := range col.Artifacts {
		if isAttestation && a.Type == ArtifactTypeAttestation {
			return &a, nil
		}
		if !isAttestation && a.Type == ArtifactTypeBOM {
			return &a, nil
		}
	}

	return nil, ErrNotFound
}

// GetArtifactData retrieves the raw bytes and metadata for artifact download.
func (s *Service) GetArtifactData(ctx context.Context, artifactUUID string, version int, isLatest bool) (*ArtifactData, error) {
	rel, isVEX, _, err := s.resolveArtifactTarget(ctx, artifactUUID)
	if err != nil || rel == nil {
		return nil, ErrNotFound
	}

	if isVEX {
		artifact, err := s.GetArtifact(ctx, artifactUUID, version, isLatest)
		if err != nil {
			return nil, err
		}
		snapshot, err := s.store.GetSnapshot(ctx, rel.SBOMID.String(), 0, artifact.Version)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(snapshot.VEXBytes)
		return &ArtifactData{
			Version: artifact.Version, Filename: rel.SBOMID.String() + ".openvex.json",
			ContentType: MediaTypeOpenVEXJSON, SHA256Hash: hex.EncodeToString(sum[:]),
			SizeBytes: uint64(len(snapshot.VEXBytes)), Body: io.NopCloser(bytes.NewReader(snapshot.VEXBytes)),
		}, nil
	}
	if !isLatest && version != 1 {
		return nil, ErrNotFound
	}
	data, err := s.store.GetArtifactData(ctx, rel.SBOMID.String())
	if data != nil {
		data.Version = 1
	}
	return data, err
}

// Helper methods

func (s *Service) findProduct(ctx context.Context, idOrUUID string) (*ProductSummary, error) {
	idOrUUID = strings.TrimSpace(idOrUUID)

	// 1. Try direct project name query
	if sum, err := s.store.QueryProductByName(ctx, idOrUUID); err == nil && sum != nil {
		return sum, nil
	}

	// 2. Check in-memory index
	s.mu.RLock()
	projectName, found := s.projectIndex[idOrUUID]
	s.mu.RUnlock()

	if found {
		if sum, err := s.store.QueryProductByName(ctx, projectName); err == nil && sum != nil {
			return sum, nil
		}
	}

	// 3. Populate index across full catalogue without 1,000 ceiling (#534)
	if err := s.refreshProjectIndex(ctx); err != nil {
		return nil, err
	}

	s.mu.RLock()
	projectName, found = s.projectIndex[idOrUUID]
	s.mu.RUnlock()

	if found {
		if sum, err := s.store.QueryProductByName(ctx, projectName); err == nil && sum != nil {
			return sum, nil
		}
	}

	return nil, ErrNotFound
}

func (s *Service) refreshProjectIndex(ctx context.Context) error {
	var page uint64 = 1
	const pageSize = 1000

	newIndex := make(map[string]string)
	for {
		summaries, total, err := s.store.QueryProducts(ctx, page, pageSize)
		if err != nil {
			return err
		}
		for _, sum := range summaries {
			newIndex[sum.ProjectName] = sum.ProjectName
			newIndex[ProductUUID(sum.ProjectName)] = sum.ProjectName
			newIndex[ComponentUUID(sum.RootPURL, sum.ProjectName)] = sum.ProjectName
		}
		if page*pageSize >= total || len(summaries) == 0 {
			break
		}
		page++
	}

	s.mu.Lock()
	s.projectIndex = newIndex
	s.mu.Unlock()
	return nil
}

func (s *Service) findReleaseByComponentReleaseUUID(ctx context.Context, targetUUID string) (*models.SBOM, error) {
	targetUUID = strings.TrimSpace(targetUUID)
	// 1. Direct sbom_id match
	if rel, err := s.store.QueryReleaseBySBOMID(ctx, targetUUID); err == nil && rel != nil {
		return rel, nil
	}

	// 2. Reversible component-release derivation match (O(1) direct lookup, no ceiling #534)
	if origID, ok := ReverseComponentReleaseUUID(targetUUID); ok {
		if rel, err := s.store.QueryReleaseBySBOMID(ctx, origID); err == nil && rel != nil {
			if ComponentReleaseUUID(rel.SBOMID.String()) == targetUUID {
				return rel, nil
			}
		}
	}

	return nil, ErrNotFound
}

func (s *Service) resolveArtifactTarget(ctx context.Context, artifactUUID string) (rel *models.SBOM, isVEX bool, isAttestation bool, err error) {
	artifactUUID = strings.TrimSpace(artifactUUID)
	// 1. Try direct SBOM ID (BOM artifact)
	if r, err := s.store.QueryReleaseBySBOMID(ctx, artifactUUID); err == nil && r != nil {
		return r, false, false, nil
	}

	// 2. Reversible VEX artifact match (O(1) direct lookup, no ceiling #534)
	if origID, ok := ReverseArtifactVEXUUID(artifactUUID); ok {
		if r, err := s.store.QueryReleaseBySBOMID(ctx, origID); err == nil && r != nil {
			if ArtifactVEXUUID(r.SBOMID.String()) == artifactUUID {
				return r, true, false, nil
			}
		}
	}

	// 3. Reversible Attestation artifact match (O(1) direct lookup, no ceiling #534)
	if origID, ok := ReverseArtifactAttestationUUID(artifactUUID); ok {
		if r, err := s.store.QueryReleaseBySBOMID(ctx, origID); err == nil && r != nil {
			if ArtifactAttestationUUID(r.SBOMID.String()) == artifactUUID {
				return r, false, true, nil
			}
		}
	}

	return nil, false, false, ErrNotFound
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

func toProductRelease(r models.SBOM, projectName, authority string) ProductRelease {
	compUUID := ComponentUUID(r.RootPURL, projectName)
	compRelUUID := ComponentReleaseUUID(r.SBOMID.String())

	var idents []Identifier
	if r.RootPURL != "" {
		idents = append(idents, Identifier{IDType: "PURL", IDValue: r.RootPURL})
		idents = append(idents, Identifier{IDType: "TEI", IDValue: EncodePURLTEI(authority, r.RootPURL)})
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
