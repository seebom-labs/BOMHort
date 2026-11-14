package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/tea"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

type fakeTEAStore struct {
	products []tea.ProductSummary
	releases []models.SBOM
	vexCount int
	rawBlobs map[string][]byte
}

func (f *fakeTEAStore) QueryProducts(_ context.Context, page, pageSize uint64) ([]tea.ProductSummary, uint64, error) {
	start := (page - 1) * pageSize
	if start >= uint64(len(f.products)) {
		return nil, uint64(len(f.products)), nil
	}
	end := start + pageSize
	if end > uint64(len(f.products)) {
		end = uint64(len(f.products))
	}
	return f.products[start:end], uint64(len(f.products)), nil
}

func (f *fakeTEAStore) QueryProductByName(_ context.Context, name string) (*tea.ProductSummary, error) {
	for _, p := range f.products {
		if p.ProjectName == name {
			return &p, nil
		}
	}
	return nil, tea.ErrNotFound
}

func (f *fakeTEAStore) QueryAllReleases(_ context.Context, page, pageSize uint64) ([]models.SBOM, uint64, error) {
	start := (page - 1) * pageSize
	if start >= uint64(len(f.releases)) {
		return nil, uint64(len(f.releases)), nil
	}
	end := start + pageSize
	if end > uint64(len(f.releases)) {
		end = uint64(len(f.releases))
	}
	return f.releases[start:end], uint64(len(f.releases)), nil
}

func (f *fakeTEAStore) QueryReleasesByProject(_ context.Context, project string, page, pageSize uint64) ([]models.SBOM, uint64, error) {
	var filtered []models.SBOM
	for _, r := range f.releases {
		if r.Project == project {
			filtered = append(filtered, r)
		}
	}
	start := (page - 1) * pageSize
	if start >= uint64(len(filtered)) {
		return nil, uint64(len(filtered)), nil
	}
	end := start + pageSize
	if end > uint64(len(filtered)) {
		end = uint64(len(filtered))
	}
	return filtered[start:end], uint64(len(filtered)), nil
}

func (f *fakeTEAStore) QueryReleaseBySBOMID(_ context.Context, sbomID string) (*models.SBOM, error) {
	for _, r := range f.releases {
		if r.SBOMID.String() == sbomID {
			return &r, nil
		}
	}
	return nil, tea.ErrNotFound
}

func (f *fakeTEAStore) QueryReleasesByPURL(_ context.Context, purl string) ([]models.SBOM, error) {
	var out []models.SBOM
	for _, r := range f.releases {
		if r.RootPURL == purl {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeTEAStore) QueryVEXStatementsCount(_ context.Context, _ string) (int, error) {
	return f.vexCount, nil
}

func (f *fakeTEAStore) QueryVEXStatements(_ context.Context, _ string) ([]models.VEXStatement, error) {
	return nil, nil
}

func (f *fakeTEAStore) GetArtifactData(_ context.Context, sbomID string) (*tea.ArtifactData, error) {
	raw, ok := f.rawBlobs[sbomID]
	if !ok {
		return nil, tea.ErrNotFound
	}
	h := sha256.Sum256(raw)
	return &tea.ArtifactData{
		Filename:    sbomID + ".spdx.json",
		ContentType: tea.MediaTypeSPDXJSON,
		SHA256Hash:  hex.EncodeToString(h[:]),
		SizeBytes:   uint64(len(raw)),
		Body:        io.NopCloser(bytes.NewReader(raw)),
	}, nil
}

func setupTEAGateway(t *testing.T, authEnabled bool) (http.Handler, *fakeTEAStore, uuid.UUID, string, string) {
	t.Helper()
	testSBOMID := uuid.MustParse("22222222-3333-4444-5555-666666666666")
	testPURL := "pkg:golang/github.com/seebom-labs/bomhort@v0.8.0"
	testRaw := []byte(`{"spdxVersion":"SPDX-2.3","name":"bomhort-demo"}`)
	h := sha256.Sum256(testRaw)
	testSHA := hex.EncodeToString(h[:])

	store := &fakeTEAStore{
		products: []tea.ProductSummary{
			{
				ProjectName:     "bomhort-platform",
				Parent:          "Security",
				RootPURL:        testPURL,
				ReleaseCount:    1,
				LatestVersion:   "v0.8.0",
				LatestTimestamp: time.Now(),
				LatestSBOMID:    testSBOMID,
			},
		},
		releases: []models.SBOM{
			{
				SBOMID:          testSBOMID,
				Project:         "bomhort-platform",
				Parent:          "Security",
				DocumentVersion: "v0.8.0",
				RootPURL:        testPURL,
				CreationDate:    time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC),
				IngestedAt:      time.Date(2026, 11, 10, 12, 5, 0, 0, time.UTC),
				SourceFile:      "bomhort-platform.spdx.json",
				SHA256Hash:      testSHA,
			},
		},
		rawBlobs: map[string][]byte{
			testSBOMID.String(): testRaw,
		},
	}

	svc := tea.NewService(store)
	teaHandler := tea.NewHandler(svc, "https://bomhort.example.com/api/v1/tea")

	mux := http.NewServeMux()
	mux.Handle("GET /.well-known/tea", teaHandler)
	mux.Handle("GET /api/v1/tea/", teaHandler)

	handler := authMiddleware(authEnabled, false, "valid-service-token", []string{"valid-api-key"}, mux)
	return handler, store, testSBOMID, testPURL, testSHA
}

func TestTEAGateway_WellKnownPublic(t *testing.T) {
	// Must succeed without auth even when AUTH_ENABLED=true
	handler, _, _, _, _ := setupTEAGateway(t, true)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/tea", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /.well-known/tea, got %d", rec.Code)
	}

	var doc tea.WellKnownDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshaling well-known: %v", err)
	}
	if doc.SchemaVersion != 1 {
		t.Errorf("schemaVersion = %d, want 1", doc.SchemaVersion)
	}
	if len(doc.Endpoints) == 0 || doc.Endpoints[0].URL != "https://bomhort.example.com/api/v1/tea" {
		t.Errorf("unexpected endpoint URL in discovery: %+v", doc.Endpoints)
	}
}

func TestTEAGateway_AuthEnforced(t *testing.T) {
	handler, _, _, testPURL, _ := setupTEAGateway(t, true)

	// Unauthenticated request to /api/v1/tea/discovery must be rejected with 401
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tea/discovery?purl="+testPURL, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthorized for unauthenticated tea call, got %d", rec.Code)
	}

	// With API key, request must succeed
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/v1/tea/discovery?purl="+testPURL, nil)
	reqAuth.Header.Set("X-API-Key", "valid-api-key")
	recAuth := httptest.NewRecorder()
	handler.ServeHTTP(recAuth, reqAuth)

	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid API key, got %d: %s", recAuth.Code, recAuth.Body.String())
	}
}

func TestTEAGateway_ResolveAndDownloadMatchingHash(t *testing.T) {
	handler, _, testSBOMID, testPURL, expectedSHA := setupTEAGateway(t, false)

	// 1. Resolve via TEI (urn:tei:purl:...)
	tei := tea.EncodeURNTEI(testPURL)
	reqDisc := httptest.NewRequest(http.MethodGet, "/api/v1/tea/discovery?tei="+tei, nil)
	recDisc := httptest.NewRecorder()
	handler.ServeHTTP(recDisc, reqDisc)

	if recDisc.Code != http.StatusOK {
		t.Fatalf("discovery failed: %d %s", recDisc.Code, recDisc.Body.String())
	}

	var infos []tea.DiscoveryInfo
	if err := json.Unmarshal(recDisc.Body.Bytes(), &infos); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(infos) != 1 || infos[0].ProductReleaseUUID != testSBOMID.String() {
		t.Fatalf("expected release UUID %q, got %+v", testSBOMID.String(), infos)
	}

	// 2. Fetch Collection
	reqCol := httptest.NewRequest(http.MethodGet, "/api/v1/tea/productRelease/"+testSBOMID.String()+"/collection/latest", nil)
	recCol := httptest.NewRecorder()
	handler.ServeHTTP(recCol, reqCol)

	if recCol.Code != http.StatusOK {
		t.Fatalf("collection lookup failed: %d %s", recCol.Code, recCol.Body.String())
	}

	var col tea.Collection
	if err := json.Unmarshal(recCol.Body.Bytes(), &col); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(col.Artifacts) == 0 {
		t.Fatal("expected artifacts in collection")
	}

	artifact := col.Artifacts[0]
	if len(artifact.Formats) == 0 || len(artifact.Formats[0].Checksums) == 0 {
		t.Fatal("missing format checksums")
	}
	advertisedHash := artifact.Formats[0].Checksums[0].AlgValue
	if advertisedHash != expectedSHA {
		t.Fatalf("advertised checksum %q != expected %q", advertisedHash, expectedSHA)
	}

	// 3. Download artifact bytes
	reqDL := httptest.NewRequest(http.MethodGet, "/api/v1/tea/artifact/"+artifact.UUID+"/latest/download", nil)
	recDL := httptest.NewRecorder()
	handler.ServeHTTP(recDL, reqDL)

	if recDL.Code != http.StatusOK {
		t.Fatalf("download failed: %d %s", recDL.Code, recDL.Body.String())
	}

	downloadedBytes := recDL.Body.Bytes()
	actualHash := sha256.Sum256(downloadedBytes)
	actualSHA := hex.EncodeToString(actualHash[:])

	if actualSHA != advertisedHash {
		t.Fatalf("downloaded bytes SHA256 %q does not match advertised hash %q", actualSHA, advertisedHash)
	}
}
