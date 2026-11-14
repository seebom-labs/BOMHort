package tea

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

type mockStore struct {
	products    []ProductSummary
	releases    []models.SBOM
	vexCount    int
	vexStmts    []models.VEXStatement
	rawArtifact map[string][]byte
}

func (m *mockStore) QueryProducts(_ context.Context, page, pageSize uint64) ([]ProductSummary, uint64, error) {
	start := (page - 1) * pageSize
	if start >= uint64(len(m.products)) {
		return nil, uint64(len(m.products)), nil
	}
	end := start + pageSize
	if end > uint64(len(m.products)) {
		end = uint64(len(m.products))
	}
	return m.products[start:end], uint64(len(m.products)), nil
}

func (m *mockStore) QueryProductByName(_ context.Context, name string) (*ProductSummary, error) {
	for _, p := range m.products {
		if p.ProjectName == name {
			return &p, nil
		}
	}
	return nil, ErrNotFound
}

func (m *mockStore) QueryAllReleases(_ context.Context, page, pageSize uint64) ([]models.SBOM, uint64, error) {
	start := (page - 1) * pageSize
	if start >= uint64(len(m.releases)) {
		return nil, uint64(len(m.releases)), nil
	}
	end := start + pageSize
	if end > uint64(len(m.releases)) {
		end = uint64(len(m.releases))
	}
	return m.releases[start:end], uint64(len(m.releases)), nil
}

func (m *mockStore) QueryReleasesByProject(_ context.Context, project string, page, pageSize uint64) ([]models.SBOM, uint64, error) {
	var filtered []models.SBOM
	for _, r := range m.releases {
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

func (m *mockStore) QueryReleaseBySBOMID(_ context.Context, sbomID string) (*models.SBOM, error) {
	for _, r := range m.releases {
		if r.SBOMID.String() == sbomID {
			return &r, nil
		}
	}
	return nil, ErrNotFound
}

func (m *mockStore) QueryReleasesByPURL(_ context.Context, purl string) ([]models.SBOM, error) {
	var out []models.SBOM
	for _, r := range m.releases {
		if r.RootPURL == purl {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *mockStore) QueryVEXStatementsCount(_ context.Context, _ string) (int, error) {
	return m.vexCount, nil
}

func (m *mockStore) QueryVEXStatements(_ context.Context, _ string) ([]models.VEXStatement, error) {
	return m.vexStmts, nil
}

func (m *mockStore) GetArtifactData(_ context.Context, sbomID string) (*ArtifactData, error) {
	raw, ok := m.rawArtifact[sbomID]
	if !ok {
		return nil, ErrNotFound
	}
	h := sha256.Sum256(raw)
	shaHex := hex.EncodeToString(h[:])
	return &ArtifactData{
		Filename:    sbomID + ".spdx.json",
		ContentType: MediaTypeSPDXJSON,
		SHA256Hash:  shaHex,
		SizeBytes:   uint64(len(raw)),
		Body:        io.NopCloser(bytes.NewReader(raw)),
	}, nil
}

func setupTestHandler() (*Handler, *mockStore, uuid.UUID, string) {
	testSBOMID := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	demoPURL := "pkg:golang/github.com/seebom-labs/bomhort@v0.8.0"
	sampleSBOMBytes := []byte(`{"spdxVersion":"SPDX-2.3","name":"demo-sbom"}`)
	h := sha256.Sum256(sampleSBOMBytes)
	shaHex := hex.EncodeToString(h[:])

	store := &mockStore{
		products: []ProductSummary{
			{
				ProjectName:     "payment-service",
				Parent:          "Checkout",
				RootPURL:        demoPURL,
				ReleaseCount:    1,
				LatestVersion:   "v0.8.0",
				LatestTimestamp: time.Now(),
				LatestSBOMID:    testSBOMID,
			},
		},
		releases: []models.SBOM{
			{
				SBOMID:          testSBOMID,
				Project:         "payment-service",
				Parent:          "Checkout",
				DocumentVersion: "v0.8.0",
				RootPURL:        demoPURL,
				CreationDate:    time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC),
				IngestedAt:      time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC),
				SourceFile:      "payment-service.spdx.json",
				SHA256Hash:      shaHex,
			},
		},
		rawArtifact: map[string][]byte{
			testSBOMID.String(): sampleSBOMBytes,
		},
	}

	svc := NewService(store)
	handler := NewHandler(svc, "https://api.example.com/api/v1/tea")
	return handler, store, testSBOMID, demoPURL
}

func TestWellKnownDiscovery(t *testing.T) {
	handler, _, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/tea", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var doc WellKnownDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("invalid json: %v", err)
	}

	if doc.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", doc.SchemaVersion)
	}
	if len(doc.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(doc.Endpoints))
	}
	if doc.Endpoints[0].URL != "https://api.example.com/api/v1/tea" {
		t.Errorf("url = %q, want 'https://api.example.com/api/v1/tea'", doc.Endpoints[0].URL)
	}
	if len(doc.Endpoints[0].Versions) != 1 || doc.Endpoints[0].Versions[0] != "1.0.0" {
		t.Errorf("versions = %v, want ['1.0.0']", doc.Endpoints[0].Versions)
	}
}

func TestDiscovery_PURLAndTEI(t *testing.T) {
	handler, _, testSBOMID, demoPURL := setupTestHandler()

	// 1. Direct PURL query
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tea/discovery?purl="+demoPURL, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for ?purl=, got %d: %s", rec.Code, rec.Body.String())
	}

	var infos []DiscoveryInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &infos); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 discovery info, got %d", len(infos))
	}
	if infos[0].ProductReleaseUUID != testSBOMID.String() {
		t.Errorf("ProductReleaseUUID = %q, want %q", infos[0].ProductReleaseUUID, testSBOMID.String())
	}

	// 2. TEI with purl type
	tei := EncodePURLTEI("api.example.com", demoPURL)
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/tea/discovery?tei="+tei, nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 for ?tei=, got %d: %s", rec2.Code, rec2.Body.String())
	}

	// 3. TEI with urn:tei:purl:...
	urnTEI := EncodeURNTEI(demoPURL)
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/tea/discovery?tei="+urnTEI, nil)
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusOK {
		t.Fatalf("expected 200 for urn ?tei=, got %d: %s", rec3.Code, rec3.Body.String())
	}

	// 4. Bad request when both supplied
	req4 := httptest.NewRequest(http.MethodGet, "/api/v1/tea/discovery?purl=a&tei=b", nil)
	rec4 := httptest.NewRecorder()
	handler.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when both purl and tei provided, got %d", rec4.Code)
	}

	// 5. 404 when purl not found
	req5 := httptest.NewRequest(http.MethodGet, "/api/v1/tea/discovery?purl=pkg:unknown/notfound@1.0", nil)
	rec5 := httptest.NewRecorder()
	handler.ServeHTTP(rec5, req5)
	if rec5.Code != http.StatusNotFound {
		t.Errorf("expected 404 when purl unknown, got %d", rec5.Code)
	}
}

func TestCollectionAndArtifactDownloadWithMatchingHash(t *testing.T) {
	handler, _, testSBOMID, _ := setupTestHandler()

	// 1. Fetch collection for release
	colURL := "/api/v1/tea/productRelease/" + testSBOMID.String() + "/collection/latest"
	req := httptest.NewRequest(http.MethodGet, colURL, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for collection, got %d: %s", rec.Code, rec.Body.String())
	}

	var col Collection
	if err := json.Unmarshal(rec.Body.Bytes(), &col); err != nil {
		t.Fatalf("invalid json: %v", err)
	}

	if col.UUID != testSBOMID.String() {
		t.Errorf("collection UUID = %q, want %q", col.UUID, testSBOMID.String())
	}
	if len(col.Artifacts) == 0 {
		t.Fatal("expected at least 1 artifact in collection")
	}

	bomArtifact := col.Artifacts[0]
	if bomArtifact.Type != ArtifactTypeBOM {
		t.Errorf("artifact type = %q, want %q", bomArtifact.Type, ArtifactTypeBOM)
	}
	if len(bomArtifact.Formats) == 0 || len(bomArtifact.Formats[0].Checksums) == 0 {
		t.Fatal("expected format checksums in artifact")
	}

	expectedSHA := bomArtifact.Formats[0].Checksums[0].AlgValue

	// 2. Download the artifact content
	dlURL := "/api/v1/tea/artifact/" + bomArtifact.UUID + "/latest/download"
	dlReq := httptest.NewRequest(http.MethodGet, dlURL, nil)
	dlRec := httptest.NewRecorder()
	handler.ServeHTTP(dlRec, dlReq)

	if dlRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for download, got %d: %s", dlRec.Code, dlRec.Body.String())
	}

	downloadedBytes := dlRec.Body.Bytes()
	actualHash := sha256.Sum256(downloadedBytes)
	actualHex := hex.EncodeToString(actualHash[:])

	// 3. Verify hash matches producer's checksum exactly!
	if actualHex != expectedSHA {
		t.Fatalf("downloaded artifact SHA256 %q does not match advertised checksum %q", actualHex, expectedSHA)
	}

	// 4. Verify ETag and conditional 304 Not Modified
	etag := dlRec.Header().Get("ETag")
	if etag == "" || !strings.Contains(etag, expectedSHA) {
		t.Errorf("expected ETag header containing hash, got %q", etag)
	}

	condReq := httptest.NewRequest(http.MethodGet, dlURL, nil)
	condReq.Header.Set("If-None-Match", etag)
	condRec := httptest.NewRecorder()
	handler.ServeHTTP(condRec, condReq)

	if condRec.Code != http.StatusNotModified {
		t.Errorf("expected 304 Not Modified on matching If-None-Match, got %d", condRec.Code)
	}
}

func TestProductAndComponentEndpoints(t *testing.T) {
	handler, _, testSBOMID, _ := setupTestHandler()

	// 1. GET /products
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tea/products", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("products failed: %d", rec.Code)
	}

	var prodResp PaginatedResponse[Product]
	if err := json.Unmarshal(rec.Body.Bytes(), &prodResp); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(prodResp.Results) != 1 {
		t.Fatalf("expected 1 product, got %d", len(prodResp.Results))
	}
	prodUUID := prodResp.Results[0].UUID

	// 2. GET /product/{uuid}
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/tea/product/"+prodUUID, nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("get product failed: %d", rec2.Code)
	}

	// 3. GET /product/{uuid}/releases
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/tea/product/"+prodUUID+"/releases", nil)
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("product releases failed: %d", rec3.Code)
	}

	// 4. GET /productRelease/{uuid}
	req4 := httptest.NewRequest(http.MethodGet, "/api/v1/tea/productRelease/"+testSBOMID.String(), nil)
	rec4 := httptest.NewRecorder()
	handler.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusOK {
		t.Fatalf("product release detail failed: %d", rec4.Code)
	}

	// 5. GET /components
	req5 := httptest.NewRequest(http.MethodGet, "/api/v1/tea/components", nil)
	rec5 := httptest.NewRecorder()
	handler.ServeHTTP(rec5, req5)
	if rec5.Code != http.StatusOK {
		t.Fatalf("components failed: %d", rec5.Code)
	}
}

func TestSignatureDownloadReturns404(t *testing.T) {
	handler, _, testSBOMID, _ := setupTestHandler()

	sigURL := "/api/v1/tea/artifact/" + testSBOMID.String() + "/latest/signature/download"
	req := httptest.NewRequest(http.MethodGet, sigURL, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for signature download, got %d", rec.Code)
	}
}
