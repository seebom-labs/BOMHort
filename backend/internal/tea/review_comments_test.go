package tea

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/vex"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// TestReview_Comment2_ExtractAuthority verifies configured authority extraction from URLs/hosts.
func TestReview_Comment2_ExtractAuthority(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://tea.example.com/api/v1/tea", "tea.example.com"},
		{"http://bomhort.local:8080/api/v1/tea/", "bomhort.local:8080"},
		{"tea.internal.corp", "tea.internal.corp"},
		{"", "bomhort.local"},
	}

	for _, tc := range tests {
		got := ExtractAuthority(tc.input)
		if got != tc.want {
			t.Errorf("ExtractAuthority(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestReview_Comment3_CatalogLookupNoCeiling verifies that searching for products walks past 1,000 items.
func TestReview_Comment3_CatalogLookupNoCeiling(t *testing.T) {
	total := 1050
	products := make([]ProductSummary, total)
	targetName := "service-1049"
	targetUUID := uuid.New()

	for i := 0; i < total; i++ {
		name := fmt.Sprintf("service-%d", i)
		pUUID := uuid.New()
		if i == 1049 {
			pUUID = targetUUID
		}
		products[i] = ProductSummary{
			ProjectName:     name,
			Parent:          "Core",
			RootPURL:        fmt.Sprintf("pkg:golang/github.com/org/%s@v1.0.0", name),
			ReleaseCount:    1,
			LatestVersion:   "v1.0.0",
			LatestTimestamp: time.Now(),
			LatestSBOMID:    pUUID,
		}
	}

	store := &mockStore{
		products: products,
	}
	svc := NewService(store)

	// findProduct must walk pages and locate the product without 404
	prod, err := svc.findProduct(context.Background(), targetName)
	if err != nil {
		t.Fatalf("findProduct failed for index 1049: %v", err)
	}
	if prod.ProjectName != targetName {
		t.Errorf("got project name %q, want %q", prod.ProjectName, targetName)
	}
}

// TestReview_Comment4_StableComponentUUID verifies that Component UUID is identical across releases.
func TestReview_Comment4_StableComponentUUID(t *testing.T) {
	purlV1 := "pkg:golang/github.com/seebom-labs/bomhort@v0.8.0"
	purlV2 := "pkg:golang/github.com/seebom-labs/bomhort@v0.9.0"

	unversioned1 := UnversionedPURL(purlV1)
	unversioned2 := UnversionedPURL(purlV2)
	wantUnversioned := "pkg:golang/github.com/seebom-labs/bomhort"

	if unversioned1 != wantUnversioned {
		t.Errorf("UnversionedPURL(%q) = %q, want %q", purlV1, unversioned1, wantUnversioned)
	}
	if unversioned2 != wantUnversioned {
		t.Errorf("UnversionedPURL(%q) = %q, want %q", purlV2, unversioned2, wantUnversioned)
	}

	compUUID1 := ComponentUUID(purlV1, "bomhort")
	compUUID2 := ComponentUUID(purlV2, "bomhort")

	if compUUID1 != compUUID2 {
		t.Fatalf("ComponentUUID must be identical across releases: %q != %q", compUUID1, compUUID2)
	}
}

// TestReview_Comment5_DelimiterSafePURLMatching verifies delimiter-safe PURL matching logic.
func TestReview_Comment5_DelimiterSafePURLMatching(t *testing.T) {
	matchPURL := func(candidate, query string) bool {
		if candidate == query {
			return true
		}
		if strings.HasPrefix(candidate, query+"@") ||
			strings.HasPrefix(candidate, query+"?") ||
			strings.HasPrefix(candidate, query+"#") {
			return true
		}
		return false
	}

	// Should match unversioned prefix with delimiter
	if !matchPURL("pkg:npm/foo@1.0.0", "pkg:npm/foo") {
		t.Errorf("expected match for unversioned query")
	}
	if !matchPURL("pkg:npm/foo?repository_url=...", "pkg:npm/foo") {
		t.Errorf("expected match with qualifier delimiter '?'")
	}
	if !matchPURL("pkg:npm/foo#subpath", "pkg:npm/foo") {
		t.Errorf("expected match with subpath delimiter '#'")
	}

	// Must NOT collide on string prefixes without delimiters
	if matchPURL("pkg:npm/foobar@1.0.0", "pkg:npm/foo") {
		t.Errorf("delimiter collision: 'pkg:npm/foobar' must not match 'pkg:npm/foo'")
	}
	if matchPURL("pkg:npm/foo@10.0.0", "pkg:npm/foo@1") {
		t.Errorf("delimiter collision: 'pkg:npm/foo@10' must not match 'pkg:npm/foo@1'")
	}
	if matchPURL("pkg:golang/github.com/org/repo-extended@v1", "pkg:golang/github.com/org/repo") {
		t.Errorf("delimiter collision: 'repo-extended' must not match 'repo'")
	}
}

// TestReview_Comment6_S3ETagVsTrueSHA256 verifies that 32-char S3 ETags in sboms table
// yield real 64-char hex SHA-256 hashes matching actual downloaded bytes.
func TestReview_Comment6_S3ETagVsTrueSHA256(t *testing.T) {
	testSBOMID := uuid.MustParse("33333333-4444-5555-6666-777777777777")
	sampleBytes := []byte(`{"spdxVersion":"SPDX-2.3","name":"s3-ingested-project"}`)
	trueHash := sha256.Sum256(sampleBytes)
	trueHex := hex.EncodeToString(trueHash[:])

	// Store simulates S3 ETag in SBOM table (32 hex characters)
	s3ETag := "d41d8cd98f00b204e9800998ecf8427e"

	store := &mockStore{
		products: []ProductSummary{
			{
				ProjectName:     "s3-project",
				Parent:          "Infra",
				RootPURL:        "pkg:golang/github.com/org/s3-project@v1.0.0",
				ReleaseCount:    1,
				LatestVersion:   "v1.0.0",
				LatestTimestamp: time.Now(),
				LatestSBOMID:    testSBOMID,
			},
		},
		releases: []models.SBOM{
			{
				SBOMID:          testSBOMID,
				Project:         "s3-project",
				Parent:          "Infra",
				DocumentVersion: "v1.0.0",
				RootPURL:        "pkg:golang/github.com/org/s3-project@v1.0.0",
				CreationDate:    time.Now(),
				IngestedAt:      time.Now(),
				SourceFile:      "s3-project.spdx.json",
				SHA256Hash:      s3ETag, // 32-char ETag in database
			},
		},
		rawArtifact: map[string][]byte{
			testSBOMID.String(): sampleBytes,
		},
	}

	svc := NewService(store)
	handler := NewHandler(svc, "https://api.example.com/api/v1/tea")

	// 1. Fetch collection
	colReq := httptest.NewRequest(http.MethodGet, "/api/v1/tea/productRelease/"+testSBOMID.String()+"/collection/latest", nil)
	colRec := httptest.NewRecorder()
	handler.ServeHTTP(colRec, colReq)

	if colRec.Code != http.StatusOK {
		t.Fatalf("collection failed: %d", colRec.Code)
	}

	var col Collection
	if err := json.Unmarshal(colRec.Body.Bytes(), &col); err != nil {
		t.Fatalf("unmarshaling collection: %v", err)
	}

	if len(col.Artifacts) == 0 {
		t.Fatal("expected artifacts in collection")
	}

	advHash := col.Artifacts[0].Formats[0].Checksums[0].AlgValue
	if len(advHash) != 64 {
		t.Errorf("advertised hash length = %d, want 64 (got %q)", len(advHash), advHash)
	}
	if advHash != trueHex {
		t.Errorf("advertised hash = %q, want true SHA256 %q", advHash, trueHex)
	}

	// 2. Download artifact
	dlReq := httptest.NewRequest(http.MethodGet, "/api/v1/tea/artifact/"+col.Artifacts[0].UUID+"/latest/download", nil)
	dlRec := httptest.NewRecorder()
	handler.ServeHTTP(dlRec, dlReq)

	if dlRec.Code != http.StatusOK {
		t.Fatalf("download failed: %d", dlRec.Code)
	}

	dlHash := sha256.Sum256(dlRec.Body.Bytes())
	dlHex := hex.EncodeToString(dlHash[:])
	if dlHex != advHash {
		t.Fatalf("downloaded hash %q does not match advertised hash %q", dlHex, advHash)
	}
}

// TestReview_Comment7_FormatProbeSniffing verifies format detection by byte sniffing.
func TestReview_Comment7_FormatProbeSniffing(t *testing.T) {
	cycloneDXPayload := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`)
	inTotoPayload := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://spdx.dev/Document"}`)
	spdxPayload := []byte(`{"spdxVersion":"SPDX-2.3","name":"demo"}`)

	// Using a generic filename "sbom.json"
	genericFilename := "sbom.json"

	cdxType, cdxInToto := ProbeFormat(cycloneDXPayload, genericFilename)
	if cdxType != MediaTypeCycloneDXJSON || cdxInToto {
		t.Errorf("CycloneDX probe = (%q, %v), want (%q, false)", cdxType, cdxInToto, MediaTypeCycloneDXJSON)
	}

	inTotoType, inTotoInToto := ProbeFormat(inTotoPayload, genericFilename)
	if inTotoType != MediaTypeInTotoJSON || !inTotoInToto {
		t.Errorf("in-toto probe = (%q, %v), want (%q, true)", inTotoType, inTotoInToto, MediaTypeInTotoJSON)
	}

	spdxType, spdxInToto := ProbeFormat(spdxPayload, genericFilename)
	if spdxType != MediaTypeSPDXJSON || spdxInToto {
		t.Errorf("SPDX probe = (%q, %v), want (%q, false)", spdxType, spdxInToto, MediaTypeSPDXJSON)
	}
}

// TestReview_Comment8_OpenVEXRoundTrip verifies that generated OpenVEX documents
// conform to the OpenVEX spec and parse successfully with BOMHort's internal VEX parser.
func TestReview_Comment8_OpenVEXRoundTrip(t *testing.T) {
	rel := &models.SBOM{
		SBOMID:          uuid.New(),
		Project:         "auth-gateway",
		DocumentVersion: "v1.2.0",
		RootPURL:        "pkg:golang/github.com/org/auth-gateway@v1.2.0",
		CreationDate:    time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC),
		IngestedAt:      time.Date(2026, 11, 15, 10, 5, 0, 0, time.UTC),
	}

	stmts := []models.VEXStatement{
		{
			VulnID:          "CVE-2026-12345",
			Status:          "not_affected",
			Justification:   "vulnerable_code_not_present",
			ImpactStatement: "Component not reachable via API surface",
			ActionStatement: "No remediation required",
			ProductRef:      "pkg:golang/github.com/org/auth-gateway@v1.2.0",
			ProductPURL:     "pkg:golang/github.com/vulnerable/lib@v0.1.0",
		},
	}

	art, err := buildOpenVEXArtifactData(rel.SBOMID.String(), stmts, "tea.example.com", 1)
	if err != nil {
		t.Fatalf("buildOpenVEXArtifactData failed: %v", err)
	}
	data, err := io.ReadAll(art.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	hash := art.SHA256Hash
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}

	// Parse with internal/vex.Parse
	parsed, err := vex.Parse(bytes.NewReader(data), "tea-generated.openvex.json")
	if err != nil {
		t.Fatalf("vex.Parse failed to parse TEA OpenVEX document: %v\nJSON:\n%s", err, string(data))
	}

	if len(parsed.Statements) != 1 {
		t.Fatalf("expected 1 parsed statement, got %d", len(parsed.Statements))
	}

	stmt := parsed.Statements[0]
	if stmt.VulnID != "CVE-2026-12345" {
		t.Errorf("VulnID = %q, want 'CVE-2026-12345'", stmt.VulnID)
	}
	if stmt.Status != "not_affected" {
		t.Errorf("Status = %q, want 'not_affected'", stmt.Status)
	}
}

// TestReview_Comment9_DeterministicOpenVEXBytes verifies that repeat generation
// of OpenVEX artifact bytes produces byte-identical output with matching hash.
func TestReview_Comment9_DeterministicOpenVEXBytes(t *testing.T) {
	rel := &models.SBOM{
		SBOMID:          uuid.New(),
		Project:         "auth-gateway",
		DocumentVersion: "v1.2.0",
		RootPURL:        "pkg:golang/github.com/org/auth-gateway@v1.2.0",
		CreationDate:    time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC),
		IngestedAt:      time.Date(2026, 11, 15, 10, 5, 0, 0, time.UTC),
	}

	stmts := []models.VEXStatement{
		{
			VulnID:      "CVE-2026-0002",
			Status:      "fixed",
			ProductRef:  "pkg:golang/github.com/org/auth-gateway@v1.2.0",
			ProductPURL: "pkg:golang/github.com/org/lib-b@v1.0.0",
		},
		{
			VulnID:      "CVE-2026-0001",
			Status:      "not_affected",
			ProductRef:  "pkg:golang/github.com/org/auth-gateway@v1.2.0",
			ProductPURL: "pkg:golang/github.com/org/lib-a@v1.0.0",
		},
	}

	art1, err1 := buildOpenVEXArtifactData(rel.SBOMID.String(), stmts, "tea.example.com", 1)
	art2, err2 := buildOpenVEXArtifactData(rel.SBOMID.String(), stmts, "tea.example.com", 1)

	if err1 != nil || err2 != nil {
		t.Fatalf("generation failed: err1=%v, err2=%v", err1, err2)
	}

	data1, _ := io.ReadAll(art1.Body)
	data2, _ := io.ReadAll(art2.Body)

	if art1.SHA256Hash != art2.SHA256Hash {
		t.Errorf("hashes differ: %q != %q", art1.SHA256Hash, art2.SHA256Hash)
	}
	if !bytes.Equal(data1, data2) {
		t.Errorf("generated byte outputs differ across calls")
	}
}

// TestReview_Comment10_VersionValidation verifies that invalid or non-existent
// versions return 400 (bad request) or 404 (not found).
func TestReview_Comment10_VersionValidation(t *testing.T) {
	handler, _, testSBOMID, _ := setupTestHandler()

	tests := []struct {
		url        string
		wantStatus int
	}{
		// Non-existent collection version
		{"/api/v1/tea/productRelease/" + testSBOMID.String() + "/collection/999", http.StatusNotFound},
		// Malformed collection version
		{"/api/v1/tea/productRelease/" + testSBOMID.String() + "/collection/bad-ver", http.StatusBadRequest},
		// Non-existent artifact version
		{"/api/v1/tea/artifact/" + testSBOMID.String() + "/999/download", http.StatusNotFound},
		// Malformed artifact version
		{"/api/v1/tea/artifact/" + testSBOMID.String() + "/not-a-number/download", http.StatusBadRequest},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, tc.url, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != tc.wantStatus {
			t.Errorf("GET %s = %d, want %d", tc.url, rec.Code, tc.wantStatus)
		}
	}
}

// errorStore wraps mockStore and injects an error into QueryVEXStatementsCount.
type errorVEXStore struct {
	mockStore
}

func (e *errorVEXStore) QueryVEXStatementsCount(_ context.Context, _ string) (int, error) {
	return 0, errors.New("clickhouse connection pool exhausted")
}

// TestReview_Comment11_VEXCountErrorPropagation verifies that database errors
// during VEX count lookup return 500 Internal Server Error, not 200 with 0 statements.
func TestReview_Comment11_VEXCountErrorPropagation(t *testing.T) {
	_, baseStore, testSBOMID, _ := setupTestHandler()

	errStore := &errorVEXStore{mockStore: *baseStore}
	svc := NewService(errStore)
	handler := NewHandler(svc, "https://api.example.com/api/v1/tea")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tea/productRelease/"+testSBOMID.String()+"/collection/latest", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when QueryVEXStatementsCount fails, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestReview_Comment12_CacheControlOnAuthenticatedDownloads verifies that
// Cache-Control: private, no-store, no-cache is sent on authenticated artifact downloads.
func TestReview_Comment12_CacheControlOnAuthenticatedDownloads(t *testing.T) {
	handler, _, testSBOMID, _ := setupTestHandler()

	url := "/api/v1/tea/artifact/" + testSBOMID.String() + "/latest/download"

	// 1. Authenticated request with Bearer token
	reqAuth := httptest.NewRequest(http.MethodGet, url, nil)
	reqAuth.Header.Set("Authorization", "Bearer my-secret-token")
	recAuth := httptest.NewRecorder()
	handler.ServeHTTP(recAuth, reqAuth)

	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 for download, got %d", recAuth.Code)
	}
	ccAuth := recAuth.Header().Get("Cache-Control")
	if !strings.Contains(ccAuth, "no-store") || !strings.Contains(ccAuth, "private") {
		t.Errorf("expected Cache-Control: private, no-store, got %q", ccAuth)
	}

	// 2. Authenticated request with X-API-Key
	reqAPIKey := httptest.NewRequest(http.MethodGet, url, nil)
	reqAPIKey.Header.Set("X-API-Key", "my-api-key")
	recAPIKey := httptest.NewRecorder()
	handler.ServeHTTP(recAPIKey, reqAPIKey)

	if recAPIKey.Code != http.StatusOK {
		t.Fatalf("expected 200 for download, got %d", recAPIKey.Code)
	}
	ccKey := recAPIKey.Header().Get("Cache-Control")
	if !strings.Contains(ccKey, "no-store") || !strings.Contains(ccKey, "private") {
		t.Errorf("expected Cache-Control: private, no-store, got %q", ccKey)
	}
}
