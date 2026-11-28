package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/advisory"
	"github.com/seebom-labs/bomhort/backend/internal/clearlydefined"
	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/evaluate"
	gh "github.com/seebom-labs/bomhort/backend/internal/github"
	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/osv"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

type mockOSVScanner struct {
	batchResp *osv.BatchResponse
	hydrated  map[string]*osv.VulnEntry
	err       error
	delay     time.Duration
}

func (m *mockOSVScanner) QueryBatch(ctx context.Context, purls []string) (*osv.BatchResponse, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if m.err != nil {
		return nil, m.err
	}
	if m.batchResp != nil {
		return m.batchResp, nil
	}
	return &osv.BatchResponse{Results: make([]osv.QueryResult, len(purls))}, nil
}

func (m *mockOSVScanner) HydrateVulns(_ context.Context, _ []string) (map[string]*osv.VulnEntry, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.hydrated != nil {
		return m.hydrated, nil
	}
	return map[string]*osv.VulnEntry{}, nil
}

const testSPDX = `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-service",
  "documentNamespace": "https://example.com/test-service-1.0",
  "packages": [
    {
      "name": "test-service",
      "SPDXID": "SPDXRef-Package-Root",
      "versionInfo": "1.0.0",
      "downloadLocation": "NONE",
      "licenseConcluded": "MIT",
      "licenseDeclared": "MIT",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:golang/example.com/test-service@1.0.0"
        }
      ]
    },
    {
      "name": "leftpad",
      "SPDXID": "SPDXRef-Package-Leftpad",
      "versionInfo": "1.3.0",
      "downloadLocation": "NONE",
      "licenseConcluded": "GPL-3.0-only",
      "licenseDeclared": "GPL-3.0-only",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/leftpad@1.3.0"
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-Root",
      "relationshipType": "DESCRIBES"
    },
    {
      "spdxElementId": "SPDXRef-Package-Root",
      "relatedSpdxElement": "SPDXRef-Package-Leftpad",
      "relationshipType": "DEPENDS_ON"
    }
  ]
}`

func TestScanHandler_AuthRequiredWhenDisabled(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled: false,
	}
	handler := scanHandler(scanDeps{cfg: cfg})

	req := httptest.NewRequest(http.MethodPost, scanPath, strings.NewReader(testSPDX))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when AuthEnabled=false, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Scan requires AUTH_ENABLED=true") {
		t.Errorf("expected error message to mention AUTH_ENABLED=true, got %s", rec.Body.String())
	}
}

func TestScanHandler_SuccessAndPolicyPass(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:     true,
		MaxUploadSizeMB: 10,
		ScanTimeout:     10,
		ScanMaxPURLs:    100,
	}
	mock := &mockOSVScanner{}
	handler := scanHandler(scanDeps{
		cfg:       cfg,
		osvClient: mock,
	})

	req := httptest.NewRequest(http.MethodPost, scanPath+"?fail_on=critical", strings.NewReader(testSPDX))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var resp dto.ScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.PolicyResult != "pass" {
		t.Errorf("expected policy_result pass, got %s", resp.PolicyResult)
	}
	if resp.Summary.PackageCount != 2 {
		t.Errorf("expected 2 packages, got %d", resp.Summary.PackageCount)
	}
	if resp.Summary.VulnCount != 0 {
		t.Errorf("expected 0 vulnerabilities, got %d", resp.Summary.VulnCount)
	}
	if resp.Summary.LicenseViolations != 1 {
		t.Errorf("expected 1 license violation (GPL-3.0-only), got %d", resp.Summary.LicenseViolations)
	}
}

func TestScanHandler_PolicyGating_Fail(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:     true,
		MaxUploadSizeMB: 10,
		ScanTimeout:     10,
	}
	mock := &mockOSVScanner{
		batchResp: &osv.BatchResponse{
			Results: []osv.QueryResult{
				{
					Vulns: []osv.VulnEntry{
						{ID: "GHSA-abcd-1234"},
					},
				},
				{},
			},
		},
		hydrated: map[string]*osv.VulnEntry{
			"GHSA-abcd-1234": {
				ID:      "GHSA-abcd-1234",
				Summary: "Buffer overflow",
				DatabaseSpecific: map[string]interface{}{
					"severity": "HIGH",
				},
			},
		},
	}
	handler := scanHandler(scanDeps{
		cfg:       cfg,
		osvClient: mock,
	})

	// 1. fail_on=high should fail on HIGH vuln
	req := httptest.NewRequest(http.MethodPost, scanPath+"?fail_on=high", strings.NewReader(testSPDX))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with policy failure, got %d", rec.Code)
	}

	var resp dto.ScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.PolicyResult != "fail" {
		t.Errorf("expected policy_result fail, got %s", resp.PolicyResult)
	}
	if !strings.Contains(resp.PolicyReason, "high or critical") {
		t.Errorf("expected policy_reason to mention high or critical, got %s", resp.PolicyReason)
	}

	// 2. fail_on=license should fail on GPL-3.0-only violation
	req2 := httptest.NewRequest(http.MethodPost, scanPath+"?fail_on=license", strings.NewReader(testSPDX))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	var resp2 dto.ScanResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp2.PolicyResult != "fail" {
		t.Errorf("expected policy_result fail on license violation, got %s", resp2.PolicyResult)
	}
	if !strings.Contains(resp2.PolicyReason, "license") {
		t.Errorf("expected policy_reason to mention license, got %s", resp2.PolicyReason)
	}
}

func TestScanHandler_InvalidJSONAndShape(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:     true,
		MaxUploadSizeMB: 10,
	}
	handler := scanHandler(scanDeps{cfg: cfg})

	// Empty body
	req := httptest.NewRequest(http.MethodPost, scanPath, strings.NewReader(""))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty body: expected 400, got %d", rec.Code)
	}

	// Not valid JSON
	req = httptest.NewRequest(http.MethodPost, scanPath, strings.NewReader("not json"))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid json: expected 400, got %d", rec.Code)
	}

	// JSON array instead of object
	req = httptest.NewRequest(http.MethodPost, scanPath, strings.NewReader("[]"))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("json array: expected 400, got %d", rec.Code)
	}

	// Trailing data
	req = httptest.NewRequest(http.MethodPost, scanPath, strings.NewReader("{}\n{}"))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("trailing data: expected 400, got %d", rec.Code)
	}
}

func TestScanHandler_PURLCapExceeded(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:     true,
		MaxUploadSizeMB: 10,
		ScanMaxPURLs:    1, // testSPDX has 2 PURLs
	}
	handler := scanHandler(scanDeps{
		cfg:       cfg,
		osvClient: &mockOSVScanner{},
	})

	req := httptest.NewRequest(http.MethodPost, scanPath, strings.NewReader(testSPDX))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 Request Entity Too Large, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestScanHandler_InvalidFailOn(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:     true,
		MaxUploadSizeMB: 10,
	}
	handler := scanHandler(scanDeps{
		cfg:       cfg,
		osvClient: &mockOSVScanner{},
	})

	req := httptest.NewRequest(http.MethodPost, scanPath+"?fail_on=invalid-level", strings.NewReader(testSPDX))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
	}
}

func TestScanHandler_Timeout(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:     true,
		MaxUploadSizeMB: 10,
		ScanTimeout:     1, // 1 second timeout
	}
	mock := &mockOSVScanner{
		delay: 2 * time.Second, // artificially delay to trigger timeout
	}
	handler := scanHandler(scanDeps{
		cfg:       cfg,
		osvClient: mock,
	})

	req := httptest.NewRequest(http.MethodPost, scanPath, strings.NewReader(testSPDX))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("expected 504 Gateway Timeout, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestScanHandler_MaxBodySize(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:     true,
		MaxUploadSizeMB: 1, // 1MB limit
	}
	handler := scanHandler(scanDeps{cfg: cfg})

	// Create payload larger than 1MB
	largePayload := bytes.Repeat([]byte(" "), 2*1024*1024)
	req := httptest.NewRequest(http.MethodPost, scanPath, bytes.NewReader(largePayload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 Request Entity Too Large for oversized body, got %d", rec.Code)
	}
}

func TestScanHandler_OSVUnavailable_QueryFailed(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:     true,
		MaxUploadSizeMB: 10,
		ScanTimeout:     10,
	}
	mock := &mockOSVScanner{
		err: errors.New("upstream connection refused"),
	}
	handler := scanHandler(scanDeps{
		cfg:       cfg,
		osvClient: mock,
	})

	req := httptest.NewRequest(http.MethodPost, scanPath+"?fail_on=critical", strings.NewReader(testSPDX))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// If OSV fails, must NOT return 200 with policy_result: pass. Must return 502 Bad Gateway.
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway when OSV query fails, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Vulnerability check unavailable") {
		t.Errorf("expected error message to explain vulnerability check unavailable, got %s", rec.Body.String())
	}
}

func TestScanHandler_OSVUnavailable_IncompleteHydration(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:     true,
		MaxUploadSizeMB: 10,
		ScanTimeout:     10,
	}
	mock := &mockOSVScanner{
		batchResp: &osv.BatchResponse{
			Results: []osv.QueryResult{
				{
					Vulns: []osv.VulnEntry{
						{ID: "GHSA-abcd-1234"},
						{ID: "GHSA-efgh-5678"},
					},
				},
				{},
			},
		},
		// only hydrates 1 of 2 IDs
		hydrated: map[string]*osv.VulnEntry{
			"GHSA-abcd-1234": {ID: "GHSA-abcd-1234"},
		},
	}
	handler := scanHandler(scanDeps{
		cfg:       cfg,
		osvClient: mock,
	})

	req := httptest.NewRequest(http.MethodPost, scanPath+"?fail_on=critical", strings.NewReader(testSPDX))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway when OSV hydration is incomplete, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Vulnerability check unavailable") {
		t.Errorf("expected error message to explain vulnerability check unavailable, got %s", rec.Body.String())
	}
}

func TestScanHandler_RejectsEmptyObjectAndInvalidSBOM(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:     true,
		MaxUploadSizeMB: 10,
	}
	handler := scanHandler(scanDeps{cfg: cfg})

	req := httptest.NewRequest(http.MethodPost, scanPath, strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for empty JSON object {}, got %d", rec.Code)
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "invalid sbom") {
		t.Errorf("expected error message to mention Invalid SBOM, got %s", rec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, scanPath, strings.NewReader(`{"not":"an_sbom"}`))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for non-SBOM JSON object, got %d", rec2.Code)
	}
	if !strings.Contains(strings.ToLower(rec2.Body.String()), "invalid sbom") {
		t.Errorf("expected error message to mention Invalid SBOM, got %s", rec2.Body.String())
	}
}

func TestScanHandler_SkipOSVWithVulnGateFails(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:     true,
		MaxUploadSizeMB: 10,
		SkipOSV:         true,
	}
	handler := scanHandler(scanDeps{
		cfg:       cfg,
		osvClient: nil,
	})

	req := httptest.NewRequest(http.MethodPost, scanPath+"?fail_on=critical", strings.NewReader(testSPDX))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway when SkipOSV=true with vulnerability gate, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Vulnerability check unavailable") {
		t.Errorf("expected error to explain vulnerability check unavailable, got %s", rec.Body.String())
	}
}

type testFeedStore struct {
	recs []advisory.StoredRecord
}

func (s testFeedStore) LookupAdvisoryRecords(_ context.Context, _, _ []string) ([]advisory.StoredRecord, error) {
	return s.recs, nil
}

func TestScanHandler_AdvisoryMatcher(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:     true,
		MaxUploadSizeMB: 10,
		ScanTimeout:     10,
	}
	rec := osv.VulnEntry{
		ID:      "CGA-1234",
		Summary: "Advisory finding from feed",
		Aliases: []string{"CVE-2026-9999"},
		Affected: []osv.Affected{
			{
				Package: osv.AffectedPackage{
					Ecosystem: "npm",
					Name:      "leftpad",
					PURL:      "pkg:npm/leftpad",
				},
				Ranges: []osv.Range{
					{
						Type:   "SEMVER",
						Events: []osv.Event{{Introduced: "0"}},
					},
				},
			},
		},
	}
	matcher := advisory.NewMatcher(
		[]advisory.Source{{Name: "vendor-feed", Index: "https://example.com/feed.json", Prefixes: []string{"pkg:npm"}}},
		testFeedStore{recs: []advisory.StoredRecord{{Source: "vendor-feed", Record: rec}}},
	)
	mock := &mockOSVScanner{
		batchResp: &osv.BatchResponse{
			Results: []osv.QueryResult{
				{},
				{},
			},
		},
	}
	handler := scanHandler(scanDeps{
		cfg:       cfg,
		osvClient: mock,
		matcher:   matcher,
	})

	req := httptest.NewRequest(http.MethodPost, scanPath+"?fail_on=license", strings.NewReader(testSPDX))
	recHttp := httptest.NewRecorder()
	handler.ServeHTTP(recHttp, req)

	if recHttp.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with advisory matcher, got %d (body: %s)", recHttp.Code, recHttp.Body.String())
	}

	var resp dto.ScanResponse
	if err := json.Unmarshal(recHttp.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	found := false
	for _, v := range resp.Vulnerabilities {
		if v.VulnID == "CGA-1234" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected finding CGA-1234 from advisory matcher in vulnerabilities, got: %+v", resp.Vulnerabilities)
	}

	// Verify feed-closed (not_affected) findings do not fail the policy gate.
	closedRec := osv.VulnEntry{
		ID:      "CGA-CLOSED-1",
		Summary: "Closed by distro feed",
		Aliases: []string{"CVE-2026-8888"},
		Affected: []osv.Affected{
			{
				Package: osv.AffectedPackage{
					Ecosystem: "npm",
					Name:      "leftpad",
					PURL:      "pkg:npm/leftpad",
				},
				DatabaseSpecific: map[string]interface{}{
					"status": "not_affected",
				},
				Ranges: []osv.Range{
					{
						Type:   "SEMVER",
						Events: []osv.Event{{Introduced: "0"}},
					},
				},
			},
		},
	}
	closedMatcher := advisory.NewMatcher(
		[]advisory.Source{{Name: "vendor-feed", Index: "https://example.com/feed.json", Prefixes: []string{"pkg:npm"}}},
		testFeedStore{recs: []advisory.StoredRecord{{Source: "vendor-feed", Record: closedRec}}},
	)
	closedMock := &mockOSVScanner{
		batchResp: &osv.BatchResponse{
			Results: []osv.QueryResult{
				{},
				{Vulns: []osv.VulnEntry{{ID: "CVE-2026-8888"}}},
			},
		},
		hydrated: map[string]*osv.VulnEntry{
			"CVE-2026-8888": {
				ID:               "CVE-2026-8888",
				Summary:          "Upstream HIGH",
				DatabaseSpecific: map[string]interface{}{"severity": "HIGH"},
			},
		},
	}
	closedHandler := scanHandler(scanDeps{
		cfg:       cfg,
		osvClient: closedMock,
		matcher:   closedMatcher,
	})

	reqClosed := httptest.NewRequest(http.MethodPost, scanPath+"?fail_on=high", strings.NewReader(testSPDX))
	recClosed := httptest.NewRecorder()
	closedHandler.ServeHTTP(recClosed, reqClosed)
	if recClosed.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for feed-closed finding, got %d (body: %s)", recClosed.Code, recClosed.Body.String())
	}
	var respClosed dto.ScanResponse
	if err := json.Unmarshal(recClosed.Body.Bytes(), &respClosed); err != nil {
		t.Fatalf("failed to decode closed response: %v", err)
	}
	if respClosed.PolicyResult != "pass" {
		t.Errorf("expected policy_result pass when feed closed finding as not_affected, got %s (%s)", respClosed.PolicyResult, respClosed.PolicyReason)
	}
	if respClosed.Summary.HighVulns != 0 || respClosed.Summary.VulnCount != 0 {
		t.Errorf("expected 0 active vulns in summary for feed-closed finding, got vuln_count=%d high=%d", respClosed.Summary.VulnCount, respClosed.Summary.HighVulns)
	}
	if len(respClosed.Vulnerabilities) != 1 || respClosed.Vulnerabilities[0].VEXStatus != "not_affected" {
		t.Errorf("expected finding annotated with vex_status=not_affected, got: %+v", respClosed.Vulnerabilities)
	}
}

func TestScanHandler_PrivatePackagesNeverQueriedExternally(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:            true,
		MaxUploadSizeMB:        10,
		ScanTimeout:            10,
		PrivatePackagePrefixes: []string{"@acme-internal/"},
	}
	privateSPDX := `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "priv-app",
  "documentNamespace": "https://example.com/priv-app-1.0",
  "packages": [
    {
      "name": "@acme-internal/secret-lib",
      "SPDXID": "SPDXRef-Package-Priv",
      "versionInfo": "1.0.0",
      "downloadLocation": "NONE",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/%40acme-internal/secret-lib@1.0.0"
        }
      ]
    }
  ]
}`
	res := &dummyResolver{name: "npm"}
	handler := scanHandler(scanDeps{
		cfg:       cfg,
		osvClient: &mockOSVScanner{},
		registryResolvers: []evaluate.RegistryResolver{
			{Name: "npm", Resolver: res},
		},
	})

	req := httptest.NewRequest(http.MethodPost, scanPath, strings.NewReader(privateSPDX))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if entries := res.NewCacheEntries(); len(entries) != 0 {
		t.Fatalf("expected 0 external registry lookups for private package, got: %v", entries)
	}
}

type delayedReader struct{}

func (d *delayedReader) Read(p []byte) (int, error) {
	return 0, os.ErrDeadlineExceeded
}

func TestScanHandler_SlowBodyReadTimeout(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:     true,
		MaxUploadSizeMB: 10,
		ScanTimeout:     1,
	}
	handler := scanHandler(scanDeps{
		cfg:       cfg,
		osvClient: &mockOSVScanner{},
	})

	req := httptest.NewRequest(http.MethodPost, scanPath, &delayedReader{})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("expected 504 Gateway Timeout for slow body read, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

type mockScanStore struct {
	registryInserts map[string]map[string]string
	ghLicenseCalls  int
	ghMetaCalls     int
}

func newMockScanStore() *mockScanStore {
	return &mockScanStore{
		registryInserts: make(map[string]map[string]string),
	}
}

func (m *mockScanStore) InsertRegistryLicenseCache(_ context.Context, ecosystem string, entries map[string]string) error {
	if m.registryInserts[ecosystem] == nil {
		m.registryInserts[ecosystem] = make(map[string]string)
	}
	for k, v := range entries {
		m.registryInserts[ecosystem][k] = v
	}
	return nil
}

func (m *mockScanStore) InsertGitHubLicenseCache(_ context.Context, entries map[string]string) error {
	m.ghLicenseCalls += len(entries)
	return nil
}

func (m *mockScanStore) InsertGitHubRepoMetadata(_ context.Context, entries []*gh.RepoMetadata) error {
	m.ghMetaCalls += len(entries)
	return nil
}

type dummyResolver struct {
	license.ResolverCache
	name string
}

func (d *dummyResolver) Resolve(_ context.Context, purl string) string {
	if lic, _, ok := d.Load(purl); ok {
		return lic
	}
	d.StoreResult(purl, "MIT", "")
	return "MIT"
}

const unknownLicenseSPDX = `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-service",
  "documentNamespace": "https://example.com/test-service-1.0",
  "packages": [
    {
      "name": "leftpad",
      "SPDXID": "SPDXRef-Package-Leftpad",
      "versionInfo": "1.3.0",
      "downloadLocation": "NONE",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/leftpad@1.3.0"
        }
      ]
    }
  ]
}`

func TestScanHandler_WarmCacheDoesNotPersistTwice(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:     true,
		MaxUploadSizeMB: 10,
		ScanTimeout:     10,
	}
	store := newMockScanStore()
	res := &dummyResolver{name: "npm"}
	cdRes := clearlydefined.NewResolverWithRegistry("http://127.0.0.1:0")
	cdRes.PreloadCache(map[string]string{
		"npm/npmjs/-/preloaded-dep/1.0.0": "MIT",
	})
	deps := scanDeps{
		cfg:       cfg,
		chClient:  store,
		osvClient: &mockOSVScanner{},
		registryResolvers: []evaluate.RegistryResolver{
			{Name: "npm", Resolver: res},
			{Name: "clearlydefined", Resolver: cdRes},
		},
	}
	handler := scanHandler(deps)

	req1 := httptest.NewRequest(http.MethodPost, scanPath, strings.NewReader(unknownLicenseSPDX))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first scan: expected 200, got %d (body: %s)", rec1.Code, rec1.Body.String())
	}

	if len(store.registryInserts["npm"]) == 0 {
		t.Fatal("expected new entries to be persisted on cold scan")
	}

	store.registryInserts = make(map[string]map[string]string)

	req2 := httptest.NewRequest(http.MethodPost, scanPath, strings.NewReader(unknownLicenseSPDX))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second scan: expected 200, got %d (body: %s)", rec2.Code, rec2.Body.String())
	}

	if len(store.registryInserts["npm"]) > 0 {
		t.Fatalf("expected 0 new entries persisted on warm scan, got: %v", store.registryInserts["npm"])
	}
	if len(store.registryInserts["clearlydefined"]) > 0 {
		t.Fatalf("expected 0 preloaded clearlydefined entries persisted on warm scan, got: %v", store.registryInserts["clearlydefined"])
	}
}

func TestScanHandler_ResponseDocContract(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled:     true,
		MaxUploadSizeMB: 10,
		ScanTimeout:     10,
	}
	handler := scanHandler(scanDeps{
		cfg:       cfg,
		osvClient: &mockOSVScanner{},
	})

	req := httptest.NewRequest(http.MethodPost, scanPath+"?fail_on=license", strings.NewReader(testSPDX))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	for _, key := range []string{"policy_result", "policy_reason", "summary", "vulnerabilities", "license_compliance"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing top-level key %q in scan response", key)
		}
	}

	summary, ok := raw["summary"].(map[string]interface{})
	if !ok {
		t.Fatalf("summary is not a JSON object")
	}

	expectedSummaryFields := []string{
		"package_count",
		"vuln_count",
		"critical_vulns",
		"high_vulns",
		"medium_vulns",
		"low_vulns",
		"license_violations",
		"license_exemptions",
	}
	for _, field := range expectedSummaryFields {
		if _, ok := summary[field]; !ok {
			t.Errorf("missing summary field %q", field)
		}
	}

	if _, ok := summary["critical_count"]; ok {
		t.Errorf("summary should not contain critical_count")
	}
	if _, ok := summary["high_count"]; ok {
		t.Errorf("summary should not contain high_count")
	}

	lc, ok := raw["license_compliance"].([]interface{})
	if !ok {
		t.Fatalf("license_compliance is not an array")
	}
	if len(lc) == 0 {
		t.Fatalf("expected at least one license_compliance entry")
	}
	firstLC, ok := lc[0].(map[string]interface{})
	if !ok {
		t.Fatalf("license_compliance[0] is not a JSON object")
	}
	for _, field := range []string{"license_id", "category", "package_count", "packages", "package_scopes"} {
		if _, ok := firstLC[field]; !ok {
			t.Errorf("missing license_compliance field %q", field)
		}
	}
}
