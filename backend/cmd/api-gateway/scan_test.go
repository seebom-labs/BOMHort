package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/osv"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

type mockOSVScanner struct {
	batchResp *osv.BatchResponse
	hydrated  map[string]*osv.VulnEntry
	err       error
	delay     time.Duration
}

func (m *mockOSVScanner) QueryBatch(ctx context.Context, _ []string) (*osv.BatchResponse, error) {
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
	return &osv.BatchResponse{}, nil
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
