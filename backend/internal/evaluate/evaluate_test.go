package evaluate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/osv"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

type mockOSV struct {
	batchResp *osv.BatchResponse
	hydrated  map[string]*osv.VulnEntry
	err       error
}

func (m *mockOSV) QueryBatch(_ context.Context, _ []string) (*osv.BatchResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.batchResp != nil {
		return m.batchResp, nil
	}
	return &osv.BatchResponse{}, nil
}

func (m *mockOSV) HydrateVulns(_ context.Context, _ []string) (map[string]*osv.VulnEntry, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.hydrated != nil {
		return m.hydrated, nil
	}
	return map[string]*osv.VulnEntry{}, nil
}

const sampleSPDX = `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "sample-app",
  "documentNamespace": "https://example.com/sample-app-1.0",
  "packages": [
    {
      "name": "sample-app",
      "SPDXID": "SPDXRef-Package-Root",
      "versionInfo": "1.0.0",
      "downloadLocation": "NONE",
      "licenseConcluded": "MIT",
      "licenseDeclared": "MIT",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:golang/example.com/sample-app@1.0.0"
        }
      ]
    },
    {
      "name": "logrus",
      "SPDXID": "SPDXRef-Package-Logrus",
      "versionInfo": "1.8.1",
      "downloadLocation": "NONE",
      "licenseConcluded": "MIT",
      "licenseDeclared": "MIT",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:golang/github.com/sirupsen/logrus@1.8.1"
        }
      ]
    },
    {
      "name": "vulnerable-lib",
      "SPDXID": "SPDXRef-Package-Vuln",
      "versionInfo": "0.1.0",
      "downloadLocation": "NONE",
      "licenseConcluded": "GPL-3.0-only",
      "licenseDeclared": "GPL-3.0-only",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:golang/example.com/vuln-lib@0.1.0"
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
      "relatedSpdxElement": "SPDXRef-Package-Logrus",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-Package-Logrus",
      "relatedSpdxElement": "SPDXRef-Package-Vuln",
      "relationshipType": "DEPENDS_ON"
    }
  ]
}`

func TestEvaluate_Basic(t *testing.T) {
	mock := &mockOSV{
		batchResp: &osv.BatchResponse{
			Results: []osv.QueryResult{
				{
					Vulns: []osv.VulnEntry{
						{ID: "GHSA-1234-5678-90ab"},
					},
				},
				{},
				{},
			},
		},
		hydrated: map[string]*osv.VulnEntry{
			"GHSA-1234-5678-90ab": {
				ID:      "GHSA-1234-5678-90ab",
				Summary: "Sample critical vulnerability",
				Aliases: []string{"CVE-2024-9999"},
				DatabaseSpecific: map[string]interface{}{
					"severity": "CRITICAL",
				},
			},
		},
	}

	opts := Options{
		SourceFile: "sample.spdx.json",
		SHA256Hash: "abc",
		OSVClient:  mock,
		FailOn:     "high",
	}

	res, err := Evaluate(context.Background(), strings.NewReader(sampleSPDX), opts)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if res.SBOM.DocumentName != "sample-app" {
		t.Errorf("expected document name sample-app, got %q", res.SBOM.DocumentName)
	}
	if len(res.Packages.PackageNames) != 3 {
		t.Errorf("expected 3 packages, got %d", len(res.Packages.PackageNames))
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.VulnID != "GHSA-1234-5678-90ab" || f.CVEID != "CVE-2024-9999" {
		t.Errorf("finding mismatch: id=%q cve=%q", f.VulnID, f.CVEID)
	}
	if f.Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", f.Severity)
	}

	if res.Summary.PackageCount != 3 {
		t.Errorf("summary PackageCount = %d, want 3", res.Summary.PackageCount)
	}
	if res.Summary.CriticalVulns != 1 {
		t.Errorf("summary CriticalVulns = %d, want 1", res.Summary.CriticalVulns)
	}
	if res.Summary.LicenseViolations != 1 {
		t.Errorf("summary LicenseViolations = %d, want 1 (GPL-3.0-only)", res.Summary.LicenseViolations)
	}

	// Policy failed because fail_on=high and we have 1 CRITICAL
	if res.PolicyResult != "fail" {
		t.Errorf("expected policy_result fail, got %s", res.PolicyResult)
	}
	if !strings.Contains(res.PolicyReason, "critical") {
		t.Errorf("expected policy reason mentioning critical, got %q", res.PolicyReason)
	}
}

func TestEvaluate_PURLCapExceeded(t *testing.T) {
	opts := Options{
		SourceFile: "sample.spdx.json",
		MaxPURLs:   2, // sample has 3 PURLs
	}

	_, err := Evaluate(context.Background(), strings.NewReader(sampleSPDX), opts)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrPURLCapExceeded) {
		t.Errorf("expected ErrPURLCapExceeded, got %v", err)
	}
}

func TestEvaluatePolicy(t *testing.T) {
	summary := dto.ScanSummary{
		PackageCount:      10,
		VulnCount:         3,
		CriticalVulns:     1,
		HighVulns:         1,
		MediumVulns:       1,
		LowVulns:          0,
		LicenseViolations: 2,
		LicenseExemptions: 1,
	}

	tests := []struct {
		failOn     string
		wantResult string
		wantErr    bool
	}{
		{"", "pass", false},
		{"none", "pass", false},
		{"critical", "fail", false},
		{"high", "fail", false},
		{"medium", "fail", false},
		{"low", "fail", false},
		{"license", "fail", false},
		{"critical,license", "fail", false},
		{"unknown-threshold", "", true},
	}

	for _, tt := range tests {
		res, _, err := EvaluatePolicy(tt.failOn, summary)
		if tt.wantErr {
			if err == nil {
				t.Errorf("failOn=%q: expected error, got nil", tt.failOn)
			}
			continue
		}
		if err != nil {
			t.Errorf("failOn=%q: unexpected error %v", tt.failOn, err)
			continue
		}
		if res != tt.wantResult {
			t.Errorf("failOn=%q: got %q, want %q", tt.failOn, res, tt.wantResult)
		}
	}

	// Test passing case
	cleanSummary := dto.ScanSummary{
		PackageCount: 10,
		VulnCount:    0,
	}
	res, reason, err := EvaluatePolicy("high", cleanSummary)
	if err != nil || res != "pass" || reason != "" {
		t.Errorf("clean summary failOn=high: got res=%q reason=%q err=%v", res, reason, err)
	}
}

func TestEvaluate_LicenseExceptions(t *testing.T) {
	rawExceptions := []byte(`{
		"version": "1.0.0",
		"blanketExceptions": [],
		"exceptions": [
			{
				"id": "test-ex-1",
				"package": "vulnerable-lib",
				"license": "GPL-3.0-only",
				"status": "approved",
				"approvedDate": "2026-01-01"
			}
		]
	}`)
	idx, err := license.ParseExceptions(rawExceptions, "inline")
	if err != nil {
		t.Fatalf("ParseExceptions: %v", err)
	}

	opts := Options{
		SourceFile: "sample.spdx.json",
		SkipOSV:    true,
		Exceptions: func() *license.ExceptionIndex { return idx },
		FailOn:     "license",
	}

	res, err := Evaluate(context.Background(), strings.NewReader(sampleSPDX), opts)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if res.Summary.LicenseViolations != 0 {
		t.Errorf("expected 0 license violations with exception, got %d", res.Summary.LicenseViolations)
	}
	if res.Summary.LicenseExemptions != 1 {
		t.Errorf("expected 1 exempted package, got %d", res.Summary.LicenseExemptions)
	}
	if res.PolicyResult != "pass" {
		t.Errorf("expected policy pass, got %s (reason: %s)", res.PolicyResult, res.PolicyReason)
	}
}
