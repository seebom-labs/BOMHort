package vex

import (
	"strings"
	"testing"
	"time"
)

const testOpenVEXJSON = `{
	"@context": "https://openvex.dev/ns/v0.2.0",
	"@id": "https://example.com/vex/2025-001",
	"author": "Test Author",
	"role": "vendor",
	"timestamp": "2025-06-15T10:00:00Z",
	"version": 1,
	"statements": [
		{
			"vulnerability": {
				"name": "CVE-2024-1234"
			},
			"products": [
				{
					"@id": "pkg:npm/package-a@1.0.0"
				},
				{
					"@id": "some-product",
					"identifiers": {
						"purl": "pkg:npm/package-b@2.0.0"
					}
				}
			],
			"status": "not_affected",
			"justification": "vulnerable_code_not_present",
			"impact_statement": "The vulnerable function is not called in our usage."
		},
		{
			"vulnerability": {
				"name": "CVE-2024-5678",
				"aliases": ["GHSA-xxxx-yyyy-zzzz"]
			},
			"products": [
				{
					"@id": "pkg:npm/package-c@3.0.0"
				}
			],
			"status": "fixed",
			"action_statement": "Upgrade to version 3.0.1"
		},
		{
			"vulnerability": {},
			"products": [{"@id": "pkg:npm/skip-me@1.0.0"}],
			"status": "affected"
		}
	]
}`

func TestParse(t *testing.T) {
	result, err := Parse(strings.NewReader(testOpenVEXJSON), "test.openvex.json")
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	if result.DocumentID != "https://example.com/vex/2025-001" {
		t.Errorf("expected document ID, got %s", result.DocumentID)
	}

	// 2 products in first statement + 1 in second = 3 (third is skipped: no vuln ID)
	if len(result.Statements) != 3 {
		t.Fatalf("expected 3 statements, got %d", len(result.Statements))
	}

	// First statement, first product
	s0 := result.Statements[0]
	if s0.VulnID != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %s", s0.VulnID)
	}
	if s0.ProductPURL != "pkg:npm/package-a@1.0.0" {
		t.Errorf("expected PURL from @id, got %s", s0.ProductPURL)
	}
	if s0.Status != "not_affected" {
		t.Errorf("expected not_affected, got %s", s0.Status)
	}
	if s0.Justification != "vulnerable_code_not_present" {
		t.Errorf("expected justification, got %s", s0.Justification)
	}
	if s0.ImpactStatement == "" {
		t.Error("expected non-empty impact statement")
	}

	// First statement, second product (PURL from identifiers)
	s1 := result.Statements[1]
	if s1.ProductPURL != "pkg:npm/package-b@2.0.0" {
		t.Errorf("expected PURL from identifiers, got %s", s1.ProductPURL)
	}

	// Second statement
	s2 := result.Statements[2]
	if s2.VulnID != "CVE-2024-5678" {
		t.Errorf("expected CVE-2024-5678, got %s", s2.VulnID)
	}
	if s2.Status != "fixed" {
		t.Errorf("expected fixed, got %s", s2.Status)
	}
	if s2.ActionStatement != "Upgrade to version 3.0.1" {
		t.Errorf("expected action statement, got %s", s2.ActionStatement)
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := Parse(strings.NewReader(`{invalid`), "bad.json")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParse_EmptyDocument(t *testing.T) {
	_, err := Parse(strings.NewReader(`{}`), "empty.json")
	if err == nil {
		t.Error("expected error for empty document, got nil")
	}
}

func TestNormalizeVulnID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"CVE-2024-1234", "CVE-2024-1234"},
		{"GO-2025-4188", "GO-2025-4188"},
		{"GHSA-xxxx-yyyy-zzzz", "GHSA-xxxx-yyyy-zzzz"},
		{"https://pkg.go.dev/vuln/GO-2025-4188", "GO-2025-4188"},
		{"https://github.com/advisories/GHSA-xxxx-yyyy-zzzz", "GHSA-xxxx-yyyy-zzzz"},
		{"https://nvd.nist.gov/vuln/detail/CVE-2024-1234", "CVE-2024-1234"},
		{"http://example.com/vuln/TEST-001", "TEST-001"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeVulnID(tt.input)
			if got != tt.want {
				t.Errorf("normalizeVulnID(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParse_VulnIDFromURL(t *testing.T) {
	// OpenVEX document where vulnerability @id is a URL, not a plain ID.
	doc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://example.com/vex/url-test",
		"timestamp": "2025-01-01T00:00:00Z",
		"version": 1,
		"statements": [{
			"vulnerability": {"@id": "https://pkg.go.dev/vuln/GO-2025-9999"},
			"products": [{"@id": "pkg:golang/example.com/foo@v1.0.0"}],
			"status": "not_affected",
			"justification": "component_not_present"
		}]
	}`

	result, err := Parse(strings.NewReader(doc), "url-test.openvex.json")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(result.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(result.Statements))
	}
	if result.Statements[0].VulnID != "GO-2025-9999" {
		t.Errorf("expected normalized vuln ID GO-2025-9999, got %q", result.Statements[0].VulnID)
	}
}

// #413: OpenVEX statements can carry action_statement_timestamp, the time the
// action statement was issued. It must survive parsing next to
// action_statement, stay optional, and fall back to the zero time when it is
// absent or not RFC 3339 — the same tolerance the statement timestamp gets.
// The statement timestamp itself must stay untouched by the new field.
func TestParseActionStatementTimestamp(t *testing.T) {
	doc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://example.com/vex/ast",
		"author": "Vendor",
		"timestamp": "2025-06-15T10:00:00Z",
		"version": 1,
		"statements": [
			{
				"vulnerability": {"name": "CVE-2025-1000"},
				"products": [{"@id": "pkg:npm/pkg-a@1.0.0"}],
				"status": "affected",
				"action_statement": "Upgrade to 1.0.1",
				"action_statement_timestamp": "2025-06-20T12:30:00Z"
			},
			{
				"vulnerability": {"name": "CVE-2025-1001"},
				"products": [{"@id": "pkg:npm/pkg-b@1.0.0"}],
				"status": "affected",
				"action_statement": "Investigating"
			},
			{
				"vulnerability": {"name": "CVE-2025-1002"},
				"products": [{"@id": "pkg:npm/pkg-c@1.0.0"}],
				"status": "affected",
				"action_statement": "Upgrade to 2.0.0",
				"action_statement_timestamp": "not-a-timestamp"
			}
		]
	}`

	result, err := Parse(strings.NewReader(doc), "ast.openvex.json")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(result.Statements) != 3 {
		t.Fatalf("expected 3 statements, got %d", len(result.Statements))
	}

	want := time.Date(2025, 6, 20, 12, 30, 0, 0, time.UTC)
	if got := result.Statements[0].ActionStatementTimestamp.UTC(); !got.Equal(want) {
		t.Errorf("statement 0: ActionStatementTimestamp = %v, want %v", got, want)
	}
	if !result.Statements[1].ActionStatementTimestamp.IsZero() {
		t.Errorf("statement 1: ActionStatementTimestamp = %v, want zero (field absent)",
			result.Statements[1].ActionStatementTimestamp)
	}
	if !result.Statements[2].ActionStatementTimestamp.IsZero() {
		t.Errorf("statement 2: ActionStatementTimestamp = %v, want zero (not RFC 3339)",
			result.Statements[2].ActionStatementTimestamp)
	}
	// The statement timestamp keeps its own meaning; the new field never
	// overwrites it.
	if got := result.Statements[0].VEXTimestamp.UTC(); !got.Equal(time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("statement 0: VEXTimestamp = %v, want 2025-06-15T10:00:00Z", got)
	}
}
