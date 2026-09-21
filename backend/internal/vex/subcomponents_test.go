package vex

import (
	"strings"
	"testing"
)

// TestParse_Subcomponents verifies the spec-shape handling (#350): the product
// identifies the SBOM/deliverable, the subcomponent purl is what matches
// vulnerabilities.purl.
func TestParse_Subcomponents(t *testing.T) {
	doc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://example-org.dev/vex/example-app-2026-09-17",
		"author": "Example Org Security Team",
		"statements": [
			{
				"vulnerability": {"name": "CVE-2026-1111"},
				"products": [
					{
						"@id": "pkg:oci/example-app@sha256%3Aabc123",
						"subcomponents": [
							{"@id": "pkg:golang/golang.org/x/net@v0.17.0"},
							{"@id": "pkg:golang/golang.org/x/crypto@v0.14.0"}
						]
					}
				],
				"status": "not_affected",
				"justification": "vulnerable_code_not_in_execute_path"
			}
		]
	}`

	result, err := Parse(strings.NewReader(doc), "example.openvex.json")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(result.Statements) != 2 {
		t.Fatalf("expected 2 statements (one per subcomponent), got %d", len(result.Statements))
	}

	wantPURLs := map[string]bool{
		"pkg:golang/golang.org/x/net@v0.17.0":    false,
		"pkg:golang/golang.org/x/crypto@v0.14.0": false,
	}
	for _, stmt := range result.Statements {
		if stmt.ProductRef != "pkg:oci/example-app@sha256%3Aabc123" {
			t.Errorf("product_ref = %q, want the product @id", stmt.ProductRef)
		}
		if _, ok := wantPURLs[stmt.ProductPURL]; !ok {
			t.Errorf("unexpected match purl %q", stmt.ProductPURL)
		}
		wantPURLs[stmt.ProductPURL] = true
	}
	for purl, seen := range wantPURLs {
		if !seen {
			t.Errorf("subcomponent %q missing from statements", purl)
		}
	}
}

// TestParse_ComponentShape verifies the Trivy-style shape keeps working: the
// product IS the vulnerable component, no subcomponents.
func TestParse_ComponentShape(t *testing.T) {
	doc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://example-org.dev/vex/component-style",
		"statements": [
			{
				"vulnerability": {"name": "CVE-2026-2222"},
				"products": [{"@id": "pkg:golang/golang.org/x/net@v0.17.0"}],
				"status": "fixed"
			}
		]
	}`

	result, err := Parse(strings.NewReader(doc), "component.openvex.json")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(result.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(result.Statements))
	}
	s := result.Statements[0]
	if s.ProductPURL != "pkg:golang/golang.org/x/net@v0.17.0" {
		t.Errorf("product_purl = %q", s.ProductPURL)
	}
	if s.ProductRef != "pkg:golang/golang.org/x/net@v0.17.0" {
		t.Errorf("product_ref = %q, want same as purl in component shape", s.ProductRef)
	}
	if s.SBOMID != "" {
		t.Errorf("sbom_id = %q, want empty before scoping", s.SBOMID)
	}
}
