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

// One document stating the same vulnerability for the same component in two
// products must yield two statements with two distinct storage keys.
// vex_statements is a ReplacingMergeTree ordered by (vuln_id, product_purl,
// vex_id); when vex_id left the product out, both statements shared a key
// and ClickHouse silently kept only one of them.
func TestParse_SameComponentInTwoProducts(t *testing.T) {
	docs := map[string]string{
		"one statement, two products": `{
			"@context": "https://openvex.dev/ns/v0.2.0",
			"@id": "https://example.com/vex/payments",
			"statements": [{
				"vulnerability": {"name": "CVE-2021-44228"},
				"products": [
					{"@id": "urn:uuid:payments-3.2.0", "subcomponents": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]},
					{"@id": "urn:uuid:payments-3.3.0", "subcomponents": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}
				],
				"status": "not_affected",
				"justification": "vulnerable_code_not_in_execute_path"
			}]
		}`,
		"two statements, two products": `{
			"@context": "https://openvex.dev/ns/v0.2.0",
			"@id": "https://example.com/vex/payments",
			"statements": [
				{"vulnerability": {"name": "CVE-2021-44228"},
				 "products": [{"@id": "urn:uuid:payments-3.2.0", "subcomponents": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}],
				 "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"},
				{"vulnerability": {"name": "CVE-2021-44228"},
				 "products": [{"@id": "urn:uuid:orders-1.0.0", "subcomponents": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}],
				 "status": "affected", "action_statement": "Upgrade to 2.17.1."}
			]
		}`,
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			res, err := Parse(strings.NewReader(doc), "multi-product.openvex.json")
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Statements) != 2 {
				t.Fatalf("got %d statements, want 2", len(res.Statements))
			}
			type storageKey struct{ vuln, purl, id string }
			keys := map[storageKey]string{}
			for _, s := range res.Statements {
				k := storageKey{s.VulnID, s.ProductPURL, s.VEXID.String()}
				if other, dup := keys[k]; dup {
					t.Fatalf("products %q and %q share the storage key %v; one statement would be lost", other, s.ProductRef, k)
				}
				keys[k] = s.ProductRef
			}

			// The id stays deterministic: parsing the same document again
			// yields the same ids, so a re-processed document replaces its
			// own rows instead of adding new ones.
			again, err := Parse(strings.NewReader(doc), "multi-product.openvex.json")
			if err != nil {
				t.Fatal(err)
			}
			for i := range res.Statements {
				if res.Statements[i].VEXID != again.Statements[i].VEXID {
					t.Errorf("statement %d: id changed between parses", i)
				}
			}
		})
	}
}
