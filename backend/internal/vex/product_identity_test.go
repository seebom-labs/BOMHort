package vex

import (
	"strings"
	"testing"
)

// Two products may share a purl identifier while naming different SBOMs by
// their @id. The @id is the product's identity: it must reach the storage key
// and the ref used for SBOM scoping (#591 review).
func TestParse_ProductsSharingAPurlIdentifier(t *testing.T) {
	doc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://example.com/vex/images",
		"statements": [{
			"vulnerability": {"name": "CVE-2021-44228"},
			"products": [
				{"@id": "urn:uuid:11111111-1111-4111-8111-111111111111",
				 "identifiers": {"purl": "pkg:oci/app?repository_url=registry.example/app"},
				 "subcomponents": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]},
				{"@id": "urn:uuid:22222222-2222-4222-8222-222222222222",
				 "identifiers": {"purl": "pkg:oci/app?repository_url=registry.example/app"},
				 "subcomponents": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}
			],
			"status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"
		}]
	}`
	res, err := Parse(strings.NewReader(doc), "images.openvex.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Statements) != 2 {
		t.Fatalf("got %d statements, want 2", len(res.Statements))
	}
	a, b := res.Statements[0], res.Statements[1]
	if a.VEXID == b.VEXID {
		t.Fatal("both products got the same vex_id; one statement would be replaced")
	}
	if a.ProductRef != "urn:uuid:11111111-1111-4111-8111-111111111111" || b.ProductRef != "urn:uuid:22222222-2222-4222-8222-222222222222" {
		t.Errorf("product refs = %q, %q; want each product's @id", a.ProductRef, b.ProductRef)
	}
}

// A product without subcomponents keeps matching on its purl identifier,
// while its ref is the @id.
func TestParse_ProductWithoutSubcomponentsKeepsPurlIdentifier(t *testing.T) {
	doc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://example.com/vex/x",
		"statements": [{
			"vulnerability": {"name": "CVE-2024-1"},
			"products": [{"@id": "some-product", "identifiers": {"purl": "pkg:npm/package-b@2.0.0"}}],
			"status": "not_affected", "justification": "component_not_present"
		}]
	}`
	res, err := Parse(strings.NewReader(doc), "x.openvex.json")
	if err != nil {
		t.Fatal(err)
	}
	s := res.Statements[0]
	if s.ProductRef != "some-product" || s.ProductPURL != "pkg:npm/package-b@2.0.0" || !s.ProductWide {
		t.Errorf("ref %q, purl %q, product-wide %v", s.ProductRef, s.ProductPURL, s.ProductWide)
	}
}

const (
	newerAssessment = `{"vulnerability": {"name": "CVE-2021-45046"}, "timestamp": "2024-03-01T09:00:00Z",
		"products": [{"@id": "urn:uuid:p", "subcomponents": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}],
		"status": "affected", "action_statement": "Upgrade."}`
	olderAssessment = `{"vulnerability": {"name": "CVE-2021-45046"}, "timestamp": "2024-01-10T10:00:00Z",
		"products": [{"@id": "urn:uuid:p", "subcomponents": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}],
		"status": "not_affected", "justification": "vulnerable_code_not_present"}`
)

// One document may state the same vulnerability for the same product more
// than once as its assessment changed. Those statements share a storage key
// and an ingested_at, so the parser keeps the newest, in either order
// (#591 review).
func TestParse_SuccessiveStatementsKeepTheNewest(t *testing.T) {
	for name, stmts := range map[string]string{
		"newer first": newerAssessment + "," + olderAssessment,
		"older first": olderAssessment + "," + newerAssessment,
	} {
		t.Run(name, func(t *testing.T) {
			doc := `{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.com/vex/s", "statements": [` + stmts + `]}`
			res, err := Parse(strings.NewReader(doc), "s.openvex.json")
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Statements) != 1 {
				t.Fatalf("got %d statements, want one per storage key", len(res.Statements))
			}
			if s := res.Statements[0]; s.Status != "affected" || s.VEXTimestamp.Format("2006-01-02") != "2024-03-01" {
				t.Errorf("kept %s from %s, want the newer affected", s.Status, s.VEXTimestamp)
			}
		})
	}

	// Equal timestamps: the later statement in the document wins.
	same := `{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.com/vex/t",
		"timestamp": "2024-01-01T00:00:00Z", "statements": [
		{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:npm/a@1"}], "status": "under_investigation"},
		{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:npm/a@1"}], "status": "fixed"}]}`
	res, err := Parse(strings.NewReader(same), "t.openvex.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Statements) != 1 || res.Statements[0].Status != "fixed" {
		t.Errorf("equal timestamps: %+v, want the later fixed", res.Statements)
	}
}
