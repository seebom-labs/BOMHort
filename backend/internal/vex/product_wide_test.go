package vex

import (
	"bytes"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// A statement that names only products[] — no subcomponents[] — asserts the
// status for the product as a whole. It carries no component purl, so the
// parser has to flag it: the worker then rewrites ProductPURL to
// models.VEXProductWide once the product resolves to an SBOM.
//
// Before this, such a statement was stored with product_purl = the product IRI,
// which no vulnerabilities.purl can ever equal, and it suppressed nothing —
// silently, which is the worst way for a security control to fail.
func TestProductWideStatementIsFlagged(t *testing.T) {
	doc := []byte(`{
	  "@context": "https://openvex.dev/ns/v0.2.0",
	  "@id": "https://example.com/vex/app-2025-001",
	  "author": "Platform Team",
	  "timestamp": "2025-09-01T09:00:00Z",
	  "version": 1,
	  "statements": [
	    {
	      "vulnerability": { "name": "CVE-2020-8203" },
	      "products": [ { "@id": "https://example.com/sbom/payment-api-1.4.2" } ],
	      "status": "not_affected",
	      "justification": "vulnerable_code_not_present"
	    }
	  ]
	}`)

	res, err := Parse(bytes.NewReader(doc), "payment-api.openvex.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Statements) != 1 {
		t.Fatalf("got %d statements, want 1", len(res.Statements))
	}

	s := res.Statements[0]
	if !s.ProductWide {
		t.Error("ProductWide = false; a product without subcomponents covers the whole product")
	}
	if s.ProductRef != "https://example.com/sbom/payment-api-1.4.2" {
		t.Errorf("ProductRef = %q, want the product @id so the worker can resolve the SBOM", s.ProductRef)
	}
}

// The component shape (Trivy et al.) names the vulnerable purl as the product.
// It must NOT be treated as product-wide by the worker, which decides using the
// sboms lookup — but the parser still reports "no subcomponents", so the flag
// alone is not a licence to rewrite: see scopeVEXStatements, which only
// rewrites when the ref actually resolves to an SBOM.
func TestSubcomponentStatementIsNotProductWide(t *testing.T) {
	doc := []byte(`{
	  "@context": "https://openvex.dev/ns/v0.2.0",
	  "@id": "https://example.com/vex/app-2025-002",
	  "author": "Platform Team",
	  "timestamp": "2025-09-01T09:00:00Z",
	  "version": 1,
	  "statements": [
	    {
	      "vulnerability": { "name": "CVE-2020-8203" },
	      "products": [ {
	        "@id": "https://example.com/sbom/payment-api-1.4.2",
	        "subcomponents": [ { "@id": "pkg:npm/lodash@4.17.15" } ]
	      } ],
	      "status": "not_affected"
	    }
	  ]
	}`)

	res, err := Parse(bytes.NewReader(doc), "payment-api.openvex.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Statements) != 1 {
		t.Fatalf("got %d statements, want 1", len(res.Statements))
	}

	s := res.Statements[0]
	if s.ProductWide {
		t.Error("ProductWide = true although subcomponents pin the statement to one component")
	}
	if s.ProductPURL != "pkg:npm/lodash@4.17.15" {
		t.Errorf("ProductPURL = %q, want the subcomponent purl", s.ProductPURL)
	}
	if s.ProductPURL == models.VEXProductWide {
		t.Error("a component-scoped statement must never carry the product-wide sentinel")
	}
}
