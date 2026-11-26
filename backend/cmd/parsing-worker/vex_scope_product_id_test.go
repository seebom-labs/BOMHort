package main

import (
	"context"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// The product ref is the @id; a product without subcomponents that does not
// resolve by it still resolves by its purl identifier, as before (#591).
func TestScopeVEXStatements_ProductIDThenPurlIdentifier(t *testing.T) {
	const sbomA, sbomB = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	stmts := []models.VEXStatement{
		// The @id resolves: product-wide on that SBOM, even though the purl
		// identifier would resolve to another one.
		{ProductRef: "urn:uuid:a", ProductPURL: "pkg:oci/app@1", ProductWide: true},
		// Unknown @id, the purl identifier resolves.
		{ProductRef: "unknown-product", ProductPURL: "https://github.com/org/b", ProductWide: true},
		// Subcomponent statement: only the @id is a product reference.
		{ProductRef: "unknown-product", ProductPURL: "https://github.com/org/b", ProductWide: false},
	}
	r := &fakeSBOMResolver{byRef: map[string]string{
		"urn:uuid:a":               sbomA,
		"pkg:oci/app@1":            sbomB,
		"https://github.com/org/b": sbomB,
	}}
	scopeVEXStatements(context.Background(), r, models.IngestionJob{}, stmts)

	if stmts[0].SBOMID != sbomA || stmts[0].ProductPURL != models.VEXProductWide {
		t.Errorf("by @id: sbom %q purl %q, want %s product-wide", stmts[0].SBOMID, stmts[0].ProductPURL, sbomA)
	}
	if stmts[1].SBOMID != sbomB || stmts[1].ProductPURL != models.VEXProductWide {
		t.Errorf("by purl identifier: sbom %q purl %q, want %s product-wide", stmts[1].SBOMID, stmts[1].ProductPURL, sbomB)
	}
	if stmts[2].SBOMID != "" {
		t.Errorf("a subcomponent purl must not be resolved as a product, got sbom %q", stmts[2].SBOMID)
	}
}
