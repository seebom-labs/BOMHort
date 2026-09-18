package main

import (
	"context"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// resolverFunc adapts a function to the sbomResolver interface.
type resolverFunc func(ctx context.Context, ref string) (string, error)

func (f resolverFunc) ResolveSBOMByProductRef(ctx context.Context, ref string) (string, error) {
	return f(ctx, ref)
}

// A product-wide statement (products[] with no subcomponents[]) only becomes a
// wildcard once the ref is known to name a product — which is exactly what a
// successful sboms lookup tells us.
func TestProductWideBecomesWildcardWhenResolved(t *testing.T) {
	stmts := []models.VEXStatement{{
		ProductRef:  "https://example.com/sbom/payment-api-1.4.2",
		ProductPURL: "https://example.com/sbom/payment-api-1.4.2",
		ProductWide: true,
		VulnID:      "CVE-2020-8203",
	}}

	resolver := resolverFunc(func(_ context.Context, ref string) (string, error) {
		return "7298e78d-1fc7-577e-a19c-3b211be17aa6", nil
	})

	scopeVEXStatements(context.Background(), resolver, models.IngestionJob{}, stmts)

	if stmts[0].SBOMID != "7298e78d-1fc7-577e-a19c-3b211be17aa6" {
		t.Errorf("SBOMID = %q, want the resolved SBOM", stmts[0].SBOMID)
	}
	if stmts[0].ProductPURL != models.VEXProductWide {
		t.Errorf("ProductPURL = %q, want %q — otherwise the suppression join can never match, since a product IRI is not a package purl",
			stmts[0].ProductPURL, models.VEXProductWide)
	}
}

// The component shape must survive untouched: its product @id *is* the
// vulnerable purl, and rewriting it to '*' would suppress every finding of that
// CVE in the SBOM instead of the one component the statement is about.
func TestComponentShapeKeepsItsPURL(t *testing.T) {
	stmts := []models.VEXStatement{{
		ProductRef:  "pkg:npm/lodash@4.17.15",
		ProductPURL: "pkg:npm/lodash@4.17.15",
		ProductWide: true, // no subcomponents in the document
		VulnID:      "CVE-2020-8203",
	}}

	// A component purl matches no SBOM.
	resolver := resolverFunc(func(_ context.Context, _ string) (string, error) {
		return "", nil
	})

	scopeVEXStatements(context.Background(), resolver, models.IngestionJob{}, stmts)

	if stmts[0].ProductPURL != "pkg:npm/lodash@4.17.15" {
		t.Errorf("ProductPURL = %q, want the component purl untouched", stmts[0].ProductPURL)
	}
	if stmts[0].SBOMID != "" {
		t.Errorf("SBOMID = %q, want empty: an unresolvable ref stays unscoped", stmts[0].SBOMID)
	}
}

// An explicit ?sbom_id= on upload names the product outright, so a statement
// without subcomponents covers that product as a whole.
func TestExplicitTargetAppliesWildcard(t *testing.T) {
	stmts := []models.VEXStatement{
		{ProductRef: "whatever", ProductPURL: "whatever", ProductWide: true},
		{ProductRef: "whatever", ProductPURL: "pkg:npm/lodash@4.17.15", ProductWide: false},
	}

	resolver := resolverFunc(func(_ context.Context, _ string) (string, error) {
		t.Error("resolver must not be consulted when TargetSBOMID is set")
		return "", nil
	})

	job := models.IngestionJob{TargetSBOMID: "11111111-1111-1111-1111-111111111111"}
	scopeVEXStatements(context.Background(), resolver, job, stmts)

	if stmts[0].ProductPURL != models.VEXProductWide {
		t.Errorf("product-wide statement: ProductPURL = %q, want %q", stmts[0].ProductPURL, models.VEXProductWide)
	}
	if stmts[1].ProductPURL != "pkg:npm/lodash@4.17.15" {
		t.Errorf("component statement: ProductPURL = %q, want it untouched", stmts[1].ProductPURL)
	}
	for i := range stmts {
		if stmts[i].SBOMID != job.TargetSBOMID {
			t.Errorf("stmt %d: SBOMID = %q, want %q", i, stmts[i].SBOMID, job.TargetSBOMID)
		}
	}
}
