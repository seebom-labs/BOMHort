package main

import (
	"context"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

type fakeSBOMResolver struct {
	byRef map[string]string
	calls int
}

func (f *fakeSBOMResolver) ResolveSBOMByProductRef(_ context.Context, ref string) (string, error) {
	f.calls++
	return f.byRef[ref], nil
}

func TestScopeVEXStatements_ExplicitMapping(t *testing.T) {
	stmts := []models.VEXStatement{
		{ProductRef: "pkg:oci/app@1"},
		{ProductRef: "pkg:oci/other@2"},
	}
	r := &fakeSBOMResolver{}
	job := models.IngestionJob{TargetSBOMID: "11111111-1111-1111-1111-111111111111"}

	scopeVEXStatements(context.Background(), r, job, stmts)

	for i, s := range stmts {
		if s.SBOMID != job.TargetSBOMID {
			t.Errorf("statement %d: sbom_id = %q, want explicit mapping", i, s.SBOMID)
		}
	}
	if r.calls != 0 {
		t.Errorf("resolver called %d times despite explicit mapping", r.calls)
	}
}

func TestScopeVEXStatements_AutoResolve(t *testing.T) {
	stmts := []models.VEXStatement{
		{ProductRef: "https://github.com/example-org/example-app"},
		{ProductRef: "https://github.com/example-org/example-app"}, // repeated → cached
		{ProductRef: "pkg:oci/unknown@1"},                          // no match → global
	}
	r := &fakeSBOMResolver{byRef: map[string]string{
		"https://github.com/example-org/example-app": "22222222-2222-2222-2222-222222222222",
	}}

	scopeVEXStatements(context.Background(), r, models.IngestionJob{}, stmts)

	if stmts[0].SBOMID != "22222222-2222-2222-2222-222222222222" || stmts[1].SBOMID != stmts[0].SBOMID {
		t.Errorf("auto-resolve failed: %q / %q", stmts[0].SBOMID, stmts[1].SBOMID)
	}
	if stmts[2].SBOMID != "" {
		t.Errorf("unknown product must stay global, got %q", stmts[2].SBOMID)
	}
	// 1 call for the repo ref (cached on repeat) + up to 2 for the unknown
	// ref (raw + normalised retry is skipped for non-URL refs).
	if r.calls > 3 {
		t.Errorf("resolver called %d times, memoisation broken", r.calls)
	}
}

func TestScopeVEXStatements_NormalisedRepoRetry(t *testing.T) {
	// Product IRI in git+…@ref form; sboms.source_repo stores the
	// normalised https URL — the second lookup must hit.
	raw := "git+https://github.com/example-org/example-app.git@v1.2.3"
	norm := "https://github.com/example-org/example-app"
	stmts := []models.VEXStatement{{ProductRef: raw}}
	r := &fakeSBOMResolver{byRef: map[string]string{norm: "33333333-3333-3333-3333-333333333333"}}

	scopeVEXStatements(context.Background(), r, models.IngestionJob{}, stmts)

	if stmts[0].SBOMID != "33333333-3333-3333-3333-333333333333" {
		t.Errorf("normalised retry failed, sbom_id = %q", stmts[0].SBOMID)
	}
}
