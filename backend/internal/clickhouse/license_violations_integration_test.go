package clickhouse

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/depgraph"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// TestProjectLicenseViolationsSeeded runs the full and the summary listing of
// /projects/license-compliance against seeded rows. TestQueriesExecute only
// proves the SQL plans; this checks that streaming the joined rows, the
// batched scope lookup and the reduction to counts agree with each other.
//
// Writes to sboms, sbom_packages and license_compliance, so run it only
// against a disposable database. Skipped unless CLICKHOUSE_HOST is set.
func TestProjectLicenseViolationsSeeded(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sbomID := uuid.New()
	project := "violations-it-" + sbomID.String()[:8]
	source := "integration-test/" + project + ".spdx.json"
	t.Cleanup(func() {
		for _, table := range []string{"sboms", "sbom_packages", "license_compliance"} {
			_ = c.Conn.Exec(context.Background(),
				"ALTER TABLE "+table+" DELETE WHERE sbom_id = ? SETTINGS mutations_sync = 1", sbomID)
		}
	})
	if err := c.InsertSBOM(ctx, &models.SBOM{
		IngestedAt:   time.Now(),
		SBOMID:       sbomID,
		SourceFile:   source,
		SPDXVersion:  "SPDX-2.3",
		DocumentName: project,
		SHA256Hash:   uuid.NewString(),
		CreationDate: time.Now(),
	}); err != nil {
		t.Fatalf("InsertSBOM: %v", err)
	}
	if err := c.InsertSBOMPackages(ctx, &models.SBOMPackages{
		IngestedAt:       time.Now(),
		SBOMID:           sbomID,
		SourceFile:       source,
		PackageSPDXIDs:   []string{"SPDXRef-0", "SPDXRef-1", "SPDXRef-2"},
		PackageNames:     []string{"product", "gpl-direct", "gpl-transitive"},
		PackageVersions:  []string{"1", "1", "1"},
		PackagePURLs:     []string{"", "", ""},
		PackageLicenses:  []string{"MIT", "GPL-3.0-only", "GPL-3.0-only"},
		RelSourceIndices: []uint32{0, 1},
		RelTargetIndices: []uint32{1, 2},
		RelTypes:         []string{"DEPENDS_ON", "DEPENDS_ON"},
		PackageDepths:    []uint16{0, 1, 2},
	}); err != nil {
		t.Fatalf("InsertSBOMPackages: %v", err)
	}
	if err := c.InsertLicenseCompliance(ctx, []models.LicenseCompliance{
		{
			CheckedAt: time.Now(), SBOMID: sbomID, SourceFile: source,
			LicenseID: "GPL-3.0-only", Category: "copyleft", PackageCount: 2,
			NonCompliantPackages: []string{"gpl-direct", "gpl-transitive"},
			ExemptedPackages:     []string{},
		},
		{
			CheckedAt: time.Now(), SBOMID: sbomID, SourceFile: source,
			LicenseID: "MIT", Category: "permissive", PackageCount: 1,
			NonCompliantPackages: []string{}, ExemptedPackages: []string{},
		},
	}); err != nil {
		t.Fatalf("InsertLicenseCompliance: %v", err)
	}

	full, err := c.QueryProjectsWithLicenseViolations(ctx, nil)
	if err != nil {
		t.Fatalf("QueryProjectsWithLicenseViolations: %v", err)
	}
	var found bool
	for _, p := range full {
		if p.SBOMID != sbomID.String() {
			continue
		}
		found = true
		if p.DocumentName != project || p.CopyleftCount != 2 || !slices.Equal(p.ViolatingLicenses, []string{"GPL-3.0-only"}) ||
			!slices.Equal(p.NonCompliantPackages, []string{"gpl-direct", "gpl-transitive"}) ||
			p.PackageScopes["gpl-direct"] != depgraph.ScopeDirect || p.PackageScopes["gpl-transitive"] != depgraph.ScopeTransitive {
			t.Errorf("full listing = %+v", p)
		}
	}
	if !found {
		t.Fatalf("seeded SBOM missing from the full listing")
	}

	summaries, err := c.QueryProjectLicenseViolationSummaries(ctx, nil, "")
	if err != nil {
		t.Fatalf("QueryProjectLicenseViolationSummaries: %v", err)
	}
	found = false
	for _, s := range summaries {
		if s.SBOMID != sbomID.String() {
			continue
		}
		found = true
		if s.DocumentName != project || s.CopyleftCount != 2 || s.NonCompliantPackageCount != 2 ||
			s.DirectCount != 1 || s.TransitiveCount != 1 {
			t.Errorf("summary = %+v", s)
		}
	}
	if !found {
		t.Fatalf("seeded SBOM missing from the summary listing")
	}

	// ?search= narrows server-side (#492): the seeded project is found by a
	// case-insensitive substring and absent for a term that matches nothing.
	hits, err := c.QueryProjectLicenseViolationSummaries(ctx, nil, strings.ToUpper(project))
	if err != nil {
		t.Fatalf("summaries with search: %v", err)
	}
	if len(hits) != 1 || hits[0].SBOMID != sbomID.String() {
		t.Errorf("search hits = %+v, want only %s", hits, sbomID)
	}
	if miss, err := c.QueryProjectLicenseViolationSummaries(ctx, nil, project+"-nope"); err != nil || len(miss) != 0 {
		t.Errorf("search miss = %+v, %v", miss, err)
	}
}
