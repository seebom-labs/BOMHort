package clickhouse

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// TestLicenseRecheckQueries runs the queries behind the retroactive license
// recheck against a real ClickHouse: the newest recheck job is found by its
// enqueue time (status rows written later must not reorder it), and the
// stored compliance rows come back deduplicated with their SBOM's document
// name, which project-scoped exceptions match against.
//
// Writes to ingestion_queue, sboms and license_compliance, so run it only
// against a disposable database. Skipped unless CLICKHOUSE_HOST is set.
func TestLicenseRecheckQueries(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	recheck := func(digest string) models.IngestionJob {
		job := models.IngestionJob{
			// Enqueue time orders rechecks; ensureLicenseRecheck sets it.
			CreatedAt:  time.Now(),
			JobID:      uuid.New(),
			SourceFile: "license-exceptions@" + digest[:12],
			SHA256Hash: digest,
			Status:     models.JobStatusPending,
			JobType:    models.JobTypeLicenseRecheck,
			// Far enough ahead that no other test's ClaimJobs picks it up.
			RetryAfter: time.Now().Add(time.Hour),
		}
		if err := c.EnqueueJobs(ctx, []models.IngestionJob{job}); err != nil {
			t.Fatalf("EnqueueJobs: %v", err)
		}
		return job
	}
	// created_at has second resolution.
	tick := func() { time.Sleep(1100 * time.Millisecond) }

	first := recheck("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tick()
	second := recheck("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	tick()
	// A late status row of the older job must not make it the latest.
	first.ClaimedBy = "test"
	if err := c.FailJob(ctx, first, "boom"); err != nil {
		t.Fatalf("FailJob: %v", err)
	}

	latest, err := c.LatestLicenseRecheck(ctx)
	if err != nil {
		t.Fatalf("LatestLicenseRecheck: %v", err)
	}
	if latest == nil || latest.JobID != second.JobID || latest.Digest != second.SHA256Hash || latest.Status != models.JobStatusPending || latest.UpdatedAt.IsZero() {
		t.Fatalf("latest = %+v, want job %s pending", latest, second.JobID)
	}

	tick()
	if err := c.FailJob(ctx, second, "boom"); err != nil {
		t.Fatalf("FailJob: %v", err)
	}
	if latest, err = c.LatestLicenseRecheck(ctx); err != nil || latest.Status != models.JobStatusFailed {
		t.Fatalf("latest = %+v, %v; want failed", latest, err)
	}

	sbomID := uuid.New()
	if err := c.InsertSBOM(ctx, &models.SBOM{
		IngestedAt:   time.Now(),
		SBOMID:       sbomID,
		SourceFile:   "integration-test/recheck.spdx.json",
		SPDXVersion:  "SPDX-2.3",
		DocumentName: "recheck-project",
		SHA256Hash:   uuid.NewString(),
		CreationDate: time.Now(),
	}); err != nil {
		t.Fatalf("InsertSBOM: %v", err)
	}
	if err := c.InsertSBOMPackages(ctx, &models.SBOMPackages{
		IngestedAt: time.Now(), SBOMID: sbomID, SourceFile: "integration-test/recheck.spdx.json",
		PackageSPDXIDs:        []string{"SPDXRef-a", "SPDXRef-b", "SPDXRef-mit"},
		PackageNames:          []string{"a", "b", "mit"},
		PackageVersions:       []string{"1", "2", "3"},
		PackagePURLs:          []string{"pkg:generic/a", "pkg:generic/b", "pkg:generic/mit"},
		PackageLicenses:       []string{"GPL-3.0-only", "GPL-3.0-only", "MIT"},
		PackageLicenseSources: []string{"declared", "declared", "declared"},
		PackageDepths:         []uint16{1, 1, 1},
	}); err != nil {
		t.Fatalf("InsertSBOMPackages: %v", err)
	}
	row := models.LicenseCompliance{
		CheckedAt:            time.Now().Add(-time.Minute),
		SBOMID:               sbomID,
		SourceFile:           "integration-test/recheck.spdx.json",
		LicenseID:            "GPL-3.0-only",
		Category:             "copyleft",
		PackageCount:         2,
		NonCompliantPackages: []string{"a", "b"},
		ExemptedPackages:     []string{},
		Project:              "p",
	}
	updated := row
	updated.CheckedAt = time.Now()
	updated.NonCompliantPackages = []string{"b"}
	updated.ExemptedPackages = []string{"a"}
	updated.ExemptionReason = "granted"
	if err := c.InsertLicenseCompliance(ctx, []models.LicenseCompliance{row}); err != nil {
		t.Fatalf("InsertLicenseCompliance: %v", err)
	}
	if err := c.InsertLicenseCompliance(ctx, []models.LicenseCompliance{updated}); err != nil {
		t.Fatalf("InsertLicenseCompliance: %v", err)
	}
	permissive := models.LicenseCompliance{
		CheckedAt: time.Now(), SBOMID: sbomID, SourceFile: "integration-test/recheck.spdx.json",
		LicenseID: "MIT", Category: "permissive", PackageCount: 1,
		NonCompliantPackages: []string{}, ExemptedPackages: []string{},
	}
	if err := c.InsertLicenseCompliance(ctx, []models.LicenseCompliance{permissive}); err != nil {
		t.Fatalf("InsertLicenseCompliance (permissive): %v", err)
	}

	var got []StoredLicenseCompliance
	err = c.EachLicenseCompliance(ctx, func(r StoredLicenseCompliance) error {
		if r.SBOMID == sbomID {
			got = append(got, r)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("EachLicenseCompliance: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows for the SBOM, want 2 (FINAL)", len(got))
	}
	byLicense := map[string]StoredLicenseCompliance{}
	for _, row := range got {
		byLicense[row.LicenseID] = row
	}
	r := byLicense["GPL-3.0-only"]
	if r.DocumentName != "recheck-project" || r.Category != "copyleft" || r.PackageCount != 2 || r.Project != "p" ||
		!slices.Equal(r.NonCompliantPackages, []string{"b"}) || !slices.Equal(r.ExemptedPackages, []string{"a"}) || r.ExemptionReason != "granted" {
		t.Fatalf("row = %+v", r)
	}
	if len(r.PackageNames) != 0 {
		t.Fatalf("non-permissive row should not duplicate source names: %v", r.PackageNames)
	}
	permissiveRow := byLicense["MIT"]
	if permissiveRow.Category != "permissive" || !slices.Equal(permissiveRow.PackageNames, []string{"mit"}) {
		t.Fatalf("permissive row source package names = %v, want [mit]", permissiveRow.PackageNames)
	}
}
