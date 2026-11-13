package clickhouse

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func TestCloneImageSBOMCopiesRelatedRowsAndIsIdempotent(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sourceID := uuid.New()
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	identity, err := json.Marshal([]string{digest, "registry.example/target", "target-cluster", "team", "app", "ci"})
	if err != nil {
		t.Fatal(err)
	}
	targetID := uuid.NewSHA1(uuid.NameSpaceURL, identity)
	for _, table := range []string{"sbom_packages", "vulnerabilities", "license_compliance", "document_store", "vex_statements", "sboms"} {
		table := table
		t.Cleanup(func() {
			if err := c.Conn.Exec(context.Background(), "ALTER TABLE "+table+" DELETE WHERE sbom_id IN (?, ?) SETTINGS mutations_sync = 1", sourceID, targetID); err != nil {
				t.Errorf("cleanup %s: %v", table, err)
			}
		})
	}

	now := time.Now()
	source := models.SBOM{
		IngestedAt: now, SBOMID: sourceID, SourceFile: "test-source.json",
		SPDXVersion: "SPDX-2.3", DocumentName: "clone-test", SHA256Hash: strings.Repeat("a", 64),
		CreationDate: now, CreatorTools: []string{}, Tags: []string{}, QualityFlags: []string{},
		Cluster: "source-cluster", ImageRef: "registry.example/source",
		ImageDigest: digest,
	}
	if err := c.InsertSBOM(ctx, &source); err != nil {
		t.Fatal(err)
	}
	packages := models.SBOMPackages{
		IngestedAt: now, SBOMID: sourceID, SourceFile: source.SourceFile,
		PackageSPDXIDs: []string{"SPDXRef-Root"}, PackageNames: []string{"root"},
		PackageVersions: []string{"1"}, PackagePURLs: []string{"pkg:generic/root@1"},
		PackageLicenses: []string{"MIT"}, PackageLicenseSources: []string{"declared"},
		PackageDepths: []uint16{0}, Cluster: source.Cluster, ImageDigest: digest,
	}
	if err := c.InsertSBOMPackages(ctx, &packages); err != nil {
		t.Fatal(err)
	}
	if err := c.InsertVulnerabilities(ctx, []models.Vulnerability{{
		DiscoveredAt: now, SBOMID: sourceID, SourceFile: source.SourceFile,
		PURL: "pkg:generic/root@1", VulnID: "GHSA-test-0000", Severity: "HIGH",
		Cluster: source.Cluster, ImageDigest: digest,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := c.InsertLicenseCompliance(ctx, []models.LicenseCompliance{{
		CheckedAt: now, SBOMID: sourceID, SourceFile: source.SourceFile,
		LicenseID: "MIT", Category: "permissive", PackageCount: 1, Cluster: source.Cluster,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := c.InsertStoredDocument(ctx, &models.StoredDocument{
		StoredAt: now, SBOMID: sourceID, Cluster: source.Cluster, SourceFile: source.SourceFile,
		StorageBackend: "fs", StorageRef: "fs://test/source", SHA256Hash: strings.Repeat("a", 64),
		SizeBytes: 1, ContentType: "application/json",
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.InsertVEXStatements(ctx, []models.VEXStatement{{
		IngestedAt: now, VEXID: uuid.New(), DocumentID: "test-vex", SourceFile: "test.vex.json",
		SBOMID: sourceID.String(), ProductPURL: "pkg:generic/root@1", VulnID: "GHSA-test-0000",
		Status: models.VEXStatusNotAffected, VEXTimestamp: now, Cluster: source.Cluster,
	}}); err != nil {
		t.Fatal(err)
	}

	ref := ImageSBOMRef{SBOMID: sourceID}
	id, err := c.CloneImageSBOM(ctx, ref, digest, "registry.example/target", "", "", "target-cluster", "team", "app", "", "ci", []string{"fleet"})
	if err != nil {
		t.Fatalf("CloneImageSBOM: %v", err)
	}
	if id != targetID.String() {
		t.Fatalf("clone ID = %s, want deterministic %s", id, targetID)
	}
	if err := c.Conn.Exec(ctx, "ALTER TABLE sbom_packages DELETE WHERE sbom_id = ? SETTINGS mutations_sync = 1", targetID); err != nil {
		t.Fatalf("remove cloned package row for retry check: %v", err)
	}
	retryID, err := c.CloneImageSBOM(ctx, ref, digest, "registry.example/target", "", "", "target-cluster", "team", "app", "", "ci", []string{"fleet"})
	if err != nil {
		t.Fatalf("CloneImageSBOM retry: %v", err)
	}
	if retryID != id {
		t.Fatalf("retry ID = %s, want %s", retryID, id)
	}

	for _, table := range []string{"sbom_packages", "vulnerabilities", "license_compliance", "document_store", "vex_statements", "sboms"} {
		var count uint64
		if err := c.Conn.QueryRow(ctx, "SELECT count() FROM "+table+" FINAL WHERE sbom_id = ?", targetID).Scan(&count); err != nil {
			t.Fatalf("count cloned %s: %v", table, err)
		}
		if count != 1 {
			t.Errorf("cloned %s rows = %d, want 1", table, count)
		}
	}
	var imageRef, cluster, origin string
	if err := c.Conn.QueryRow(ctx, "SELECT image_ref, cluster, origin FROM sboms FINAL WHERE sbom_id = ?", targetID).Scan(&imageRef, &cluster, &origin); err != nil {
		t.Fatal(err)
	}
	if imageRef != "registry.example/target" || cluster != "target-cluster" || origin != "ci" {
		t.Errorf("clone identity = %q / %q / %q", imageRef, cluster, origin)
	}
	detail, err := c.QueryImage(ctx, digest, 1, 10)
	if err != nil {
		t.Fatalf("QueryImage: %v", err)
	}
	found := false
	for _, item := range detail.SBOMs {
		if item.SBOMID == id && item.Origin != "ci" {
			t.Errorf("image detail origin = %q, want ci", item.Origin)
		}
		found = found || item.SBOMID == id
	}
	if !found {
		t.Errorf("QueryImage omitted cloned SBOM %s", id)
	}
}
