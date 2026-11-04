package main

import (
	"testing"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// testJob is a job carrying all four ownership dimensions, so a test can tell
// "copied correctly" apart from "left at the zero value".
func testJob() models.IngestionJob {
	return models.IngestionJob{
		JobID:     uuid.New(),
		Cluster:   "prod-eu",
		Namespace: "payments",
		Project:   "payment-service",
		Origin:    "cluster-scan",
	}
}

func assertOwnership(t *testing.T, what, cluster, namespace, project, origin string) {
	t.Helper()
	if cluster != "prod-eu" {
		t.Errorf("%s: cluster = %q, want prod-eu", what, cluster)
	}
	if namespace != "payments" {
		t.Errorf("%s: namespace = %q, want payments", what, namespace)
	}
	if project != "payment-service" {
		t.Errorf("%s: project = %q, want payment-service", what, project)
	}
	if origin != "cluster-scan" {
		t.Errorf("%s: origin = %q, want cluster-scan", what, origin)
	}
}

func TestOwnershipOf(t *testing.T) {
	own := ownershipOf(testJob())
	assertOwnership(t, "ownershipOf", own.cluster, own.namespace, own.project, own.origin)
}

func TestOwnershipAppliesToEveryRowType(t *testing.T) {
	own := ownershipOf(testJob())

	t.Run("SBOM", func(t *testing.T) {
		var m models.SBOM
		own.applySBOM(&m)
		assertOwnership(t, "SBOM", m.Cluster, m.Namespace, m.Project, m.Origin)
	})

	t.Run("SBOMPackages", func(t *testing.T) {
		var m models.SBOMPackages
		own.applyPackages(&m)
		assertOwnership(t, "SBOMPackages", m.Cluster, m.Namespace, m.Project, m.Origin)
	})

	t.Run("Vulnerability", func(t *testing.T) {
		var m models.Vulnerability
		own.applyVulnerability(&m)
		assertOwnership(t, "Vulnerability", m.Cluster, m.Namespace, m.Project, m.Origin)
	})

	t.Run("LicenseCompliance", func(t *testing.T) {
		var m models.LicenseCompliance
		own.applyLicenseCompliance(&m)
		assertOwnership(t, "LicenseCompliance", m.Cluster, m.Namespace, m.Project, m.Origin)
	})

	t.Run("StoredDocument", func(t *testing.T) {
		var m models.StoredDocument
		own.applyStoredDocument(&m)
		assertOwnership(t, "StoredDocument", m.Cluster, m.Namespace, m.Project, m.Origin)
	})

	t.Run("VEXStatement", func(t *testing.T) {
		var m models.VEXStatement
		own.applyVEXStatement(&m)
		assertOwnership(t, "VEXStatement", m.Cluster, m.Namespace, m.Project, m.Origin)
	})
}

// The VEX parser never sees the job, so every statement in a document has to
// be stamped. `cluster` was silently empty on all of them between #131 and
// #138 for exactly this reason.
func TestOwnershipAppliesToAllVEXStatements(t *testing.T) {
	own := ownershipOf(testJob())

	stmts := []models.VEXStatement{
		{VulnID: "CVE-2024-0001"},
		{VulnID: "CVE-2024-0002"},
		{VulnID: "CVE-2024-0003"},
	}
	own.applyVEXStatements(stmts)

	for i, s := range stmts {
		assertOwnership(t, "statement "+s.VulnID, s.Cluster, s.Namespace, s.Project, s.Origin)
		if stmts[i].VulnID == "" {
			t.Errorf("statement %d: stamping must not clobber other fields", i)
		}
	}
}

func TestOwnershipAppliesToEmptyVEXSlice(t *testing.T) {
	// A VEX document with no statements is valid; stamping must not panic.
	ownershipOf(testJob()).applyVEXStatements(nil)
	ownershipOf(testJob()).applyVEXStatements([]models.VEXStatement{})
}

// An unassigned job must produce unassigned rows — not stale values from
// whatever the struct happened to contain.
func TestOwnershipEmptyJobClearsFields(t *testing.T) {
	own := ownershipOf(models.IngestionJob{})

	m := models.SBOM{Cluster: "stale", Namespace: "stale", Project: "stale", Origin: "stale"}
	own.applySBOM(&m)

	if m.Cluster != "" || m.Namespace != "" || m.Project != "" || m.Origin != "" {
		t.Errorf("empty job left stale values: (%q, %q, %q, %q)", m.Cluster, m.Namespace, m.Project, m.Origin)
	}
}

// Stamping must only touch the three dimensions.
func TestOwnershipDoesNotClobberOtherFields(t *testing.T) {
	own := ownershipOf(testJob())

	id := uuid.New()
	m := models.SBOM{
		SBOMID:       id,
		DocumentName: "my-service",
		SourceFile:   "prod-eu/payments/payment-service/app.spdx.json",
		SHA256Hash:   "abc123",
	}
	own.applySBOM(&m)

	if m.SBOMID != id {
		t.Error("applySBOM overwrote SBOMID")
	}
	if m.DocumentName != "my-service" {
		t.Errorf("applySBOM overwrote DocumentName: %q", m.DocumentName)
	}
	if m.SourceFile != "prod-eu/payments/payment-service/app.spdx.json" {
		t.Errorf("applySBOM overwrote SourceFile: %q", m.SourceFile)
	}
	if m.SHA256Hash != "abc123" {
		t.Errorf("applySBOM overwrote SHA256Hash: %q", m.SHA256Hash)
	}
}

// DocumentNamespace (the SPDX document URI) and Namespace (the deployment
// namespace) are unrelated fields with confusingly similar names. Conflating
// them would corrupt the SBOM's identity.
func TestOwnershipDoesNotTouchSPDXDocumentNamespace(t *testing.T) {
	own := ownershipOf(testJob())

	m := models.SBOM{DocumentNamespace: "https://example.com/spdx/my-service"}
	own.applySBOM(&m)

	if m.DocumentNamespace != "https://example.com/spdx/my-service" {
		t.Errorf("applySBOM modified DocumentNamespace: %q", m.DocumentNamespace)
	}
	if m.Namespace != "payments" {
		t.Errorf("Namespace = %q, want payments", m.Namespace)
	}
}
