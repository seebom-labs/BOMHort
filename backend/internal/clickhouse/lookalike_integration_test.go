package clickhouse

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// TestLookalikeColdCacheVisibleInTree verifies that when an SBOM is ingested
// with a cold cache (empty lookalike_of in sbom_packages), the subsequent
// population of lookalike_cache makes the lookalike visible when querying the
// dependency tree (#531).
func TestLookalikeColdCacheVisibleInTree(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sbomID := uuid.New()
	if err := c.InsertSBOM(ctx, &models.SBOM{
		IngestedAt:   time.Now(),
		SBOMID:       sbomID,
		SourceFile:   "cold-cache-test.spdx.json",
		SPDXVersion:  "SPDX-2.3",
		DocumentName: "cold-cache-project",
		SHA256Hash:   uuid.NewString(),
		CreationDate: time.Now(),
	}); err != nil {
		t.Fatalf("InsertSBOM: %v", err)
	}

	// Ingest SBOM packages with empty LookalikeOf (cold cache).
	pkgName := "crossenv-" + uuid.NewString()[:8]
	purl := "pkg:npm/" + pkgName + "@1.0.0"
	if err := c.InsertSBOMPackages(ctx, &models.SBOMPackages{
		IngestedAt:       time.Now(),
		SBOMID:           sbomID,
		SourceFile:       "cold-cache-test.spdx.json",
		PackageSPDXIDs:   []string{"SPDXRef-1"},
		PackageNames:     []string{pkgName},
		PackageVersions:  []string{"1.0.0"},
		PackagePURLs:     []string{purl},
		PackageLicenses:  []string{"MIT"},
		RelSourceIndices: []uint32{},
		RelTargetIndices: []uint32{},
		RelTypes:         []string{},
		PackageDepths:    []uint16{0},
		LookalikeOf:      []string{""}, // Empty on cold ingest
	}); err != nil {
		t.Fatalf("InsertSBOMPackages: %v", err)
	}

	// 1. Before cache is populated: tree node has no lookalikes.
	nodes, err := c.QuerySBOMDependencies(ctx, sbomID.String())
	if err != nil {
		t.Fatalf("QuerySBOMDependencies: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if len(nodes[0].LookalikeOf) != 0 {
		t.Fatalf("expected empty LookalikeOf on cold cache, got %v", nodes[0].LookalikeOf)
	}

	// 2. Background lookup completes and writes to lookalike_cache.
	wantLookalikes := []string{"cross-env"}
	if err := c.InsertLookalikeCache(ctx, map[string][]string{
		"npm:" + pkgName: wantLookalikes,
	}); err != nil {
		t.Fatalf("InsertLookalikeCache: %v", err)
	}

	// 3. Querying the dependency tree now reads from cache and shows the lookalike.
	nodesAfter, err := c.QuerySBOMDependencies(ctx, sbomID.String())
	if err != nil {
		t.Fatalf("QuerySBOMDependencies after cache: %v", err)
	}
	if len(nodesAfter) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodesAfter))
	}
	if !reflect.DeepEqual(nodesAfter[0].LookalikeOf, wantLookalikes) {
		t.Fatalf("LookalikeOf in tree = %v, want %v", nodesAfter[0].LookalikeOf, wantLookalikes)
	}
}

// TestPackageDetailEcosystemAmbiguity verifies that querying package detail
// with an ecosystem returns the correct candidate, and when omitted without
// ambiguity returns the candidate, but avoids returning an arbitrary candidate
// if multiple ecosystems exist for that name (#531).
func TestPackageDetailEcosystemAmbiguity(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pkgName := "ambig-" + uuid.NewString()[:8]
	npmLookalikes := []string{"npm-target"}
	pypiLookalikes := []string{"pypi-target"}

	// Insert into lookalike_cache for two different ecosystems.
	if err := c.InsertLookalikeCache(ctx, map[string][]string{
		"npm:" + pkgName:  npmLookalikes,
		"pypi:" + pkgName: pypiLookalikes,
	}); err != nil {
		t.Fatalf("InsertLookalikeCache: %v", err)
	}

	// 1. Specifying ecosystem returns exact ecosystem candidate.
	detailNPM, err := c.QueryPackageDetail(ctx, pkgName, "npm", 1, 10)
	if err != nil {
		t.Fatalf("QueryPackageDetail npm: %v", err)
	}
	if !reflect.DeepEqual(detailNPM.LookalikeOf, npmLookalikes) {
		t.Fatalf("npm lookalike = %v, want %v", detailNPM.LookalikeOf, npmLookalikes)
	}

	detailPyPI, err := c.QueryPackageDetail(ctx, pkgName, "pypi", 1, 10)
	if err != nil {
		t.Fatalf("QueryPackageDetail pypi: %v", err)
	}
	if !reflect.DeepEqual(detailPyPI.LookalikeOf, pypiLookalikes) {
		t.Fatalf("pypi lookalike = %v, want %v", detailPyPI.LookalikeOf, pypiLookalikes)
	}

	// 2. Omitting ecosystem when ambiguous returns NO candidate (avoids arbitrary match).
	detailAmbig, err := c.QueryPackageDetail(ctx, pkgName, "", 1, 10)
	if err != nil {
		t.Fatalf("QueryPackageDetail ambiguous: %v", err)
	}
	if len(detailAmbig.LookalikeOf) != 0 {
		t.Fatalf("expected empty lookalikes for ambiguous package, got %v", detailAmbig.LookalikeOf)
	}

	// 3. Unambiguous package without ecosystem returns its candidate.
	unambigPkg := "unambig-" + uuid.NewString()[:8]
	unambigLookalikes := []string{"unambig-target"}
	if err := c.InsertLookalikeCache(ctx, map[string][]string{
		"npm:" + unambigPkg: unambigLookalikes,
	}); err != nil {
		t.Fatalf("InsertLookalikeCache: %v", err)
	}

	detailUnambig, err := c.QueryPackageDetail(ctx, unambigPkg, "", 1, 10)
	if err != nil {
		t.Fatalf("QueryPackageDetail unambig: %v", err)
	}
	if !reflect.DeepEqual(detailUnambig.LookalikeOf, unambigLookalikes) {
		t.Fatalf("unambig lookalike = %v, want %v", detailUnambig.LookalikeOf, unambigLookalikes)
	}
}

