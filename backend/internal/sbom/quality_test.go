package sbom

import (
	"reflect"
	"testing"
	"time"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func TestEvaluateQuality_CompleteDocument(t *testing.T) {
	refTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	sbom := &models.SBOM{
		DocumentName:    "notification-hub",
		DocumentVersion: "2.3.0",
		Supplier:        "Organization: BOMHort Fleet Demo",
		CreationDate:    refTime.Add(-24 * time.Hour),
		CreatorTools:    []string{"Tool: syft-1.18.1"},
		SPDXVersion:     "SPDX-2.3",
	}
	pkgs := &models.SBOMPackages{
		PackageNames:    []string{"notification-hub", "gin", "protobuf"},
		PackageVersions: []string{"2.3.0", "v1.6.0", "v1.33.0"},
		PackagePURLs:    []string{"pkg:golang/github.com/example/notification-hub@v2.3.0", "pkg:golang/github.com/gin-gonic/gin@v1.6.0", "pkg:golang/google.golang.org/protobuf@v1.33.0"},
		PackageLicenses: []string{"Apache-2.0", "MIT", "BSD-3-Clause"},
		RelTypes:        []string{"DEPENDS_ON", "DEPENDS_ON"},
		RootIndices:     []uint32{0},
	}

	score, flags := EvaluateQualityAt(sbom, pkgs, refTime)
	if score != 100 {
		t.Fatalf("expected 100, got %d (flags: %v)", score, flags)
	}
	if len(flags) != 0 {
		t.Fatalf("expected 0 flags, got %v", flags)
	}
}

func TestEvaluateQuality_FlatList(t *testing.T) {
	refTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	sbom := &models.SBOM{
		DocumentName:    "flat-app",
		DocumentVersion: "1.0.0",
		Supplier:        "Acme Corp",
		CreationDate:    refTime.Add(-10 * 24 * time.Hour),
		CreatorTools:    []string{"Tool: flat-scanner"},
	}
	pkgs := &models.SBOMPackages{
		PackageNames:    []string{"flat-app", "dep-a", "dep-b"},
		PackageVersions: []string{"1.0.0", "1.2.0", "2.0.0"},
		PackagePURLs:    []string{"pkg:npm/flat-app@1.0.0", "pkg:npm/dep-a@1.2.0", "pkg:npm/dep-b@2.0.0"},
		PackageLicenses: []string{"MIT", "Apache-2.0", "BSD-3-Clause"},
		RelTypes:        nil, // Flat list: no relationships
		RootIndices:     []uint32{0},
	}

	score, flags := EvaluateQualityAt(sbom, pkgs, refTime)
	// Missing relationship graph loses 15 points: 100 - 15 = 85
	if score != 85 {
		t.Fatalf("expected score 85, got %d (flags: %v)", score, flags)
	}
	wantFlags := []string{FlagNoDependencyGraph}
	if !reflect.DeepEqual(flags, wantFlags) {
		t.Fatalf("got flags %v, want %v", flags, wantFlags)
	}
}

func TestEvaluateQuality_MissingSupplierAndPURLs(t *testing.T) {
	refTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	sbom := &models.SBOM{
		DocumentName:    "legacy-tool",
		DocumentVersion: "0.1.0",
		Supplier:        "", // missing supplier
		CreationDate:    refTime.Add(-5 * 24 * time.Hour),
		CreatorTools:    []string{"Tool: legacy-gen"},
	}
	pkgs := &models.SBOMPackages{
		PackageNames:    []string{"legacy-tool", "dep1"},
		PackageVersions: []string{"0.1.0", "1.0.0"},
		PackagePURLs:    []string{"", ""}, // 0 PURLs
		PackageLicenses: []string{"MIT", "MIT"},
		RelTypes:        []string{"DEPENDS_ON"},
		RootIndices:     []uint32{0},
	}

	score, flags := EvaluateQualityAt(sbom, pkgs, refTime)
	// Loses supplier (10) and PURLs (15): 100 - 25 = 75
	if score != 75 {
		t.Fatalf("expected score 75, got %d (flags: %v)", score, flags)
	}
	wantFlags := []string{FlagMissingSupplier, FlagNoPURLs}
	if !reflect.DeepEqual(flags, wantFlags) {
		t.Fatalf("got flags %v, want %v", flags, wantFlags)
	}
}

func TestEvaluateQuality_NoLicenses(t *testing.T) {
	refTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	sbom := &models.SBOM{
		DocumentName:    "nolic-app",
		DocumentVersion: "1.0.0",
		Supplier:        "Acme",
		CreationDate:    refTime.Add(-10 * 24 * time.Hour),
		CreatorTools:    []string{"Tool: test"},
	}
	pkgs := &models.SBOMPackages{
		PackageNames:    []string{"nolic-app", "dep1"},
		PackageVersions: []string{"1.0.0", "1.0.0"},
		PackagePURLs:    []string{"pkg:npm/nolic-app@1.0.0", "pkg:npm/dep1@1.0.0"},
		PackageLicenses: []string{"NOASSERTION", "NONE"}, // 0 valid licenses
		RelTypes:        []string{"DEPENDS_ON"},
		RootIndices:     []uint32{0},
	}

	score, flags := EvaluateQualityAt(sbom, pkgs, refTime)
	// Loses license coverage (15): 100 - 15 = 85
	if score != 85 {
		t.Fatalf("expected score 85, got %d (flags: %v)", score, flags)
	}
	wantFlags := []string{FlagNoLicenses}
	if !reflect.DeepEqual(flags, wantFlags) {
		t.Fatalf("got flags %v, want %v", flags, wantFlags)
	}
}

func TestEvaluateQuality_TimestampFlags(t *testing.T) {
	refTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

	// 1. Missing timestamp
	s1 := &models.SBOM{DocumentName: "app", DocumentVersion: "1.0", Supplier: "A", CreatorTools: []string{"t"}}
	p1 := &models.SBOMPackages{PackageNames: []string{"app"}, PackageVersions: []string{"1.0"}, PackagePURLs: []string{"pkg:npm/app@1.0"}, PackageLicenses: []string{"MIT"}, RootIndices: []uint32{0}}
	_, f1 := EvaluateQualityAt(s1, p1, refTime)
	foundMissing := false
	for _, f := range f1 {
		if f == FlagMissingTimestamp {
			foundMissing = true
		}
	}
	if !foundMissing {
		t.Fatalf("expected FlagMissingTimestamp in %v", f1)
	}

	// 2. Future timestamp
	s2 := &models.SBOM{DocumentName: "app", DocumentVersion: "1.0", Supplier: "A", CreatorTools: []string{"t"}, CreationDate: refTime.Add(48 * time.Hour)}
	_, f2 := EvaluateQualityAt(s2, p1, refTime)
	foundFuture := false
	for _, f := range f2 {
		if f == FlagFutureTimestamp {
			foundFuture = true
		}
	}
	if !foundFuture {
		t.Fatalf("expected FlagFutureTimestamp in %v", f2)
	}

	// 3. Stale timestamp (> 2 years old)
	s3 := &models.SBOM{DocumentName: "app", DocumentVersion: "1.0", Supplier: "A", CreatorTools: []string{"t"}, CreationDate: refTime.Add(-800 * 24 * time.Hour)}
	_, f3 := EvaluateQualityAt(s3, p1, refTime)
	foundStale := false
	for _, f := range f3 {
		if f == FlagStaleDocument {
			foundStale = true
		}
	}
	if !foundStale {
		t.Fatalf("expected FlagStaleDocument in %v", f3)
	}
}

func TestEvaluateQuality_NoRootComponent(t *testing.T) {
	refTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	// DocumentName is present, but no root component is designated in RootIndices, DirectIndices, or RootPURL.
	sbom := &models.SBOM{
		DocumentName:    "unrooted-app",
		DocumentVersion: "1.0.0",
		Supplier:        "Acme",
		CreationDate:    refTime.Add(-24 * time.Hour),
		CreatorTools:    []string{"Tool: test"},
		SPDXVersion:     "SPDX-2.3",
	}
	pkgs := &models.SBOMPackages{
		PackageNames:    []string{"pkg-a", "pkg-b"},
		PackageVersions: []string{"1.0.0", "2.0.0"},
		PackagePURLs:    []string{"pkg:npm/pkg-a@1.0.0", "pkg:npm/pkg-b@2.0.0"},
		PackageLicenses: []string{"MIT", "Apache-2.0"},
		RelTypes:        []string{"DEPENDS_ON"},
		RootIndices:     nil, // No root component designated
	}

	score, flags := EvaluateQualityAt(sbom, pkgs, refTime)
	// Loses root component (5 points): 100 - 5 = 95
	if score != 95 {
		t.Fatalf("expected score 95, got %d (flags: %v)", score, flags)
	}
	foundNoRoot := false
	for _, f := range flags {
		if f == FlagNoRootComponent {
			foundNoRoot = true
			break
		}
	}
	if !foundNoRoot {
		t.Fatalf("expected FlagNoRootComponent in %v", flags)
	}
}
