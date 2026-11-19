package clickhouse

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// TestSearchWildcardEscapeSeeded verifies that user-supplied search filters
// treat '_' and '%' as literal characters rather than ClickHouse ILIKE wildcards.
// If escapeLikePattern is omitted at query call sites, searching for "foo_bar"
// matches "foo-bar" as well.
//
// Skipped unless CLICKHOUSE_HOST is set. The name contains "Seeded" so CI's
// query-smoke job runs it against a live ClickHouse instance.
func TestSearchWildcardEscapeSeeded(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	prefix := "it_escape_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	pkgUnderscore := prefix + "_bar"
	pkgHyphen := prefix + "-bar"
	pkgPercent := prefix + "%pct"
	pkgOther := prefix + "Xpct"

	sbomID := uuid.New()
	if err := c.InsertSBOM(ctx, &models.SBOM{
		IngestedAt:   time.Now(),
		SBOMID:       sbomID,
		SourceFile:   "integration-test/search-escape.spdx.json",
		SPDXVersion:  "SPDX-2.3",
		DocumentName: prefix + "-doc",
		SHA256Hash:   uuid.NewString(),
		CreationDate: time.Now(),
	}); err != nil {
		t.Fatalf("InsertSBOM: %v", err)
	}

	if err := c.InsertSBOMPackages(ctx, &models.SBOMPackages{
		IngestedAt:      time.Now(),
		SBOMID:          sbomID,
		SourceFile:      "integration-test/search-escape.spdx.json",
		PackageSPDXIDs:  []string{"SPDXRef-1", "SPDXRef-2", "SPDXRef-3", "SPDXRef-4"},
		PackageNames:    []string{pkgUnderscore, pkgHyphen, pkgPercent, pkgOther},
		PackageVersions: []string{"1.0.0", "1.0.0", "1.0.0", "1.0.0"},
		PackagePURLs: []string{
			"pkg:generic/" + pkgUnderscore + "@1.0.0",
			"pkg:generic/" + pkgHyphen + "@1.0.0",
			"pkg:generic/" + pkgPercent + "@1.0.0",
			"pkg:generic/" + pkgOther + "@1.0.0",
		},
		PackageLicenses: []string{"MIT", "MIT", "MIT", "MIT"},
	}); err != nil {
		t.Fatalf("InsertSBOMPackages: %v", err)
	}

	// 1. Search with underscore: must match only pkgUnderscore, not pkgHyphen.
	res, err := c.QueryDependencySearch(ctx, pkgUnderscore, 1, 10)
	if err != nil {
		t.Fatalf("QueryDependencySearch(%q): %v", pkgUnderscore, err)
	}
	if res.TotalResults != 1 || len(res.Items) != 1 || res.Items[0].PackageName != pkgUnderscore {
		t.Fatalf("QueryDependencySearch(%q) total = %d, items = %+v; want exactly 1 match for %q",
			pkgUnderscore, res.TotalResults, res.Items, pkgUnderscore)
	}

	// 2. Search with percent: must match only pkgPercent, not pkgOther.
	res, err = c.QueryDependencySearch(ctx, pkgPercent, 1, 10)
	if err != nil {
		t.Fatalf("QueryDependencySearch(%q): %v", pkgPercent, err)
	}
	if res.TotalResults != 1 || len(res.Items) != 1 || res.Items[0].PackageName != pkgPercent {
		t.Fatalf("QueryDependencySearch(%q) total = %d, items = %+v; want exactly 1 match for %q",
			pkgPercent, res.TotalResults, res.Items, pkgPercent)
	}
}
