package clickhouse

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	gh "github.com/seebom-labs/bomhort/backend/internal/github"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// TestArchivedPackagesAndDependenciesSeeded runs the archived-repo views and
// the dependency tree against seeded data. TestQueriesExecute only proves the
// queries plan on an empty database — where QueryArchivedPackages returns
// before its purl scan, because no repo is archived — so the SQL that matters
// would otherwise never execute in CI.
//
// Writes to sboms, sbom_packages and github_repo_metadata under random owner
// names, so run it only against a disposable database. Skipped unless
// CLICKHOUSE_HOST is set.
func TestArchivedPackagesAndDependenciesSeeded(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	owner := "bomhort-it-" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	direct := owner + "/archived"
	gopkgIn := owner + "/legacy"
	alive := owner + "/alive"

	if err := c.InsertGitHubRepoMetadata(ctx, []*gh.RepoMetadata{
		{Repo: direct, Archived: true, Stargazers: 42},
		{Repo: gopkgIn, Archived: true, Stargazers: 7},
		{Repo: alive, Archived: false, Stargazers: 1},
	}); err != nil {
		t.Fatalf("InsertGitHubRepoMetadata: %v", err)
	}

	sbomID := uuid.New()
	if err := c.InsertSBOM(ctx, &models.SBOM{
		IngestedAt:   time.Now(),
		SBOMID:       sbomID,
		SourceFile:   "integration-test/archived.spdx.json",
		SPDXVersion:  "SPDX-2.3",
		DocumentName: owner + "-project",
		SHA256Hash:   uuid.NewString(),
		CreationDate: time.Now(),
	}); err != nil {
		t.Fatalf("InsertSBOM: %v", err)
	}

	// Before the packages exist the SBOM is known but has no tree: that is
	// an empty result, not a failure (the mid-ingest window).
	nodes, err := c.QuerySBOMDependencies(ctx, sbomID.String())
	if err != nil || nodes == nil || len(nodes) != 0 {
		t.Fatalf("dependencies before packages = %v, %v; want empty slice, nil", nodes, err)
	}
	if _, err := c.QuerySBOMDependencies(ctx, uuid.NewString()); !errors.Is(err, ErrSBOMNotFound) {
		t.Fatalf("dependencies for unknown id: err = %v, want ErrSBOMNotFound", err)
	}

	names := []string{"root", "direct-sub", "via-gopkg-in", "not-archived", "npm"}
	purls := []string{
		"",
		// Mixed case and a subpath/version: cleaned and lowercased before mapping.
		"pkg:golang/github.com/" + strings.ToUpper(owner[:1]) + owner[1:] + "/archived/sub/pkg@v1.2.3",
		// gopkg.in/user/pkg.vN → github.com/user/pkg: only the Go mapping knows it.
		"pkg:golang/gopkg.in/" + owner + "/legacy.v2@v2.0.0",
		"pkg:golang/github.com/" + owner + "/alive@v0.1.0",
		"pkg:npm/" + owner + "@1.0.0",
	}
	if err := c.InsertSBOMPackages(ctx, &models.SBOMPackages{
		IngestedAt:       time.Now(),
		SBOMID:           sbomID,
		SourceFile:       "integration-test/archived.spdx.json",
		PackageSPDXIDs:   []string{"SPDXRef-0", "SPDXRef-1", "SPDXRef-2", "SPDXRef-3", "SPDXRef-4"},
		PackageNames:     names,
		PackageVersions:  []string{"1", "1.2.3", "2.0.0", "0.1.0", "1.0.0"},
		PackagePURLs:     purls,
		PackageLicenses:  []string{"MIT", "MIT", "MIT", "MIT", "MIT"},
		RelSourceIndices: []uint32{0, 0, 0, 0},
		RelTargetIndices: []uint32{1, 2, 3, 4},
		RelTypes:         []string{"DEPENDS_ON", "DEPENDS_ON", "DEPENDS_ON", "DEPENDS_ON"},
		PackageDepths:    []uint16{0, 1, 1, 1, 1},
	}); err != nil {
		t.Fatalf("InsertSBOMPackages: %v", err)
	}

	if nodes, err = c.QuerySBOMDependencies(ctx, sbomID.String()); err != nil || len(nodes) != len(names) {
		t.Fatalf("dependencies after packages = %d nodes, %v; want %d", len(nodes), err, len(names))
	}

	all, err := c.QueryArchivedPackages(ctx, "")
	if err != nil {
		t.Fatalf("QueryArchivedPackages: %v", err)
	}
	got := map[string]ArchivedPackageInfo{}
	for _, p := range all {
		if p.SBOMID == sbomID.String() {
			got[p.PackageName] = p
		}
	}
	if len(got) != 2 {
		t.Fatalf("archived packages for the SBOM = %+v, want direct-sub and via-gopkg-in", got)
	}
	// Scoped to the SBOM: the same two rows and nothing from other SBOMs.
	scoped, err := c.QueryArchivedPackages(ctx, sbomID.String())
	if err != nil {
		t.Fatalf("QueryArchivedPackages(sbom): %v", err)
	}
	if len(scoped) != 2 || scoped[0].SBOMID != sbomID.String() || scoped[1].SBOMID != sbomID.String() {
		t.Fatalf("scoped archived packages = %+v, want the 2 rows of %s", scoped, sbomID)
	}
	if other, err := c.QueryArchivedPackages(ctx, uuid.NewString()); err != nil || len(other) != 0 {
		t.Fatalf("archived packages for unknown SBOM = %v, %v; want empty", other, err)
	}
	if p := got["direct-sub"]; p.Repo != direct || p.Stars != 42 || p.ProjectName != owner+"-project" || p.PackagePURL != purls[1] {
		t.Errorf("direct-sub = %+v", p)
	}
	if p := got["via-gopkg-in"]; p.Repo != gopkgIn || p.Stars != 7 {
		t.Errorf("via-gopkg-in = %+v", p)
	}

	// Grouped view: both seeded repos present, each with exactly this SBOM
	// once, even though "direct" is matched via a purl with a subpath.
	grouped, err := c.QueryArchivedRepos(ctx, 1, 500)
	if err != nil {
		t.Fatalf("QueryArchivedRepos: %v", err)
	}
	if grouped.Total < 2 || grouped.Page != 1 || grouped.PageSize != 500 {
		t.Fatalf("QueryArchivedRepos meta = total %d page %d size %d", grouped.Total, grouped.Page, grouped.PageSize)
	}
	found := 0
	for _, g := range grouped.Data {
		if g.Repo != direct && g.Repo != gopkgIn {
			continue
		}
		found++
		n := 0
		for _, sb := range g.SBOMs {
			if sb.SBOMID == sbomID.String() {
				n++
				if sb.ProjectName != owner+"-project" {
					t.Errorf("%s sbom = %+v", g.Repo, sb)
				}
			}
		}
		if n != 1 {
			t.Errorf("%s lists the SBOM %d times, want once: %+v", g.Repo, n, g.SBOMs)
		}
	}
	if found != 2 {
		t.Errorf("grouped repos found = %d, want direct and gopkg-in", found)
	}
	if empty, err := c.QueryArchivedRepos(ctx, grouped.Total+1, 500); err != nil || len(empty.Data) != 0 || empty.Total != grouped.Total {
		t.Fatalf("page past the end = %+v, %v; want empty data, same total", empty, err)
	}

	inUse, err := c.QueryArchivedReposInUse(ctx)
	if err != nil {
		t.Fatalf("QueryArchivedReposInUse: %v", err)
	}
	if inUse < 2 {
		t.Errorf("QueryArchivedReposInUse = %d, want at least the 2 seeded repos", inUse)
	}
}
