package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Semantic tests for the project read model (#398). Unlike TestQueriesExecute
// these assert *numbers*, so they need fixtures: a project with two versions
// that share most of their components and findings, and a parent/child pair
// expressed through tags.
//
// Fixture names carry a random suffix so the test is safe against a database
// that already holds real data (make dev / demo-fleet), and everything is
// deleted again in Cleanup. Skipped without CLICKHOUSE_HOST like the others.

type projectFixture struct {
	parent string // project with its own SBOM, also used as a tag on the child
	child  string // sub-project: two versions, tagged with parent
	orphan string // unrelated project, to prove filters scope correctly

	childV1, childV2, parentSBOM, orphanSBOM string
}

func insertProjectFixture(t *testing.T, c *Client) projectFixture {
	t.Helper()
	ctx := context.Background()
	suffix := uuid.New().String()[:8]
	f := projectFixture{
		parent:     "fx-parent-" + suffix,
		child:      "fx-child-" + suffix,
		orphan:     "fx-orphan-" + suffix,
		childV1:    uuid.New().String(),
		childV2:    uuid.New().String(),
		parentSBOM: uuid.New().String(),
		orphanSBOM: uuid.New().String(),
	}
	now := time.Now().UTC().Truncate(time.Second)
	hash := func(seed string) string {
		// FixedString(64): any 64 ascii bytes will do; make it unique per row.
		s := seed + suffix
		for len(s) < 64 {
			s += "0"
		}
		return s[:64]
	}

	sbom := func(id, project, version, repo string, tags []string, at time.Time) {
		err := c.Conn.Exec(ctx, `
			INSERT INTO sboms (ingested_at, sbom_id, source_file, spdx_version, document_name,
				document_namespace, sha256_hash, creation_date, creator_tools,
				cluster, namespace, project, source_repo, source_ref, document_version, tags)
			VALUES (?, ?, ?, 'SPDX-2.3', ?, '', ?, ?, [], '', '', ?, ?, '', ?, ?)`,
			at, id, "fixtures/"+project+"/"+version+".spdx.json", project+" "+version,
			hash(id), at, project, repo, version, tags)
		if err != nil {
			t.Fatalf("insert sbom fixture: %v", err)
		}
	}
	pkgs := func(id string, names, versions, purls []string) {
		ids := make([]string, len(names))
		lics := make([]string, len(names))
		for i := range names {
			ids[i] = fmt.Sprintf("SPDXRef-%d", i)
			lics[i] = "MIT"
		}
		err := c.Conn.Exec(ctx, `
			INSERT INTO sbom_packages (ingested_at, sbom_id, source_file, package_spdx_ids,
				package_names, package_versions, package_purls, package_licenses,
				rel_source_indices, rel_target_indices, rel_types, cluster, namespace, project)
			VALUES (?, ?, '', ?, ?, ?, ?, ?, [], [], [], '', '', '')`,
			now, id, ids, names, versions, purls, lics)
		if err != nil {
			t.Fatalf("insert packages fixture: %v", err)
		}
	}
	vuln := func(id, purl, vulnID, severity string) {
		err := c.Conn.Exec(ctx, `
			INSERT INTO vulnerabilities (discovered_at, sbom_id, source_file, purl, vuln_id,
				severity, summary, affected_versions, fixed_version, osv_json, aliases,
				cluster, namespace, project)
			VALUES (?, ?, '', ?, ?, ?, 'fixture', [], '', '{}', [], '', '', '')`,
			now, id, purl, vulnID, severity)
		if err != nil {
			t.Fatalf("insert vulnerability fixture: %v", err)
		}
	}

	// Parent: one SBOM, no tags of its own.
	sbom(f.parentSBOM, f.parent, "2.0.0", "https://github.com/fx/parent", nil, now.Add(-3*time.Hour))
	pkgs(f.parentSBOM, []string{"parentlib"}, []string{"1.0"}, []string{"pkg:golang/fx/parentlib@1.0"})

	// Child v1 and v2 share libcurl and zlib; v2 adds openssl. Both are
	// tagged with the parent's name — the layout "tag/project" outcome.
	// v2 is newer, and it is the one that carries a source_repo.
	sbom(f.childV1, f.child, "1.0.0", "", []string{f.parent, "subprojects"}, now.Add(-2*time.Hour))
	pkgs(f.childV1,
		[]string{"libcurl", "zlib"},
		[]string{"7.0", "1.2"},
		[]string{"pkg:generic/libcurl@7.0", "pkg:generic/zlib@1.2"})
	sbom(f.childV2, f.child, "1.1.0", "https://github.com/fx/child", []string{f.parent, "subprojects"}, now.Add(-1*time.Hour))
	pkgs(f.childV2,
		[]string{"libcurl", "zlib", "openssl"},
		[]string{"7.0", "1.2", "3.0"},
		[]string{"pkg:generic/libcurl@7.0", "pkg:generic/zlib@1.2", "pkg:generic/openssl@3.0"})

	// The same CVE on libcurl in both versions (must count once); a second
	// CVE only in v2. Different severities across versions for CVE-A: the
	// project view must keep the higher one.
	vuln(f.childV1, "pkg:generic/libcurl@7.0", "CVE-2024-0001", "HIGH")
	vuln(f.childV2, "pkg:generic/libcurl@7.0", "CVE-2024-0001", "CRITICAL")
	vuln(f.childV2, "pkg:generic/openssl@3.0", "CVE-2024-0002", "MEDIUM")

	// Orphan: shares a component name with the child but must never leak in.
	sbom(f.orphanSBOM, f.orphan, "0.1.0", "", nil, now)
	pkgs(f.orphanSBOM, []string{"libcurl"}, []string{"7.0"}, []string{"pkg:generic/libcurl@7.0"})
	vuln(f.orphanSBOM, "pkg:generic/libcurl@7.0", "CVE-2024-0001", "HIGH")

	t.Cleanup(func() {
		ids := []string{f.childV1, f.childV2, f.parentSBOM, f.orphanSBOM}
		for _, table := range []string{"sboms", "sbom_packages", "vulnerabilities"} {
			_ = c.Conn.Exec(ctx,
				fmt.Sprintf("ALTER TABLE %s DELETE WHERE sbom_id IN (?) SETTINGS mutations_sync = 1", table), ids)
		}
	})
	return f
}

func TestProjectListDeduplicatesAcrossVersions(t *testing.T) {
	c := testClient(t)
	f := insertProjectFixture(t, c)
	ctx := context.Background()

	resp, err := c.QueryProjects(ctx, 1, 10, f.child, "")
	if err != nil {
		t.Fatalf("QueryProjects: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("expected exactly the child project, got %d rows: %+v", len(resp.Data), resp.Data)
	}
	p := resp.Data[0]

	if p.SBOMCount != 2 {
		t.Errorf("sbom_count = %d, want 2", p.SBOMCount)
	}
	// libcurl, zlib, openssl — not 2+3=5.
	if p.PackageCount != 3 {
		t.Errorf("package_count = %d, want 3 (distinct across versions; the old sum would be 5)", p.PackageCount)
	}
	// (CVE-0001, libcurl) once + (CVE-0002, openssl) — not 3 rows.
	if p.VulnCount != 2 {
		t.Errorf("vuln_count = %d, want 2 (distinct pairs; the old row count would be 3)", p.VulnCount)
	}
	if p.LatestSBOMID != f.childV2 {
		t.Errorf("latest_sbom_id = %s, want the newer version %s", p.LatestSBOMID, f.childV2)
	}
	if len(p.Tags) != 2 || p.Tags[0] != f.parent || p.Tags[1] != "subprojects" {
		t.Errorf("tags = %v, want [%s subprojects]", p.Tags, f.parent)
	}
}

func TestProjectDetailAggregatesAndResolvesHierarchy(t *testing.T) {
	c := testClient(t)
	f := insertProjectFixture(t, c)
	ctx := context.Background()

	// ── child ──
	d, err := c.QueryProjectDetail(ctx, f.child)
	if err != nil {
		t.Fatalf("QueryProjectDetail(child): %v", err)
	}
	if d.SBOMCount != 2 || d.PackageCount != 3 || d.VulnCount != 2 {
		t.Errorf("child counts = sboms %d pkgs %d vulns %d, want 2/3/2", d.SBOMCount, d.PackageCount, d.VulnCount)
	}
	// CVE-0001 was HIGH in v1 and CRITICAL in v2 → counted once, as CRITICAL.
	if d.CriticalVulns != 1 || d.HighVulns != 0 || d.MediumVulns != 1 {
		t.Errorf("severity = crit %d high %d med %d, want 1/0/1 (highest severity wins per pair)",
			d.CriticalVulns, d.HighVulns, d.MediumVulns)
	}
	if d.LatestVersion != "1.1.0" || d.LatestSBOMID != f.childV2 {
		t.Errorf("latest = %s/%s, want 1.1.0/%s", d.LatestVersion, d.LatestSBOMID, f.childV2)
	}
	if d.SourceRepo != "https://github.com/fx/child" {
		t.Errorf("source_repo = %q, want the one from v2 (v1 has none)", d.SourceRepo)
	}
	if len(d.Parents) != 1 || d.Parents[0] != f.parent {
		t.Errorf("parents = %v, want [%s] — the tag that is also a project", d.Parents, f.parent)
	}
	if d.RelatedProjectCount != 0 {
		t.Errorf("child related_project_count = %d, want 0 (nothing is tagged with the child's name)", d.RelatedProjectCount)
	}
	if len(d.Clusters) != 0 || len(d.Namespaces) != 0 {
		t.Errorf("catalogue fixture must have no clusters/namespaces, got %v / %v", d.Clusters, d.Namespaces)
	}

	// ── parent ──
	pd, err := c.QueryProjectDetail(ctx, f.parent)
	if err != nil {
		t.Fatalf("QueryProjectDetail(parent): %v", err)
	}
	if pd.RelatedProjectCount != 1 {
		t.Errorf("parent related_project_count = %d, want 1 (the child is tagged with the parent's name)", pd.RelatedProjectCount)
	}
	if len(pd.Parents) != 0 {
		t.Errorf("parent has no parents, got %v", pd.Parents)
	}
	if pd.PackageCount != 1 {
		t.Errorf("parent package_count = %d, want 1 — the parent's own view does not absorb its children", pd.PackageCount)
	}

	// ── unknown ──
	if _, err := c.QueryProjectDetail(ctx, "fx-nope-"+uuid.New().String()); !errors.Is(err, ErrSBOMNotFound) {
		t.Errorf("unknown project: err = %v, want ErrSBOMNotFound", err)
	}
}

func TestProjectVulnerabilitiesOneRowPerPair(t *testing.T) {
	c := testClient(t)
	f := insertProjectFixture(t, c)

	items, err := c.QueryProjectVulnerabilities(context.Background(), f.child, "")
	if err != nil {
		t.Fatalf("QueryProjectVulnerabilities: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 distinct (vuln_id, purl) rows, got %d: %+v", len(items), items)
	}
	// Sorted by severity: the CRITICAL libcurl pair first.
	first := items[0]
	if first.VulnID != "CVE-2024-0001" || first.Severity != "CRITICAL" {
		t.Errorf("first row = %s/%s, want CVE-2024-0001/CRITICAL", first.VulnID, first.Severity)
	}
	if first.AffectedSBOMs != 2 {
		t.Errorf("CVE-2024-0001 affected_sboms = %d, want 2 (present in both versions)", first.AffectedSBOMs)
	}
	if items[1].AffectedSBOMs != 1 {
		t.Errorf("CVE-2024-0002 affected_sboms = %d, want 1", items[1].AffectedSBOMs)
	}
	// The orphan's identical finding must not have leaked into the count.
	for _, it := range items {
		if it.AffectedSBOMs > 2 {
			t.Errorf("%s affected_sboms = %d > 2: another project's SBOM leaked into the scope", it.VulnID, it.AffectedSBOMs)
		}
	}
}

func TestProjectVulnerabilitiesPrefersEvidenceOverNewerSBOM(t *testing.T) {
	c := testClient(t)
	f := insertProjectFixture(t, c)
	evidenceAt := time.Now().UTC().Truncate(time.Second)
	if err := c.Conn.Exec(context.Background(), `
		ALTER TABLE vulnerabilities
		UPDATE reachability = 'reachable', evidence_source = 'govulncheck test',
			evidence_ref = 'older-sbom', evidence_at = ?
		WHERE sbom_id = ? AND vuln_id = 'CVE-2024-0001'
		SETTINGS mutations_sync = 1`, evidenceAt, f.childV1); err != nil {
		t.Fatalf("set evidence on older SBOM: %v", err)
	}

	items, err := c.QueryProjectVulnerabilities(context.Background(), f.child, "")
	if err != nil {
		t.Fatalf("QueryProjectVulnerabilities: %v", err)
	}
	if len(items) == 0 {
		t.Fatal("expected project vulnerability findings")
	}
	if items[0].Reachability != "reachable" || items[0].EvidenceSource != "govulncheck test" || items[0].EvidenceRef != "older-sbom" {
		t.Errorf("project evidence = %q/%q/%q, want reachable/govulncheck test/older-sbom",
			items[0].Reachability, items[0].EvidenceSource, items[0].EvidenceRef)
	}
}

func TestProjectPackagesDistinctWithReach(t *testing.T) {
	c := testClient(t)
	f := insertProjectFixture(t, c)
	ctx := context.Background()

	resp, err := c.QueryProjectPackages(ctx, f.child, 1, 50, "")
	if err != nil {
		t.Fatalf("QueryProjectPackages: %v", err)
	}
	if resp.Total != 3 || len(resp.Data) != 3 {
		t.Fatalf("expected 3 distinct components, got total=%d rows=%d", resp.Total, len(resp.Data))
	}
	byName := map[string]uint64{}
	vulnsByName := map[string]uint64{}
	for _, p := range resp.Data {
		byName[p.Name] = p.SBOMCount
		vulnsByName[p.Name] = p.VulnCount
	}
	if byName["libcurl"] != 2 || byName["zlib"] != 2 || byName["openssl"] != 1 {
		t.Errorf("sbom_count per component = %v, want libcurl:2 zlib:2 openssl:1", byName)
	}
	if vulnsByName["libcurl"] != 1 || vulnsByName["openssl"] != 1 || vulnsByName["zlib"] != 0 {
		t.Errorf("vuln_count per component = %v, want libcurl:1 openssl:1 zlib:0", vulnsByName)
	}
	// Most exposed first, then most widespread.
	if resp.Data[0].VulnCount == 0 {
		t.Errorf("first row should be a vulnerable component, got %+v", resp.Data[0])
	}

	// Search narrows within the project.
	s, err := c.QueryProjectPackages(ctx, f.child, 1, 50, "curl")
	if err != nil {
		t.Fatalf("QueryProjectPackages(search): %v", err)
	}
	if s.Total != 1 || s.Data[0].Name != "libcurl" {
		t.Errorf("search 'curl' = %+v, want exactly libcurl", s.Data)
	}
}

func TestSBOMListProjectFilterIsExact(t *testing.T) {
	c := testClient(t)
	f := insertProjectFixture(t, c)
	ctx := context.Background()

	// ?project= is exact identity; the orphan shares a component with the
	// child but is a different project and must not appear.
	resp, err := c.QuerySBOMs(ctx, 1, 50, "", f.child, 0)
	if err != nil {
		t.Fatalf("QuerySBOMs(project): %v", err)
	}
	if resp.Total != 2 {
		t.Fatalf("project filter total = %d, want 2", resp.Total)
	}
	for _, s := range resp.Data {
		if s.Project != f.child {
			t.Errorf("row %s has project %q, want %q", s.SBOMID, s.Project, f.child)
		}
	}

	// project + search compose.
	narrowed, err := c.QuerySBOMs(ctx, 1, 50, "1.1.0", f.child, 0)
	if err != nil {
		t.Fatalf("QuerySBOMs(project+search): %v", err)
	}
	if narrowed.Total != 1 || narrowed.Data[0].SBOMID != f.childV2 {
		t.Errorf("project+search = %d rows, want just v2", narrowed.Total)
	}

	// Sanity: the substring search alone is what the UI used to do, and it
	// is exactly the behaviour #398 complains about — the prefix "fx-" matches
	// all three fixture projects.
	loose, err := c.QuerySBOMs(ctx, 1, 50, "fx-", "", 0)
	if err != nil {
		t.Fatalf("QuerySBOMs(search): %v", err)
	}
	if loose.Total < 4 {
		t.Errorf("substring search 'fx-' total = %d, expected ≥ 4 (it is not an identity filter)", loose.Total)
	}
}

func TestTagsMarkParentProjects(t *testing.T) {
	c := testClient(t)
	f := insertProjectFixture(t, c)

	tags, err := c.QueryTags(context.Background())
	if err != nil {
		t.Fatalf("QueryTags: %v", err)
	}
	var sawParent, sawSubprojects bool
	for _, tg := range tags {
		switch tg.Tag {
		case f.parent:
			sawParent = true
			if !tg.IsProject {
				t.Errorf("tag %q is a project name and must have is_project=true", tg.Tag)
			}
			if tg.ProjectCount != 1 {
				t.Errorf("tag %q project_count = %d, want 1 (the child)", tg.Tag, tg.ProjectCount)
			}
		case "subprojects":
			sawSubprojects = true
			if tg.IsProject {
				t.Errorf("tag %q is not a project name and must have is_project=false", tg.Tag)
			}
		}
	}
	if !sawParent || !sawSubprojects {
		t.Errorf("expected both fixture tags in the listing, saw parent=%v subprojects=%v", sawParent, sawSubprojects)
	}
}

// TestProjectRowsUsePrimaryKey is the guard for #344-E: project-scoped stats
// must read only the selected projects' SBOMs from the large tables. Moving
// the project filter back to an outer WHERE of the JOIN would still return
// correct numbers — and silently scan the whole table again — so the
// assertion is on the plan, not on the result. The fixture is needed because
// ClickHouse skips index analysis entirely for an empty table.
func TestProjectRowsUsePrimaryKey(t *testing.T) {
	c := testClient(t)
	f := insertProjectFixture(t, c)
	ctx := context.Background()

	for _, table := range []string{"sbom_packages", "vulnerabilities"} {
		t.Run(table, func(t *testing.T) {
			rows, err := c.Conn.Query(ctx, "EXPLAIN indexes = 1 SELECT count() FROM "+
				projectRows("sbom_id", table, "s.project_name IN (?)"), []string{f.child})
			if err != nil {
				t.Fatalf("EXPLAIN: %v", err)
			}
			defer rows.Close()

			var plan strings.Builder
			reading := ""
			for rows.Next() {
				var line string
				if err := rows.Scan(&line); err != nil {
					t.Fatalf("scan: %v", err)
				}
				plan.WriteString(line + "\n")
				if strings.Contains(line, "ReadFromMergeTree (") {
					reading = line
				}
				if strings.HasSuffix(reading, "."+table+")") &&
					strings.Contains(line, "Condition:") && strings.Contains(line, "sbom_id in") {
					return
				}
			}
			t.Errorf("%s is not read through its sbom_id primary key:\n%s", table, plan.String())
		})
	}
}

// TestProjectBadgeStatsSeeded verifies project badge stats resolution:
//  1. Default (version="") resolves latest SBOM, ignoring resolved vulnerabilities from older versions.
//  2. Fully exempted copyleft packages (present in sbom_packages, with non_compliant_packages=[])
//     correctly evaluate to 0 violations.
//  3. Explicit version lookup resolves historical version stats.
func TestProjectBadgeStatsSeeded(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	suffix := uuid.New().String()[:8]
	projectName := "badge-seeded-" + suffix
	sbomV1 := uuid.New().String()
	sbomV2 := uuid.New().String()

	now := time.Now().UTC().Truncate(time.Second)
	hash := func(seed string) string {
		s := seed + suffix
		for len(s) < 64 {
			s += "0"
		}
		return s[:64]
	}

	// Insert v1 (older, 1 critical CVE)
	if err := c.Conn.Exec(ctx, `
		INSERT INTO sboms (ingested_at, sbom_id, source_file, spdx_version, document_name,
			document_namespace, sha256_hash, creation_date, creator_tools,
			cluster, namespace, project, source_repo, source_ref, document_version, tags)
		VALUES (?, ?, ?, 'SPDX-2.3', ?, '', ?, ?, [], '', '', ?, '', '', '1.0.0', [])`,
		now.Add(-2*time.Hour), sbomV1, "fixtures/"+projectName+"/1.0.0.spdx.json", projectName+" 1.0.0",
		hash(sbomV1), now.Add(-2*time.Hour), projectName,
	); err != nil {
		t.Fatalf("insert sbom v1: %v", err)
	}

	if err := c.Conn.Exec(ctx, `
		INSERT INTO sbom_packages (ingested_at, sbom_id, source_file, package_spdx_ids,
			package_names, package_versions, package_purls, package_licenses,
			rel_source_indices, rel_target_indices, rel_types, cluster, namespace, project)
		VALUES (?, ?, '', ['SPDXRef-1'], ['oldlib'], ['1.0'], ['pkg:generic/oldlib@1.0'], ['MIT'],
			[], [], [], '', '', '')`,
		now.Add(-2*time.Hour), sbomV1,
	); err != nil {
		t.Fatalf("insert packages v1: %v", err)
	}

	if err := c.Conn.Exec(ctx, `
		INSERT INTO vulnerabilities (discovered_at, sbom_id, source_file, purl, vuln_id,
			severity, summary, affected_versions, fixed_version, osv_json, aliases,
			cluster, namespace, project)
		VALUES (?, ?, '', 'pkg:generic/oldlib@1.0', 'CVE-2024-V1-CRIT',
			'CRITICAL', 'fixture', [], '', '{}', [], '', '', '')`,
		now.Add(-2*time.Hour), sbomV1,
	); err != nil {
		t.Fatalf("insert vuln v1: %v", err)
	}

	// Insert v2 (latest, zero CVEs, 1 copyleft package in sbom_packages that is fully exempted)
	if err := c.Conn.Exec(ctx, `
		INSERT INTO sboms (ingested_at, sbom_id, source_file, spdx_version, document_name,
			document_namespace, sha256_hash, creation_date, creator_tools,
			cluster, namespace, project, source_repo, source_ref, document_version, tags)
		VALUES (?, ?, ?, 'SPDX-2.3', ?, '', ?, ?, [], '', '', ?, '', '', '2.0.0', [])`,
		now.Add(-1*time.Hour), sbomV2, "fixtures/"+projectName+"/2.0.0.spdx.json", projectName+" 2.0.0",
		hash(sbomV2), now.Add(-1*time.Hour), projectName,
	); err != nil {
		t.Fatalf("insert sbom v2: %v", err)
	}

	// Crucial: add sbom_packages row with GPL-3.0-only to reproduce the step-2 refill case
	if err := c.Conn.Exec(ctx, `
		INSERT INTO sbom_packages (ingested_at, sbom_id, source_file, package_spdx_ids,
			package_names, package_versions, package_purls, package_licenses,
			rel_source_indices, rel_target_indices, rel_types, cluster, namespace, project)
		VALUES (?, ?, '', ['SPDXRef-2'], ['exempted-tool'], ['1.0'], ['pkg:generic/exempted-tool@1.0'], ['GPL-3.0-only'],
			[], [], [], '', '', '')`,
		now.Add(-1*time.Hour), sbomV2,
	); err != nil {
		t.Fatalf("insert packages v2: %v", err)
	}

	if err := c.Conn.Exec(ctx, `
		INSERT INTO license_compliance (checked_at, sbom_id, source_file, license_id, category,
			package_count, non_compliant_packages, exempted_packages, exemption_reason,
			cluster, namespace, project)
		VALUES (?, ?, '', 'GPL-3.0-only', 'copyleft', 1, [], ['pkg:generic/exempted-tool@1.0'], 'approved tool', '', '', '')`,
		now.Add(-1*time.Hour), sbomV2,
	); err != nil {
		t.Fatalf("insert license_compliance v2: %v", err)
	}

	t.Cleanup(func() {
		ids := []string{sbomV1, sbomV2}
		for _, table := range []string{"sboms", "sbom_packages", "vulnerabilities", "license_compliance"} {
			_ = c.Conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s DELETE WHERE sbom_id IN (?) SETTINGS mutations_sync = 1", table), ids)
		}
	})

	// 1. Latest version (default): 0 vulns, 0 violations
	latestStats, err := c.QueryProjectBadgeStats(ctx, projectName, "")
	if err != nil {
		t.Fatalf("QueryProjectBadgeStats (latest): %v", err)
	}
	if latestStats.CriticalVulns != 0 || latestStats.HighVulns != 0 || latestStats.MediumVulns != 0 || latestStats.LowVulns != 0 {
		t.Errorf("expected 0 vulnerabilities on latest version, got C=%d H=%d M=%d L=%d",
			latestStats.CriticalVulns, latestStats.HighVulns, latestStats.MediumVulns, latestStats.LowVulns)
	}
	if latestStats.Violations != 0 {
		t.Errorf("expected 0 license violations for fully exempted package, got %d", latestStats.Violations)
	}

	// 2. Historical version (1.0.0): 1 critical vuln
	v1Stats, err := c.QueryProjectBadgeStats(ctx, projectName, "1.0.0")
	if err != nil {
		t.Fatalf("QueryProjectBadgeStats (v1): %v", err)
	}
	if v1Stats.CriticalVulns != 1 {
		t.Errorf("expected 1 critical vuln for version 1.0.0, got %d", v1Stats.CriticalVulns)
	}
}
