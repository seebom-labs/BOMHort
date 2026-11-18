package clickhouse

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/projectgroup"
)

// Semantic test for the parent grouping read path: signals → Resolve →
// grouped listing with counts de-duplicated across the whole group.
//
// Fixture: a parent project and a subproject in the same GitHub org, with
// folder-style names that do not match (fxp-<sfx> vs fxsub-<sfx>/one), plus an
// unrelated project. The subproject has two versions. libcurl ships in the
// parent and in both subproject versions and carries the same CVE everywhere.
// Skipped without CLICKHOUSE_HOST like the other query tests.

type groupFixture struct {
	parent, child, orphan string
	ids                   []string
}

func insertGroupFixture(t *testing.T, c *Client) groupFixture {
	t.Helper()
	ctx := context.Background()
	sfx := uuid.New().String()[:8]
	f := groupFixture{
		parent: "fxp-" + sfx,
		child:  "fxsub-" + sfx + "/one",
		orphan: "fxorphan-" + sfx,
	}
	org := "fxorg-" + sfx
	now := time.Now().UTC().Truncate(time.Second)

	sbom := func(project, version, repo string, pkgs []string, cve bool, at time.Time) {
		id := uuid.New().String()
		f.ids = append(f.ids, id)
		hash := (id + sfx + "0000000000000000000000000000000000000000000000000000000000000000")[:64]
		if err := c.Conn.Exec(ctx, `
			INSERT INTO sboms (ingested_at, sbom_id, source_file, spdx_version, document_name,
				document_namespace, sha256_hash, creation_date, creator_tools,
				cluster, namespace, project, source_repo, source_ref, document_version, tags,
				parent, root_purl, supplier)
			VALUES (?, ?, ?, 'SPDX-2.3', ?, '', ?, ?, [], '', '', ?, ?, '', ?, [], '', '', '')`,
			at, id, "fixtures/"+project+"/"+version+".spdx.json", project+" "+version,
			hash, at, project, repo, version); err != nil {
			t.Fatalf("insert sbom fixture: %v", err)
		}
		ids := make([]string, len(pkgs))
		names := make([]string, len(pkgs))
		vers := make([]string, len(pkgs))
		purls := make([]string, len(pkgs))
		lics := make([]string, len(pkgs))
		for i, p := range pkgs {
			ids[i], names[i], vers[i], purls[i], lics[i] = fmt.Sprintf("SPDXRef-%d", i), p, "1.0", "pkg:generic/"+p+"@1.0", "MIT"
		}
		if err := c.Conn.Exec(ctx, `
			INSERT INTO sbom_packages (ingested_at, sbom_id, source_file, package_spdx_ids,
				package_names, package_versions, package_purls, package_licenses,
				rel_source_indices, rel_target_indices, rel_types, cluster, namespace, project)
			VALUES (?, ?, '', ?, ?, ?, ?, ?, [], [], [], '', '', '')`,
			now, id, ids, names, vers, purls, lics); err != nil {
			t.Fatalf("insert packages fixture: %v", err)
		}
		if cve {
			if err := c.Conn.Exec(ctx, `
				INSERT INTO vulnerabilities (discovered_at, sbom_id, source_file, purl, vuln_id,
					severity, summary, affected_versions, fixed_version, osv_json, aliases,
					cluster, namespace, project)
				VALUES (?, ?, '', 'pkg:generic/libcurl@1.0', 'CVE-2024-9999', 'HIGH', 'fixture', [], '', '{}', [], '', '', '')`,
				now, id); err != nil {
				t.Fatalf("insert vulnerability fixture: %v", err)
			}
		}
	}

	sbom(f.parent, "2.0.0", "https://github.com/"+org+"/core", []string{"libcurl"}, true, now.Add(-3*time.Hour))
	sbom(f.child, "1.0.0", "https://github.com/"+org+"/one", []string{"libcurl", "zlib"}, true, now.Add(-2*time.Hour))
	sbom(f.child, "1.1.0", "https://github.com/"+org+"/one", []string{"libcurl", "zlib", "openssl"}, true, now.Add(-1*time.Hour))
	sbom(f.orphan, "0.1.0", "https://github.com/elsewhere-"+sfx+"/x", []string{"libcurl"}, true, now)

	t.Cleanup(func() {
		for _, table := range []string{"sboms", "sbom_packages", "vulnerabilities"} {
			_ = c.Conn.Exec(ctx,
				fmt.Sprintf("ALTER TABLE %s DELETE WHERE sbom_id IN (?) SETTINGS mutations_sync = 1", table), f.ids)
		}
	})
	return f
}

func TestProjectGroupsResolveAndDeduplicate(t *testing.T) {
	c := testClient(t)
	f := insertGroupFixture(t, c)
	ctx := context.Background()

	signals, err := c.QueryProjectSignals(ctx)
	if err != nil {
		t.Fatalf("QueryProjectSignals: %v", err)
	}
	var childSignals projectgroup.Signals
	for _, s := range signals {
		if s.Project == f.child {
			childSignals = s
		}
	}
	if childSignals.SourceRepo == "" || childSignals.DocumentName != f.child+" 1.1.0" {
		t.Errorf("child signals = %+v, want its repo and the newest document name", childSignals)
	}

	assignments := projectgroup.Resolve(signals, nil)
	if a := assignments[f.child]; a.Parent != f.parent || a.Source != projectgroup.SourceRepo {
		t.Fatalf("child assignment = %+v, want %s via repo", a, f.parent)
	}
	if _, ok := assignments[f.orphan]; ok {
		t.Errorf("orphan must stay standalone: %+v", assignments[f.orphan])
	}

	// Searching for the child finds its group.
	resp, err := c.QueryProjectGroups(ctx, assignments, 1, 10, f.child, "", "")
	if err != nil {
		t.Fatalf("QueryProjectGroups: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("want exactly the parent's group, got %d: %+v", len(resp.Data), resp.Data)
	}
	g := resp.Data[0]
	if g.Name != f.parent || !g.IsProject || g.ProjectCount != 2 {
		t.Errorf("group = %s (is_project=%v, projects=%d), want %s, true, 2", g.Name, g.IsProject, g.ProjectCount, f.parent)
	}
	if len(g.Members) != 2 || g.Members[0].ProjectName != f.parent || g.Members[1].ProjectName != f.child {
		t.Errorf("members = %+v, want the parent first, then the child", g.Members)
	}
	if g.Members[1].Parent != f.parent || g.Members[1].ParentSource != "repo" {
		t.Errorf("child member parent = %q/%q", g.Members[1].Parent, g.Members[1].ParentSource)
	}
	if g.SBOMCount != 3 {
		t.Errorf("sbom_count = %d, want 3", g.SBOMCount)
	}
	// libcurl, zlib, openssl across the whole group — not 1+3=4.
	if g.PackageCount != 3 {
		t.Errorf("package_count = %d, want 3 (de-duplicated across members)", g.PackageCount)
	}
	// One (CVE, libcurl) pair across all four SBOMs of the group.
	if g.VulnCount != 1 {
		t.Errorf("vuln_count = %d, want 1 (de-duplicated across members)", g.VulnCount)
	}
	if g.Members[1].PackageCount != 3 || g.Members[0].PackageCount != 1 {
		t.Errorf("member package counts = %d/%d, want 1/3", g.Members[0].PackageCount, g.Members[1].PackageCount)
	}
	if len(g.Sources) != 1 || g.Sources[0] != "repo" || g.Owner == "" {
		t.Errorf("sources/owner = %v/%q, want [repo] and the org", g.Sources, g.Owner)
	}

	// The orphan is a group of one.
	resp, err = c.QueryProjectGroups(ctx, assignments, 1, 10, f.orphan, "", "")
	if err != nil {
		t.Fatalf("QueryProjectGroups(orphan): %v", err)
	}
	if len(resp.Data) != 1 || resp.Data[0].Name != f.orphan || resp.Data[0].ProjectCount != 1 || len(resp.Data[0].Sources) != 0 {
		t.Errorf("orphan group = %+v", resp.Data)
	}

	// Project detail: children of the parent, parent of the child.
	detail, err := c.QueryProjectDetail(ctx, f.parent)
	if err != nil {
		t.Fatalf("QueryProjectDetail: %v", err)
	}
	AnnotateProjectDetail(detail, assignments)
	if len(detail.Children) != 1 || detail.Children[0] != f.child || detail.Parent != "" {
		t.Errorf("parent detail children/parent = %v/%q", detail.Children, detail.Parent)
	}
}
