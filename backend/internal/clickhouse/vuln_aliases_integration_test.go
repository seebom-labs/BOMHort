package clickhouse

// Integration tests for #412: a finding OSV stores as GO-… must be
// findable, displayable and VEX-matchable by its CVE and GHSA aliases.
// Skipped without CLICKHOUSE_HOST like the other query tests.

import (
	"context"
	"fmt"
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

type aliasFixture struct {
	sbomID, project, goID, cveID, ghsaID string
	cluster, namespace, tag              string
}

func insertAliasFixture(t *testing.T, c *Client) aliasFixture {
	t.Helper()
	ctx := context.Background()
	n := rand.Intn(900000) + 100000
	f := aliasFixture{
		sbomID:  uuid.New().String(),
		project: fmt.Sprintf("fx-alias-%d", n),
		goID:    fmt.Sprintf("GO-2099-%d", n),
		cveID:   fmt.Sprintf("CVE-2099-%d", n),
		ghsaID:  fmt.Sprintf("GHSA-fx%d-test", n),
		// Ownership on the SBOM only: the finding row stays empty, as on
		// refresher-written rows, so filters must read it from sboms.
		cluster:   fmt.Sprintf("fx-cl-%d", n),
		namespace: fmt.Sprintf("fx-ns-%d", n),
		tag:       fmt.Sprintf("fx-tag-%d", n),
	}
	now := time.Now().UTC().Truncate(time.Second)
	purl := fmt.Sprintf("pkg:golang/example.com/fx%d@v1.0.0", n)
	hash := fmt.Sprintf("%064d", n)

	exec := func(what, query string, args ...any) {
		if err := c.Conn.Exec(ctx, query, args...); err != nil {
			t.Fatalf("insert %s fixture: %v", what, err)
		}
	}
	exec("sbom", `
		INSERT INTO sboms (ingested_at, sbom_id, source_file, spdx_version, document_name,
			document_namespace, sha256_hash, creation_date, creator_tools,
			cluster, namespace, project, source_repo, source_ref, document_version, tags)
		VALUES (?, ?, ?, 'SPDX-2.3', ?, '', ?, ?, [], ?, ?, ?, '', '', '1.0.0', [?])`,
		now, f.sbomID, "fixtures/"+f.project+".spdx.json", f.project, hash, now, f.cluster, f.namespace, f.project, f.tag)
	exec("packages", `
		INSERT INTO sbom_packages (ingested_at, sbom_id, source_file, package_spdx_ids,
			package_names, package_versions, package_purls, package_licenses,
			rel_source_indices, rel_target_indices, rel_types, cluster, namespace, project)
		VALUES (?, ?, '', ['SPDXRef-0'], ['fxlib'], ['v1.0.0'], [?], ['MIT'], [], [], [], '', '', '')`,
		now, f.sbomID, purl)
	exec("vulnerability", `
		INSERT INTO vulnerabilities (discovered_at, sbom_id, source_file, purl, vuln_id,
			severity, summary, affected_versions, fixed_version, osv_json, aliases,
			cluster, namespace, project)
		VALUES (?, ?, '', ?, ?, 'HIGH', 'alias fixture', [], '', '{}', [?, ?], '', '', '')`,
		now, f.sbomID, purl, f.goID, f.ghsaID, f.cveID)
	// The VEX author used the CVE, not the id the finding is stored under.
	exec("vex", `
		INSERT INTO vex_statements (ingested_at, vex_id, document_id, source_file, product_purl,
			vuln_id, status, justification, vex_timestamp, sbom_id)
		VALUES (?, ?, 'fx-doc', 'fx.openvex.json', ?, ?, 'not_affected', 'vulnerable_code_not_in_execute_path', ?, ?)`,
		now, uuid.New().String(), purl, f.cveID, now, f.sbomID)

	t.Cleanup(func() {
		for _, table := range []string{"sboms", "sbom_packages", "vulnerabilities", "vex_statements"} {
			_ = c.Conn.Exec(ctx,
				fmt.Sprintf("ALTER TABLE %s DELETE WHERE toString(sbom_id) = ? SETTINGS mutations_sync = 1", table), f.sbomID)
		}
	})
	return f
}

func TestFindingsCarryCVEAndAliases(t *testing.T) {
	c := testClient(t)
	f := insertAliasFixture(t, c)
	ctx := context.Background()
	wantAliases := []string{f.cveID, f.ghsaID}
	slices.Sort(wantAliases)

	sbomVulns, err := c.QuerySBOMVulnerabilities(ctx, f.sbomID, "")
	if err != nil {
		t.Fatalf("QuerySBOMVulnerabilities: %v", err)
	}
	if len(sbomVulns) != 1 {
		t.Fatalf("want 1 finding, got %+v", sbomVulns)
	}
	v := sbomVulns[0]
	if v.VulnID != f.goID || v.CVEID != f.cveID || !slices.Equal(v.Aliases, wantAliases) {
		t.Errorf("sbom finding = vuln_id %s cve_id %s aliases %v; want %s / %s / %v",
			v.VulnID, v.CVEID, v.Aliases, f.goID, f.cveID, wantAliases)
	}
	if v.VEXStatus != "not_affected" {
		t.Errorf("VEX written against the CVE alias must still apply, got %q", v.VEXStatus)
	}

	projectVulns, err := c.QueryProjectVulnerabilities(ctx, f.project, "")
	if err != nil {
		t.Fatalf("QueryProjectVulnerabilities: %v", err)
	}
	if len(projectVulns) != 1 || projectVulns[0].CVEID != f.cveID || !slices.Equal(projectVulns[0].Aliases, wantAliases) {
		t.Errorf("project findings = %+v, want cve_id %s aliases %v", projectVulns, f.cveID, wantAliases)
	}

	all, err := c.QueryVulnerabilities(ctx, 1, 500, "", VulnFilter{})
	if err != nil {
		t.Fatalf("QueryVulnerabilities: %v", err)
	}
	found := false
	for _, item := range all.Data {
		if item.VulnID == f.goID {
			found = true
			if item.CVEID != f.cveID || !slices.Equal(item.Aliases, wantAliases) {
				t.Errorf("instance listing: cve_id %s aliases %v", item.CVEID, item.Aliases)
			}
		}
	}
	if !found && all.Total <= 500 {
		t.Errorf("fixture finding %s missing from the instance listing", f.goID)
	}
}

func TestAffectedProjectsByAnyAlias(t *testing.T) {
	c := testClient(t)
	f := insertAliasFixture(t, c)
	ctx := context.Background()

	for _, id := range []string{f.goID, f.cveID, f.ghsaID} {
		projects, err := c.QueryAffectedProjectsByCVE(ctx, id)
		if err != nil {
			t.Fatalf("QueryAffectedProjectsByCVE(%s): %v", id, err)
		}
		if len(projects) != 1 || projects[0].SBOMID != f.sbomID {
			t.Errorf("lookup by %s: want the fixture SBOM, got %+v", id, projects)
			continue
		}
		if projects[0].VEXStatus != "not_affected" {
			t.Errorf("lookup by %s: vex_status = %q, want not_affected", id, projects[0].VEXStatus)
		}
	}
	none, err := c.QueryAffectedProjectsByCVE(ctx, "CVE-2099-0000001")
	if err != nil || len(none) != 0 {
		t.Errorf("unknown id: got %+v, %v", none, err)
	}
}

func TestVEXStatementsAndSearchCarryAliases(t *testing.T) {
	c := testClient(t)
	f := insertAliasFixture(t, c)
	ctx := context.Background()

	stmts, err := c.QuerySBOMVEXStatements(ctx, f.sbomID)
	if err != nil {
		t.Fatalf("QuerySBOMVEXStatements: %v", err)
	}
	wantStmtAliases := []string{f.ghsaID, f.goID}
	slices.Sort(wantStmtAliases)
	if len(stmts) != 1 || stmts[0].VulnID != f.cveID || stmts[0].CVEID != f.cveID ||
		!slices.Equal(stmts[0].Aliases, wantStmtAliases) {
		t.Errorf("statement = %+v, want vuln_id/cve_id %s aliases %v", stmts, f.cveID, wantStmtAliases)
	}

	// Searching by an alias finds the finding stored under its OSV id.
	resp, err := c.QueryGlobalSearch(ctx, f.ghsaID, 5)
	if err != nil {
		t.Fatalf("QueryGlobalSearch: %v", err)
	}
	if len(resp.Vulnerabilities) != 1 || resp.Vulnerabilities[0].VulnID != f.goID ||
		resp.Vulnerabilities[0].CVEID != f.cveID {
		t.Errorf("search by %s = %+v, want %s with cve_id %s", f.ghsaID, resp.Vulnerabilities, f.goID, f.cveID)
	}
}
