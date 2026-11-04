package clickhouse

import (
	"context"
	"testing"
)

// TestVulnerabilityOwnershipFilter checks the #459 filters against a real
// server: ownership comes from sboms, values within a field are ORed and
// fields are ANDed, and the count matches the rows.
func TestVulnerabilityOwnershipFilter(t *testing.T) {
	c := testClient(t)
	a := insertAliasFixture(t, c)
	b := insertAliasFixture(t, c)
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		f    VulnFilter
		want []string
	}{
		{"one project", VulnFilter{Projects: []string{a.project}}, []string{a.goID}},
		{"OR within a field", VulnFilter{Projects: []string{a.project, b.project}}, []string{a.goID, b.goID}},
		{"parent members", VulnFilter{ParentMembers: []string{b.project}}, []string{b.goID}},
		{"AND across fields", VulnFilter{Projects: []string{a.project}, ParentMembers: []string{b.project}}, nil},
		{"cluster", VulnFilter{Clusters: []string{a.cluster}}, []string{a.goID}},
		{"namespace", VulnFilter{Namespaces: []string{b.namespace}}, []string{b.goID}},
		{"tag", VulnFilter{Tags: []string{a.tag, b.tag}}, []string{a.goID, b.goID}},
		{"cluster mismatch", VulnFilter{Projects: []string{a.project}, Clusters: []string{"no-such-cluster"}}, nil},
		{"namespace mismatch", VulnFilter{Projects: []string{a.project}, Namespaces: []string{"no-such-ns"}}, nil},
		{"tag mismatch", VulnFilter{Projects: []string{a.project}, Tags: []string{"no-such-tag"}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := c.QueryVulnerabilities(ctx, 1, 50, "", tc.f)
			if err != nil {
				t.Fatalf("QueryVulnerabilities: %v", err)
			}
			got := map[string]bool{}
			for _, it := range resp.Data {
				got[it.VulnID] = true
			}
			if len(got) != len(tc.want) || resp.Total != uint64(len(resp.Data)) {
				t.Fatalf("got %v (total %d), want %v", got, resp.Total, tc.want)
			}
			for _, id := range tc.want {
				if !got[id] {
					t.Fatalf("missing %s in %v", id, got)
				}
			}

			cur, err := c.StreamVulnerabilities(ctx, "direct", tc.f)
			if err != nil {
				t.Fatalf("StreamVulnerabilities with scope and filter: %v", err)
			}
			for cur.Next() {
			}
			if err := cur.Err(); err != nil {
				t.Fatalf("cursor: %v", err)
			}
			_ = cur.Close()
		})
	}
}

// TestAffectedProjectsAndDashboardOwnership covers parts 3 and 4 of #459:
// affected-project rows carry the SBOM's cluster and namespace and honour the
// filter, and a filtered dashboard counts only the matching SBOMs.
func TestAffectedProjectsAndDashboardOwnership(t *testing.T) {
	c := testClient(t)
	a := insertAliasFixture(t, c)
	b := insertAliasFixture(t, c)
	ctx := context.Background()

	rows, err := c.QueryAffectedProjectsByCVE(ctx, a.goID, VulnFilter{})
	if err != nil {
		t.Fatalf("QueryAffectedProjectsByCVE: %v", err)
	}
	if len(rows) != 1 || rows[0].Cluster != a.cluster || rows[0].Namespace != a.namespace {
		t.Fatalf("rows = %+v, want cluster %s namespace %s", rows, a.cluster, a.namespace)
	}
	if rows, err := c.QueryAffectedProjectsByCVE(ctx, a.goID, VulnFilter{Clusters: []string{b.cluster}}); err != nil || len(rows) != 0 {
		t.Fatalf("other cluster: rows = %+v, err %v", rows, err)
	}

	stats, err := c.QueryDashboardStats(ctx, VulnFilter{Clusters: []string{a.cluster, b.cluster}})
	if err != nil {
		t.Fatalf("QueryDashboardStats: %v", err)
	}
	// Each fixture: one SBOM, one package, one HIGH finding suppressed by VEX.
	if stats.TotalSBOMs != 2 || stats.TotalPackages != 2 || stats.TotalVulnerabilities != 2 ||
		stats.HighVulns != 2 || stats.SuppressedByVEX != 2 || stats.EffectiveVulnerabilities != 0 {
		t.Fatalf("filtered dashboard = %+v", stats)
	}
}
