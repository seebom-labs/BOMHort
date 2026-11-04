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
