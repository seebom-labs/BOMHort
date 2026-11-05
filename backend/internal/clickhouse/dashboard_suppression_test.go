package clickhouse

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDashboardSuppressionCountExecutes is the regression guard for the
// dashboard's suppressed_by_vex counter.
//
// It counted findings with `WHERE EXISTS (SELECT 1 FROM vex_statements vx
// WHERE vx.vuln_id = v.vuln_id ...)`. ClickHouse does not support a correlated
// subquery referencing an outer column and rejects the whole statement with
// UNSUPPORTED_METHOD ("Resolve identifier ... from parent scope only supported
// for constants and CTE"). The error was discarded with `_ =`, so the API kept
// reporting suppressed_by_vex: 0 and effective_vulnerabilities ==
// total_vulnerabilities — a VEX feature that silently did nothing.
//
// QueryDashboardStats now returns that error, so this test fails loudly if the
// construct ever comes back.
func TestDashboardSuppressionCountExecutes(t *testing.T) {
	c := testClient(t)
	stats, err := c.QueryDashboardStats(context.Background(), VulnFilter{})
	if err != nil {
		t.Fatalf("dashboard stats query broken: %v", err)
	}
	if stats.EffectiveVulnerabilities+stats.SuppressedByVEX != stats.TotalVulnerabilities {
		t.Errorf("effective (%d) + suppressed (%d) != total (%d)",
			stats.EffectiveVulnerabilities, stats.SuppressedByVEX, stats.TotalVulnerabilities)
	}
}

// TestNoCorrelatedSubqueries keeps the construct out of the package without
// needing a database: ClickHouse cannot plan a subquery that references a
// column of the enclosing query, and every such query fails at runtime only.
// Rewrite as a JOIN against a pre-aggregated derived table instead.
func TestNoCorrelatedSubqueries(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("failed to read package directory: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("failed to read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			// Comments may name the construct to explain why it is avoided.
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if strings.Contains(strings.ToUpper(line), "WHERE EXISTS (") {
				t.Errorf("%s:%d: correlated subquery (WHERE EXISTS) — ClickHouse rejects these at plan time; use a JOIN against a derived table", name, i+1)
			}
		}
	}
}
