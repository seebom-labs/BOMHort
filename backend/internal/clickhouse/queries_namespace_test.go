package clickhouse

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// readNamespaceSource loads this package's own source so the tests below can
// assert on the SQL without needing a running ClickHouse.
func readNamespaceSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean("queries_namespace.go"))
	if err != nil {
		t.Fatalf("failed to read queries_namespace.go: %v", err)
	}
	return string(b)
}

// TestQueryNamespaceMethodsExist pins the signatures the API gateway depends
// on. The cluster filter is a separate parameter (not folded into the name)
// because a namespace name is only unique within a cluster.
func TestQueryNamespaceMethodsExist(t *testing.T) {
	var c *Client
	var _ func(context.Context, string) ([]dto.NamespaceListItem, error) = c.QueryNamespaces
	var _ func(context.Context, string, string) (*dto.NamespaceStats, error) = c.QueryNamespaceStats
	var _ func(context.Context, string, string, uint64, uint64) (*dto.PaginatedResponse[dto.SBOMListItem], error) = c.QueryNamespaceSBOMs
	var _ func(context.Context) ([]dto.FleetCluster, error) = c.QueryFleetTree
}

// TestNamespaceStatsDTO mirrors TestClusterStatsDTO: both drill-downs must
// expose the same shape so the UI can render them with one component.
func TestNamespaceStatsDTO(t *testing.T) {
	stats := dto.NamespaceStats{
		Namespace:            "payments",
		Clusters:             []string{"prod-eu", "prod-us", "staging"},
		TotalSBOMs:           3,
		TotalPackages:        11,
		TotalVulnerabilities: 6,
		CriticalVulns:        1,
		HighVulns:            2,
		MediumVulns:          2,
		LowVulns:             1,
		LicenseBreakdown:     map[string]uint64{"permissive": 11},
	}

	if len(stats.Clusters) != 3 {
		t.Fatalf("expected the namespace to span 3 clusters, got %d", len(stats.Clusters))
	}
	if stats.CriticalVulns+stats.HighVulns+stats.MediumVulns+stats.LowVulns != stats.TotalVulnerabilities {
		t.Errorf("severity sum mismatch")
	}
}

// TestNamespaceQueriesUseParameterisedClusterFilter guards the "no filter"
// escape hatch: the filter must be passed as a bound parameter (`? = ”`),
// never interpolated, and it must be applied to every table that carries the
// cluster column — otherwise a filtered listing would mix package or
// vulnerability counts from other clusters into the numbers.
func TestNamespaceQueriesUseParameterisedClusterFilter(t *testing.T) {
	src := readNamespaceSource(t)

	if strings.Contains(src, "fmt.Sprintf(`") || strings.Contains(src, `"WHERE cluster = '" +`) {
		t.Error("namespace queries must never interpolate the cluster filter into SQL")
	}

	// Three tables carry the cluster column and are aggregated per namespace.
	if got := strings.Count(src, "? = '' OR cluster = ?"); got < 3 {
		t.Errorf("expected the optional cluster filter on at least 3 aggregations, found %d", got)
	}
}

// TestFleetTreeGroupsByAllThreeDimensions ensures the tree query keeps the
// full ownership triple. Dropping one level would silently collapse distinct
// projects from different namespaces into one node.
func TestFleetTreeGroupsByAllThreeDimensions(t *testing.T) {
	src := readNamespaceSource(t)

	if !strings.Contains(src, "GROUP BY cluster, namespace, project") {
		t.Error("fleet tree must group by cluster, namespace and project")
	}
	if !strings.Contains(src, "ORDER BY s.cluster, s.namespace, s.project") {
		t.Error("fleet tree relies on ordered rows to build the tree without map lookups")
	}
}
