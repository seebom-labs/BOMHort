package clickhouse

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
)

// Integration smoke test: execute every read query against a real ClickHouse.
//
// Why this exists: the queries in this package are only ever type-checked, not
// planned. Two classes of defect therefore reach production untouched by the
// unit tests —
//
//   - projection/Scan arity drift (covered statically by
//     query_scan_contract_test.go, but only for literal single-SELECT queries),
//   - semantic SQL errors: unknown columns, and aliases that shadow a column
//     referenced across a JOIN boundary, which ClickHouse resolves recursively
//     and rejects with "aggregate function … is found inside another aggregate
//     function".
//
// Both shipped: the SBOM detail view (#332/#347) and /sboms/{id}/vulnerabilities
// (#350/#351) returned 500 for every request until a manual run caught them.
//
// The test runs against the schema created by db/migrations and asserts only
// that each query *plans and executes*; an empty database is enough, because
// the failure mode is the server rejecting the query, not the data.
//
// Skipped unless CLICKHOUSE_HOST is set:
//
//	make dev-up   # or any ClickHouse with the migrations applied
//	CLICKHOUSE_HOST=localhost go test ./internal/clickhouse/ -run TestQueriesExecute
func testClient(t *testing.T) *Client {
	t.Helper()

	host := os.Getenv("CLICKHOUSE_HOST")
	if host == "" {
		t.Skip("CLICKHOUSE_HOST not set — skipping query smoke test (see file comment)")
	}
	port := os.Getenv("CLICKHOUSE_PORT")
	if port == "" {
		port = "9000"
	}
	db := os.Getenv("CLICKHOUSE_DATABASE")
	if db == "" {
		db = "bomhort"
	}

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{host + ":" + port},
		Auth: clickhouse.Auth{
			Database: db,
			Username: envOr("CLICKHOUSE_USER", "default"),
			Password: os.Getenv("CLICKHOUSE_PASSWORD"),
		},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to open ClickHouse connection: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		t.Fatalf("ClickHouse at %s:%s is not reachable: %v", host, port, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return &Client{Conn: conn}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// TestQueriesExecute runs every read query once. A query that cannot be
// planned fails here instead of in production.
func TestQueriesExecute(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Any UUID works: the point is that the server accepts the query, and an
	// empty result exercises the same plan as a populated one.
	someID := uuid.New().String()

	cases := []struct {
		name string
		run  func() error
	}{
		{"QueryDashboardStats", func() error { _, err := c.QueryDashboardStats(ctx); return err }},
		{"QuerySBOMs", func() error { _, err := c.QuerySBOMs(ctx, 1, 10, ""); return err }},
		{"QuerySBOMs/search", func() error { _, err := c.QuerySBOMs(ctx, 1, 10, "test"); return err }},
		{"QuerySBOMDetail", func() error { _, err := c.QuerySBOMDetail(ctx, someID); return err }},
		{"QuerySBOMVulnerabilities", func() error { _, err := c.QuerySBOMVulnerabilities(ctx, someID); return err }},
		{"QuerySBOMLicenses", func() error { _, err := c.QuerySBOMLicenses(ctx, someID); return err }},
		{"QuerySBOMVEXStatements", func() error { _, err := c.QuerySBOMVEXStatements(ctx, someID); return err }},
		{"QueryVulnerabilities", func() error { _, err := c.QueryVulnerabilities(ctx, 1, 10); return err }},
		{"QueryVEXStatements", func() error { _, err := c.QueryVEXStatements(ctx, 1, 10); return err }},
		{"QueryClusters", func() error { _, err := c.QueryClusters(ctx); return err }},
		{"QueryClusterSBOMs", func() error { _, err := c.QueryClusterSBOMs(ctx, "test", 1, 10); return err }},
		{"ResolveSBOMByProductRef", func() error {
			_, err := c.ResolveSBOMByProductRef(ctx, "https://github.com/example-org/example-app")
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err != nil && !isEmptyResult(err) {
				t.Errorf("query failed against a real ClickHouse: %v", err)
			}
		})
	}
}

// isEmptyResult reports whether err only means "this row does not exist".
// Single-row queries surface that as an error, but the query itself planned
// and executed — which is all this test asserts.
func isEmptyResult(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no rows in result set")
}

// TestSBOMDetailProjectionMatchesScan is the regression guard for #332/#347:
// the detail query gained source_repo/source_ref in the Scan but not in the
// projection, so every request 500'd with
// "expected 6 destination arguments in Scan, not 8".
func TestSBOMDetailProjectionMatchesScan(t *testing.T) {
	c := testClient(t)
	_, err := c.QuerySBOMDetail(context.Background(), uuid.New().String())
	if err != nil && !isEmptyResult(err) {
		t.Fatalf("SBOM detail query broken: %v", err)
	}
}

// TestSBOMVulnerabilitiesVEXJoin is the regression guard for #350/#351: the
// scoped-VEX join aliased argMax results after the columns they read, which
// ClickHouse resolves recursively across the JOIN and rejects with
// "aggregate function ... is found inside another aggregate function".
func TestSBOMVulnerabilitiesVEXJoin(t *testing.T) {
	c := testClient(t)
	_, err := c.QuerySBOMVulnerabilities(context.Background(), uuid.New().String())
	if err != nil && !isEmptyResult(err) {
		t.Fatalf("SBOM vulnerabilities query broken: %v", err)
	}
}

// TestClusterSBOMsQuery is the regression guard for the cluster listing, which
// used "FROM sboms FINAL AS s" — invalid ClickHouse ("Syntax error ... AS s").
// The endpoint returned 500 for every request; no unit test executed it.
func TestClusterSBOMsQuery(t *testing.T) {
	c := testClient(t)
	if _, err := c.QueryClusterSBOMs(context.Background(), "any-cluster", 1, 10); err != nil {
		t.Fatalf("cluster SBOM listing broken: %v", err)
	}
}
