package clickhouse

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// This file guards the SELECT ↔ Scan contract, without a running ClickHouse.
//
// Why: a query's projection list and the Scan() destinations next to it are two
// hand-maintained descriptions of the same row shape. Nothing forces them to
// agree. When they drift, nothing fails at build time and no unit test in this
// package notices — the endpoint just returns 500 at runtime
// ("expected 6 destination arguments in Scan, not 8"), which is how the SBOM
// detail view shipped broken in #332/#347: source_repo/source_ref were added to
// the Scan but not to the projection.
//
// This is a cheap static check over this package's own source. It catches
// arity drift, but not semantic SQL errors — the sibling regression in
// #350/#351 (an aggregate alias shadowing a column across a JOIN boundary,
// which ClickHouse resolves recursively) only surfaces when the server plans
// the query. That class is covered by queries_integration_test.go, which runs
// every read query against a real ClickHouse when one is configured.

// ------------------------------------------------------------------ helpers

// selectColumnCount counts the projection expressions of the OUTERMOST SELECT.
//
// Commas inside parentheses (function arguments, tuples) and inside nested
// SELECTs belong to a subexpression, so only depth-0 commas between the first
// SELECT and its matching FROM are counted. Returns -1 when the shape is not a
// plain "SELECT ... FROM ..." we can reason about, so the caller can skip it.
func selectColumnCount(sql string) int {
	s := stripSQLComments(sql)
	upper := strings.ToUpper(s)

	start := strings.Index(upper, "SELECT")
	if start < 0 {
		return -1
	}
	// A UNION means the row shape is not described by the first projection.
	if strings.Contains(upper, "UNION") {
		return -1
	}
	i := start + len("SELECT")

	depth := 0
	columns := 1
	for ; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return -1 // the SELECT is itself inside parentheses; not the outer one
			}
		case ',':
			if depth == 0 {
				columns++
			}
		case 'f', 'F':
			// Only a depth-0 FROM terminates the projection list.
			if depth == 0 && isWordAt(upper, i, "FROM") {
				return columns
			}
		}
	}
	return -1
}

// isWordAt reports whether word occurs at i delimited by non-word characters.
func isWordAt(s string, i int, word string) bool {
	if i+len(word) > len(s) || s[i:i+len(word)] != word {
		return false
	}
	if i > 0 && isWordByte(s[i-1]) {
		return false
	}
	if i+len(word) < len(s) && isWordByte(s[i+len(word)]) {
		return false
	}
	return true
}

func isWordByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// stripSQLComments is shared with migrations_schema_test.go in this package.

// sqlLiteralOf returns the SQL string literal a Query/QueryRow call carries.
// Dynamically built queries (fmt.Sprintf) return ok=false and are skipped.
func sqlLiteralOf(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	if sel.Sel.Name != "Query" && sel.Sel.Name != "QueryRow" {
		return "", false
	}
	if len(call.Args) < 2 {
		return "", false
	}
	lit, ok := call.Args[1].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	sql, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return sql, true
}

// queryScanPair is one checkable SELECT ↔ Scan correspondence.
type queryScanPair struct {
	fn   string
	sql  string
	args int
}

// collectQueryScanPairs walks every non-test .go file in this package and
// pairs each Scan with the query that produces its row.
//
// Two shapes occur, and they must be paired differently:
//
//	c.Conn.QueryRow(ctx, SQL).Scan(a, b)   → the query is the Scan's receiver
//	rows, _ := c.Conn.Query(ctx, SQL)      → the query is the last Query call
//	for rows.Next() { rows.Scan(a, b) }      lexically preceding the Scan
//
// Pairing the first shape by position would be wrong: the Scan call expression
// starts at "c", i.e. *before* the SQL literal nested inside it.
//
// A dynamically built query (fmt.Sprintf) acts as a barrier: its projection is
// unknown, so any rows.Scan after it must not be attributed to an earlier
// literal query — that would compare unrelated shapes.
func collectQueryScanPairs(t *testing.T) []queryScanPair {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("failed to read package dir: %v", err)
	}

	var pairs []queryScanPair
	fset := token.NewFileSet()

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", name, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			fnName := name + ":" + fn.Name.Name

			// QueryRow calls consumed directly by .Scan() belong to shape 1 and
			// must not be offered to a later rows.Scan().
			consumed := make(map[int]bool)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Scan" {
					if recv, ok := sel.X.(*ast.CallExpr); ok {
						consumed[int(recv.Pos())] = true
					}
				}
				return true
			})

			// Every Query/QueryRow call in source order. sql == "" marks a
			// dynamically built query, which acts as a barrier below.
			type posSQL struct {
				pos int
				sql string
			}
			var queries []posSQL
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "Query" && sel.Sel.Name != "QueryRow") {
					return true
				}
				if consumed[int(call.Pos())] {
					return true
				}
				sql, _ := sqlLiteralOf(call) // "" when built dynamically
				queries = append(queries, posSQL{pos: int(call.Pos()), sql: sql})
				return true
			})

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Scan" {
					return true
				}

				// Shape 1: the receiver is the QueryRow call itself.
				if recv, ok := sel.X.(*ast.CallExpr); ok {
					if sql, ok := sqlLiteralOf(recv); ok {
						pairs = append(pairs, queryScanPair{fn: fnName, sql: sql, args: len(call.Args)})
					}
					return true
				}

				// Shape 2: rows.Scan — nearest preceding standalone Query.
				scanPos := int(call.Pos())
				best := -1
				for i := range queries {
					if queries[i].pos < scanPos && (best < 0 || queries[i].pos > queries[best].pos) {
						best = i
					}
				}
				// An unparseable (dynamic) nearest query is a barrier, not a
				// reason to reach further back.
				if best >= 0 && queries[best].sql != "" {
					pairs = append(pairs, queryScanPair{fn: fnName, sql: queries[best].sql, args: len(call.Args)})
				}
				return true
			})
			return false
		})
	}
	return pairs
}

// ------------------------------------------------------------------- tests

// TestSelectColumnsMatchScanDestinations compares each query's projection
// width with the number of Scan destinations reading its rows.
func TestSelectColumnsMatchScanDestinations(t *testing.T) {
	pairs := collectQueryScanPairs(t)
	if len(pairs) == 0 {
		t.Fatal("no query/scan pairs found — the AST walk is broken, not the code")
	}

	checked := 0
	for _, p := range pairs {
		want := selectColumnCount(p.sql)
		if want < 0 {
			continue // shape we cannot parse confidently (UNION, nested SELECT, …)
		}
		checked++
		if want != p.args {
			t.Errorf("%s: SELECT projects %d column(s) but Scan takes %d destination(s)\n--- query ---\n%s",
				p.fn, want, p.args, strings.TrimSpace(p.sql))
		}
	}

	// Guard the guard: if the pairing silently stops matching anything, the
	// test would pass while checking nothing.
	if checked < 20 {
		t.Errorf("only %d query/scan pairs checked — the pairing logic likely broke", checked)
	}
}

// TestVulnerabilityListSQLProjectionGuards verifies that subquery s in
// vulnerabilityListSQL explicitly projects every column referenced by outer
// expressions (e.g. argMax(s.<col>, ...)), preventing ClickHouse unknown-column
// runtime errors (#413 review).
func TestVulnerabilityListSQLProjectionGuards(t *testing.T) {
	sql := vulnerabilityListSQL("")
	sStart := strings.Index(sql, "INNER JOIN (")
	if sStart < 0 {
		t.Fatal("INNER JOIN not found in vulnerabilityListSQL")
	}
	sPart := sql[sStart:]
	sFrom := strings.Index(sPart, "FROM vex_statements")
	if sFrom < 0 {
		t.Fatal("FROM vex_statements not found in subquery s")
	}
	sProjection := sPart[:sFrom]

	expectedCols := []string{
		"sbom_id", "vuln_id", "product_purl", "status",
		"action_statement", "action_statement_timestamp", "author", "vex_timestamp",
	}
	for _, col := range expectedCols {
		if !strings.Contains(sProjection, col) {
			t.Errorf("subquery s projection is missing column %q required by outer aggregations/joins", col)
		}
	}
}
