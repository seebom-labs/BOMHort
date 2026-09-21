package clickhouse

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// This file guards the INSERT ↔ value-list contract, without a running
// ClickHouse.
//
// Why: an INSERT's column list and the values handed to it are two
// hand-maintained descriptions of the same row, and the sibling guards in this
// package do not compare them:
//
//   - TestInsertColumnsExistInSchema checks that every named column exists.
//   - TestInsertsPersistOwnershipColumns checks that the ownership dimensions
//     are named.
//   - TestSelectColumnsMatchScanDestinations only covers SELECT ↔ Scan.
//
// None of them notice when the column list is SHORTER than the value list,
// which is exactly how #357 broke: `tags` was appended to InsertSBOM's
// batch.Append but never added to the INSERT column list. The column names
// present were all valid and all ownership dimensions were there, so every
// existing test passed — while the driver would reject every insert at runtime
// ("expected 15 arguments, got 16"), i.e. on the ingestion path only, after a
// worker had already claimed the job.
//
// The same arity trap exists in the Exec shape, where the placeholder count is
// a third hand-maintained copy: adding a column to queueColumns without adding
// a `?` to CompleteJob/FailJob silently drops the last value.

// ------------------------------------------------------------------ helpers

// insertSourceFiles are the files in this package that write rows. Kept
// explicit (rather than globbing) so a new writer has to be added here
// consciously — the same convention the sibling schema guards follow.
var insertSourceFiles = []string{
	"insert.go",
	"queue.go",
	"queries_document_store.go",
}

// resolveStringExpr flattens a Go string expression into its literal value.
//
// It handles the one indirection this package uses for SQL: concatenation with
// the shared queueColumns const, as in
//
//	"INSERT INTO ingestion_queue (" + queueColumns + ")"
//
// Anything else (a variable, fmt.Sprintf) returns ok=false so the caller skips
// it rather than guessing at a shape it cannot verify.
func resolveStringExpr(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.Ident:
		// The only const we resolve; its value is compiled into this test.
		if v.Name == "queueColumns" {
			return queueColumns, true
		}
		return "", false
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		left, ok := resolveStringExpr(v.X)
		if !ok {
			return "", false
		}
		right, ok := resolveStringExpr(v.Y)
		if !ok {
			return "", false
		}
		return left + right, true
	}
	return "", false
}

// insertColumnCount returns how many columns an INSERT names, or -1 when the
// statement is not an INSERT we can read.
func insertColumnCount(sql string) int {
	m := insertStmtRe.FindStringSubmatch(sql)
	if m == nil {
		return -1
	}
	n := 0
	for _, c := range strings.Split(m[2], ",") {
		if strings.TrimSpace(c) != "" {
			n++
		}
	}
	return n
}

// valuesPlaceholderCount counts the `?` placeholders in a VALUES clause, or -1
// when the statement has none (the PrepareBatch shape).
func valuesPlaceholderCount(sql string) int {
	upper := strings.ToUpper(stripSQLComments(sql))
	idx := strings.Index(upper, "VALUES")
	if idx < 0 {
		return -1
	}
	return strings.Count(sql[idx:], "?")
}

// insertCall is one checkable INSERT ↔ values correspondence.
type insertCall struct {
	fn     string // file:function, for the failure message
	sql    string
	values int    // batch.Append args, or Exec args after (ctx, sql)
	shape  string // "batch" or "exec"
}

// collectInsertCalls pairs every INSERT statement with the values written
// through it.
//
// Two shapes occur:
//
//	batch, _ := c.Conn.PrepareBatch(ctx, INSERT)  → values are batch.Append(...)
//	c.Conn.Exec(ctx, INSERT ... VALUES (?, ?), a, b)  → values are the trailing args
//
// An Append is attributed to the nearest PrepareBatch lexically preceding it,
// which is sound because each function in this package prepares at most one
// batch before appending to it.
func collectInsertCalls(t *testing.T) []insertCall {
	t.Helper()

	var calls []insertCall
	fset := token.NewFileSet()

	for _, name := range insertSourceFiles {
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

			// Every PrepareBatch in source order, with its resolved SQL.
			type posSQL struct {
				pos int
				sql string
			}
			var batches []posSQL

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || len(call.Args) < 2 {
					return true
				}
				switch sel.Sel.Name {
				case "PrepareBatch":
					if sql, ok := resolveStringExpr(call.Args[1]); ok {
						batches = append(batches, posSQL{pos: int(call.Pos()), sql: sql})
					}
				case "Exec":
					sql, ok := resolveStringExpr(call.Args[1])
					if !ok {
						return true
					}
					// Only INSERTs carry a value list worth checking.
					if insertColumnCount(sql) < 0 {
						return true
					}
					calls = append(calls, insertCall{
						fn:     fnName,
						sql:    sql,
						values: len(call.Args) - 2, // minus ctx and the SQL itself
						shape:  "exec",
					})
				}
				return true
			})

			// Pair each Append with the batch it writes into.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Append" {
					return true
				}
				appendPos := int(call.Pos())
				best := -1
				for i := range batches {
					if batches[i].pos < appendPos && (best < 0 || batches[i].pos > batches[best].pos) {
						best = i
					}
				}
				if best < 0 {
					return true
				}
				calls = append(calls, insertCall{
					fn:     fnName,
					sql:    batches[best].sql,
					values: len(call.Args),
					shape:  "batch",
				})
				return true
			})
			return false
		})
	}
	return calls
}

// -------------------------------------------------------------------- tests

// TestInsertColumnsMatchAppendedValues is the test that would have caught the
// #357 tags drift: an INSERT writing more values than it names columns.
func TestInsertColumnsMatchAppendedValues(t *testing.T) {
	calls := collectInsertCalls(t)
	if len(calls) == 0 {
		t.Fatal("no INSERT/value pairs found — the AST walk is broken, not the code")
	}

	checked := 0
	for _, c := range calls {
		cols := insertColumnCount(c.sql)
		if cols < 0 {
			continue
		}
		checked++
		if cols != c.values {
			t.Errorf("%s: INSERT names %d column(s) but %d value(s) are written\n--- statement ---\n%s",
				c.fn, cols, c.values, strings.TrimSpace(c.sql))
		}
	}

	// Guard the guard: if the pairing silently stops matching, the test would
	// pass while checking nothing.
	if checked < 6 {
		t.Errorf("only %d INSERT/value pairs checked — the pairing logic likely broke", checked)
	}
}

// TestInsertPlaceholdersMatchColumns covers the Exec shape, where the `?` list
// is a third copy of the column count. queueColumns is shared by all writers,
// so growing it without growing CompleteJob/FailJob's VALUES list would drop
// the new dimension on every status transition.
func TestInsertPlaceholdersMatchColumns(t *testing.T) {
	calls := collectInsertCalls(t)

	checked := 0
	for _, c := range calls {
		if c.shape != "exec" {
			continue
		}
		placeholders := valuesPlaceholderCount(c.sql)
		if placeholders < 0 {
			continue
		}
		cols := insertColumnCount(c.sql)
		checked++
		if cols != placeholders {
			t.Errorf("%s: INSERT names %d column(s) but VALUES has %d placeholder(s)\n--- statement ---\n%s",
				c.fn, cols, placeholders, strings.TrimSpace(c.sql))
		}
	}

	if checked < 2 {
		t.Errorf("only %d Exec INSERT(s) checked — expected at least CompleteJob and FailJob", checked)
	}
}

