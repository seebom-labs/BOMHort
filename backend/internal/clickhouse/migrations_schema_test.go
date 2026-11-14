package clickhouse

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// This file tests the migrations themselves, without a running ClickHouse.
//
// Why: the INSERT column lists in this package and the migrations in
// db/migrations/ are two hand-maintained descriptions of the same schema.
// Nothing forces them to agree, and when they disagree the failure is a
// runtime error on every insert ("No such column X in table Y") that only
// shows up once a worker actually processes a job — not at build time, and
// not in any unit test that does not touch the database.
//
// So we reconstruct the expected schema by replaying the migration files and
// assert the Go code only ever writes columns that exist.

// ---------------------------------------------------------------- migrations

// migrationsDir walks up from the package directory to the repository root.
func migrationsDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("failed to resolve repo root: %v", err)
	}
	path := filepath.Join(dir, "db", "migrations")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("migrations directory not found at %s: %v", path, err)
	}
	return path
}

var (
	// CREATE TABLE [IF NOT EXISTS] name ( ... ) ENGINE
	createTableRe = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?` +
		"`?([a-z_0-9]+)`?" + `\s*\((.*?)\)\s*ENGINE`)
	// ALTER TABLE name <clauses up to the statement terminator>
	alterTableRe = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+` + "`?([a-z_0-9]+)`?" + `\s+(.*?);`)
	// ADD COLUMN [IF NOT EXISTS] name
	addColumnRe = regexp.MustCompile(`(?is)ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?` + "`?([a-z_0-9]+)`?")
	// MATERIALIZED VIEW bodies are not plain tables; their columns come from a
	// SELECT and are not written to directly by this package.
	materializedViewRe = regexp.MustCompile(`(?is)CREATE\s+MATERIALIZED\s+VIEW`)
)

// stripSQLComments removes "--" line comments so commented-out DDL and prose
// mentioning column names cannot be mistaken for schema.
func stripSQLComments(sql string) string {
	lines := strings.Split(sql, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// parseColumnNames extracts the leading identifier of each top-level entry in
// a CREATE TABLE body, ignoring nested parentheses (e.g. FixedString(64),
// LowCardinality(String), DEFAULT now()).
func parseColumnNames(body string) []string {
	var (
		cols  []string
		depth int
		cur   strings.Builder
	)
	flush := func() {
		entry := strings.TrimSpace(cur.String())
		cur.Reset()
		if entry == "" {
			return
		}
		fields := strings.Fields(entry)
		if len(fields) == 0 {
			return
		}
		name := strings.Trim(fields[0], "`")
		// Table-level clauses are not columns.
		switch strings.ToUpper(name) {
		case "INDEX", "PRIMARY", "CONSTRAINT", "PROJECTION":
			return
		}
		cols = append(cols, name)
	}

	for _, r := range body {
		switch r {
		case '(':
			depth++
			cur.WriteRune(r)
		case ')':
			depth--
			cur.WriteRune(r)
		case ',':
			if depth == 0 {
				flush()
				continue
			}
			cur.WriteRune(r)
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return cols
}

// schemaFromMigrations replays every migration in order and returns
// table -> set of columns.
func schemaFromMigrations(t *testing.T) map[string]map[string]bool {
	t.Helper()
	dir := migrationsDir(t)

	entries, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		t.Fatalf("failed to list migrations: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("no migrations found in %s", dir)
	}
	sort.Strings(entries) // numeric prefixes make lexical order == apply order

	schema := make(map[string]map[string]bool)

	for _, file := range entries {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("failed to read %s: %v", file, err)
		}
		sql := stripSQLComments(string(raw))

		for _, m := range createTableRe.FindAllStringSubmatch(sql, -1) {
			table, body := m[1], m[2]
			if materializedViewRe.MatchString(sql[:strings.Index(sql, m[0])+len(m[0])]) {
				// Only skip when this specific statement is the MV one.
				if strings.Contains(strings.ToUpper(m[0]), "MATERIALIZED") {
					continue
				}
			}
			if schema[table] == nil {
				schema[table] = make(map[string]bool)
			}
			for _, col := range parseColumnNames(body) {
				schema[table][col] = true
			}
		}

		for _, m := range alterTableRe.FindAllStringSubmatch(sql, -1) {
			table, clauses := m[1], m[2]
			if schema[table] == nil {
				// An ALTER against a table no migration created is itself a bug.
				t.Errorf("%s: ALTER TABLE %s, but no migration creates that table",
					filepath.Base(file), table)
				continue
			}
			for _, c := range addColumnRe.FindAllStringSubmatch(clauses, -1) {
				schema[table][c[1]] = true
			}
		}
	}

	return schema
}

func TestMigrationsParseIntoASchema(t *testing.T) {
	schema := schemaFromMigrations(t)

	// Sanity: the core tables must exist with a few known columns, otherwise a
	// silently broken parser would make every other test in this file vacuous.
	want := map[string][]string{
		"sboms":              {"sbom_id", "source_file", "document_name", "cluster", "namespace", "project", "image_ref", "image_digest"},
		"sbom_packages":      {"sbom_id", "package_purls", "cluster", "namespace", "project", "image_digest"},
		"vulnerabilities":    {"sbom_id", "vuln_id", "purl", "cluster", "namespace", "project", "image_digest"},
		"license_compliance": {"sbom_id", "license_id", "exempted_packages", "cluster", "namespace", "project"},
		"ingestion_queue":    {"job_id", "status", "cluster", "namespace", "project", "image_ref", "image_digest"},
		"vex_statements":     {"vuln_id", "product_purl", "cluster", "namespace", "project"},
		"document_store":     {"sbom_id", "storage_ref", "content_encoding", "cluster", "namespace", "project"},
	}

	for table, cols := range want {
		got, ok := schema[table]
		if !ok {
			t.Errorf("table %s is never created by any migration", table)
			continue
		}
		for _, col := range cols {
			if !got[col] {
				t.Errorf("table %s: column %q missing from the migrations", table, col)
			}
		}
	}
}

// Every table that carries per-SBOM data must carry all three ownership
// dimensions. A new table added without them would silently be invisible to
// cluster/namespace/project filtering — and back-filling it is only possible
// by re-ingesting.
func TestOwnershipColumnsOnAllDataTables(t *testing.T) {
	schema := schemaFromMigrations(t)

	dataTables := []string{
		"sboms", "sbom_packages", "vulnerabilities", "license_compliance",
		"ingestion_queue", "vex_statements", "document_store",
	}

	for _, table := range dataTables {
		cols, ok := schema[table]
		if !ok {
			t.Errorf("table %s not found in the migrations", table)
			continue
		}
		for _, dim := range []string{"cluster", "namespace", "project"} {
			if !cols[dim] {
				t.Errorf("table %s is missing the %q ownership column", table, dim)
			}
		}
	}
}

// ------------------------------------------------------- code-vs-schema drift

var insertStmtRe = regexp.MustCompile(`(?is)INSERT\s+INTO\s+` + "`?([a-z_0-9]+)`?" + `\s*\(([^)]*)\)`)

// insertTargetsFromSource extracts (table, columns) from every INSERT INTO
// literal in the given Go source files.
func insertTargetsFromSource(t *testing.T, files ...string) map[string][][]string {
	t.Helper()
	found := make(map[string][][]string)

	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("failed to read %s: %v", file, err)
		}
		src := string(raw)

		// Resolve the one indirection this package uses, so the shared queue
		// column list is checked rather than skipped.
		if strings.Contains(src, "queueColumns") {
			src = strings.ReplaceAll(src, `"+queueColumns+"`, queueColumns)
			src = strings.ReplaceAll(src, "`+queueColumns+`", queueColumns)
		}

		for _, m := range insertStmtRe.FindAllStringSubmatch(src, -1) {
			table := m[1]
			var cols []string
			for _, c := range strings.Split(m[2], ",") {
				c = strings.TrimSpace(c)
				// Skip Go expressions that survived (none expected today, but a
				// future `"+someVar+"` must not be asserted as a column name).
				if c == "" || strings.ContainsAny(c, `"+()`) {
					continue
				}
				cols = append(cols, c)
			}
			if len(cols) > 0 {
				found[table] = append(found[table], cols)
			}
		}
	}

	return found
}

// TestInsertColumnsExistInSchema is the test that would have caught the
// content_encoding drift: an INSERT naming a column no migration creates.
func TestInsertColumnsExistInSchema(t *testing.T) {
	schema := schemaFromMigrations(t)

	inserts := insertTargetsFromSource(t,
		"insert.go",
		"queue.go",
		"queries_document_store.go",
	)

	if len(inserts) == 0 {
		t.Fatal("no INSERT statements found — the extractor is broken")
	}

	for table, statements := range inserts {
		cols, ok := schema[table]
		if !ok {
			t.Errorf("code inserts into %s, but no migration creates that table", table)
			continue
		}
		for _, stmt := range statements {
			for _, col := range stmt {
				if !cols[col] {
					t.Errorf("INSERT INTO %s references column %q, which no migration creates",
						table, col)
				}
			}
		}
	}
}

// The ownership dimensions are only useful if every writer actually persists
// them. An INSERT into a data table that omits one would write DEFAULT ”
// rows that look "unassigned" forever.
func TestInsertsPersistOwnershipColumns(t *testing.T) {
	inserts := insertTargetsFromSource(t,
		"insert.go",
		"queue.go",
		"queries_document_store.go",
	)

	dataTables := map[string]bool{
		"sboms": true, "sbom_packages": true, "vulnerabilities": true,
		"license_compliance": true, "ingestion_queue": true,
		"vex_statements": true, "document_store": true,
	}

	for table, statements := range inserts {
		if !dataTables[table] {
			continue
		}
		for i, stmt := range statements {
			have := make(map[string]bool, len(stmt))
			for _, c := range stmt {
				have[c] = true
			}
			for _, dim := range []string{"cluster", "namespace", "project"} {
				if !have[dim] {
					t.Errorf("INSERT INTO %s (statement #%d) does not write the %q column",
						table, i+1, dim)
				}
			}
		}
	}
}

// All five ingestion_queue writers must agree on the column set. The queue is
// append-only — a status transition rewrites the whole row — so a writer
// omitting a column silently blanks it for that job.
func TestQueueWritersShareOneColumnList(t *testing.T) {
	inserts := insertTargetsFromSource(t, "queue.go")

	statements, ok := inserts["ingestion_queue"]
	if !ok {
		t.Fatal("no ingestion_queue INSERTs found in queue.go")
	}
	if len(statements) < 4 {
		t.Fatalf("expected at least 4 queue writers (enqueue, claim, complete, fail), found %d",
			len(statements))
	}

	want := strings.Join(statements[0], ",")
	for i, stmt := range statements[1:] {
		if got := strings.Join(stmt, ","); got != want {
			t.Errorf("queue writer #%d has a different column list:\n  got:  %s\n  want: %s",
				i+2, got, want)
		}
	}
}

// Migration numbers must be unique: two files claiming the same number is how
// #256 and #138 collided during planning, and lexical apply order would make
// the outcome depend on the filename suffix.
func TestMigrationNumbersAreUniqueAndContiguous(t *testing.T) {
	dir := migrationsDir(t)
	files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		t.Fatalf("failed to list migrations: %v", err)
	}

	numRe := regexp.MustCompile(`^(\d+)_`)
	seen := make(map[string]string, len(files))
	var numbers []int

	for _, f := range files {
		base := filepath.Base(f)
		m := numRe.FindStringSubmatch(base)
		if m == nil {
			t.Errorf("migration %s does not start with a numeric prefix", base)
			continue
		}
		if prev, dup := seen[m[1]]; dup {
			t.Errorf("duplicate migration number %s: %s and %s", m[1], prev, base)
			continue
		}
		seen[m[1]] = base

		n := 0
		for _, r := range m[1] {
			n = n*10 + int(r-'0')
		}
		numbers = append(numbers, n)
	}

	sort.Ints(numbers)
	for i, n := range numbers {
		if want := i + 1; n != want {
			t.Errorf("migration numbering has a gap: expected %03d, found %03d", want, n)
			break
		}
	}
}
