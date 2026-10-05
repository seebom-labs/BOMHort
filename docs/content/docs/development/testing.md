---
title: "Testing"
linkTitle: "Testing"
type: docs
weight: 1
description: >
  How to run tests, write new tests, and understand the test structure.
---

## Quick Start

```bash
# Run all tests
cd backend && go test ./... -count=1

# Run with verbose output
go test ./... -v -count=1

# Run tests for a specific package
go test ./internal/vex/ -v -count=1

# Run a single test by name
go test ./internal/vex/ -run TestNormalizeVulnID -v

# Run with race detection (used in CI)
go test ./... -count=1 -race

# Check coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Test Structure

Tests live next to the code they test, using Go's `_test.go` convention:

```
backend/
├── cmd/
│   └── api-gateway/
│       ├── main.go
│       └── main_test.go            ← auth middleware, input validation
├── internal/
│   ├── clickhouse/
│   │   ├── client.go
│   │   └── client_test.go          ← query method signatures, cluster helpers
│   ├── config/
│   │   ├── config.go
│   │   └── config_test.go          ← Load(), S3 buckets, auth, ignore prefix, shared settings
│   ├── cyclonedx/
│   │   ├── parser.go
│   │   └── parser_test.go          ← CycloneDX parsing
│   ├── github/
│   │   ├── purl.go
│   │   ├── purl_test.go
│   │   ├── resolver.go
│   │   └── resolver_test.go
│   ├── license/
│   │   ├── checker.go
│   │   └── checker_test.go
│   ├── osv/
│   │   ├── client.go
│   │   └── client_test.go
│   ├── osvutil/
│   │   ├── osvutil.go
│   │   └── osvutil_test.go
│   ├── protobomparser/
│   │   ├── parser.go
│   │   └── parser_test.go          ← protobom backend detection
│   ├── repo/
│   │   ├── scanner.go
│   │   └── scanner_test.go         ← file scanning, ignore prefix, generic JSON
│   ├── s3/
│   │   ├── client.go
│   │   └── client_test.go
│   ├── sbom/
│   │   ├── dispatch.go
│   │   └── dispatch_test.go        ← multi-format detection
│   ├── spdx/
│   │   ├── parser.go
│   │   └── parser_test.go
│   └── vex/
│       ├── parser.go
│       └── parser_test.go
├── pkg/
│   ├── dto/
│   │   └── dto_test.go             ← JSON serialization, fields
│   └── models/
│       └── models_test.go          ← cluster fields, omitempty
```

## Current Test Inventory

Counted on 2026-10-04 with `CLICKHOUSE_HOST=localhost go test ./... -count=1 -race -json` against `make dev-up` (top-level tests and `t.Run` subtests that ran). Without `CLICKHOUSE_HOST`, the four query smoke tests in `internal/clickhouse/queries_integration_test.go` are skipped — run them whenever you add or change a query, and add new queries to `TestQueriesExecute`.

| Package | Tests | Subtests | What's Covered |
|---------|-------|----------|---------------|
| `cmd/api-gateway` | 70 | 77 | Auth middleware (Bearer/API-Key/disabled), CORS, input validation, public paths, upload, project routes |
| `cmd/ingestion-watcher` | 11 | 11 | Bucket-prefix stripping, per-object ownership resolution, explicit-config precedence |
| `cmd/mcp-server` | 23 | 8 | Tool surface, transports, Origin/token guards |
| `cmd/parsing-worker` | 30 | 30 | **License pipeline golden test**, **docs-sync test** (see below), license provenance and unresolved-reason precedence, first-party detection, registry resolvers, ownership propagation to every row type incl. all statements in a VEX document |
| `internal/apiclient` | 11 | 4 | Read-only REST client used by the MCP server |
| `internal/clickhouse` | 37 | 54 | Query helpers, license source labels, `package_license_sources` padding, **query smoke tests against a real ClickHouse** (every read query plans and executes; needs `CLICKHOUSE_HOST`), **migration/schema drift (no DB required)**: migrations replayed into an in-memory schema, every `INSERT INTO` column asserted to exist, ownership columns required on all data tables, all `ingestion_queue` writers share one column list, migration numbers unique + contiguous |
| `internal/config` | 45 | 6 | Defaults, env vars, S3 buckets JSON, shared settings inheritance, auth modes, resolver switches |
| `internal/cyclonedx` | 16 | 4 | CycloneDX parsing |
| `internal/depsdev` | 8 | 19 | deps.dev batch + per-version lookups, raw-license recovery, versionless (`@*`) resolution, negative reasons |
| `internal/docstore` | 27 | 8 | fs/S3 original-document store, reference-driven reads |
| `internal/github` | 20 | 23 | PURL → repository mapping (well-known table, gopkg.in rule), Resolve, metadata, cache |
| `internal/ingestpath` | 14 | 19 | Layout parsing and derivation, `_` skip token, precedence |
| `internal/license` | 51 | 36 | Categorize, policy, exceptions, expressions and modes, deprecated IDs, `Normalize`, `Recover`, `LicenseRef`, provenance vocabulary and cache markers |
| `internal/licensetext` | 1 | 15 | License-text classification |
| `internal/npm` | 5 | 25 | Version manifest parsing, `latest` fallback, not-published / no-license-upstream |
| `internal/nuget` | 5 | 8 | `licenseExpression`, `licenseUrl` mapping, GitHub delegation |
| `internal/osv` | 6 | 0 | QueryBatch, errors, cancellation, cache |
| `internal/osvutil` | 5 | 35 | Severity, CVSS, fixed and affected versions |
| `internal/packagist` | 5 | 0 | p2 minified format, dev branches → latest stable, OR-joined license arrays, negatives |
| `internal/projectgroup` | 14 | 0 | Parent resolution signals and ambiguity guard |
| `internal/protobomparser` | 4 | 0 | Backend detection, opt-in dispatch |
| `internal/pypi` | 3 | 15 | PEP 503 names, `license_expression` > classifiers > free text, no latest fallback for missing versions |
| `internal/repo` | 8 | 6 | File scanning, ignore prefix, generic JSON, SHA256 |
| `internal/s3` | 10 | 20 | ClassifyKey, ParseURI, bucket config |
| `internal/sbom` | 14 | 12 | Multi-format detection (SPDX, CycloneDX, in-toto), Yarn PURL repair |
| `internal/sbomname` | 9 | 29 | Document-name fallback |
| `internal/sourcerepo` | 6 | 66 | `source_repo` extraction |
| `internal/spdx` | 33 | 39 | Full parse, in-toto, deterministic IDs, package names |
| `internal/tags` | 7 | 10 | Tag normalisation |
| `internal/vex` | 12 | 13 | Parse, normalizeVulnID, URL patterns |
| `pkg/dto` | 8 | 0 | JSON serialization |
| `pkg/models` | 6 | 0 | Ownership fields, omitempty |
| **Total** | **524** | **592** | |

### License resolution: golden and docs-sync tests

Every license heuristic is a documented decision (see [License Resolution](/docs/license-resolution/)). Two tests keep code, behaviour and documentation together:

- **`TestLicensePipelineGolden`** (`cmd/parsing-worker/golden_test.go`) runs `testdata/license_golden.spdx.json` — one synthetic package per path through the pipeline — through the real parser, `resolvePackageLicenses` (with offline registry fakes that implement `Explain`), the real policy and the compliance exclusion, and pins license, source, category and exclusion per package in `licenseGolden`.
- **`TestDocsLicenseResolutionInSync`** (`cmd/parsing-worker/docs_sync_test.go`) parses the tables between `<!-- name:start -->` / `<!-- name:end -->` markers on the docs page and asserts: the source vocabulary equals the code's origins (in resolver order), modifiers and `license.UnresolvedReasons`; each normalization example matches `license.Recover` and the default policy; the worked examples equal `licenseGolden` row for row.

A new rule therefore needs a fixture package, a golden row, a docs row and a decision-log entry; any one missing fails `go test`.

## Test Patterns

### Table-Driven Tests

```go
func TestCategorize(t *testing.T) {
    tests := []struct {
        input    string
        expected Category
    }{
        {"MIT", CategoryPermissive},
        {"GPL-3.0-only", CategoryCopyleft},
    }
    for _, tt := range tests {
        t.Run(tt.input, func(t *testing.T) {
            got := Categorize(tt.input)
            if got != tt.expected {
                t.Errorf("Categorize(%q) = %q, want %q", tt.input, got, tt.expected)
            }
        })
    }
}
```

### httptest Mock Server

```go
func TestQueryBatch_MockServer(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"results": [{"vulns": [...]}]}`))
    }))
    defer server.Close()
    // Use server.URL as base URL...
}
```

### t.TempDir() for Filesystem Tests

```go
func TestScanner_Scan(t *testing.T) {
    tmpDir := t.TempDir()
    os.WriteFile(filepath.Join(tmpDir, "test.spdx.json"), []byte(`{...}`), 0644)
    scanner := NewScanner(tmpDir)
    files, err := scanner.Scan()
    // Assert...
}
```

## Test Requirements

- **No external dependencies.** No running ClickHouse, network, or Docker needed.
- **No test order dependency.** Each test is self-contained.
- **Race-safe.** All tests must pass with `-race` flag.
- **Use subtests** (`t.Run()`) for table-driven tests.

## CI Integration

Tests run automatically on every push/PR:

```yaml
- name: Test
  working-directory: backend
  run: go test ./... -count=1 -race
```

## Angular (Frontend) Tests

The Angular frontend uses **Vitest** (not Karma/Jasmine). Tests live alongside components as `*.spec.ts` files.

### Quick Start

```bash
cd ui

# Run all tests
npx ng test

# Run once (no watch)
npx ng test --watch=false
```

### Current Test Inventory (Frontend)

| Spec File | Tests | What's Covered |
|-----------|-------|---------------|
| `app.spec.ts` | 6 | App creation, navbar, navigation |
| `api.service.spec.ts` | 18 | HTTP methods incl. license sources, error handling, pagination params |
| `archived-packages.component.spec.ts` | 10 | Data loading, grouped display |
| `dashboard.component.spec.ts` | 3 | Component creation, data loading, Not Approved license segment |
| `fleet-view.component.spec.ts` | 3 | Cluster → namespace → project tree |
| `license-overview.component.spec.ts` | 4 | Category cards, License Resolution panel: resolved share, unknown reasons with hints, first-party excluded |
| `project-detail.component.spec.ts` | 12 | Project detail tabs and stats |
| `project-list.component.spec.ts` | 18 | Project loading, search, tags, grouping |
| `parent-group-list.component.spec.ts` | 6 | Parent → project grouping |
| `project-group-list.component.spec.ts` | 9 | Project → version grouping |
| `sbom-detail.component.spec.ts` | 8 | Tabs, licenses, dependency license-source tooltip |
| `sbom-list.component.spec.ts` | 10 | SBOM list loading |
| `cve-impact.component.spec.ts` | 2 | CVE search, project listing |
| `dependency-stats.component.spec.ts` | 2 | Top dependencies, unique deps counter |
| `global-search-results.component.spec.ts` | 3 | Global search results |
| `license-violations.component.spec.ts` | 7 | Violations tab, exceptions tab, not-approved badge |
| `package-search.spec.ts` | 8 | Search, expandable results, detail navigation |
| `version-skew.spec.ts` | 3 | Paginated loading, search |
| `vulnerability-list.component.spec.ts` | 2 | Component creation, vuln list loading |
| `global-search.component.spec.ts` | 5 | Navbar search box |
| `license-source.spec.ts` | 5 | License source labels, tooltips, reason hints |
| **Total** | **144** | **21 spec files** |

### Test Patterns (Angular)

- **Model tests** — Verify TypeScript interfaces match API shapes (no HTTP mocking needed)
- **Component tests** — Use `TestBed` with `provideHttpClientTesting()` for HTTP mocking
- **OnPush strategy** — Tests call `fixture.detectChanges()` and verify DOM output

