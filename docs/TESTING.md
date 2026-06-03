# SeeBOM – Testing Guide

> **Updated:** 2026-06-03

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

---

## Test Structure

### File Location

Tests live next to the code they test, using Go's `_test.go` convention:

```
backend/
├── cmd/
│   └── api-gateway/
│       ├── main.go
│       └── main_test.go            ← tests for auth middleware, download endpoint, input validation
├── internal/
│   ├── clickhouse/
│   │   ├── client.go
│   │   └── client_test.go          ← tests for query method signatures, cluster helpers
│   ├── config/
│   │   ├── config.go
│   │   └── config_test.go          ← tests for Load() defaults, env vars, S3 buckets, auth, ignore prefix, shared settings
│   ├── cyclonedx/
│   │   ├── parser.go
│   │   └── parser_test.go          ← tests for CycloneDX parsing (minimal, full, invalid)
│   ├── github/
│   │   ├── purl.go
│   │   ├── purl_test.go            ← tests for ExtractGitHubRepo (19 PURL patterns incl. well-known Go module mappings)
│   │   ├── resolver.go
│   │   └── resolver_test.go        ← tests for Resolve, ResolveWithMetadata, cache, well-known overrides (httptest mock)
│   ├── license/
│   │   ├── checker.go
│   │   ├── checker_test.go         ← tests for Categorize, Check, LoadPolicy, exceptions, prefix match, Go temp names
│   │   └── exceptions.go
│   ├── osv/
│   │   ├── client.go
│   │   └── client_test.go          ← tests for QueryBatch (with httptest mock)
│   ├── osvutil/
│   │   ├── osvutil.go
│   │   └── osvutil_test.go         ← tests for ClassifySeverity, ParseCVSSScore, ComputeCVSSv3BaseScore, ExtractFixedVersion, ExtractAffectedVersions
│   ├── protobomparser/
│   │   ├── parser.go
│   │   └── parser_test.go          ← tests for protobom backend detection
│   ├── repo/
│   │   ├── scanner.go
│   │   └── scanner_test.go         ← tests for Scan, ignore prefix, generic JSON, nested dirs, SHA256 consistency
│   ├── s3/
│   │   ├── client.go
│   │   └── client_test.go          ← tests for ClassifyKey, ParseURI, BucketConfig, ObjectInfo
│   ├── sbom/
│   │   ├── dispatch.go
│   │   └── dispatch_test.go        ← tests for multi-format detection (SPDX, CycloneDX, in-toto)
│   ├── spdx/
│   │   ├── parser.go
│   │   └── parser_test.go          ← tests for Parse (plain SPDX + in-toto attestation + GoTempModule + CleanPackageName)
│   └── vex/
│       ├── parser.go
│       └── parser_test.go          ← tests for Parse, normalizeVulnID
├── pkg/
│   ├── dto/
│   │   └── dto_test.go             ← tests for VersionSkew JSON, ProjectListItem fields, ClusterDTOs
│   └── models/
│       └── models_test.go          ← tests for Cluster fields, SBOM omitempty, IngestionJob propagation
```

### No Tests Needed

These packages contain only thin orchestration (`main()` functions) with no testable logic:

- `cmd/ingestion-watcher/` – Wires scanner + queue (all components tested individually)
- `cmd/parsing-worker/` – Wires parser + OSV + license + ClickHouse (all components tested)
- `cmd/cve-refresher/` – Wires OSV + ClickHouse refresh queries

---

## Current Test Inventory

| Package | Top-Level | Subtests | What's Covered |
|---------|-----------|----------|---------------|
| `cmd/api-gateway` | 23 | 7 | Auth middleware (12 scenarios: disabled/enabled, Bearer/X-Service-Token/X-API-Key, public paths, OPTIONS bypass, coexistence), download endpoint (content-disposition, invalid UUID), input validation |
| `internal/clickhouse` | 4 | 0 | Query method signatures exist, cluster helper functions, SanitizeClusterName |
| `internal/config` | 17 | 0 | Default values, custom env vars, S3 buckets JSON, single S3 bucket, shared S3 credentials, shared settings inheritance (endpoint/region/pathstyle/SSL), invalid S3 JSON, S3BucketNames, ClusterName, bucket cluster override, auth modes (disabled/token/apikeys/empty), IgnorePrefix (default/custom) |
| `internal/cyclonedx` | 3 | 0 | CycloneDX parsing (minimal valid, full with licenses+deps, not-CycloneDX rejection) |
| `internal/github` | 35 | 22 | ExtractGitHubRepo (19 PURL patterns: golang github.com, subpath, pkg:github, well-known Go module mappings for golang.org/x/crypto, gopkg.in/yaml.v3, go.uber.org/zap, k8s.io/client-go, oras.land/oras-go/v2, dario.cat/mergo, unknown non-github, npm, empty), RepoKey (5 patterns), Resolve (happy path, cache hit, non-GitHub PURL, well-known mapping), ResolveWithMetadata (archived repo, not-found, non-GitHub, cache hit), PreloadCache, PreloadMetadataCache, CacheEntries, MetadataCacheEntries, ETag sanitization |
| `internal/license` | 44 | 20 | Categorize (15 SPDX IDs incl. BSD-3-Clause, ISC, 0BSD, NOASSERTION, NONE), Check, CheckWithExceptions (blanket + package + prefix), LoadPolicy, LoadExceptions, LoadExceptionsWithFallback (4 scenarios), BuildIndex (empty, All CNCF Projects promoted to blanket, compound OR, compound AND), IsExempt substring matching (package+license, package-any), SplitLicenses (7 patterns), GoTempNamesFiltered, GetPolicy, edge cases |
| `internal/osv` | 6 | 0 | Empty input, mock server, server error, context cancellation, no-vulns response, HydrateVulns cache |
| `internal/osvutil` | 40 | 35 | ClassifySeverity (17 CVSS scenarios incl. vector strings, database-specific fallback), ParseCVSSScore (9 inputs incl. vectors), ComputeCVSSv3BaseScore (5 scenarios), ExtractFixedVersion (5 scenarios), ExtractAffectedVersions (4 scenarios) |
| `internal/protobomparser` | 2 | 0 | Backend detection, opt-in dispatch |
| `internal/repo` | 7 | 0 | File scanning (SBOM + VEX detection), empty dir, nested dirs, SHA256 consistency, nonexistent dir, ignore prefix (skip/noskip/empty), generic JSON acceptance (with config file exclusion) |
| `internal/s3` | 25 | 20 | ClassifyKey (10 patterns incl. _spdx.json, case-insensitive, generic .json), ParseURI (7 patterns), BucketConfig defaults, ObjectInfo URI |
| `internal/sbom` | 4 | 0 | Multi-format detection: detects SPDX, detects CycloneDX, detects in-toto envelope, protobom backend |
| `internal/spdx` | 15 | 7 | Full parse, in-toto attestation envelope unwrapping, invalid JSON, empty packages, deterministic SBOM ID, license fallback, GoTempModuleName, CleanPackageName (8 patterns) |
| `internal/vex` | 13 | 8 | Full parse, invalid JSON, empty doc, normalizeVulnID (9 URL patterns), URL-based vuln @id |
| `pkg/dto` | 3 | 0 | VersionSkew JSON serialization, ProjectListItem fields, ClusterStats DTO |
| `pkg/models` | 6 | 0 | Cluster fields, SBOM ClusterOmitEmpty, VEXStatement cluster, LicenseCompliance cluster, IngestionJob cluster propagation, Vulnerability cluster |
| **Total** | **247** | **119** | **366 test invocations** |

---

## How to Write Tests

### 1. Naming Convention

```go
// Test function: Test<FunctionName>_<Scenario>
func TestParse_InvalidJSON(t *testing.T) { ... }
func TestQueryBatch_ServerError(t *testing.T) { ... }
func TestScanner_Scan_EmptyDir(t *testing.T) { ... }

// Table-driven subtests: use t.Run()
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

### 2. Test Patterns Used in This Project

#### Table-Driven Tests (preferred for multiple inputs)

Used in: `license/checker_test.go`, `vex/parser_test.go`

```go
func TestNormalizeVulnID(t *testing.T) {
    tests := []struct {
        input string
        want  string
    }{
        {"CVE-2024-1234", "CVE-2024-1234"},
        {"https://pkg.go.dev/vuln/GO-2025-4188", "GO-2025-4188"},
        {"", ""},
    }
    for _, tt := range tests {
        t.Run(tt.input, func(t *testing.T) {
            got := normalizeVulnID(tt.input)
            if got != tt.want {
                t.Errorf("normalizeVulnID(%q) = %q, want %q", tt.input, got, tt.want)
            }
        })
    }
}
```

#### Inline JSON Test Data (for parsers)

Used in: `spdx/parser_test.go`, `vex/parser_test.go`

```go
const testSPDXJSON = `{
    "spdxVersion": "SPDX-2.3",
    "name": "test-document",
    ...
}`

func TestParse(t *testing.T) {
    result, err := Parse(strings.NewReader(testSPDXJSON), "test.spdx.json", "abc123")
    if err != nil {
        t.Fatalf("Parse() returned error: %v", err)
    }
    // Assert fields...
}
```

#### httptest Mock Server (for HTTP clients)

Used in: `osv/client_test.go`

```go
func TestQueryBatch_MockServer(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        _, _ = w.Write([]byte(`{"results": [{"vulns": [...]}]}`))
    }))
    defer server.Close()

    client := &Client{
        baseURL:    server.URL,
        httpClient: server.Client(),
        limiter:    getGlobalLimiter(),
    }

    resp, err := client.QueryBatch(context.Background(), []string{"pkg:npm/test@1.0.0"})
    // Assert...
}
```

#### t.TempDir() for Filesystem Tests

Used in: `repo/scanner_test.go`, `license/checker_test.go`

```go
func TestScanner_Scan(t *testing.T) {
    tmpDir := t.TempDir()  // Automatically cleaned up after test

    os.WriteFile(filepath.Join(tmpDir, "test.spdx.json"), []byte(`{...}`), 0644)
    os.WriteFile(filepath.Join(tmpDir, "cve.openvex.json"), []byte(`{...}`), 0644)

    scanner := NewScanner(tmpDir)
    files, err := scanner.Scan()
    // Assert file count, types, hashes...
}
```

#### t.Setenv() for Environment Variables

Used in: `config/config_test.go`

```go
func TestLoad_CustomEnv(t *testing.T) {
    t.Setenv("CLICKHOUSE_HOST", "ch-prod")   // Automatically restored after test
    t.Setenv("SKIP_OSV", "true")

    cfg, err := Load()
    // Assert config values...
}
```

### 3. What Every Test Must Cover

For each function, write tests for:

| Scenario | Example |
|----------|---------|
| **Happy path** | `TestParse` – valid SPDX JSON → correct result |
| **Invalid input** | `TestParse_InvalidJSON` – malformed JSON → error |
| **Empty input** | `TestCheck_EmptyInput` – nil slices → no panic, empty result |
| **Edge cases** | `TestNormalizeVulnID` – URLs, empty string, plain IDs |
| **Error conditions** | `TestLoadPolicy_MissingFile` – file not found → error |
| **Determinism** | `TestParse_DeterministicSBOMID` – same input → same output |

### 4. Test Requirements

- **No external dependencies.** Tests must not require a running ClickHouse, network access, or Docker. Use `httptest` for HTTP, `t.TempDir()` for files, `t.Setenv()` for env vars.
- **No test order dependency.** Each test must be self-contained and pass in isolation.
- **Use `t.Fatalf` for setup failures.** If a precondition fails, stop immediately. Use `t.Errorf` for assertion failures (allows multiple failures per test).
- **Use `t.Run()` for subtests.** Table-driven tests must use subtests for clear output.
- **No `init()` in test files.** All setup happens inside the test function.
- **Prefer `strings.NewReader` over files** for parser tests (faster, no I/O).
- **Race-safe.** All tests must pass with `-race` flag.

---

## CI Integration

Tests run automatically on every push/PR via GitHub Actions (`.github/workflows/ci.yml`):

```yaml
- name: Test Backend
  working-directory: backend
  run: go test ./... -count=1 -race

- name: Test Frontend
  working-directory: ui
  run: npx ng test --watch=false
```

The `-race` flag enables Go's race detector – this catches concurrent access bugs in the workers/queue code.

---

## Frontend Tests (Angular / Vitest)

### Quick Start

```bash
cd ui
npx ng test                    # Watch mode (interactive)
npx ng test --watch=false      # Single run (CI mode)
```

### Test Inventory (15 spec files, 57 tests)

| Component | Tests | What's Covered |
|-----------|-------|---------------|
| `app.spec.ts` | 3 | App creation, navbar rendering, route structure |
| `api.service.spec.ts` | 16 | All HTTP methods, error handling, pagination params |
| `dashboard.component.spec.ts` | 2 | Component creation, initial data load |
| `sbom-list.component.spec.ts` | 2 | Component creation, SBOM list loading |
| `sbom-detail.component.spec.ts` | 4 | Component creation, tab switching, vuln/license/deps loading |
| `vulnerability-list.component.spec.ts` | 2 | Component creation, vuln list loading |
| `license-overview.component.spec.ts` | 2 | Component creation, license data loading |
| `vex-list.component.spec.ts` | 2 | Component creation, VEX statement loading |
| `cve-impact.component.spec.ts` | 2 | Component creation, CVE search |
| `dependency-stats.component.spec.ts` | 2 | Component creation, top deps loading |
| `license-violations.component.spec.ts` | 3 | Component creation, violations loading, exception tab |
| `version-skew.spec.ts` | 3 | Component creation, paginated loading, search |
| `package-search.spec.ts` | 8 | Component creation, search, expandable results, detail navigation |
| `archived-packages.component.spec.ts` | 3 | Component creation, data loading, grouped display |
| `project-list.component.spec.ts` | 3 | Component creation, project loading, search with debounce |

### Test Patterns

- **`provideHttpClientTesting()`** – Mock HTTP layer for all API calls
- **`httpMock.expectOne()`** – Verify exact API URL + params
- **`fixture.detectChanges()`** – Trigger OnPush change detection
- **`setTimeout` + `await`** – Test debounced search inputs

---

## Adding Tests for New Features

When adding a new feature, follow this checklist:

1. **Create `<package>_test.go`** next to the source file
2. **Write at minimum:**
   - One happy-path test
   - One error/invalid-input test
   - One edge-case test
3. **Run locally:** `go test ./internal/<package>/ -v -count=1`
4. **Check coverage:** `go test ./internal/<package>/ -coverprofile=c.out && go tool cover -func=c.out`
5. **Run full suite:** `go test ./... -count=1 -race`
6. **CI will enforce:** all tests must pass before merge

---

## Packages That Still Need More Tests

The `internal/clickhouse/` package (queries, insert, queue) has basic signature tests but no full integration tests because it requires a running ClickHouse instance. Future work:

- **Option A:** Integration tests with [testcontainers-go](https://golang.testcontainers.org/) spinning up a ClickHouse container
- **Option B:** Interface-based mocking of the ClickHouse client for query logic tests

The `cmd/` packages (ingestion-watcher, parsing-worker, cve-refresher) are tested implicitly through integration via Docker Compose but have no unit tests. These are thin orchestration layers that wire together the tested internal packages. The `cmd/api-gateway` package has 23 unit tests covering auth middleware and endpoint validation.

