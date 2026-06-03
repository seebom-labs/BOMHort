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

| Package | Tests | Subtests | What's Covered |
|---------|-------|----------|---------------|
| `cmd/api-gateway` | 23 | 7 | Auth middleware (Bearer/API-Key/disabled), input validation, public paths |
| `internal/clickhouse` | 4 | 0 | Query method signatures, SanitizeClusterName |
| `internal/config` | 17 | 0 | Defaults, env vars, S3 buckets JSON, shared credentials, shared settings inheritance, auth modes, IgnorePrefix |
| `internal/cyclonedx` | 3 | 0 | CycloneDX parsing (minimal, full, rejection) |
| `internal/github` | 35 | 22 | ExtractGitHubRepo (19 PURL patterns), RepoKey, Resolve, ResolveWithMetadata, cache, preload |
| `internal/license` | 44 | 20 | Categorize, Check, policy, exceptions, prefix matching, Go temp names |
| `internal/osv` | 6 | 0 | QueryBatch, errors, cancellation, cache |
| `internal/osvutil` | 40 | 35 | Severity, CVSS, ComputeCVSSv3BaseScore, fixed versions, affected versions |
| `internal/protobomparser` | 2 | 0 | Backend detection, opt-in dispatch |
| `internal/repo` | 7 | 0 | File scanning, ignore prefix, generic JSON, SHA256, nested dirs |
| `internal/s3` | 25 | 20 | ClassifyKey, ParseURI, BucketConfig defaults, ObjectInfo |
| `internal/sbom` | 4 | 0 | Multi-format detection (SPDX, CycloneDX, in-toto) |
| `internal/spdx` | 15 | 7 | Full parse, in-toto, invalid JSON, deterministic IDs, GoTemp, CleanPackageName |
| `internal/vex` | 13 | 8 | Parse, normalizeVulnID, URL patterns |
| `pkg/dto` | 3 | 0 | JSON serialization, ProjectListItem, ClusterStats |
| `pkg/models` | 6 | 0 | Cluster fields, omitempty, propagation |
| **Total** | **247** | **119** | **366 test invocations** |

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
| `app.spec.ts` | 3 | App creation, navbar brand, navigation links |
| `api.service.spec.ts` | 16 | All HTTP methods, error handling, pagination params |
| `dashboard.component.spec.ts` | 2 | Component creation, data loading |
| `sbom-list.component.spec.ts` | 2 | Component creation, SBOM list loading |
| `sbom-detail.component.spec.ts` | 4 | Tab switching, vuln/license/dep views |
| `vulnerability-list.component.spec.ts` | 2 | Component creation, vuln list loading |
| `license-overview.component.spec.ts` | 2 | Component creation, license data |
| `vex-list.component.spec.ts` | 2 | Component creation, VEX statement loading |
| `cve-impact.component.spec.ts` | 2 | CVE search, project listing |
| `dependency-stats.component.spec.ts` | 2 | Top dependencies, unique deps counter |
| `license-violations.component.spec.ts` | 3 | Violations tab, exceptions tab |
| `version-skew.spec.ts` | 3 | Paginated loading, search |
| `package-search.spec.ts` | 8 | Search, expandable results, detail navigation |
| `archived-packages.component.spec.ts` | 3 | Data loading, grouped display |
| `project-list.component.spec.ts` | 3 | Project loading, search with debounce |
| **Total** | **57** | **15 spec files** |

### Test Patterns (Angular)

- **Model tests** — Verify TypeScript interfaces match API shapes (no HTTP mocking needed)
- **Component tests** — Use `TestBed` with `provideHttpClientTesting()` for HTTP mocking
- **OnPush strategy** — Tests call `fixture.detectChanges()` and verify DOM output

