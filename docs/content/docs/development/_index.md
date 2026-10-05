---
title: "Development"
linkTitle: "Development"
type: docs
weight: 4
description: >
  Development guide — local setup, code style, configuration, and contribution guidelines.
---

{{% pageinfo %}}
How to set up a local development environment, run the stack, and contribute to BOMHort.
{{% /pageinfo %}}

## Local Development Setup

### Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Go | 1.26+ | Backend binaries — `backend/go.mod` pins `go 1.26.8` |
| Node.js | 22+ | Angular UI, and the PostCSS chain Hugo runs for the docs |
| Docker + Docker Compose | v2.20+ | ClickHouse and full-stack mode |

### Option A: Full Stack via Docker Compose

The fastest way to get everything running:

```bash
make dev
```

This starts ClickHouse, all 4 Go binaries, and the Angular UI. Open **http://localhost:8090**.

### Option B: Hot Reload (Backend + UI separately)

For iterating on code changes without rebuilding Docker images:

```bash
# Terminal 1: ClickHouse only
make ch-only
make ch-migrate     # First time only

# Terminal 2: API Gateway (restarts on save via go run)
make api

# Terminal 3: Ingestion Watcher (runs once)
make ingest

# Terminal 4: Parsing Worker
make worker

# Terminal 5: Angular dev server (hot reload, proxies /api/* to localhost:8080)
make ui-dev
```

Open **http://localhost:4200** for the Angular dev server.

## Configuration

Copy `.env.example` to `.env` and adjust as needed. Key variables for development:

| Variable | Recommended for Dev | Why |
|----------|-------------------|-----|
| `SBOM_LIMIT` | `50`–`200` | Faster ingestion cycles during development |
| `SKIP_OSV` | `true` (initial load) | Skip OSV API calls for fast bulk loading, re-enable after |
| `GITHUB_TOKEN` | Set it | Avoids 60 req/h rate limit; see [FAQ: Should I use a GitHub token?](/docs/faq/#should-i-use-a-github-token) |
| `WORKER_REPLICAS` | `1` | Sufficient for local development |

## Code Style

### Go Backend

- **Standard idiomatic Go.** Handle errors explicitly; never swallow them.
- **HTTP routing:** Go 1.22+ stdlib `net/http` with method-pattern registration (e.g., `mux.HandleFunc("GET /api/v1/sboms", ...)`). No web framework.
- **Minimal dependencies:** Only 6 direct dependencies (`clickhouse-go/v2`, `goccy/go-json`, `google/uuid`, `minio/minio-go/v7`, `protobom/protobom`, `modelcontextprotocol/go-sdk`). Adding another one is a maintainer decision.
- **JSON parsing:** Use `goccy/go-json` for all SPDX document parsing (performance-critical).
- **OSV integration:** Use batch endpoints (`/v1/querybatch`). Shared logic in `internal/osvutil`.
- **License logic:** All categorization and normalization in `internal/license` with externalized policy files; registry lookups in their own resolver packages (`internal/npm`, `nuget`, `depsdev`, `packagist`, `pypi`, `github`). Three rules apply:
  - **Every heuristic is a documented decision.** A new or changed rule needs an entry in the decision log on [License Resolution](/docs/license-resolution/), a row in the synced tables there, and a package in the golden fixture. `TestLicensePipelineGolden` and `TestDocsLicenseResolutionInSync` fail if code, fixture and page drift apart (see [Testing](/docs/development/testing/#license-resolution-golden-and-docs-sync-tests)).
  - **Never guess.** Map a license name to an SPDX ID only when it names one license unambiguously. Ambiguous names (`BSD`, `Apache Software License`, `Public Domain`) are kept as declared and categorized **unapproved** — mapping them would approve a license nobody approved. A declared license is never overridden by a resolver.
  - **Every unknown carries a reason.** A license that stays `NOASSERTION` records why (`license.UnresolvedReasons`); a new reason needs its UI label and a docs row too.

### Angular Frontend

- **Strict TypeScript mode** and standalone components.
- **OnPush change detection** for data-heavy components.
- **Virtual scrolling** (`@angular/cdk ScrollingModule`) for large lists.
- **Vitest** for unit tests (not Karma/Jasmine).
- **Never use `bypassSecurityTrustHtml`** — use `sanitizer.sanitize(SecurityContext.HTML, ...)`.

## Example SBOM Files

The `sboms/` directory includes several example files for testing. See [FAQ: What example files are included?](/docs/faq/#what-example-files-are-included) for a full description of each file.

## Useful Commands

| Command | Description |
|---------|-------------|
| `make backend-build` | Build all Go binaries |
| `make backend-test` | Run all Go tests |
| `make backend-vet` | Run `go fmt` + `go vet` |
| `make ui-build` | Build Angular for production |
| `make ch-shell` | Open ClickHouse SQL shell |
| `make dev-status` | Show container status + ingestion progress |
| `make dev-logs` | Follow Docker Compose logs |
| `make re-ingest` | Re-trigger the Ingestion Watcher |
| `make re-scan` | Wipe vulns/licenses and re-process all SBOMs |
| `make cherry-pick PR=<n> BRANCH=0.8` | Backport a fix merged on `main` to `release/v0.8` as a pull request ([Release Branches](/docs/release/#release-branches)) |
| `make kind-deploy-release VERSION=0.8.0-rc.1` | Install a published release candidate into the local Kind cluster to test it |

## Branches

Open every pull request against `main` — also fixes for a released version. Each minor has a release branch `release/vX.Y` that only receives backports of merged fixes; see [Release → Release Branches](/docs/release/#release-branches) and `CONTRIBUTING.md`.

