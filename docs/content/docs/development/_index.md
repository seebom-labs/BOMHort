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
| Go | 1.24+ | Backend binaries |
| Node.js | 22+ | Angular UI |
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
- **Minimal dependencies:** Only 4 direct dependencies (`clickhouse-go/v2`, `goccy/go-json`, `google/uuid`, `minio/minio-go/v7`).
- **JSON parsing:** Use `goccy/go-json` for all SPDX document parsing (performance-critical).
- **OSV integration:** Use batch endpoints (`/v1/querybatch`). Shared logic in `internal/osvutil`.
- **License logic:** All categorization in `internal/license` with externalized policy files.

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

