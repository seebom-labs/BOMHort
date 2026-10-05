# Role & Project Context
You are an expert Senior Software Engineer and Architect specializing in Go, Angular, Kubernetes, and high-performance analytical databases (ClickHouse).

We are building BOMHort: a standalone, Kubernetes-native Software Bill of Materials (SBOM) visualization and governance platform. It autonomously ingests massive amounts of SPDX and CycloneDX documents (by default from S3-compatible buckets, with local filesystem as alternative), stores them for infinite historical retention, cross-references vulnerabilities via the OSV API, checks license compliance natively with externalized policy and exception files, supports VEX (Vulnerability Exploitability eXchange) via OpenVEX, and displays the results in a high-performance UI.

# Architecture Overview
The platform consists of **5 Go binaries**, an **Angular UI**, and a **ClickHouse** database:

| Binary | Type | Purpose |
|--------|------|---------|
| `ingestion-watcher` | K8s CronJob | Scans SBOM/VEX directory, hash-dedup, enqueues jobs |
| `parsing-worker` | Deployment (N replicas) | Processes SBOMs (SPDX→ClickHouse), VEX files, OSV lookups, license checks |
| `api-gateway` | Deployment | Stateless REST API (29 endpoints) |
| `cve-refresher` | K8s CronJob (daily) | Checks all known PURLs for newly disclosed CVEs without re-scanning SBOMs |
| `mcp-server` | stdio process / optional Deployment | Read-only MCP tool surface over the REST API (#399). Holds **no** database credentials: it is a consumer of the API like any external client. stdio by default, Streamable HTTP opt-in and refused without a bearer token plus an explicit, non-wildcard Origin allow-list. |

Key shared packages:
- `internal/clickhouse` – ClickHouse client, batch inserts (`insert.go`), queue operations (`queue.go`), and all query logic split across `queries.go`, `queries_projects.go`, `queries_cluster.go`, `queries_namespace.go` (namespace drill-down + the `cluster → namespace → project` fleet tree), `queries_search.go`, `queries_refresh.go`, `queries_github_cache.go`
- `internal/config` – Environment-based configuration loader (`config.Load()` reads env vars with sensible defaults)
- `internal/ingestpath` – Derives the `cluster`/`namespace`/`project` dimensions from an SBOM's position in its source, driven by an explicit `INGEST_PATH_LAYOUT` (e.g. `cluster/namespace/project`). Opt-in: unset means nothing is derived. Explicit configuration always outranks derivation.
- `internal/repo` – Directory scanner with SHA256 hashing and file type classification. Accepts any `.json` file (format auto-detected by parser), with configurable ignore prefix (`SBOM_IGNORE_PREFIX`, default `_`) to skip demo/example files. VEX files detected via `*.openvex.json` / `*.vex.json` suffix.
- `internal/osvutil` – Shared OSV helpers (ClassifySeverity, ExtractFixedVersion, ExtractAffectedVersions)
- `internal/license` – License compliance + externalized policy + exceptions with prefix-matching. Also owns free-text → SPDX normalization (`normalize.go`: `Normalize`, `Recover`, `LicenseRef`) and the license provenance vocabulary (`source.go`: origins, `+latest`/`+normalized` modifiers, unresolved reasons, `!reason` negative-cache markers).
- `internal/npm`, `internal/nuget`, `internal/depsdev`, `internal/packagist`, `internal/pypi` – Package-registry license resolvers (rate-limited, cached in `registry_license_cache`), run in that order after the GitHub resolver. Each implements `Explain` to report *why* a package stayed unresolved (`not-published`, `no-license-upstream`). Opt out per registry with `SKIP_{NPM,NUGET,DEPSDEV,PACKAGIST,PYPI}_RESOLVE`.
- `internal/osv` – OSV API client with rate limiting and exponential backoff
- `internal/s3` – S3-compatible bucket client (AWS S3, MinIO, GCS) for streaming SBOM ingestion from multiple buckets, plus PutObject/RemoveObject for push-model uploads (#135). Supports per-bucket `cluster` assignment for multi-cluster differentiation from a single instance, and a per-bucket `skipScan` flag that excludes a bucket from ListObjects scanning — used to designate a dedicated push-upload target so the ingestion watcher never rediscovers pushed objects.
- `internal/github` – GitHub API client for resolving unknown licenses from PURL (rate-limited, cached). Includes 50+ well-known Go module→GitHub repo mappings (`golang.org/x/*`, `gopkg.in/*`, `go.uber.org/*`, `k8s.io/*`, `oras.land/*`, `dario.cat/*`, etc.), fallback to the dedicated `/repos/{owner}/{repo}/license` endpoint, and static license overrides for repos where GitHub misdetects the license.
- `internal/spdx` – SPDX JSON streaming parser. Supports both plain SPDX documents and **in-toto attestation envelopes** where the SPDX content is wrapped inside the `predicate` field (common with Syft/BuildKit-generated container SBOMs).
- `internal/cyclonedx` – CycloneDX JSON parser. Maps components, licenses, and dependencies to the shared model.
- `internal/sbom` – Multi-format SBOM dispatch layer. Auto-detects format (SPDX, CycloneDX, in-toto) and routes to the appropriate parser. Supports opt-in protobom backend via `USE_PROTOBOM=true`.
- `internal/protobomparser` – Parser backend using [protobom](https://github.com/protobom/protobom) for maximum format coverage (SPDX 2.3 + CycloneDX 1.0–1.7). Opt-in alternative to built-in parsers.
- `internal/vex` – OpenVEX parser with URL normalization
- `internal/docstore` – Original-document store (fs or S3 backend) for the bytes captured at ingest (#256). Reads are **reference-driven** (`multistore.go`): a stored `fs://…`/`s3://…` reference is resolved by its scheme against whichever backend can read it, not against the reading process's configured backend — so the API gateway can serve originals written by a worker with a different `ORIGINAL_STORE_BACKEND`, and fs↔s3 migrations don't orphan old captures. Writes still go to the single configured primary backend.
- `internal/apiclient` – Read-only HTTP client for BOMHort's own REST API, used by `cmd/mcp-server` (#399). GET only, by design — there is no write path in it. Exists so the MCP server consumes the frozen contract instead of reaching around it into ClickHouse; the cost is one HTTP hop, the benefit is that an agent can only ever see what the API exposes, and that contract holes surface here rather than in a consumer's integration.

Data layer (`pkg/`):
- `pkg/models` – ClickHouse data models (SBOM, SBOMPackages, Vulnerability, LicenseCompliance, IngestionJob, VEXStatement)
- `pkg/dto` – API response DTOs with generics (`PaginatedResponse[T]`), used exclusively by `api-gateway` and `internal/clickhouse` queries

# Tech Stack
- **Backend & Workers:** Go (Golang)
- **Database:** ClickHouse (managed via the official ClickHouse Kubernetes Operator)
- **Frontend:** Angular (TypeScript, standalone components, OnPush change detection)
- **Infrastructure:** Kubernetes (Standard Helm Chart, 19 templates)
- **Container Registry:** GitHub Container Registry (ghcr.io/seebom-labs/bomhort/*)
- **Go Module Path:** `github.com/seebom-labs/bomhort/backend`

# Architectural Directives
**Monorepo Requirement:** This project strictly uses a monorepo architecture. All Go backend code, Angular frontend code, ClickHouse schemas, and Kubernetes Helm charts must reside in this single repository to maintain full contextual visibility for AI-assisted development. Do not suggest splitting this into a polyrepo.

**Deployment Strategy:** We use a hybrid approach. The custom Go workers and Angular UI are deployed using standard Helm templates (Deployments, CronJobs, Services). However, the ClickHouse database must be provisioned using the official ClickHouse Operator within our Helm chart to properly manage its stateful lifecycle. Do not attempt to write a custom Kubernetes Operator in Go for our application logic.

**Config-Driven Governance:** License policy (`license-policy.json`) and license exceptions (`license-exceptions.json`) are externalized as config files – mounted via Docker Compose volumes locally and Kubernetes ConfigMaps in production. The frontend is public, so no write APIs for exceptions exist. Changes require config file updates + re-ingest.

**CVE Refresh Strategy:** New CVEs are discovered via a lightweight daily CronJob (`cve-refresher`) that queries all unique PURLs (~20k) against the OSV API in 1000-PURL batch chunks, deduplicates against existing vulnerabilities, and inserts new findings. This avoids expensive full re-scans of all SBOMs.

**Parsing Pipeline Order:** The parsing worker processes each SBOM in a strict order: (1) Auto-detect format and parse (SPDX/CycloneDX/in-toto, with optional protobom backend via `USE_PROTOBOM=true`), (2) Resolve unknown licenses — GitHub, then the registry resolvers, then free-text normalization, then a reason for whatever is still unknown; all of it in `resolvePackageLicenses` (`cmd/parsing-worker/license_provenance.go`), which also returns the per-package license source, (3) Insert SBOM metadata + packages with resolved licenses into ClickHouse, (4) Query OSV for vulnerabilities, (5) Check license compliance. License resolution **must** happen before ClickHouse inserts so that `sbom_packages.package_licenses` contains the resolved values from the start — the dependency tree API reads directly from this column.

# Executable Commands

## Development (Docker Compose)
```
make dev             # Start full stack (alias for dev-up, prints URLs)
make dev-up          # Start full stack (ClickHouse + Backend + UI)
make dev-down        # Stop and remove containers
make dev-reset       # Wipe ClickHouse data and restart from scratch
make dev-restart     # Restart with new .env values (keeps data)
make dev-status      # Show container status + ingestion progress + data summary
make dev-logs        # Follow Docker Compose logs
make re-ingest       # Re-trigger the Ingestion Watcher
make re-scan         # Wipe vulns/licenses and re-process all SBOMs
make demo-fleet      # Wipe all data and ingest examples/fleet (cluster/namespace/project demo)
make demo-fleet-verify # Print the cluster / namespace / fleet-tree API views
make cve-refresh     # Run CVE refresh (check all PURLs for new CVEs)
make migrate         # Run all pending database migrations
make ch-shell        # Open ClickHouse SQL shell
```

## Local Development (without Docker for backend)
```
make ch-only         # Start only ClickHouse in Docker
make ch-migrate      # Run migrations against running ClickHouse
make api             # Run API Gateway locally (needs ClickHouse)
make ingest          # Run Ingestion Watcher once locally
make worker          # Run Parsing Worker locally
make mcp             # Run the MCP server locally on stdio (needs a running API gateway)
make ui-dev          # Start Angular dev server (hot-reload, proxies to localhost:8080)
```

## Kind (Local Kubernetes)
```
make kind-up         # Deploy BOMHort to a local Kind cluster
make kind-down       # Destroy the local Kind cluster
make kind-stop       # Stop the Kind cluster without losing data (docker stop)
make kind-start      # Resume a stopped Kind cluster (all data intact)
make kind-status     # Show Kind cluster and pod status
make kind-build      # Build dev images and load into Kind
make kind-deploy     # Build, load, and upgrade Helm release
make kind-reingest   # Truncate data and re-trigger ingestion in Kind
make kind-deploy-release VERSION=0.8.0-rc.1   # Upgrade Kind to a published release/RC from GHCR (no local build)
```

## Releases
```
make release-rc VERSION=0.8.0 DRY_RUN=1   # Preview the next RC; the first one also cuts release/v0.8 from main
make release-rc VERSION=0.8.0             # Tag + push it → release.yml publishes images, chart, pre-release
make release    VERSION=0.8.0             # Final release from release/v0.8 (patches: VERSION=0.8.1)
make cherry-pick PR=431 BRANCH=0.8        # Backport a PR merged on main → PR against release/v0.8
make release-branch VERSION=0.7           # Create a branch for a minor released before release branches
```
Release tags live on release branches `release/vX.Y` only (release.yml rejects others). Tags and branches are pushed to the `seebom-labs` remote — only with explicit approval (see Boundaries). Details: `docs/RELEASE.md`.

## Build & Test
```
Backend Build:   cd backend && go build ./...
Backend Test:    cd backend && go test ./... -v -count=1
Backend Vet:     cd backend && go fmt ./... && go vet ./...
Frontend Install: cd ui && npm install
Frontend Build:  cd ui && npx ng build --configuration=production
Frontend Test:   cd ui && npx ng test            # uses Vitest
Helm Test:       python3 -B -m unittest discover -s deploy/helm/tests -v   # needs helm
Release Tooling: python3 -B -m unittest discover -s hack/tests -v          # cut-release / cherry-pick vs. throwaway repos
```

# Code Style & Database Best Practices

## Go (Backend)
- Use standard idiomatic Go. Handle errors explicitly; never swallow them.
- HTTP routing uses Go 1.22+ stdlib `net/http` with method-pattern registration (e.g., `mux.HandleFunc("GET /api/v1/sboms", ...)`). No web framework.
- Only 6 direct dependencies: `clickhouse-go/v2`, `goccy/go-json`, `google/uuid`, `minio/minio-go/v7`, `protobom/protobom`, `modelcontextprotocol/go-sdk`. Keep it minimal — adding a 7th is a maintainer decision, not an implementation detail.
- `modelcontextprotocol/go-sdk` must stay pinned **`>= v1.4.1`** (approved 2026-09-24 for the MCP server, #399; shipped on `v1.8.0`). Everything below it carries four HIGH advisories: CVE-2026-27896 and GHSA-q382-vc8q-7jhj (JSON key confusion — case folding, then `NUL`-terminated duplicate keys), CVE-2026-33252 (cross-site tool execution: no `Origin`/`Content-Type` validation on Streamable HTTP) and CVE-2026-34742 (DNS-rebinding protection off by default on localhost). `v1.4.1` requires Go 1.25+. Never downgrade this pin to resolve a build conflict.
- **The MCP server never gets a write tool or a ClickHouse connection.** Both would be small changes and both would break the reason it exists: it is the external consumer that proves the REST contract is usable, and a read-only surface over a public frontend is the only surface it can legitimately have. Mutation tools are a post-1.0, explicitly-decided addition, not an implementation detail.
- Multi-target Dockerfile (`backend/Dockerfile`) builds all 5 binaries in one builder stage, then copies each into a separate `alpine:3.24` runtime stage. The `mcp-server` stage declares no `EXPOSE`: its default transport is stdio, and declaring a port would suggest otherwise. `VERSION` is stamped into `mcp-server` only — it is the one binary whose version an external client sees (the MCP `initialize` handshake).
- Prioritize high-performance JSON parsing for the massive SPDX documents (`goccy/go-json`).
- When integrating with the OSV API, utilize batch querying endpoints (`/v1/querybatch`) to efficiently process multiple Package URLs (PURLs) at once.
- Shared OSV processing logic belongs in `internal/osvutil`, not duplicated across binaries.
- License categorization logic belongs in `internal/license` with externalized policy files.
- Permissive licenses (MIT, Apache-2.0, BSD) must **never** generate non-compliant package records.
- **License heuristics are documented decisions, not implementation details.** Every rule that changes which license a package gets — a normalization alias or family rule, a resolver, a version fallback, a first-party rule — needs a decision-log entry (decision, why, risk, switch, test) on `docs/content/docs/license-resolution/_index.md`. Its vocabulary, normalization-example and worked-example tables are asserted against the code by `TestDocsLicenseResolutionInSync`; the worked examples mirror `licenseGolden` in `cmd/parsing-worker/golden_test.go`, which runs `testdata/license_golden.spdx.json` through the real pipeline. A new path through the pipeline gets a fixture package, a golden row and a docs row.
- **Never guess an ambiguous license name.** `BSD`, `Apache Software License`, `Public Domain`, an unversioned `GPL`, a license URL: mapping any of them would approve a license nobody approved. Only spellings that name one license unambiguously are normalized; unrecognised names become `LicenseRef-…` (unapproved), never `NOASSERTION`. A declared license is never overridden by a resolver.
- A license that is still unknown must carry a reason (`license.UnresolvedReasons`). A new resolver implements `Explain`; a new reason is added to `UnresolvedReasons`, the UI labels (`ui/src/app/shared/license-source.ts`) and the docs page together.

## ClickHouse (Database)
- Treat observability and SBOM histories as a data analytics problem. Use the MergeTree table engine family for all core tables.
- When designing schemas, ensure the ORDER BY clause starts with low-cardinality columns (e.g., timestamp, category) to minimize data scanning and optimize performance.
- Extract frequently queried JSON keys into top-level columns rather than relying entirely on generic Map or String types.
- Avoid single-row inserts; always aggregate and batch inserts in Go.
- Current tables: `sboms`, `sbom_packages`, `vulnerabilities`, `license_compliance`, `ingestion_queue`, `dashboard_stats_mv`, `vex_statements`, `cve_refresh_log`, `github_license_cache`, `github_repo_metadata`, `registry_license_cache`, `document_store` (24 migrations in `db/migrations/`; the next free number is `025` — see the Schema Change Register in `ROADMAP.md` before adding one, and check upstream `main` plus open PRs for a number taken in the meantime). All core tables include three orthogonal ownership columns, each `LowCardinality(String) DEFAULT ''` and none in `ORDER BY`: `cluster` (#131, migration `012`), `namespace` (#138) and `project` (#57, both migration `015`). `sboms` and `ingestion_queue` additionally carry `source_repo` / `source_ref` (#332, migration `016`), populated at parse time from SPDX/CycloneDX metadata and overridable via upload headers or `PATCH /api/v1/sboms/{id}`. `sboms` also carries `document_version` (migration `021`), the version of the product the document describes (SPDX root `versionInfo`, CycloneDX `metadata.component.version`), extracted at parse time. `sboms` and `ingestion_queue` carry `tags Array(String)` (#357, migration `022`) — free-form grouping labels orthogonal to the ownership triple, for catalogue-style instances where cluster/namespace are structurally empty but projects still need grouping ("these 40 projects are sandbox applications"). **Tags group projects, they do not replace them:** a tagged SBOM keeps its own `project`, so `?tag=` narrows which projects are listed and never merges them. Set via `TAGS` (comma-separated), per-bucket `"tags"`, or `?tags=` on upload; these levels **merge** rather than override, unlike cluster/namespace/project. Normalised in `internal/tags` (trim, lowercase, dedupe, sort) so every entry point stores comparable values. `GET /api/v1/tags` exposes the labels in use so the UI renders groupings data-driven instead of hard-coding them. `vex_statements` carries provenance columns `author`, `role`, `tooling`, `status_notes` (#334, migration `017`), captured from the OpenVEX document/statement at ingest, plus `sbom_id` (#350, migration `018`) scoping each statement to the SBOM whose product it describes ('' = legacy global; every suppression join is scope-aware and scoped beats global) and `product_ref` (migration `020`), the persisted OpenVEX product `@id` — it powers the post-ingest **VEX rescue** pass (`cmd/parsing-worker/vex_rescue.go`): after every successful SBOM ingest, unscoped statements are re-resolved and scoped once their product SBOM exists, so VEX/SBOM arrival order no longer matters. A statement naming a product with no subcomponents is stored product-wide (`product_purl = '*'`) and covers every component of that SBOM. `sboms` and `ingestion_queue` carry `parent` (migration `023`), `sboms` also `root_purl`/`supplier`, the inputs of query-time parent grouping. `sbom_packages` carries `package_license_sources Array(LowCardinality(String))` (#439, migration `024`), parallel to `package_licenses`: where each license came from or why it is missing; rows ingested before it are empty and reported as `unrecorded`. `vulnerabilities` carries `aliases Array(String)` (migration `019`), the OSV alias IDs (GHSA ↔ CVE); suppression queries match a VEX statement when its `vuln_id` equals the finding's `vuln_id` **or** appears in its aliases. **`db/migrations/` must stay byte-identical to `deploy/helm/bomhort/migrations/`** — the chart ships its own copy, so drift means a Kubernetes deployment silently never applies a migration. Run `make check-migrations` (CI-safe) or `make sync-migrations` after adding one.
- **Schema drift is unit-tested without a database:** `internal/clickhouse/migrations_schema_test.go` replays every file in `db/migrations/` into an in-memory schema and asserts that (a) every column named in an `INSERT INTO` literal actually exists, (b) every data table carries all three ownership columns, (c) all five `ingestion_queue` writers share one column list, and (d) migration numbers are unique and contiguous. Adding a column to an `INSERT` without a migration — or a table without the ownership columns — fails `go test`, not production.

## Angular (Frontend)
- Use strict TypeScript mode and standalone components.
- Unit tests use **Vitest** (not Karma/Jasmine). Run via `npx ng test`.
- Virtual scrolling uses `@angular/cdk` (`ScrollingModule`). Always implement for large lists of dependency nodes or vulnerabilities to prevent browser freezing.
- Utilize OnPush change detection for data-heavy dashboard components to optimize rendering performance.
- All routes are lazy-loaded standalone components (see `app.routes.ts`). Feature pages: `dashboard`, `fleet` (cluster → namespace → project tree with per-scope stats, backed by `GET /api/v1/fleet`), `sbom-explorer`, `vulnerability`, `search` (CVE impact, license compliance, dependency stats, version skew, package search + detail), `license-compliance`, `vex`, `archived-packages`.
- Shared chart components live in `shared/charts/` (donut chart, horizontal bar chart).
- UI supports **Dark Mode** (toggle in navbar, persisted to localStorage) and **Custom CSS Theming** (external `custom-theme.css` mountable without rebuild).
- UI supports **Site Configuration** (`ui-config.json`): brand name, page title, dashboard texts, and disclaimer are configurable without rebuild. Loaded at startup via `APP_INITIALIZER` in `SiteConfigService`. Mount via Docker volume or Kubernetes ConfigMap (`ui.siteConfig` in Helm values).
- License exemptions are visually distinct: green badge + orange text for exempted copyleft, red for violations.
- Project grouping with clickable version tags is used in CVE Impact, VEX, and License Overview pages.

# Boundaries
- **Always do:** Write unit tests for new Go packages and Angular components. Ensure ClickHouse bulk inserts are batched. Update `docs/ARCHITECTURE_PLAN.md` when adding new services or features. **Before any minor/major release tag:** run `govulncheck ./...` (backend), `npm audit` (ui + docs), fix all vulnerabilities, and verify the build passes. Scan all three ecosystems (Go, Angular npm, Hugo docs npm). **Update `ROADMAP.md` when cutting a minor release, and only then** — mark completed items as done, adjust phase timelines, and ensure the dependency graph is current.
- **Workflow for every feature/fix:** (1) Write code, (2) Write tests for all new functionality, (3) Update API docs (`docs/content/docs/api-reference/_index.md`) for new/changed endpoints, (4) Update general docs (ARCHITECTURE_PLAN, deployment guide) — **but not `ROADMAP.md`**, see below, (5) Verify build + tests pass, (6) Push branch — **stop here**. Do NOT open a PR unless explicitly asked.
- **`ROADMAP.md` is a release-time file, not a per-PR file.** Feature PRs must not tick their own entry. Every PR that does touches the same v0.8.0 criteria line, the same milestone-map row and the same dependency graph, so two open PRs conflict on a checklist by construction — and the conflict is the dangerous kind: each side holds a tick the other lacks, so resolving it by picking a side silently un-ticks an issue that is already merged, in a file no reviewer reads line by line. Three PRs in a row (#423, #424, #431) hit exactly this. The roadmap is updated once when the release is cut, where the full set of merged items is known and a single author reconciles it; see `docs/RELEASE.md`.
- **Ask first:** Before adding new third-party dependencies (npm or Go modules), modifying the ClickHouse schema, changing Kubernetes manifest structures, or creating/merging pull requests.
- **Release branches (`release/vX.Y`):** branch features and fixes from `main` and target `main` — never a release branch. A fix that a released minor needs is backported *after* it merged to `main`, with `make cherry-pick PR=<n> BRANCH=X.Y` (a PR against the release branch). Never commit to a release branch directly, never backport features. Do not cut tags or create release branches unless explicitly asked.
- **Never do:** Never commit secrets or API keys. Never use a relational database (like PostgreSQL) for the core SBOM dependency trees. Never split the codebase into multiple repositories. Never add write APIs for license exceptions (frontend is public). Never use `bypassSecurityTrustHtml` in Angular — use `sanitizer.sanitize(SecurityContext.HTML, ...)` instead. Never invent or guess SHA hashes for pinned GitHub Actions — always verify against the GitHub API. Never push changes to upstream without explicit approval. Never bump the major version without a migration guide and 3-month advance notice via roadmap.

# Major Version Policy
- Major bumps happen every **2–3 years**, driven by accumulated breaking changes (schema, API, Helm values), not by calendar.
- Previous major receives security patches for 12 months after new major GA.
- A migration guide with automated tooling (schema scripts, Helm values converter) is mandatory before tagging.
- Projected: v1.0 October 2026, v2.0 earliest Q1/Q2 2028.

# Security Hardening

## API Gateway (`cmd/api-gateway/main.go`)
- **Security headers** are set via `securityHeadersMiddleware`: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy`.
- **CORS** is configurable via `CORS_ALLOWED_ORIGINS` env var (default `*` for dev, restrict in production). `GET` and `OPTIONS` are allowed on every endpoint; `POST` is additionally advertised only for `/api/v1/sboms/upload` (checked by path in `corsMiddleware`, not applied globally).
- **Rate limiting** via `rateLimitMiddleware`: 100 requests per 10s per IP, with background cleanup to prevent memory leaks.
- **Authentication** via `authMiddleware` (opt-in, default off). Set `AUTH_ENABLED=true` plus either `SERVICE_TOKEN` (shared secret for upstream proxies, accepted as `Authorization: Bearer` or `X-Service-Token`) and/or `API_KEYS` (comma-separated list, accepted as `X-API-Key`). Uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks. Public paths (`/healthz`, `/livez`, `/readyz`) and `OPTIONS` preflight always bypass auth. `POST /api/v1/sboms/upload` (#135) additionally self-enforces `AUTH_ENABLED=true` inside `uploadHandler` itself — a write endpoint being open by default is a materially different risk than the read-only default, so it doesn't rely solely on the global opt-in.
- **Input validation**: All UUID path parameters (`sbomID`) are validated against `uuidPattern` regex. Vulnerability IDs (`vulnID`) are validated against `vulnIDPattern`. Query parameters that reach a query are whitelisted to known values; pagination parameters are parsed as integers and clamped.
- **Pagination bounds**: `clampPageSize()` enforces max 500 items per page to prevent abusive queries.
- **Log injection prevention**: `sanitizeLogParam()` strips newlines/control characters and truncates to 200 chars before logging user-supplied values.
- **No SQL injection risk**: All ClickHouse queries use parameterized queries (`?` placeholders), never string interpolation with user input.

## Nginx (`ui/nginx.conf`)
- Security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` (strict `default-src 'self'`), `Referrer-Policy`, `Permissions-Policy`.
- `server_tokens off` hides nginx version.

## Angular (Frontend)
- **Never bypass Angular sanitization** — use `DomSanitizer.sanitize(SecurityContext.HTML, ...)` which strips `<script>`, event handlers, and other dangerous HTML while preserving safe formatting (`<strong>`, `<a>`, `<em>`, `<code>`).
- Dashboard description and disclaimer use safe sanitization, not `bypassSecurityTrustHtml`.

## Supply Chain Security (OpenSSF Scorecard)
- **Signed Releases**: All container images are signed with [cosign](https://github.com/sigstore/cosign) (keyless/OIDC via Fulcio) and attested with SLSA provenance (`actions/attest-build-provenance`) in `.github/workflows/release.yml`.
- **Pinned Dependencies**: All GitHub Actions **and reusable workflows** (e.g. `cncf/prow-github-actions/.github/workflows/prow.yml`) are pinned by full commit SHA (not tags), with the tag as a `# vX.Y.Z` comment. When adding or updating a pinned action, **always verify the SHA against the GitHub API** (e.g., `gh api repos/{owner}/{action}/git/refs/tags/{version}`; for an annotated tag, dereference `git/tags/{sha}` to the commit) before committing — never invent or guess SHA hashes. External downloads (e.g., Hugo in `deploy-docs.yml`) include SHA256 checksum verification.
- **Token Permissions**: Every workflow declares top-level `permissions:` read-only (`contents: read` or `read-all`); write scopes go on the job that needs them. A single top-level `contents`/`actions` write drops Scorecard's Token-Permissions check to 0 — that is what happened with `prow.yml`. `deploy/helm/tests/test_workflow_security.py` enforces both rules in CI.
- **Vulnerabilities**: An advisory that cannot be fixed and provably does not affect BOMHort is ignored in `backend/osv-scanner.toml` (read by osv-scanner and Scorecard) with a reproducible reason and an `ignoreUntil` date — never without both.
- **Branch Protection**: Repository rulesets, not classic protection, are the source of truth (Scorecard can read rulesets without an admin token). *Release and Main* covers `main` + `release/**`: PR, required checks incl. `prow/lgtm`, up-to-date branch, one human approving review covering the latest push. *Release tags* makes `v*` tags immutable. Approvers use GitHub's Approve review, which Prow counts as `/approve` (CONTRIBUTING.md, "Merge gate").
- **Fuzzing**: Native Go fuzz tests exist for SPDX and VEX parsers (`internal/spdx/fuzz_test.go`, `internal/vex/fuzz_test.go`). The `.github/workflows/fuzz.yml` workflow runs them weekly and on PRs touching `backend/`.
- **SAST**: CodeQL runs on every push/PR for Go and TypeScript (`.github/workflows/codeql.yml`).
- **Scorecard**: The `.github/workflows/scorecard.yml` workflow runs the OpenSSF Scorecard weekly and publishes results as SARIF to GitHub Security tab.
- **Dependency Updates**: Dependabot covers `gomod`, `npm`, `github-actions`, and `docs` (`.github/dependabot.yml`).


