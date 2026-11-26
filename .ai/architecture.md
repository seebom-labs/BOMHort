# Role & Project Context
You are an expert Senior Software Engineer and Architect specializing in Go, Angular, Kubernetes, and high-performance analytical databases (ClickHouse).

We are building BOMHort: a standalone, Kubernetes-native Software Bill of Materials (SBOM) visualization and governance platform. It autonomously ingests massive amounts of SPDX and CycloneDX documents (by default from S3-compatible buckets, with local filesystem as alternative), stores them for infinite historical retention, cross-references vulnerabilities via the OSV API, checks license compliance natively with externalized policy and exception files, supports VEX (Vulnerability Exploitability eXchange) via OpenVEX, and displays the results in a high-performance UI.

# Architecture Overview
The platform consists of **5 Go binaries**, an **Angular UI**, and a **ClickHouse** database:

| Binary | Type | Purpose |
|--------|------|---------|
| `ingestion-watcher` | K8s CronJob | Scans SBOM/VEX directory, hash-dedup, enqueues jobs |
| `parsing-worker` | Deployment (N replicas) | Processes SBOMs (SPDX→ClickHouse), VEX files, OSV lookups, license checks |
| `api-gateway` | Deployment | Stateless REST API (37 endpoints) |
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
- `internal/advisory` – OSV-format advisory feeds (`ADVISORY_SOURCES`, `name|index[|purl-prefix…]`). `Sync` (cve-refresher) keeps `advisory_records` current from each feed's `[{id, modified}]` index; `Matcher` (worker + refresher) evaluates records with apk/dpkg/rpm version order and lets a feed authoritative for a PURL prefix replace osv.dev's verdict — a backported fix drops the upstream match, `not_affected` becomes a feed-authored VEX statement. Operator docs: `docs/content/docs/advisory-feeds/_index.md`.
- `internal/exploit` – Public exploit-code indexes (Nuclei `cves.json`, Metasploit `modules_metadata_base.json`, Exploit-DB `files_exploits.csv`): fetch (https or `file://` mirror, size-capped), parse to `(cve, ref, url)`, and `Sync` each source as an independent snapshot into `exploit_refs` from the `cve-refresher`. Findings are matched at query time by `vuln_id` or alias (`internal/clickhouse/queries_exploit.go`), never copied onto `vulnerabilities`. Opt out with `SKIP_EXPLOIT_REFS`.
- `internal/s3` – S3-compatible bucket client (AWS S3, MinIO, GCS) for streaming SBOM ingestion from multiple buckets, plus PutObject/RemoveObject for push-model uploads (#135). Supports per-bucket `cluster` assignment for multi-cluster differentiation from a single instance, and a per-bucket `skipScan` flag that excludes a bucket from ListObjects scanning — used to designate a dedicated push-upload target so the ingestion watcher never rediscovers pushed objects.
- `internal/github` – GitHub API client for resolving unknown licenses from PURL (rate-limited, cached). Includes 50+ well-known Go module→GitHub repo mappings (`golang.org/x/*`, `gopkg.in/*`, `go.uber.org/*`, `k8s.io/*`, `oras.land/*`, `dario.cat/*`, etc.), fallback to the dedicated `/repos/{owner}/{repo}/license` endpoint, and static license overrides for repos where GitHub misdetects the license.
- `internal/spdx` – SPDX JSON streaming parser. Supports both plain SPDX documents and **in-toto attestation envelopes** where the SPDX content is wrapped inside the `predicate` field (common with Syft/BuildKit-generated container SBOMs).
- `internal/cyclonedx` – CycloneDX JSON parser. Maps components, licenses, and dependencies to the shared model.
- `internal/sbom` – Multi-format SBOM dispatch layer. Auto-detects format (SPDX, CycloneDX, in-toto) and routes to the appropriate parser. Supports opt-in protobom backend via `USE_PROTOBOM=true`.
- `internal/protobomparser` – Parser backend using [protobom](https://github.com/protobom/protobom) for maximum format coverage (SPDX 2.3 + CycloneDX 1.0–1.7). Opt-in alternative to built-in parsers.
- `internal/vex` – OpenVEX parser with URL normalization
- `internal/docstore` – Original-document store (fs or S3 backend) for the bytes captured at ingest (#256). Reads are **reference-driven** (`multistore.go`): a stored `fs://…`/`s3://…` reference is resolved by its scheme against whichever backend can read it, not against the reading process's configured backend — so the API gateway can serve originals written by a worker with a different `ORIGINAL_STORE_BACKEND`, and fs↔s3 migrations don't orphan old captures. Writes still go to the single configured primary backend.
- `internal/rulesource` – Fetches a rules document from a file path list, an `https://` URL (bearer token, ETag, 10 MiB cap, URL never logged) or `s3://bucket/key`, and keeps it current in a generic `Watcher[T]` with last-known-good semantics: transport errors keep the old value, a parse failure is reported (`ErrInvalid`) but never replaces it, a missing remote document is an error, never "no rules". Used for license exceptions (`license.WatchExceptions`).
- `internal/claimlock` – `Locker` around `ClaimJobs` (#483): a Kubernetes Lease via client-go leader election in-cluster (`POD_NAMESPACE` required), an in-process mutex elsewhere. A claim that outlives `maxHold` or loses the Lease returns `ErrLeaseLost` and is discarded; the worker requeues its own leftover claims on the next call.
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

**Config-Driven Governance:** License policy (`license-policy.json`) and license exceptions (`license-exceptions.json`) are externalized as config files – mounted via Docker Compose volumes locally and Kubernetes ConfigMaps in production. The frontend is public, so no write APIs for exceptions exist. Exceptions can instead come from an `https://` URL or `s3://bucket/key` (`EXCEPTIONS_SOURCE` / Helm `licenseExceptions.source`). The exceptions are **reloaded live** (`EXCEPTIONS_REFRESH_INTERVAL`, ConfigMap mounted as a directory, never `subPath`), and a change is applied **retroactively**: a worker enqueues one `license_recheck` job (`cmd/parsing-worker/license_recheck.go`) that re-evaluates the stored `license_compliance` rows with `license.Reevaluate` and rewrites only changed rows — no re-ingest. Policy changes (recategorisation) still require a re-scan. The operator-facing documentation for all of this is `docs/content/docs/license-exceptions/_index.md`, not the deployment guide.

**CVE Refresh Strategy:** New CVEs are discovered via a lightweight daily CronJob (`cve-refresher`) that queries all unique PURLs (~20k) against the OSV API in 1000-PURL batch chunks, deduplicates against existing vulnerabilities, and inserts new findings. This avoids expensive full re-scans of all SBOMs.

**Parsing Pipeline Order:** The parsing worker processes each SBOM in a strict order: (1) Auto-detect format and parse (SPDX/CycloneDX/in-toto, with optional protobom backend via `USE_PROTOBOM=true`), (2) Resolve unknown licenses — GitHub, then the registry resolvers, then free-text normalization, then a reason for whatever is still unknown; all of it in `resolvePackageLicenses` (`cmd/parsing-worker/license_provenance.go`), which also returns the per-package license source, (3) Insert SBOM metadata + packages with resolved licenses into ClickHouse, (4) Query OSV for vulnerabilities, (5) Check license compliance. License resolution **must** happen before ClickHouse inserts so that `sbom_packages.package_licenses` contains the resolved values from the start — the dependency tree API reads directly from this column.
