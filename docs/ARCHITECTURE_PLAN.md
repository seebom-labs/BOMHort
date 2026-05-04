# SeeBOM – Architecture Blueprint v7

> **Status:** K8s-DEPLOYMENT READY + CVE REFRESH  
> **Date:** 2026-03-12  
> **Author:** AI Architect

## TL;DR

Kubernetes-native SBOM platform as a monorepo. Go backend with four binaries (CronJob Ingestion-Watcher, scalable Parsing-Workers, stateless API-Gateway, background CVE-Refresher). ClickHouse as the analytical database with MergeTree tables and array-based dependency storage. Angular frontend with virtual scrolling, OnPush change detection, full-text search, dark-mode toggle, and custom CSS theming. The SPDX files already exist as 1000+ files in the repository — no external scanner needed. Job coordination via a ClickHouse queue table (no NATS/Redis). **VEX support (OpenVEX)** enables vendor-side vulnerability assessment. **Cross-project search** for CVE impact, license violations, and dependency statistics. **License policy + exceptions** fully externalized as config files (no rebuild needed). **CVE Refresher** incrementally checks all known PURLs against OSV for newly disclosed CVEs — without re-scanning all SBOMs.

---

## 1. Monorepo Directory Structure

```
seebom/
├── AGENTS.md
├── README.md
├── LICENSE
├── Makefile                    # dev, dev-reset, re-ingest, re-scan, ch-shell, etc.
├── .env.example                # All configurable variables documented
├── docker-compose.yml
├── docs/
│   ├── ARCHITECTURE_PLAN.md
│   └── DEPLOYMENT_GUIDE.md
├── backend/
│   ├── Dockerfile                  # Multi-stage, multi-target (4 binaries)
│   ├── .dockerignore
│   ├── go.mod / go.sum
│   ├── cmd/
│   │   ├── ingestion-watcher/main.go   # K8s CronJob
│   │   ├── parsing-worker/main.go      # SBOM + VEX processor
│   │   ├── api-gateway/main.go         # REST API (16 endpoints)
│   │   └── cve-refresher/main.go       # Background CVE Refresh CronJob
│   ├── internal/
│   │   ├── spdx/              # SPDX JSON streaming parser
│   │   ├── vex/               # OpenVEX parser (with URL normalization)
│   │   ├── clickhouse/
│   │   │   ├── client.go      # Connection + hash dedup
│   │   │   ├── queue.go       # ClickHouse queue (job_type: sbom|vex)
│   │   │   ├── insert.go      # Batch INSERTs (SBOM, Packages, Vulns, Licenses, VEX)
│   │   │   ├── queries.go     # Dashboard, SBOM list, vuln list, license, VEX, deps
│   │   │   ├── queries_search.go  # SBOM detail, CVE impact, license violations, dep stats
│   │   │   ├── queries_refresh.go # CVE Refresh: PURL dedup, reverse-lookup, refresh log
│   │   │   └── queries_github_cache.go # GitHub license cache read/write
│   │   ├── github/            # GitHub API client for license resolution (PURL→license)
│   │   ├── osv/               # OSV API client (rate-limited, exponential backoff retry)
│   │   ├── osvutil/           # Shared OSV helpers (severity, fixed version, affected versions)
│   │   ├── s3/                # S3-compatible bucket client (AWS S3, MinIO, GCS)
│   │   ├── license/           # License compliance + externalized policy + exceptions
│   │   ├── repo/              # Filesystem scanner (SBOM + VEX, SHA256)
│   │   └── config/            # Environment-based configuration
│   └── pkg/
│       ├── models/            # SBOM, VEXStatement, Vulnerability, License, IngestionJob
│       └── dto/               # API DTOs
├── ui/
│   ├── Dockerfile             # Angular build → Nginx
│   ├── nginx.conf             # SPA routing + API proxy
│   └── src/
│       ├── index.html             # Optionally loads custom-theme.css
│       ├── styles.scss            # CSS Custom Properties (60+ variables, light + dark)
│       ├── assets/
│       │   └── custom-theme.example.css   # Template for custom branding
│       └── app/
│           ├── app.ts                 # Navbar + dark-mode toggle
│           ├── app.routes.ts          # 10 lazy-loaded routes
│           ├── core/                  # ApiService, models, HTTP interceptor
│           ├── shared/charts/         # DonutChart, HorizontalBarChart (themeable)
│           └── features/
│               ├── archived-packages/  # Archived GitHub repos (dependency health)
│               ├── dashboard/          # Stats + donut charts + bar charts + VEX counts
│               ├── sbom-explorer/      # SBOM list + detail (vulns/licenses/deps tabs)
│               ├── vulnerability/      # Vuln list with VEX status badges + filter
│               ├── search/
│               │   ├── cve-impact.component.ts          # CVE → affected projects
│               │   ├── license-violations.component.ts  # Projects with license issues
│               │   └── dependency-stats.component.ts    # Top dependencies cross-project
│               ├── license-compliance/ # License overview
│               └── vex/                # VEX statements (with empty state)
├── db/
│   └── migrations/            # 001-011 SQL migrations
├── sboms/                     # Config files + example SBOMs/VEX
│   ├── license-policy.json        # Permissive/copyleft classification
│   ├── license-exceptions.json    # CNCF-format exceptions
│   ├── _example.spdx.json
│   ├── _example.openvex.json
│   ├── golang-common.openvex.json
│   └── otel-protobuf.openvex.json
└── deploy/
    └── helm/seebom/           # 19 Helm templates
        ├── configmap.yaml
        ├── configmap-license-exceptions.yaml
        ├── configmap-license-policy.yaml
        ├── configmap-custom-theme.yaml
        ├── configmap-migrations.yaml
        ├── configmap-nginx.yaml
        ├── configmap-ui-config.yaml
        ├── secret.yaml
        ├── deployment-api-gateway.yaml
        ├── deployment-parsing-worker.yaml  # git-sync initContainer
        ├── deployment-ui.yaml              # Optional custom-theme + ui-config volumes
        ├── cronjob-ingestion-watcher.yaml  # git-sync initContainer
        ├── cronjob-cve-refresher.yaml      # Daily CVE refresh (configurable)
        ├── job-migrate.yaml                # DB migration job (runs at install/upgrade)
        ├── job-seed-sboms.yaml             # Git-clone seed job for large SBOM repos
        ├── pvc-sbom-data.yaml              # PVC for SBOM storage
        ├── service-api-gateway.yaml
        ├── service-ui.yaml
        └── clickhouse-installation.yaml
```

## 2. Data Flow

```
┌─────────────────────────────────────────────────────────┐
│                    SBOM Sources                          │
│                                                          │
│  S3 (default):                                           │
│    s3://cncf-subproject-sboms/k3s-io/...spdx.json       │
│    s3://cncf-project-sboms/k3s-io/...spdx.json          │
│    (multiple buckets, streamed with pagination)          │
│                                                          │
│  Local (alternative):                                    │
│    sboms/*.spdx.json + *.openvex.json                   │
└──────────────────────┬──────────────────────────────────┘
       │ S3 ListObjects (streamed) + filepath.Walk (local)
       │ SHA256 hashing + file-type detection (sbom|vex)
       ▼
Ingestion Watcher (CronJob)
       │ Hash dedup → batch INSERT INTO ingestion_queue (500/batch)
       │ SBOM_LIMIT applies to SBOMs only – VEX files are always included
       │ SourceFile = relative path (local) or s3://bucket/key (S3)
       ▼
ClickHouse: ingestion_queue (status='pending')
       │ SELECT + Claim (status='processing')
       ▼
Parsing Workers (N replicas)
       ├── Local files: os.Open(filepath.Join(sbomDir, sourceFile))
       ├── S3 files:    s3.GetObject(bucket, key) → io.ReadCloser
       ├── job_type=sbom: go-json → OSV Batch (rate-limited) → License Check → Batch INSERT
       └── job_type=vex:  OpenVEX Parse (URL normalization) → INSERT vex_statements
       ▼
ClickHouse: sboms, sbom_packages, vulnerabilities, license_compliance, vex_statements
       │
       │         ┌──────────────────────────────────┐
       │         │ CVE Refresher (CronJob, daily)   │
       │         │  1. SELECT DISTINCT PURLs (~20k) │
       │         │  2. OSV BatchQuery (1000/chunk)   │
       │         │  3. Dedup vs existing vulns       │
       │         │  4. Reverse-lookup PURL→SBOMs     │
       │         │  5. INSERT new vulns + log        │
       │         └──────────────────────────────────┘
       │
       ├── Dashboard:      Aggregated stats + VEX effective/suppressed + CVE refresh status
       ├── SBOM Detail:    Vulns + licenses (with package list) + dependencies per project
       ├── SBOM Explorer:  Full-text search across project name/file path/version
       ├── CVE Impact:     has(package_purls, ?) → all affected projects
       ├── Violations:     sumIf(copyleft|unknown) − exceptions (from config file)
       └── Dep Stats:      ARRAY JOIN + count(DISTINCT sbom_id) cross-project
       ▼
API Gateway (REST) → 16 Endpoints
       │ HTTP/JSON + CORS
       ▼
Angular UI (11 lazy-loaded routes, virtual scrolling, OnPush, dark mode)
       │ Custom CSS theme mountable without Angular rebuild
```

## 3. API Endpoints (17)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/healthz` | Health check |
| GET | `/api/v1/stats/dashboard` | Dashboard statistics (incl. VEX effective/suppressed, license breakdown) |
| GET | `/api/v1/stats/dependencies?limit=N` | Top-N dependencies cross-project with vuln count |
| GET | `/api/v1/stats/version-skew?page=&page_size=&search=` | Packages with inconsistent versions across projects (paginated, searchable) |
| GET | `/api/v1/sboms?page=&page_size=&search=` | Paginated SBOM list with package/vuln counts |
| GET | `/api/v1/sboms/{id}/detail` | SBOM detail with severity breakdown |
| GET | `/api/v1/sboms/{id}/vulnerabilities` | All vulns for an SBOM with VEX status |
| GET | `/api/v1/sboms/{id}/licenses` | License breakdown per SBOM (with package list per license) |
| GET | `/api/v1/sboms/{id}/dependencies` | Dependency tree as array reconstruction |
| GET | `/api/v1/vulnerabilities?page=&vex_filter=` | Paginated vuln list (optional: vex_filter=effective) |
| GET | `/api/v1/vulnerabilities/{id}/affected-projects` | All projects affected by a CVE (direct + transitive) |
| GET | `/api/v1/licenses/compliance` | Aggregated license overview |
| GET | `/api/v1/projects/license-compliance` | Projects with copyleft/unknown licenses (filtered by exceptions) |
| GET | `/api/v1/license-exceptions` | Active license exceptions (read-only, from config file) |
| GET | `/api/v1/license-policy` | Active license classification (permissive/copyleft lists) |
| GET | `/api/v1/vex/statements?page=&page_size=` | Paginated VEX statements with matched affected_sboms |
| GET | `/api/v1/packages/archived` | Packages using archived GitHub repos (no longer maintained) |

## 4. ClickHouse Schema (11 Migrations)

| Table | Engine | ORDER BY | Purpose |
|-------|--------|----------|---------|
| `sboms` | ReplacingMergeTree | (sbom_id) | SBOM metadata |
| `sbom_packages` | MergeTree | (sbom_id) | Parallel arrays (names, PURLs, licenses, relationships) |

> **Package Name Sanitization:** Go SBOM generators (e.g. `bom` by kubernetes-sigs) frequently capture temporary build directories as package names during CI/CD builds (e.g. `tmp.ej9m9OiO2V`). These Go artifacts are cleaned up in two places:
> 1. **SPDX Parser** (`internal/spdx/parser.go`): `cleanPackageName()` detects `tmp.<alphanumeric 6+>` patterns via regex and replaces them with the PURL-based name (e.g. `github.com/cncf/xds/go`) or the SPDX ID as a fallback.
> 2. **License Checker** (`internal/license/checker.go`): As a second safety net, packages with temp names are completely excluded from compliance analysis — they appear in neither `non_compliant_packages` nor `exempted_packages`.

| `vulnerabilities` | MergeTree | (sbom_id, purl, vuln_id) | OSV results |
| `license_compliance` | SummingMergeTree | (sbom_id, license_id) | License compliance per SBOM (+exempted_packages, exemption_reason) |
| `ingestion_queue` | ReplacingMergeTree | (job_id) | Job queue (job_type: sbom/vex) |
| `dashboard_stats_mv` | SummingMergeTree (MV) | (stat_date) | Pre-aggregated daily stats |
| `vex_statements` | ReplacingMergeTree | (vuln_id, product_purl, vex_id) | OpenVEX statements |
| `cve_refresh_log` | MergeTree | (started_at, refresh_id) | CVE refresh run history (timestamp, results, status) |
| `github_license_cache` | ReplacingMergeTree | (repo) | Cache for resolved GitHub licenses (avoids API redundancy) |
| `github_repo_metadata` | ReplacingMergeTree | (repo) | GitHub repo metadata (archived, fork, stars, pushed_at) for dependency health |

### Key Queries for Search Features

**CVE Impact:** `has(package_purls, ?)` uses ClickHouse's native array search to find PURLs across all SBOMs. Direct/transitive is determined via `rel_source_indices[0]` (root package).

**License Violations:** `sumIf(package_count, category = 'copyleft')` + `groupArrayArrayIf(non_compliant_packages, ...)` aggregates per SBOM. Exceptions are filtered at query time (no re-ingest needed).

**Dependency Stats:** `ARRAY JOIN package_names, package_purls, package_versions` expands the parallel arrays, then `count(DISTINCT sbom_id)` for cross-project counting.

## 5. VEX Architecture

**Format:** OpenVEX (JSON, Spec v0.2.0)  
**File Detection:** `*.openvex.json` or `*.vex.json`  
**Storage:** `vex_statements` table (ReplacingMergeTree), ORDER BY `(vuln_id, product_purl, vex_id)`  
**Statuses:** `not_affected`, `affected`, `fixed`, `under_investigation`  
**Justifications:** `component_not_present`, `vulnerable_code_not_present`, `inline_mitigations_already_exist`, etc.  
**URL Normalization:** VEX vulnerability `@id` URLs are reduced to plain IDs (e.g. `https://pkg.go.dev/vuln/GO-2025-4188` → `GO-2025-4188`).  
**SBOM_LIMIT:** VEX files are never truncated by SBOM_LIMIT — always fully processed.

**Dashboard Integration:**
- `effective_vulnerabilities = total_vulnerabilities - suppressed_by_vex`
- `suppressed_by_vex` = COUNT(DISTINCT vulns with VEX status=not_affected)

**API Filtering:**
- `GET /api/v1/vulnerabilities?vex_filter=effective` — excludes not_affected vulns
- Vulnerability rows carry a `vex_status` field via LEFT JOIN
- VEX statements API returns `affected_sboms` array with matched SBOMs

## 6. OSV Integration

**Endpoint:** `POST https://api.osv.dev/v1/querybatch`  
**Batch Limit:** 1000 PURLs per request (chunked)  
**Rate Limiting:** Token bucket (10 req/s, burst 5) — shared globally per worker process  
**Retry:** Exponential backoff on HTTP 429/503 (up to 5 retries, 500ms → 30s)  
**Skip Mode:** `SKIP_OSV=true` for fast initial ingestion (licenses only), then `make re-scan` with `SKIP_OSV=false`

## 7. License Policy (see Section 10)

Moved to Section 10 for comprehensive coverage including exemptions and visual representation.

## 8. Angular UI Architecture

| Route | Component | Key Features |
|-------|-----------|-------------|
| `/` | DashboardComponent | KPI cards (incl. VEX, exempted), 3 donut charts, 2 bar charts, CVE refresh banner, quick links |
| `/sboms` | SbomListComponent | **Full-text search** (project name, file path, version), virtual scroll, package/vuln count |
| `/sboms/:id` | SbomDetailComponent | **3 tabs:** Vulnerabilities (VEX badges), Licenses (exemption status + package list), Dependencies (tree, exempted=orange, **archived=badge**) |
| `/vulnerabilities` | VulnerabilityListComponent | Virtual scroll, VEX status badges, all/effective toggle |
| `/cve-impact` | CVEImpactComponent | **CVE search field** → affected projects with DIRECT/TRANSITIVE badge |
| `/licenses` | LicenseOverviewComponent | Category cards + virtual scroll |
| `/license-compliance` | LicenseViolationsComponent | **2 tabs:** Violations (filtered by exceptions), active exceptions |
| `/dependencies` | DependencyStatsComponent | Top-100 dependencies, version pills, vuln count, unique deps counter |
| `/vex` | VEXListComponent | Virtual scroll, status badges, justification, empty state |
| `/archived-packages` | ArchivedPackagesComponent | Grouped by repo, project aggregation with version tags, stars, last push |

**All components:** Standalone, OnPush change detection, lazy-loaded.

**Theming:**
- 60+ CSS custom properties in `styles.scss` (layout, brand, navbar, text, severity, status, license, charts)
- **Dark Mode Toggle** in the navbar (top right), persisted to `localStorage`, respects `prefers-color-scheme`
- **Custom Theme CSS:** External `custom-theme.css` mountable without Angular rebuild. Overrides any CSS variables.
  - K8s: `seebom-custom-theme` ConfigMap (`ui.customTheme.enabled: true`)
  - Local: `CUSTOM_THEME=./my-theme.css` in `.env`
- **Site Configuration (ui-config.json):** All UI texts (brand name, page title, dashboard title/description/disclaimer, footer) configurable via external JSON file without Angular rebuild. Loaded via `APP_INITIALIZER` at app startup. Missing keys fall back to built-in defaults.
  - K8s: `seebom-ui-config` ConfigMap (`ui.siteConfig.enabled: true`, content via `ui.siteConfig.content.*` in Helm values)
  - Local: `UI_CONFIG=./my-ui-config.json` in `.env` or edit `ui/public/ui-config.json` directly

## 9. CVE Refresher (Background Job)

**Problem:** New CVEs published after ingestion remain undetected. A full re-scan of all SBOMs is too expensive.

**Solution:** Lightweight background job (`cmd/cve-refresher`) that runs as a K8s CronJob (default: daily at 2 AM).

**Flow:**
1. `SELECT DISTINCT purl FROM sbom_packages` → ~20k unique PURLs
2. OSV `QueryBatch` in 1000-item chunks → ~20 API requests (~2-5s)
3. Dedup: filter against existing `(vuln_id, purl)` combinations in ClickHouse
4. Reverse-lookup: PURL → which SBOMs contain it? (`has(package_purls, ?)`)
5. `INSERT` new vulnerability records for all affected SBOMs
6. Write refresh log to `cve_refresh_log`

**Shared Helpers:** `internal/osvutil` package (extracted from parsing-worker) for `ClassifySeverity`, `ExtractFixedVersion`, `ExtractAffectedVersions`.

**Dashboard Integration:** Banner shows last refresh timestamp + number of new vulnerabilities.

**Usage:**
- Local: `make cve-refresh`
- K8s: Automatic as CronJob (`cveRefresher.enabled: true` in values.yaml)

## 10. License Governance

**License Policy** (`license-policy.json`): Defines which SPDX IDs are permissive/copyleft. Read by API Gateway and workers. Anything not listed = `unknown`.

**License Exceptions** (`license-exceptions.json`): CNCF format with blanket and specific exceptions. Blanket exceptions support prefix matching (e.g. `MPL-2.0` matches `MPL-2.0-no-copyleft-exception`). Written at ingest time into `exempted_packages` + `exemption_reason` columns and considered at query time in the dashboard. Read-only — no write API (frontend is public).

**Permissive Licenses:** Packages with permissive licenses (MIT, Apache-2.0, BSD) are **never** tracked as non-compliant.

**Visual Representation:**
- License cards: Green = exempted copyleft, Red = actual copyleft
- Dependencies tab: Orange = exempted, Red = violation
- Dashboard donut: Dedicated "Exempted" segment (copyleft count is adjusted)

**Configuration:**
- Local: JSON files in `sboms/`, mounted via Docker Compose
- K8s: ConfigMaps (`seebom-license-policy`, `seebom-license-exceptions`)

## 10a. GitHub Dependency Health

**Problem:** Archived GitHub repositories receive no updates or security patches. Users of such dependencies should be warned.

**Solution:** During GitHub license resolution, repo metadata is automatically captured:
- `archived` (bool) — repository is archived
- `fork` (bool) — repository is a fork
- `stargazers` (int) — GitHub stars
- `pushed_at` (timestamp) — last push

**Storage:** `github_repo_metadata` table (ReplacingMergeTree), ORDER BY `(repo)`

**Data Flow:**
1. Parsing worker calls GitHub API for license resolution
2. Repo metadata is saved simultaneously
3. Dashboard shows warning count for archived repos
4. Dedicated `/archived-packages` page lists all affected packages

**API Endpoint:** `GET /api/v1/packages/archived`
- Returns all packages whose PURL points to an archived GitHub repo
- With project aggregation (name + version tags)
- Sorted by stars (most popular archived repos first)

**UI Integration:**
- Dashboard: Orange warning banner when archived_repos_count > 0
- SBOM Detail/Dependencies tab: `📦 ARCHIVED` badge next to affected packages
- Archived Packages page: Grouped by repo, then by project with version tags

## 11. Decision Log

| # | Decision | Status |
|---|----------|--------|
| 1 | Queue: ClickHouse table (`ingestion_queue`) | ✅ Implemented |
| 2 | External Go dependencies (`go-json`, `clickhouse-go`) accepted | ✅ Implemented |
| 3 | Ingestion: Local repo (`sboms/`, 1000+ files) | ✅ Implemented |
| 4 | VEX format: OpenVEX (no CSAF VEX, no CycloneDX VEX) | ✅ Implemented |
| 5 | VEX storage: Dedicated ClickHouse table with ReplacingMergeTree | ✅ Implemented |
| 6 | VEX ingestion: Same pipeline path as SBOM (job_type field) | ✅ Implemented |
| 7 | CVE impact: Array search via `has()` instead of normalization | ✅ Implemented |
| 8 | Dep stats: `ARRAY JOIN` instead of separate dependency table | ✅ Implemented |
| 9 | Direct/transitive: Relationship index analysis (idx 0 = root) | ✅ Implemented |
| 10 | License exceptions: Read-only from config file, no write API endpoint | ✅ Implemented |
| 11 | License policy: Externalized as JSON file (was hardcoded) | ✅ Implemented |
| 12 | OSV rate limiting: Token bucket + exponential backoff | ✅ Implemented |
| 13 | VEX URL normalization: `@id` URLs → plain CVE/GHSA IDs | ✅ Implemented |
| 14 | SBOM_LIMIT: Only SBOMs limited, VEX files always passed through | ✅ Implemented |
| 15 | UI theming: CSS custom properties + external custom-theme.css | ✅ Implemented |
| 16 | Dark mode: Built-in toggle with localStorage persistence | ✅ Implemented |
| 17 | CVE refresher: Background CronJob for incremental CVE checks | ✅ Implemented |
| 18 | Shared OSV helpers: `internal/osvutil` package (extracted from parsing-worker) | ✅ Implemented |
| 19 | License exemption: Blanket prefix match (MPL-2.0 → MPL-2.0-no-copyleft-exception) | ✅ Implemented |
| 20 | Permissive licenses: No non-compliant packages for permissive licenses | ✅ Implemented |
| 21 | SBOM Explorer: Client-side full-text search (project name, file, version) | ✅ Implemented |
| 22 | Dashboard: CVE refresh banner + exempted license segment in donut | ✅ Implemented |
| 23 | License overview: Project grouping with version tags (like CVE impact) | ✅ Implemented |
| 24 | GitHub license resolution: Packages with NOASSERTION resolved via GitHub API | ✅ Implemented |
| 25 | GitHub license cache: ClickHouse table avoids redundant API calls | ✅ Implemented |
| 26 | GitHub repo metadata: Archived/fork status captured for dependency health | ✅ Implemented |
| 27 | Archived repos warning: Dashboard banner + dedicated page for archived dependencies | ✅ Implemented |
| 28 | SBOM detail: Archived badge on dependencies from archived repos | ✅ Implemented |
| 29 | Go temp package name sanitization: `tmp.xxxxx` CI/CD artifacts replaced in SPDX parser with PURL-based names and filtered in license checker as fallback | ✅ Implemented |
| 30 | S3 bucket ingestion: Multi-bucket S3 support as default ingestion method via `minio-go/v7`. Streaming ListObjects with batched enqueue (500/batch). Worker fetches via `s3://` URIs. Local filesystem ingestion preserved. | ✅ Implemented |
