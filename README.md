<p align="center">
  <img src="docs/static/images/logo-with-text.png" alt="SeeBOM" width="400">
</p>

<h3 align="center">Kubernetes-native Software Bill of Materials (SBOM) Visualization & Governance Platform</h3>

<p align="center">
  <a href="https://github.com/seebom-labs/seebom/actions/workflows/ci.yml"><img src="https://github.com/seebom-labs/seebom/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/seebom-labs/seebom"><img src="https://api.scorecard.dev/projects/github.com/seebom-labs/seebom/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://www.bestpractices.dev/projects/TODO"><img src="https://www.bestpractices.dev/projects/TODO/badge" alt="OpenSSF Best Practices"></a>
</p>

Ingest 1000+ SPDX SBOMs, scan for vulnerabilities via OSV, enforce license compliance, and apply VEX statements — all visualized in a fast Angular dashboard backed by ClickHouse analytics.

<p align="center">
  <img src="docs/static/images/dashboard-screenshot.png" alt="SeeBOM Dashboard" width="900">
</p>

---

## Quick Start

### Prerequisites

| Tool | Minimum Version |
|------|----------------|
| Docker + Docker Compose | v2.20+ |
| Go | 1.24+ (only for local dev) |
| Node.js | 22+ (only for local dev) |

### Option A: Full Stack via Docker Compose (Recommended)

```bash
# 1. Clone the repo
git clone https://github.com/seebom-labs/seebom.git && cd seebom

# 2. Place your SPDX files in the sboms/ directory
#    (an example file is included: sboms/_example.spdx.json)

# 3. Start everything
make dev

# Or without make:
docker compose up --build -d
```

This starts:
- **ClickHouse** on `localhost:9000` (TCP) / `localhost:8123` (HTTP)
- **API Gateway** on `localhost:8080`
- **Ingestion Watcher** (runs once, scans `sboms/` for new files)
- **Parsing Worker** (processes queued SBOM/VEX files)
- **Angular UI** on `localhost:8090`

Open **http://localhost:8090** in your browser.

### Configuration (`.env`)

Copy `.env.example` to `.env` and adjust:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `SBOM_SOURCE_DIR` | `./sboms` | Path to your SBOM files (can point to an external repo checkout) |
| `SBOM_LIMIT` | `0` | Max SBOMs to enqueue per watcher run. `0` = unlimited. Use `50`–`200` for local dev. |
| `WORKER_REPLICAS` | `1` | Number of parallel parsing worker containers |
| `WORKER_BATCH_SIZE` | `50` | Jobs claimed per polling cycle per worker |
| `SKIP_OSV` | `false` | Skip OSV vulnerability API calls. Set `true` for fast initial bulk load (licenses only), then re-run with `false`. |
| `SKIP_GITHUB_RESOLVE` | `false` | Skip GitHub license resolution for packages with `NOASSERTION`/empty licenses. |
| `GITHUB_TOKEN` | *(empty)* | GitHub personal access token for license resolution. Increases rate limit from 60 to 5000 req/h. No scopes needed. |
| `CUSTOM_THEME` | (example file) | Path to a custom CSS theme file for the UI. See "Custom Theme" section. |
| `UI_CONFIG` | `./ui/public/ui-config.json` | Path to a JSON file with UI text overrides (brand name, dashboard texts, disclaimer). See "Site Configuration" section. |
| `S3_BUCKETS` | *(empty)* | JSON array of S3 bucket configs. See "S3 Ingestion" section. |
| `S3_BUCKET` | *(empty)* | Single S3 bucket name (simpler alternative to `S3_BUCKETS`). |
| `S3_ENDPOINT` | `s3.amazonaws.com` | S3 endpoint URL. |
| `S3_REGION` | `us-east-1` | AWS region. |
| `S3_ACCESS_KEY` | *(empty)* | Shared S3 access key (applied to all buckets). Leave empty for public buckets. |
| `S3_SECRET_KEY` | *(empty)* | Shared S3 secret key. |

**After changing `.env`:**

```bash
# Apply new values (keeps ClickHouse data):
docker compose up -d --force-recreate

# Or full reset (wipes ClickHouse data):
make dev-reset
```

### Configuration Files

Two JSON config files control license governance. Edit them and restart the affected services.

| File | Mounted in | Purpose |
|------|-----------|---------|
| `sboms/license-policy.json` | API Gateway, Workers | Defines which SPDX IDs are **permissive** vs. **copyleft**. Anything not listed = `unknown`. |
| `sboms/license-exceptions.json` | API Gateway, Workers | Exempts specific licenses (blanket) or package+license combos from violation reporting. [CNCF format](https://github.com/cncf/foundation/blob/main/license-exceptions/exceptions.json). |

### Custom Theme (CSS)

The entire UI color scheme is defined via CSS Custom Properties and can be overridden **without rebuilding** Angular.

**Local (Docker Compose):** Create a CSS file and set `CUSTOM_THEME` in `.env`:

```bash
# .env
CUSTOM_THEME=./my-theme.css
```

```css
/* my-theme.css */
:root {
  --accent: #e94560;
  --nav-bg: #1a1a2e;
  --nav-brand: #e94560;
  --severity-critical: #ff4444;
  --license-permissive: #22c55e;
}
```

```bash
docker compose up -d --force-recreate ui
```

**Kubernetes:** Enable the theme ConfigMap in Helm values:

```yaml
ui:
  customTheme:
    enabled: true
```

Then edit the ConfigMap:

```bash
kubectl create configmap seebom-custom-theme \
  --from-file=custom-theme.css=./my-theme.css \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment seebom-ui
```

See `ui/src/assets/custom-theme.example.css` for all available variables.

### Site Configuration (Texts & Branding)

All UI text content (brand name, page title, dashboard description, disclaimer, etc.) can be customised **without rebuilding** Angular via a `ui-config.json` file.

**Local (Docker Compose):** Edit the default file directly or point to your own:

```bash
# Option 1: Edit the built-in default
vim ui/public/ui-config.json

# Option 2: Use a custom file via .env
UI_CONFIG=./my-ui-config.json
docker compose up -d --force-recreate ui
```

**Example `ui-config.json`:**

```json
{
  "brandName": "My SBOM Platform",
  "pageTitle": "My SBOM Platform",
  "dashboard": {
    "title": "Overview",
    "subtitle": "Software Supply Chain Governance",
    "description": "<strong>Welcome</strong> to our internal SBOM governance platform.",
    "disclaimer": "Internal use only. Data sourced from OSV and GitHub."
  },
  "footer": {
    "enabled": true,
    "text": "© 2026 My Company"
  }
}
```

All fields are optional — any missing key falls back to the built-in SeeBOM default. HTML is supported in `description` and `disclaimer`.

**Kubernetes:** Enable the site config in Helm values:

```yaml
ui:
  siteConfig:
    enabled: true
    content:
      brandName: "My SBOM Platform"
      pageTitle: "My SBOM Platform"
      dashboard:
        title: "Overview"
        subtitle: "Software Supply Chain Governance"
        description: "<strong>Welcome</strong> to our SBOM platform."
        disclaimer: "Internal use only."
```

Changes take effect after a pod restart (`kubectl rollout restart deployment seebom-ui`). No rebuild needed.

### S3 Ingestion (Default)

Ingest SBOMs directly from S3-compatible buckets (AWS S3, MinIO, GCS). This is the default and recommended ingestion method — no volumes, PVCs, or git-sync needed.

**Single bucket:**

```bash
# .env
S3_BUCKET=cncf-subproject-sboms
S3_ENDPOINT=s3.amazonaws.com
S3_REGION=us-east-1
```

**Multiple buckets (JSON array):**

```bash
# .env
S3_BUCKETS='[{"name":"cncf-subproject-sboms","endpoint":"s3.amazonaws.com","region":"us-east-1"},{"name":"cncf-project-sboms","region":"us-east-1"}]'
```

**Private buckets with credentials:**

```bash
# .env (shared credentials for all buckets)
S3_ACCESS_KEY=AKIA...
S3_SECRET_KEY=...
S3_BUCKETS='[{"name":"my-private-bucket"}]'

# Or per-bucket credentials in JSON:
S3_BUCKETS='[{"name":"my-bucket","accessKey":"AKIA...","secretKey":"..."}]'
```

**How it works:**
- The Ingestion Watcher streams `ListObjects` from each bucket (paginated, no full listing in memory)
- Files are classified by extension: `*.spdx.json` / `*_spdx.json` → SBOM, `*.openvex.json` / `*.vex.json` → VEX
- SHA256 hashes are computed by streaming the object (not loaded into memory)
- Jobs are enqueued in batches of 500 for efficient ClickHouse inserts
- The Parsing Worker fetches S3 objects on-demand via `s3://bucket/key` URIs
- Local filesystem ingestion (from `SBOM_SOURCE_DIR`) still works alongside S3

```bash
# After editing config files:
docker compose up -d --force-recreate api-gateway parsing-worker
```

See [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) for Kubernetes deployment instructions.

### Option B: Local Kubernetes (Kind)

Deploy the full stack to a local [Kind](https://kind.sigs.k8s.io/) cluster, including ClickHouse Operator, CNCF SBOM ingestion, and the Angular UI:

```bash
# 1. Copy secrets template and fill in your values
cp examples/kind/secrets.env.example local/secrets.env
vi local/secrets.env

# 2. Deploy
make kind-up

# UI: http://localhost:8090   API: http://localhost:8080/healthz
```

See [`examples/`](examples/) for Kind and production Kubernetes deployment configs.

### Option C: Local Development (Hot Reload)

Use this when you want to iterate on code quickly:

```bash
# 1. Start only ClickHouse
make ch-only

# 2. Run the migrations (first time only)
make ch-migrate

# 3. In separate terminals:

# Terminal 1: API Gateway
make api

# Terminal 2: Run Ingestion Watcher (once)
make ingest

# Terminal 3: Start Parsing Worker
make worker

# Terminal 4: Angular dev server (hot reload, proxied to API)
make ui-dev
```

Open **http://localhost:4200** — Angular proxies `/api/*` to `localhost:8080`.

---

## Architecture

```
sboms/*.spdx.json + *.openvex.json
       │
       ▼
┌─────────────────────────┐
│   Ingestion Watcher     │  CronJob: scans files, deduplicates by SHA256,
│   (Go binary)           │  enqueues jobs into ClickHouse queue
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   Parsing Workers (N)   │  Stateless: claims jobs, parses SPDX/VEX
│   (Go binary)           │  (supports plain SPDX + in-toto attestation
│                         │  envelopes), resolves unknown licenses via
│                         │  GitHub API (50+ well-known Go module mappings),
│                         │  batch-INSERTs resolved data into ClickHouse,
│                         │  then queries OSV for vulns and checks license
│                         │  compliance
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   CVE Refresher         │  CronJob (daily): checks all PURLs for new CVEs
│   (Go binary)           │  without re-scanning all SBOMs
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   ClickHouse            │  11 tables: sboms, sbom_packages, vulnerabilities,
│                         │  license_compliance, vex_statements, ingestion_queue,
│                         │  dashboard_stats_mv, cve_refresh_log, github_license_cache,
│                         │  github_repo_metadata
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   API Gateway           │  16 REST endpoints, stateless
│   (Go binary)           │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   Angular UI            │  10 lazy-loaded pages, virtual scrolling,
│                         │  OnPush change detection, dark mode,
│                         │  CSS custom properties theming
└─────────────────────────┘
```

### Parsing Pipeline

The Parsing Worker processes each SBOM in a carefully ordered pipeline:

1. **Parse** — Decode SPDX JSON (supports plain SPDX and in-toto attestation envelopes where SPDX is wrapped in the `predicate` field)
2. **Resolve Licenses** — For packages with `NOASSERTION`/empty licenses, query the GitHub API using three resolution strategies:
   - Direct `github.com/{owner}/{repo}` extraction from PURLs
   - **Well-known Go module mappings** (50+ entries: `golang.org/x/*` → `golang/*`, `gopkg.in/*`, `go.uber.org/*`, `k8s.io/*`, `dario.cat/mergo`, etc.)
   - **Fallback** to the dedicated GitHub `/repos/{owner}/{repo}/license` endpoint
   - **Static overrides** for repos where GitHub misdetects the license (e.g., `opencontainers/go-digest`, `shopspring/decimal`)
3. **Insert** — Batch-INSERT SBOM metadata and packages (with resolved licenses) into ClickHouse
4. **Scan Vulnerabilities** — OSV batch query for all PURLs
5. **Check License Compliance** — Classify licenses against the policy and apply exceptions

See [docs/ARCHITECTURE_PLAN.md](docs/ARCHITECTURE_PLAN.md) for the full blueprint.  
See [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) for Kubernetes deployment.  
See [docs/RELEASE.md](docs/RELEASE.md) for building and publishing container images.  
See [docs/TESTING.md](docs/TESTING.md) for writing and running tests.

---

## Makefile Commands

| Command | Description |
|---------|-------------|
| **Docker Compose** | |
| `make dev` | Start full stack via Docker Compose |
| `make dev-down` | Stop all containers |
| `make dev-restart` | Restart with new `.env` values (keeps data) |
| `make dev-logs` | Follow all container logs |
| `make dev-reset` | Destroy data volumes and restart fresh |
| `make dev-status` | Show container status and ingestion progress |
| `make re-ingest` | Re-trigger the Ingestion Watcher (scans for new files) |
| `make re-scan` | Wipe all data and re-process everything (e.g. after enabling OSV) |
| `make cve-refresh` | Check all known PURLs for new CVEs (without re-scanning SBOMs) |
| `make migrate` | Run all pending database migrations |
| **Kind (Local Kubernetes)** | |
| `make kind-up` | Create Kind cluster and deploy SeeBOM via Helm |
| `make kind-down` | Destroy the Kind cluster (deletes everything) |
| `make kind-stop` | Stop the Kind cluster without losing data (preserves volumes) |
| `make kind-start` | Resume a stopped Kind cluster (all pods & data intact) |
| `make kind-status` | Show Kind cluster and pod status |
| `make kind-build` | Build all container images and load them into Kind |
| `make kind-deploy` | Build images, Helm upgrade, and restart pods |
| `make kind-reingest` | Re-ingest all SBOMs (truncate data, re-queue, no re-download) |
| **ClickHouse** | |
| `make ch-only` | Start only ClickHouse (for local dev) |
| `make ch-migrate` | Run SQL migrations against ClickHouse |
| `make ch-shell` | Open ClickHouse CLI |
| **Local Dev** | |
| `make api` | Run API Gateway locally |
| `make ingest` | Run Ingestion Watcher locally |
| `make worker` | Run Parsing Worker locally |
| `make ui-dev` | Start Angular dev server with API proxy |
| `make backend-build` | Build all Go binaries |
| `make backend-test` | Run all Go tests |
| `make backend-vet` | Run go vet + go fmt |
| `make ui-build` | Build Angular for production |
| **Images** | |
| `make images` | Build all 5 container images locally (TAG=dev) |
| `make images-push` | Build and push all images to GHCR |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/healthz` | Health check |
| GET | `/api/v1/stats/dashboard` | Dashboard stats (VEX effective/suppressed counts) |
| GET | `/api/v1/stats/dependencies?limit=N` | Top N dependencies across all projects |
| GET | `/api/v1/sboms?page=&page_size=` | Paginated SBOM list |
| GET | `/api/v1/sboms/{id}/detail` | SBOM detail with severity breakdown |
| GET | `/api/v1/sboms/{id}/vulnerabilities` | Vulnerabilities for a specific SBOM |
| GET | `/api/v1/sboms/{id}/licenses` | License breakdown for a specific SBOM |
| GET | `/api/v1/sboms/{id}/dependencies` | Dependency tree |
| GET | `/api/v1/vulnerabilities?page=&vex_filter=` | Paginated vulnerabilities (optional: `vex_filter=effective`) |
| GET | `/api/v1/vulnerabilities/{id}/affected-projects` | All projects affected by a CVE |
| GET | `/api/v1/licenses/compliance` | Global license compliance overview |
| GET | `/api/v1/projects/license-compliance` | Projects with license violations (filtered by exceptions) |
| GET | `/api/v1/license-exceptions` | Active license exceptions (read-only, from config file) |
| GET | `/api/v1/license-policy` | Active license classification policy (permissive/copyleft lists) |
| GET | `/api/v1/vex/statements?page=&page_size=` | Paginated VEX statements |
| GET | `/api/v1/packages/archived` | Packages using archived GitHub repos (no longer maintained) |

---

## Adding Your SBOMs

1. Place `.spdx.json` files in the `sboms/` directory (or set `SBOM_SOURCE_DIR` in `.env`)
2. Place `.openvex.json` or `.vex.json` files in the same directory
3. Re-trigger ingestion (see below)
4. The Parsing Worker will automatically process new files

The Ingestion Watcher deduplicates by SHA256 hash — it will skip files that have already been processed.

### Re-triggering Ingestion

```bash
# Run the watcher again (scans for new files, exits when done):
docker compose up ingestion-watcher

# If you changed SBOM_LIMIT or SBOM_SOURCE_DIR, force-recreate:
docker compose up --force-recreate ingestion-watcher

# To re-ingest everything from scratch (wipes all data):
make dev-reset
```

---

## License Policy

By default, SeeBOM enforces the [CNCF Allowed Third-Party License Policy](https://github.com/cncf/foundation/blob/main/policies-guidance/allowed-third-party-license-policy.md):

- **Permissive (allowed):** Apache-2.0, MIT, MIT-0, 0BSD, BSD-2-Clause, BSD-3-Clause, ISC, PSF-2.0, Python-2.0, PostgreSQL, UPL-1.0, X11, Zlib, OpenSSL, and a few more (18 total)
- **Copyleft (flagged):** GPL, LGPL, AGPL, MPL-2.0, EPL, EUPL, CPAL, and others (21 total)
- **Unknown:** Any license not in either list is flagged for review

### CNCF Exception List

The [CNCF license exceptions](https://github.com/cncf/foundation/blob/main/license-exceptions/exceptions.json) are automatically downloaded and applied. Packages covered by a CNCF Governing Board exception are marked as exempted rather than non-compliant.

Exceptions with `"project": "All CNCF Projects"` are treated as blanket exceptions (apply to every SBOM).

### Customising the Policy

Override the default policy via Helm values:

```yaml
licensePolicy:
  custom: |
    {
      "permissive": ["Apache-2.0", "MIT"],
      "copyleft": ["GPL-3.0-only", "AGPL-3.0-only"]
    }
```

Or edit the ConfigMap directly:

```bash
kubectl edit configmap seebom-license-policy -n seebom
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Go 1.25, net/http (stdlib) |
| Database | ClickHouse (MergeTree family) |
| Frontend | Angular 19, CDK Virtual Scrolling |
| Vuln Scanning | OSV.dev API |
| VEX | OpenVEX Spec v0.2.0 |
| Deployment | Helm 3, Docker Compose |

---

## License

[LICENSE](LICENSE)

## Badges

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/seebom-labs/seebom/badge)](https://scorecard.dev/viewer/?uri=github.com/seebom-labs/seebom)
