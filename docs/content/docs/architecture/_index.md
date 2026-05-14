---
title: "Architecture"
linkTitle: "Architecture"
type: docs
weight: 2
description: >
  System architecture, data flow, ClickHouse schema, and component overview.
---

{{% pageinfo %}}
This page contains the full architecture blueprint for SeeBOM.
{{% /pageinfo %}}

## TL;DR

Kubernetes-native SBOM platform as a monorepo. Go backend with four binaries (CronJob Ingestion-Watcher, scalable Parsing-Workers, stateless API-Gateway, background CVE-Refresher). ClickHouse as the analytical database with MergeTree tables and array-based dependency storage. Angular frontend with virtual scrolling, OnPush change detection, full-text search, dark-mode toggle, and custom CSS theming.

## Components

| Binary | Type | Purpose |
|--------|------|---------|
| `ingestion-watcher` | K8s CronJob | Scans SBOM/VEX directory, hash-dedup, enqueues jobs |
| `parsing-worker` | Deployment (N replicas) | Processes SBOMs (SPDX→ClickHouse), VEX files, OSV lookups, license resolution, compliance checks |
| `api-gateway` | Deployment | Stateless REST API (19 endpoints) |
| `cve-refresher` | K8s CronJob (daily) | Checks all known PURLs for newly disclosed CVEs |

## Data Flow

```
┌─────────────────────────────────────────────────────────┐
│                    SBOM Sources                          │
│  S3 (default):                                           │
│    s3://cncf-subproject-sboms/k3s-io/...spdx.json       │
│  Local (alternative):                                    │
│    sboms/*.spdx.json + *.openvex.json                   │
└──────────────────────┬──────────────────────────────────┘
       │ S3 ListObjects (streamed) + filepath.Walk (local)
       │ SHA256 hashing + file-type detection (sbom|vex)
       ▼
Ingestion Watcher (CronJob)
       │ Hash dedup → batch INSERT INTO ingestion_queue (500/batch)
       ▼
ClickHouse: ingestion_queue (status='pending')
       │ SELECT + Claim (status='processing')
       ▼
Parsing Workers (N replicas)
       ├── Local files: os.Open(filepath.Join(sbomDir, sourceFile))
       ├── S3 files:    s3.GetObject(bucket, key) → io.ReadCloser
       ├── job_type=sbom:
       │     1. Parse SPDX JSON (plain or in-toto attestation envelope)
       │     2. Resolve unknown licenses via GitHub API
       │        (well-known Go module mappings + API fallback + static overrides)
       │     3. Batch INSERT sboms + sbom_packages (with resolved licenses)
       │     4. OSV Batch Query → INSERT vulnerabilities
       │     5. License Compliance Check → INSERT license_compliance
       └── job_type=vex:  OpenVEX Parse → INSERT vex_statements
       ▼
ClickHouse: sboms, sbom_packages, vulnerabilities, license_compliance, vex_statements
       │
       │         ┌──────────────────────────────────┐
       │         │ CVE Refresher (CronJob, daily)   │
       │         │  OSV BatchQuery (1000/chunk)      │
       │         │  Dedup + reverse-lookup + INSERT  │
       │         └──────────────────────────────────┘
       ▼
API Gateway (REST) → 19 Endpoints → Angular UI
```

## ClickHouse Schema

| Table | Engine | Purpose |
|-------|--------|---------|
| `sboms` | ReplacingMergeTree | SBOM metadata |
| `sbom_packages` | MergeTree | Parallel arrays (names, PURLs, licenses, relationships) |
| `vulnerabilities` | MergeTree | OSV results |
| `license_compliance` | SummingMergeTree | License compliance per SBOM |
| `ingestion_queue` | ReplacingMergeTree | Job queue (job_type: sbom/vex) |
| `dashboard_stats_mv` | SummingMergeTree (MV) | Pre-aggregated daily stats |
| `vex_statements` | ReplacingMergeTree | OpenVEX statements |
| `cve_refresh_log` | MergeTree | CVE refresh run history |
| `github_license_cache` | ReplacingMergeTree | Resolved GitHub licenses cache |
| `github_repo_metadata` | ReplacingMergeTree | GitHub repo metadata (archived, fork, stars) |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/healthz` | Health check |
| GET | `/api/v1/stats/dashboard` | Dashboard statistics |
| GET | `/api/v1/stats/dependencies?limit=N` | Top-N dependencies cross-project |
| GET | `/api/v1/sboms?page=&page_size=` | Paginated SBOM list |
| GET | `/api/v1/sboms/{id}/detail` | SBOM detail with severity breakdown |
| GET | `/api/v1/sboms/{id}/vulnerabilities` | Vulnerabilities for an SBOM |
| GET | `/api/v1/sboms/{id}/licenses` | License breakdown for an SBOM |
| GET | `/api/v1/sboms/{id}/dependencies` | Dependency tree |
| GET | `/api/v1/vulnerabilities?page=&vex_filter=` | Paginated vulnerabilities |
| GET | `/api/v1/vulnerabilities/{id}/affected-projects` | CVE impact across projects |
| GET | `/api/v1/licenses/compliance` | Global license compliance |
| GET | `/api/v1/projects/license-compliance` | Projects with license violations |
| GET | `/api/v1/license-exceptions` | Active license exceptions |
| GET | `/api/v1/license-policy` | Active license policy |
| GET | `/api/v1/vex/statements?page=&page_size=` | Paginated VEX statements |
| GET | `/api/v1/packages/archived` | Archived GitHub repo packages |
| GET | `/api/v1/packages/search?q=&page=&page_size=` | Fuzzy package name search |
| GET | `/api/v1/packages/detail?name=&page=&page_size=` | All projects using a specific package |
| GET | `/api/v1/stats/version-skew?page=&page_size=&search=` | Version skew detection |

## VEX Architecture

- **Format:** OpenVEX (JSON, Spec v0.2.0)
- **File Detection:** `*.openvex.json` or `*.vex.json`
- **Statuses:** `not_affected`, `affected`, `fixed`, `under_investigation`
- **URL Normalization:** VEX vulnerability `@id` URLs are reduced to plain IDs
- **Dashboard:** `effective_vulnerabilities = total - suppressed_by_vex`

## CVE Refresher

Lightweight daily CronJob that queries all unique PURLs (~20k) against the OSV API in 1000-PURL batch chunks, deduplicates against existing vulnerabilities, and inserts new findings — without re-scanning all SBOMs.

## OSV Integration

- **Endpoint:** `POST https://api.osv.dev/v1/querybatch`
- **Batch Limit:** 1000 PURLs per request
- **Rate Limiting:** Token bucket (10 req/s, burst 5)
- **Retry:** Exponential backoff on HTTP 429/503

## License Governance

- **License Policy** (`license-policy.json`): Defines permissive vs. copyleft classifications
- **License Exceptions** (`license-exceptions.json`): CNCF format, blanket + specific
- **Permissive licenses** (MIT, Apache-2.0, BSD) are **never** tracked as non-compliant
- **Visual:** Green = exempted copyleft, Red = violation, Orange = exempted in dependency tree

## SPDX Parser

The SPDX parser (`internal/spdx`) supports two formats:

- **Plain SPDX JSON** — Standard SPDX 2.3 documents with `spdxVersion` at the top level
- **In-toto attestation envelopes** — Documents where the SPDX content is wrapped inside a `predicate` field (generated by tools like Syft + BuildKit). The parser auto-detects this when `spdxVersion` is empty and unwraps the SPDX from the `predicate` if `predicateType` contains "spdx".

## GitHub License Resolution

For packages with `NOASSERTION` or empty licenses (common in container-image SBOMs generated by Syft), the parsing worker resolves licenses via the GitHub API using multiple strategies:

1. **Direct PURL extraction** — `pkg:golang/github.com/{owner}/{repo}` → `github.com/{owner}/{repo}`
2. **Well-known Go module mappings** (50+ entries) — Maps non-GitHub import paths to their GitHub repos:
   - `golang.org/x/*` → `github.com/golang/*`
   - `gopkg.in/yaml.v3` → `github.com/go-yaml/yaml`
   - `go.uber.org/zap` → `github.com/uber-go/zap`
   - `k8s.io/client-go` → `github.com/kubernetes/client-go`
   - `oras.land/oras-go` → `github.com/oras-project/oras-go`
   - `dario.cat/mergo` → `github.com/darccio/mergo`
   - And many more (see `internal/github/purl.go`)
3. **Fallback to `/license` endpoint** — If the repo API returns `NOASSERTION`, the dedicated `/repos/{owner}/{repo}/license` endpoint is tried (it does deeper file analysis)
4. **Static overrides** — For repos where even GitHub's license detection fails (returns "Other"), manually verified overrides are applied (e.g., `opencontainers/go-digest` → Apache-2.0, `shopspring/decimal` → MIT)

Results are cached in-memory per worker and persisted to the `github_license_cache` and `github_repo_metadata` ClickHouse tables for cross-worker reuse.

{{% alert title="Important" color="warning" %}}
License resolution runs **before** the ClickHouse insert so that `sbom_packages.package_licenses` contains the resolved values from the start. This ensures the dependency tree API returns correct licenses without requiring a separate join or lookup.
{{% /alert %}}

## Angular UI

13 lazy-loaded routes with virtual scrolling, OnPush change detection, dark mode toggle, and CSS custom properties theming. Includes package search with fuzzy name matching and paginated detail views. External `custom-theme.css` and `ui-config.json` are mountable without rebuild.

