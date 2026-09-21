# BOMHort Product Roadmap

> Last updated: 2026-09-16
> Project Board: https://github.com/orgs/seebom-labs/projects/1
> Milestone v1.0.0: https://github.com/seebom-labs/BOMHort/milestone/1

## Executive Summary

BOMHort is transitioning from a single-instance SBOM visualization tool into an **enterprise-grade, multi-cluster Software Supply Chain Security platform**. Phase 1 (foundation, auth, multi-cluster model, push ingestion) is complete and shipped in v0.4–v0.6.

The roadmap is now organised around one hard deadline — the **v1.0.0 schema and API freeze** — and what must land before it:

1. **Phase 2 — v1.0 Freeze Preparation (Sep–Oct 2026):** one coordinated migration wave (`014`–`017`) for every forward-only or contract-changing item, plus versioned docs. Anything that can be added later without breaking the contract is *deliberately* pushed past 1.0.
2. **Phase 3 — Automation & Fleet Operations (v1.x, Q4 2026):** the [VEXViper](https://github.com/seebom-labs/VEXViper) integration epic (automated VEX generation), namespace/workload views, auditor exports, OSV mirror, attestation verification.
3. **Phase 4 — Analytics & Compliance (2027 H1):** CRA readiness scoring, EPSS, Scorecard, Lottery Factor, SBOM diff, enriched SBOM export.

The sequencing is driven by one rule: **if it can't be back-filled, it lands before 1.0; if it's additive, it lands after.**

---

## Phase 1: Foundation & Security ✅ (Q1–Q2 2026) — Complete

**Theme:** Make BOMHort deployable in production environments with real security requirements.

| # | Issue | Status |
|---|-------|--------|
| ~~#131~~ | ~~Cluster-aware data model~~ | ✅ `cluster` column via migration `012`. |
| ~~#134~~ | ~~API Authentication (Service Token + API Key)~~ | ✅ `authMiddleware`, constant-time compare. |
| ~~#137~~ | ~~Enhanced health checks (/readyz, /livez)~~ | ✅ `/livez`, `/readyz` (ClickHouse ping → 503). |
| ~~#139~~ | ~~Headless mode (API-only)~~ | ✅ `ui.enabled=false` skips all UI resources. |
| ~~#59~~ | ~~Expose API externally (Ingress)~~ | ✅ Ingress template + TLS docs. |
| ~~#8~~ | ~~Project List View~~ | ✅ `GET /api/v1/projects` + UI. |
| ~~#144~~ | ~~SBOM Download~~ | ✅ `GET /api/v1/sboms/{id}/download`. |
| ~~#55~~ | ~~CycloneDX Support~~ | ✅ `internal/cyclonedx`, multi-format dispatch. |
| ~~#37~~ | ~~Version Skew Detection~~ | ✅ PRs #103, #126. |
| ~~#132~~ / ~~#133~~ | ~~Cluster listing + detail endpoints~~ | ✅ `GET /api/v1/clusters`, `/clusters/{name}/{stats,sboms}`. |
| ~~#135~~ | ~~SBOM Upload (Push Model)~~ | ✅ `POST /api/v1/sboms/upload` (auth-gated, S3 or `pushed/` dir). |
| #136 | Enhanced CORS | 🟡 **Functionally done** — `POST` on the upload route, `X-API-Key`/`X-Service-Token`/`X-Filename` headers, configurable origins. Remaining scope (`CORS_ALLOW_CREDENTIALS`, configurable methods/headers) is additive → **moved to 1.x**, removed from the v1.0 milestone. |

**Delivered beyond the roadmap:** Global Search (`GET /api/v1/search`), Package Search + detail page, in-toto attestation unwrapping, protobom parsing backend, license resolution via GitHub + npm + NuGet registries with license-text classification (`internal/licensetext`), SPDX file-level filtering, dark mode, white-label theming.

---

## Phase 2: v1.0 Freeze Preparation (Sep–Oct 2026)

**Theme:** Land every forward-only data capture and every API-contract change in **one coordinated migration wave**, then freeze.

### 2a. Schema wave `014`–`017` (must land together, before the freeze)

Migration `013` is taken by `013_create_registry_license_cache` (shipped in v0.6.x). The issues below previously claimed `013` — numbering is now fixed as follows:

| Migration | # | Issue | Type | Why pre-1.0 |
|-----------|---|-------|------|-------------|
| `014_create_document_store` | **#256** | Tier-2 fidelity capture — persist original SBOM bytes at ingest | New table (`ReplacingMergeTree`, reference + `sha256` only; bytes in configurable blob store: S3/MinIO prefix **or** PVC) | **The real 1.0 driver.** Forward-only: SBOMs ingested before this exist permanently lose round-trip/export fidelity. Also needs a follow-up hook in the already-merged upload handler (#135). Enables #255, and makes every other column below back-fillable. |
| `015_add_namespace_project_columns` ✅ | **#138** | Namespace filtering | `ADD COLUMN namespace LowCardinality(String) DEFAULT ''` on core tables (same pattern as `cluster`; **no** `ORDER BY` change — not possible on MergeTree without rebuild) | Ingestion path convention (`{bucket}/{cluster}/{namespace}/…`) + upload field. `?namespace=` on list endpoints is an additive query param, but the ingestion contract should be fixed before 1.0. |
| `016_add_source_columns` ✅ | **#332** | `source_repo` / `source_ref` as first-class SBOM attribute | `ADD COLUMN source_repo String, source_ref String` on `sboms` | Cheap `ADD COLUMN`; populated at parse time from SPDX `downloadLocation`/`ExternalRef` and CycloneDX `externalReferences[vcs]`/`pedigree.commits`. Overridable via `X-Source-Repo`/`X-Source-Ref` upload headers and `PATCH /api/v1/sboms/{id}`. Correctness blocker for the VEXViper sidecar (#338). |
| `017_add_vex_provenance` ✅ | **#334** (columns only) | VEX statement provenance | `ADD COLUMN author, role, tooling, status_notes` on `vex_statements` | OpenVEX already carries these; capturing them at ingest is forward-only-ish (VEX docs are small and re-uploadable, but automated producers won't re-send). UI badge + `?vex_source=` filter → Phase 3. |
| *(bundled with 015)* | **#57** (column only) | `project` column | `ADD COLUMN project LowCardinality(String) DEFAULT ''` on core tables | Roadmap already asked to batch this with the `ADD COLUMN` wave. **Only the column** lands now; per-project policies / exception scopes are additive → Phase 3. |

### 2b. API-contract changes (before the freeze, no migration)

| # | Issue | Why pre-1.0 |
|---|-------|-------------|
| **#335** ✅ | One row per `(vuln_id, purl)` in `/sboms/{id}/vulnerabilities` — latest VEX statement wins, expose `vex_timestamp` | **Changes row semantics** of a frozen endpoint. `argMax()`/`LIMIT 1 BY` in the ClickHouse query + DTO fields (`vex_timestamp`, `vex_author`, `vex_tooling`). Small, but must be in the 1.0 contract. |
| **#177** | `cluster` in `SBOMListItem` DTO + badge | Additive DTO field; trivial. Good first issue — do it before the freeze so the list contract is complete. |

### 2c. Release engineering

| # | Issue | Notes |
|---|-------|-------|
| **#145** | Versioned documentation | Docsy `params.versions`, `release/vX.Y` branch → `docs.bomhort.dev/vX.Y/`. Must ship **with** the 1.0 tag, prepared beforehand. |
| — | Data-migration Job covers all tables | ✅ `registry_license_cache` (#341) and `document_store` (#256) both covered. |
| — | Helm chart ships every migration | ✅ Fixed while landing `015`: `013` and `014` had never been copied into `deploy/helm/bomhort/migrations/`, so Helm deployments never applied them. `make check-migrations` now guards the whole directory. |
| — | Migration guide + `values.yaml` stability review | Required by our major-version policy (see `AGENTS.md`). |

### 🎯 v1.0.0 Milestone

**Target: end of October 2026** (GitHub milestone currently says 2026-09-30 — to be moved; the 014–017 wave is ~4 weeks of work).

- API contract frozen (no breaking changes without major version bump)
- ClickHouse schema stable (no `ORDER BY`/type changes; `ADD COLUMN` and new tables remain allowed)
- Helm chart values stable
- Support policy (current − 2) takes effect
- Versioned documentation enabled (#145)

**v1.0 Criteria:**
- [x] ~~Version Skew Detection~~ (#37)
- [x] ~~API Authentication~~ (#134)
- [x] ~~Cluster-aware schema~~ (#131)
- [x] ~~Cluster listing + detail endpoints~~ (#132, #133)
- [x] ~~Upload endpoint stable~~ (#135)
- [x] ~~CycloneDX parsing~~ (#55)
- [x] ~~Health probes~~ (#137)
- [x] ~~Tier-2 fidelity capture — `document_store` + blob store (#256)~~
- [x] ~~Namespace column + ingestion convention (#138)~~ — migration `015`, `INGEST_PATH_LAYOUT`, `?namespace=` on upload
- [ ] `source_repo`/`source_ref` columns (#332)
- [ ] VEX provenance columns (#334, columns only)
- [x] ~~`project` column (#57, column only)~~ — migration `015`, `?project=` on upload
- [ ] One row per `(vuln_id, purl)` — latest VEX wins (#335)
- [ ] `cluster` in `SBOMListItem` (#177)
- [ ] Versioned docs (#145)

**Exit criteria:** Every SBOM ingested from 1.0 onward can be reproduced byte-for-byte; every column a later feature needs already exists; the vulnerability endpoint returns deterministic rows.

---

## Phase 3: Automation & Fleet Operations (v1.x, Q4 2026)

**Theme:** Make BOMHort a first-class platform for *automated* supply-chain workflows — starting with VEX generation — and finish the fleet-scale views.

### 3a. Epic #338 — Automated VEX generation (VEXViper integration)

[VEXViper](https://github.com/seebom-labs/VEXViper) is an out-of-tree Go sidecar that reads findings via the REST API, gathers evidence (govulncheck, version compare), asks a configurable LLM or rule engine and uploads go-vex-validated OpenVEX back. Sub-issues, in the order the sidecar needs them:

| # | Issue | Type | Notes |
|---|-------|------|-------|
| ~~#332~~ / ~~#335~~ | Correctness blockers | — | Landed in Phase 2. |
| **#336** | Idempotent VEX upload + `GET /api/v1/uploads/{job_id}` (applied / matched / unmatched) | New table `upload_jobs` (additive) + content-hash dedupe | Unblocks scale; also surfaces PURL/vuln-id mismatches in the UI. |
| **#333** | Incremental listing (`since`/`cursor`) + `vex_status=missing` filter | Query-only, additive params | Cuts a 15 000-SBOM sweep from >25 min to seconds. |
| **#334** | VEX provenance UI: automated vs. human badge, `status_notes`, `?vex_source=` | Frontend + query (columns from `017`) | Auditors see *who/what* decided. |
| **#337** | Outbound webhooks (`sbom.ingested`, `findings.updated`, `vex.applied`, `upload.rejected`) | New Helm values + `internal/webhook` (stdlib only) | Replaces polling; HMAC-signed payloads. |
| — | `docs/integrations/vexviper` | Docs | Once the above stabilises. |

### 3b. Fleet operations

| # | Issue | Rationale |
|---|-------|-----------|
| **#138** (API + UI) | `?namespace=` filters + namespace chips | Column landed in `015`; this is the consumer side. |
| **#267** → **#176** | Cluster filter via query param → full Cluster Picker (`/clusters` route, per-cluster dashboard) | Backend ready since #132/#133; UI has zero cluster awareness. #267 is the help-wanted Phase 1. |
| **#140** | Workload vulnerability summary | Image → posture cross-reference; powers #141. |
| **#57** (policies) | Per-project license policies, severity thresholds, exception scopes | Column landed in `015`; resolution via bucket config / upload payload / name convention. |
| **#58** | Aggregated SBOM View | Group N versions of one project into an expandable row. Depends on #57. |
| **#136** (rest) | `CORS_ALLOW_CREDENTIALS`, configurable methods/headers | Small, additive. |

### 3c. Compliance foundations

| # | Issue | Rationale |
|---|-------|-----------|
| **#266** → **#62** | CSV export for vulnerabilities (stdlib `encoding/csv`, no new dependency) → full auditor reports (PDF; needs maintainer decision on `gofpdf` vs `pdfcpu`) | Auditors don't use UIs. CSV first, PDF after the dependency decision. |
| **#60** | Local OSV Mirror | Removes the osv.dev runtime dependency; offline / air-gapped scans; no rate limits. |
| **#143** | In-toto Witness integration | New `attestations` table (additive), signature verification, provenance display. Phased: Phase 1 no new deps; Sigstore/Fulcio via `sigstore-go` later. Prerequisite for #141. |

**Exit criteria:** An external tool can discover new findings without polling, push VEX idempotently and see the result; multi-cluster/namespace views exist in the UI; vulnerability data exports to CSV; OSV works offline.

---

## Phase 4: Analytics & Compliance (2027 H1)

**Theme:** Regulatory readiness scoring and supply-chain intelligence on top of the mature data model.

| # | Issue | Rationale |
|---|-------|-----------|
| **#141** | CRA Compliance Dashboard | EU Cyber Resilience Act enforcement 2027. Needs #140, #143, #62. |
| **#255** | Editable/enriched SBOMs + enriched download (+ companion VEX, in-toto re-sign) | Builds on #256 originals. Overlay table `ReplacingMergeTree` (latest wins); export re-signed with BOMHort as transforming instance. Additive → no major bump. |
| **#254** | Evaluate protobom/storage relational schema for ClickHouse | Research issue. Informs #255's overlay design; **not** a rewrite of the analytical `sbom_packages` array model. |
| **#38** | SBOM Diff (tree divergence) | "What changed between v1.7.1 and v1.7.2?" |
| **#56** | Dependency Tree View | Hierarchical visualization of transitive chains. |
| **#63** | Blast Radius Search | Extends Package Search with version constraints, vuln context, direct/transitive. |
| **#64** | EPSS Scores | Exploit probability > CVSS. Free daily bulk data; extends `cve-refresher`. |
| **#61** | OpenSSF Scorecard | Upstream project health; extends `internal/github`. |
| **#82** | Lottery Factor | Single-maintainer risk; extends `internal/github`. |
| **#7** | CVE Fix Time (MTTR) | Key KPI for SOC2 / ISO 27001 audits. |
| **#268** | Evaluate official ClickHouse operator (vs. Altinity) | Breaking `values.yaml` change → **requires a major bump and migration guide**; only if maturity gate is met. Candidate for v2.0. |

**Exit criteria:** CRA readiness score per cluster, exploit-probability prioritisation, dependency-health metrics, SBOM diff, enriched export.

---

## Schema Change Register

Everything that touches `db/migrations/` or a frozen response shape, in one place. Rule: **`ORDER BY` or column-type changes are never allowed after 1.0** (MergeTree can't alter them in place). `ADD COLUMN … DEFAULT` and new tables are fine at any time.

| Migration | Issue | Change | Pre/Post 1.0 |
|-----------|-------|--------|:------------:|
| `012_add_cluster_column` | #131 | `ADD COLUMN cluster` on core tables | ✅ shipped |
| `013_create_registry_license_cache` | #330 | New table | ✅ shipped |
| `014_create_document_store` | #256 | New table (reference + hash; blob store external) | **pre** |
| `015_add_namespace_project_columns` | #138, #57 | `ADD COLUMN namespace`, `ADD COLUMN project` on core tables (+ `document_store`) | ✅ shipped (**pre**) |
| `016_add_source_columns` ✅ | #332 | `ADD COLUMN source_repo, source_ref` on `sboms` + `ingestion_queue` | **pre** |
| `017_add_vex_provenance` ✅ | #334 | `ADD COLUMN author, role, tooling, status_notes` on `vex_statements` | **pre** |
| `018_add_vex_sbom_scope` ✅ | #350 | `ADD COLUMN sbom_id` on `vex_statements`, `ADD COLUMN target_sbom_id` on `ingestion_queue` — VEX statements scoped to the SBOM/product they describe | **pre** |
| `019_add_vulnerability_aliases` ✅ | — | `ADD COLUMN aliases Array(String)` on `vulnerabilities` — OSV alias IDs (GHSA ↔ CVE); VEX suppression matches a statement by `vuln_id` **or** any alias | **pre** |
| `020_add_vex_product_ref` ✅ | — | `ADD COLUMN product_ref` on `vex_statements` — persisted OpenVEX product `@id`; enables the post-ingest **VEX rescue** pass that scopes previously unresolvable statements | **pre** |
| `021_add_document_version` ✅ | — | `ADD COLUMN document_version` on `sboms` — version of the described product (SPDX root `versionInfo`, CycloneDX `metadata.component.version`) | **pre** |
| `022_add_sbom_tags` ✅ | #357 | `ADD COLUMN tags Array(String)` on `sboms` + `ingestion_queue` — grouping labels orthogonal to cluster/namespace/project, for catalogue instances that group projects without deploying them. Tags label projects, they do not replace them | **pre** |
| — (query only) ✅ | #335 | Row semantics of `/sboms/{id}/vulnerabilities` | **pre** (API contract) |
| — (DTO only) | #177 | `cluster` in `SBOMListItem` | **pre** (API contract) |
| `02x_create_upload_jobs` | #336 | New table | post |
| `02x_create_attestations` | #143 | New table | post |
| `02x_*` | #64, #61, #82, #7, #255, #60 | New enrichment / overlay / mirror tables | post |
| — | #268 | Operator swap (`values.yaml` breaking) | **v2.0** |

---

## Dependency Graph

```
#256 (Fidelity capture / document_store) ──┬── #255 (Enriched SBOM export + re-sign)
                                           ├── makes #138/#332/#334 back-fillable
                                           └── follow-up hook in #135 (Upload)

#332 (source_repo) ──┐
#335 (latest VEX)  ──┼── #338 Epic (VEXViper) ── #336 (idempotent upload) ── #333 (since/cursor) ── #337 (webhooks)
#334 (provenance)  ──┘                                                       └── #334 UI badge

#131 (Cluster) ── #132/#133 ── #177 (badge) ── #267 (query-param filter) ── #176 (Cluster Picker)
              └── #138 (Namespace) ── #140 (Workload Summary) ── #141 (CRA Dashboard)
                                                                     ↑
#57 (Project column) ── #57 (policies) ── #58 (Aggregated View)     #143 (Witness) ──┘
                                                                     #62 (Reports) ─┘
                                                                        ↑
                                                                     #266 (CSV)

#60 (OSV Mirror) ── standalone
#64 (EPSS) ── extends cve-refresher
#61 (Scorecard), #82 (Lottery) ── extend internal/github
#254 (protobom schema eval) ── informs #255
#268 (operator eval) ── v2.0 candidate
```

---

## Prioritization Rationale

### Why a single migration wave before 1.0?

After the freeze we can still add columns and tables — but we can never recover data we didn't capture. #256 (original bytes) is the only truly irrecoverable one; the others (#138, #332, #334, #57) are cheap `ADD COLUMN`s whose *ingestion* side we want frozen so producers (CI pipelines, VEXViper) can rely on the contract. Landing them together minimises the number of times operators run migrations against production ClickHouse.

### Why VEXViper before analytics?

Automated VEX turns a wall of CVEs into a triaged queue. Every analytics feature (EPSS, CRA score, MTTR) is more useful once `not_affected` noise is gone. The sidecar exists today; BOMHort-side gaps (#332–#337) are the bottleneck.

### Why CRA compliance in 2027 H1, not Q4 2026?

The EU CRA reporting obligations start September 2026 for vulnerabilities; full conformity obligations December 2027. #141 needs #140, #143 and #62 first — they're Phase 3. Shipping #141 in H1 2027 still gives adopters ~9 months before the full obligations.

### Why enrichment features (EPSS/Scorecard/Lottery) as a batch?

Same pattern: fetch external data → ClickHouse table → API → UI. Implementing together maximises reuse.

### Cluster vs. project vs. namespace

Three orthogonal low-cardinality dimensions:

| Dimension | Question | Example | Cardinality | Owner |
|-----------|----------|---------|-------------|-------|
| `cluster` | Where is it deployed? | `prod-eu` | 1–50 | Platform |
| `namespace` | Which tenant/team boundary inside the cluster? | `payments` | 10–500 | Platform / team |
| `project` | What is it / who owns it? | `payment-service` | 50–5000 | Dev teams |

All three are `LowCardinality(String) DEFAULT ''` columns; none is in `ORDER BY`. Filtering is by `WHERE`, which is fine for the data volumes involved.

---

## Success Metrics

| Phase | Metric | Target |
|-------|--------|--------|
| Phase 2 | Round-trip fidelity | 100 % of SBOMs ingested post-1.0 downloadable byte-identical (`sha256` match) |
| Phase 3 | Automated triage | VEXViper `watch` pass over 15 000 SBOMs < 60 s; 0 duplicate VEX rows |
| Phase 3 | Fleet views | Cluster + namespace filter on all list pages |
| Phase 4 | CRA readiness | All 5 CRA conditions evaluable, score > 80 % for managed clusters |

---

## Non-Goals (Explicitly Out of Scope)

- **Custom Kubernetes Operator**: Helm + ClickHouse Operator. No custom CRDs.
- **In-tree VEX generation / LLM calls**: stays in the VEXViper sidecar. BOMHort has no plugin surface and a stdlib-only dependency policy.
- **Write APIs for license exceptions**: Frontend is public. Policy changes require config file updates.
- **Multi-repo split**: Monorepo is a hard constraint for AI-assisted development.
- **Real-time streaming**: Batch ingestion (CronJob + queue) plus outbound webhooks (#337) is sufficient.
- **RBAC/multi-tenancy**: Auth is binary. Fine-grained RBAC is beyond this roadmap.
- **Full OIDC in BOMHort**: User authentication is the upstream proxy's responsibility.
- **Relational rewrite of the dependency model** (#254): protobom/storage's normalized schema is evaluated for the *overlay* only; the analytical `sbom_packages` array model stays.

