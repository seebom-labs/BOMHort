---
title: "Roadmap"
linkTitle: "Roadmap"
type: docs
weight: 6
description: >
  Product roadmap for BOMHort — the v1.0 freeze, the automated-VEX epic, and what comes after.
---

{{% alert title="Last Updated" color="info" %}}
2026-09-16 · [Project Board →](https://github.com/orgs/seebom-labs/projects/1) · [v1.0.0 Milestone →](https://github.com/seebom-labs/BOMHort/milestone/1)
{{% /alert %}}

## Vision

BOMHort is transitioning from a single-instance SBOM visualization tool into an **enterprise-grade, multi-cluster Software Supply Chain Security platform**. Phase 1 (foundation, auth, multi-cluster model, push ingestion) shipped in v0.4–v0.6. The roadmap is now organised around one hard deadline — the **v1.0.0 schema and API freeze**:

1. **v1.0 Freeze Preparation** — one coordinated migration wave for everything that cannot be back-filled later
2. **Automation & Fleet Operations** — automated VEX generation ([VEXViper](https://github.com/seebom-labs/VEXViper)), namespace/workload views, auditor exports
3. **Analytics & Compliance** — CRA readiness scoring, EPSS, dependency health, SBOM diff

The guiding rule: **if it can't be back-filled, it lands before 1.0; if it's additive, it lands after.**

---

## Phase 1: Foundation & Security ✅ {#phase-1}

**Q1–Q2 2026 · Complete.** Production-ready with real security requirements.

| Status | Issue | Description |
|:------:|-------|-------------|
| ✅ | [~~#131 — Cluster-aware data model~~](https://github.com/seebom-labs/BOMHort/issues/131) | `cluster` column on all core tables (migration `012`). |
| ✅ | [~~#134 — API Authentication~~](https://github.com/seebom-labs/BOMHort/issues/134) | Service token + API key modes. Gate for all write operations. |
| ✅ | [~~#137 — Enhanced health checks~~](https://github.com/seebom-labs/BOMHort/issues/137) | `/readyz`, `/livez` for K8s probes. |
| ✅ | [~~#139 — Headless mode~~](https://github.com/seebom-labs/BOMHort/issues/139) | API-only deployment without Angular UI. |
| ✅ | [~~#59 — Expose API externally~~](https://github.com/seebom-labs/BOMHort/issues/59) | Helm Ingress template + TLS. |
| ✅ | [~~#8 — Project List View~~](https://github.com/seebom-labs/BOMHort/issues/8) | Group SBOMs by project. |
| ✅ | [~~#144 — SBOM Download~~](https://github.com/seebom-labs/BOMHort/issues/144) | Download SBOM JSON from the platform. |
| ✅ | [~~#55 — CycloneDX Support~~](https://github.com/seebom-labs/BOMHort/issues/55) | Parse CycloneDX 1.4+ SBOMs. |
| ✅ | [~~#37 — Version Skew Detection~~](https://github.com/seebom-labs/BOMHort/issues/37) | Cross-org dependency consistency. |
| ✅ | [~~#132~~](https://github.com/seebom-labs/BOMHort/issues/132) / [~~#133 — Cluster endpoints~~](https://github.com/seebom-labs/BOMHort/issues/133) | `GET /api/v1/clusters`, per-cluster stats and SBOM lists. |
| ✅ | [~~#135 — SBOM Upload (Push Model)~~](https://github.com/seebom-labs/BOMHort/issues/135) | `POST /api/v1/sboms/upload` from CI/CD pipelines. |
| 🟡 | [#136 — Enhanced CORS](https://github.com/seebom-labs/BOMHort/issues/136) | Functionally done (POST on upload, `X-API-Key`). Remaining bits (`CORS_ALLOW_CREDENTIALS`, configurable methods) are additive → 1.x. |

**Delivered beyond the roadmap:** Global Search, Package Search, in-toto attestation unwrapping, protobom parsing backend, license resolution via GitHub + npm + NuGet with license-text classification, dark mode, white-label theming.

---

## Phase 2: v1.0 Freeze Preparation {#phase-2}

**Sep–Oct 2026 · Theme:** Land every forward-only data capture and every API-contract change in **one coordinated migration wave**, then freeze.

### Schema wave `014`–`017`

{{% alert title="Migration numbering" color="warning" %}}
Migration `013` is taken by `013_create_registry_license_cache` (v0.6.x). Issues #256 and #138 previously claimed `013`; the authoritative numbering is below.
{{% /alert %}}

| Status | Migration | Issue | Change | Why pre-1.0 |
|:------:|-----------|-------|--------|-------------|
| ✅ | `014_create_document_store` | [#256 — Tier-2 fidelity capture](https://github.com/seebom-labs/BOMHort/issues/256) | New table (reference + `sha256`); original bytes in a configurable blob store (S3/MinIO prefix or PVC), **not** ClickHouse | **The real 1.0 driver.** Forward-only — SBOMs ingested before this permanently lose round-trip fidelity. Needs a follow-up hook in the upload handler (#135). Enables #255. |
| ✅ | `015_add_namespace_project_columns` | [#138 — Namespace filtering](https://github.com/seebom-labs/BOMHort/issues/138) + [#57 (column)](https://github.com/seebom-labs/BOMHort/issues/57) | `ADD COLUMN namespace`, `ADD COLUMN project` (`LowCardinality(String) DEFAULT ''`) on core tables and `document_store`; no `ORDER BY` change | Ingestion contract frozen: opt-in `INGEST_PATH_LAYOUT` (e.g. `cluster/namespace/project`), per-bucket `namespace`/`project`/`pathLayout`, and `?namespace=`/`?project=` on upload. |
| ✅ | `016_add_source_columns` | [#332 — source_repo / source_ref](https://github.com/seebom-labs/BOMHort/issues/332) | `ADD COLUMN source_repo, source_ref` on `sboms` + `ingestion_queue`; populated from SPDX/CycloneDX VCS refs; `X-Source-Repo`/`X-Source-Ref` upload headers; `PATCH /api/v1/sboms/{id}` | Correctness blocker for automated VEX (#338). |
| ✅ | `017_add_vex_provenance` | [#334 — VEX provenance (columns)](https://github.com/seebom-labs/BOMHort/issues/334) | `ADD COLUMN author, role, tooling, status_notes` on `vex_statements` | OpenVEX already carries these; automated producers won't re-send. UI → Phase 3. |

### API-contract changes (no migration)

| Status | Issue | Why pre-1.0 |
|:------:|-------|-------------|
| 🔲 | [#335 — One row per (vuln_id, purl), latest VEX wins](https://github.com/seebom-labs/BOMHort/issues/335) | Changes row semantics of `/sboms/{id}/vulnerabilities`; adds `vex_timestamp`. Must be in the frozen contract. |
| 🔲 | [#177 — `cluster` in `SBOMListItem`](https://github.com/seebom-labs/BOMHort/issues/177) | Additive DTO field + badge. Good first issue. |

### Release engineering

| Status | Issue | Notes |
|:------:|-------|-------|
| 🔲 | [#145 — Versioned documentation](https://github.com/seebom-labs/BOMHort/issues/145) | Docsy `params.versions`, `release/vX.Y` branches. Ships **with** the 1.0 tag. |
| ✅ | Data-migration Job covers `registry_license_cache` | [#341](https://github.com/seebom-labs/BOMHort/pull/341); `document_store` covered with #256. |
| ✅ | Helm chart ships every migration | Fixed while landing `015`: `013` and `014` had never been copied into `deploy/helm/bomhort/migrations/`, so Helm deployments never applied them. `make check-migrations` now guards the whole directory. |
| 🔲 | Migration guide + `values.yaml` stability review | Required by the major-version policy. |

---

## 🎯 v1.0.0 Milestone {#v1}

**Target: end of October 2026** · [GitHub Milestone →](https://github.com/seebom-labs/BOMHort/milestone/1)

From this point forward, the [Support Policy](/docs/release/#support-policy) (current − 2) takes effect and breaking changes require a major version bump.

### v1.0 Criteria

| Requirement | Status | Issue |
|-------------|:------:|-------|
| API Authentication | ✅ | [#134](https://github.com/seebom-labs/BOMHort/issues/134) |
| Cluster-aware data model | ✅ | [#131](https://github.com/seebom-labs/BOMHort/issues/131) |
| Cluster listing + detail endpoints | ✅ | [#132](https://github.com/seebom-labs/BOMHort/issues/132), [#133](https://github.com/seebom-labs/BOMHort/issues/133) |
| SBOM Upload endpoint | ✅ | [#135](https://github.com/seebom-labs/BOMHort/issues/135) |
| CycloneDX parsing | ✅ | [#55](https://github.com/seebom-labs/BOMHort/issues/55) |
| Enhanced health probes | ✅ | [#137](https://github.com/seebom-labs/BOMHort/issues/137) |
| Version Skew Detection | ✅ | [#37](https://github.com/seebom-labs/BOMHort/issues/37) |
| Tier-2 fidelity capture (`document_store` + blob store) | ✅ | [#256](https://github.com/seebom-labs/BOMHort/issues/256) |
| Namespace + project columns, ingestion convention | ✅ | [#138](https://github.com/seebom-labs/BOMHort/issues/138), [#57](https://github.com/seebom-labs/BOMHort/issues/57) |
| `source_repo` / `source_ref` columns | 🔲 | [#332](https://github.com/seebom-labs/BOMHort/issues/332) |
| VEX provenance columns | 🔲 | [#334](https://github.com/seebom-labs/BOMHort/issues/334) |
| One row per `(vuln_id, purl)` | 🔲 | [#335](https://github.com/seebom-labs/BOMHort/issues/335) |
| `cluster` in `SBOMListItem` | 🔲 | [#177](https://github.com/seebom-labs/BOMHort/issues/177) |
| Versioned documentation | 🔲 | [#145](https://github.com/seebom-labs/BOMHort/issues/145) |

### What v1.0 means

- **API contract frozen** — no endpoint removals or response shape changes without v2.0
- **ClickHouse schema stable** — no `ORDER BY` or column-type changes; `ADD COLUMN … DEFAULT` and new tables remain allowed
- **Helm values stable** — existing `values.yaml` keys won't be renamed
- **Support policy active** — current release + 2 previous minors receive security patches
- **SemVer enforced** — features in minor bumps, fixes in patches, breaking = major

### Pre-1.0 releases

All v0.x releases are development milestones. They may contain breaking changes between any minor version.

---

## Phase 3: Automation & Fleet Operations {#phase-3}

**v1.x · Q4 2026 · Theme:** Make BOMHort a first-class platform for *automated* supply-chain workflows, and finish the fleet-scale views.

### Epic #338 — Automated VEX generation (VEXViper)

[VEXViper](https://github.com/seebom-labs/VEXViper) is an out-of-tree Go sidecar: it reads findings via the REST API, gathers evidence (govulncheck, version compare), asks a configurable LLM or rule engine, and uploads go-vex-validated OpenVEX back through `/api/v1/sboms/upload`. BOMHort-side gaps, in the order the sidecar needs them:

| Status | Issue | Description |
|:------:|-------|-------------|
| ⏫ | [#332](https://github.com/seebom-labs/BOMHort/issues/332), [#335](https://github.com/seebom-labs/BOMHort/issues/335) | Correctness blockers — pulled into Phase 2. |
| 🔲 | [#336 — Idempotent VEX upload + job status](https://github.com/seebom-labs/BOMHort/issues/336) | Content-hash dedupe; `GET /api/v1/uploads/{job_id}` → applied / matched / unmatched. New table `03x_create_upload_jobs`. |
| 🔲 | [#333 — Incremental listing + `vex_status=missing`](https://github.com/seebom-labs/BOMHort/issues/333) | `?since=&cursor=` on `/sboms`; server-side "no VEX yet" filter. Query-only. |
| 🔲 | [#334 — Provenance UI](https://github.com/seebom-labs/BOMHort/issues/334) | Automated vs. human badge, `status_notes`, `?vex_source=` filter. |
| 🔲 | [#337 — Outbound webhooks](https://github.com/seebom-labs/BOMHort/issues/337) | `sbom.ingested`, `findings.updated`, `vex.applied`, `upload.rejected`; HMAC-signed; Helm values. |
| 🔲 | `docs/integrations/vexviper` | Integration guide once the above stabilises. |

### Fleet operations

| Status | Issue | Description |
|:------:|-------|-------------|
| 🔲 | [#138 — Namespace filtering (API + UI)](https://github.com/seebom-labs/BOMHort/issues/138) | `?namespace=` on list endpoints, namespace chips. Column and ingestion contract shipped in `015`; this is the additive read side. |
| 🔲 | [#267](https://github.com/seebom-labs/BOMHort/issues/267) → [#176 — Cluster Picker](https://github.com/seebom-labs/BOMHort/issues/176) | Query-param filter first (help wanted), then `/clusters` route + navbar dropdown. |
| 🔲 | [#140 — Workload vulnerability summary](https://github.com/seebom-labs/BOMHort/issues/140) | Image → posture cross-reference. Powers #141. |
| 🔲 | [#57 — Per-project policies](https://github.com/seebom-labs/BOMHort/issues/57) | License policies, severity thresholds, exception scopes per project. |
| 🔲 | [#58 — Aggregated SBOM View](https://github.com/seebom-labs/BOMHort/issues/58) | Group version history under project names. Depends on #57. |
| 🔲 | [#136 — CORS (remaining)](https://github.com/seebom-labs/BOMHort/issues/136) | `CORS_ALLOW_CREDENTIALS`, configurable methods/headers. |

### Compliance foundations

| Status | Issue | Description |
|:------:|-------|-------------|
| 🔲 | [#266](https://github.com/seebom-labs/BOMHort/issues/266) → [#62 — Auditor reports](https://github.com/seebom-labs/BOMHort/issues/62) | CSV export first (stdlib, good first issue), then PDF after the dependency decision. |
| 🔲 | [#60 — Local OSV Mirror](https://github.com/seebom-labs/BOMHort/issues/60) | Clone osv.dev into ClickHouse — offline, no rate limits. |
| 🔲 | [#143 — In-toto Witness integration](https://github.com/seebom-labs/BOMHort/issues/143) | `03x_create_attestations`, signature verification, provenance display. Prerequisite for #141. |

**Exit criteria:** External tooling discovers new findings without polling and pushes VEX idempotently; cluster + namespace filters in the UI; CSV export; OSV works offline.

---

## Phase 4: Analytics & Compliance {#phase-4}

**2027 H1 · Theme:** Regulatory readiness scoring and supply-chain intelligence.

| Status | Issue | Description |
|:------:|-------|-------------|
| 🔲 | [#141 — CRA Compliance Dashboard](https://github.com/seebom-labs/BOMHort/issues/141) | EU Cyber Resilience Act readiness scoring. Needs #140, #143, #62. |
| 🔲 | [#255 — Enriched SBOMs + enriched download](https://github.com/seebom-labs/BOMHort/issues/255) | Overlay on #256 originals; companion VEX; in-toto re-sign. |
| 🔲 | [#254 — protobom/storage schema evaluation](https://github.com/seebom-labs/BOMHort/issues/254) | Research; informs #255's overlay. Not a rewrite of `sbom_packages`. |
| 🔲 | [#38 — SBOM Diff](https://github.com/seebom-labs/BOMHort/issues/38) | Dependency tree divergence between versions. |
| 🔲 | [#56 — Dependency Tree View](https://github.com/seebom-labs/BOMHort/issues/56) | Hierarchical visualization of transitive chains. |
| 🔲 | [#63 — Blast Radius Search](https://github.com/seebom-labs/BOMHort/issues/63) | Version-constrained impact analysis. |
| 🔲 | [#64 — EPSS Scores](https://github.com/seebom-labs/BOMHort/issues/64) | Exploit probability for prioritization. |
| 🔲 | [#61 — OpenSSF Scorecard](https://github.com/seebom-labs/BOMHort/issues/61) | Upstream project health per dependency. |
| 🔲 | [#82 — Lottery Factor](https://github.com/seebom-labs/BOMHort/issues/82) | Single-maintainer risk detection. |
| 🔲 | [#7 — CVE Fix Time (MTTR)](https://github.com/seebom-labs/BOMHort/issues/7) | Mean-time-to-remediate per project. |
| 🔲 | [#268 — Official ClickHouse operator](https://github.com/seebom-labs/BOMHort/issues/268) | Breaking `values.yaml` change → v2.0 candidate with migration guide. |

**Exit criteria:** CRA readiness score, EPSS-based prioritization, dependency health metrics, SBOM diff, enriched export.

---

## Schema Change Register {#schema}

Everything that touches `db/migrations/` or a frozen response shape. The authoritative register — including Helm-values and DTO changes — is the one in [`ROADMAP.md`](https://github.com/seebom-labs/BOMHort/blob/main/ROADMAP.md#schema-change-register); check it, upstream `main` and open pull requests before claiming a number. After 1.0, `ORDER BY` and column-type changes are **never** allowed; `ADD COLUMN … DEFAULT` and new tables are fine at any time.

| Migration | Issue | Change | Pre/Post 1.0 |
|-----------|-------|--------|:------------:|
| `012_add_cluster_column` | #131 | `ADD COLUMN cluster` | ✅ shipped |
| `013_create_registry_license_cache` | #330 | New table | ✅ shipped |
| `014_create_document_store` | #256 | New table | ✅ shipped (**pre**) |
| `015_add_namespace_project_columns` | #138, #57 | `ADD COLUMN namespace, project` (core tables + `document_store`) | ✅ shipped (**pre**) |
| `016_add_source_columns` | #332 | `ADD COLUMN source_repo, source_ref` (`sboms` + `ingestion_queue`) | ✅ shipped (**pre**) |
| `017_add_vex_provenance` | #334 | `ADD COLUMN author, role, tooling, status_notes` | ✅ shipped (**pre**) |
| `018_add_vex_sbom_scope` | #350 | `ADD COLUMN sbom_id` on `vex_statements` + `target_sbom_id` on `ingestion_queue` — VEX scoped to its SBOM | ✅ shipped (**pre**) |
| `019_add_vulnerability_aliases` | — | `ADD COLUMN aliases` on `vulnerabilities` (GHSA ↔ CVE); VEX matches by alias | ✅ shipped (**pre**) |
| `020_add_vex_product_ref` | — | `ADD COLUMN product_ref` on `vex_statements` (VEX rescue pass) | ✅ shipped (**pre**) |
| `021_add_document_version` | — | `ADD COLUMN document_version` on `sboms` | ✅ shipped (**pre**) |
| `022_add_sbom_tags` | #357 | `ADD COLUMN tags` on `sboms` + `ingestion_queue` | ✅ shipped (**pre**) |
| `023_add_project_parent` | — | `ADD COLUMN parent` on `sboms`/`ingestion_queue`, `root_purl`, `supplier` on `sboms` (project groups) | ✅ shipped (**pre**) |
| `024_add_package_license_sources` | [#439](https://github.com/seebom-labs/BOMHort/issues/439) | `ADD COLUMN package_license_sources` on `sbom_packages` — where each license came from or why it is missing ([License Resolution](/docs/license-resolution/)) | **pre** (v0.8.0) |
| — | #335 | Row semantics of `/sboms/{id}/vulnerabilities` | ✅ shipped (**pre**, API) |
| — | #177 | `cluster` in `SBOMListItem` | ✅ shipped (**pre**, API) |
| `025_add_vulnerability_cvss_cwe` | #408, #409 | CVSS score/vector/version and CWE IDs on `vulnerabilities` | **pre** (v0.9.0) |
| `026_create_kev_catalog` | #410 | New table | **pre** (v0.9.0) |
| `027_create_epss_scores` | #64 | New table | **pre** (v0.9.0) |
| `028_add_vex_action_statement_timestamp` | #413 | `ADD COLUMN action_statement_timestamp` on `vex_statements` | **pre** (v0.9.0) |
| `029_create_vulnerability_resolutions` | #7 | New table | **pre** (v1.0.0, stretch) |
| `030_create_crypto_libraries` | #419 | New table (or MV over `sbom_packages`) | **pre** (v1.0.0) |
| `03x_create_upload_jobs` | #336 | New table | post |
| `03x_create_attestations` | #143 | New table | post |
| `03x_*` | #61, #82, #255, #60 | New tables | post |
| — | #268 | Operator swap | **v2.0** |

---

## Dependency Graph

```text
#256 (Fidelity capture) ──┬── #255 (Enriched export + re-sign)
                          ├── makes #138/#332/#334 back-fillable
                          └── follow-up hook in #135 (Upload)

#332 (source_repo) ──┐
#335 (latest VEX)  ──┼── #338 Epic ── #336 (idempotent upload) ── #333 (since/cursor) ── #337 (webhooks)
#334 (provenance)  ──┘                                            └── #334 UI badge

#131 (Cluster) ── #132/#133 ── #177 (badge) ── #267 (filter) ── #176 (Cluster Picker)
              └── #138 (Namespace) ── #140 (Workload Summary) ── #141 (CRA Dashboard)
                                                                     ↑
#57 (Project column) ── #57 (policies) ── #58 (Aggregated View)     #143 (Witness) ──┘
                                                                     #62 (Reports) ─┘
                                                                        ↑
                                                                     #266 (CSV)

#60 (OSV Mirror) ── standalone
#64 (EPSS) ── extends cve-refresher
#61 (Scorecard), #82 (Lottery) ── extend internal/github
#254 ── informs #255 · #268 ── v2.0 candidate
```

---

## Prioritization Philosophy

### One migration wave before 1.0
After the freeze we can still add columns and tables — but we can never recover data we didn't capture. #256 is the only truly irrecoverable item; the other columns are cheap but their *ingestion* contract should be fixed so producers can rely on it. One wave means operators run migrations once.

### VEXViper before analytics
Automated VEX turns a wall of CVEs into a triaged queue. Every analytics feature is more useful once `not_affected` noise is gone. The sidecar exists today; BOMHort-side gaps are the bottleneck.

### CRA in 2027 H1
#141 needs #140, #143 and #62 first. Shipping in H1 2027 still gives adopters ~9 months before the CRA's full conformity obligations (December 2027).

### Cluster vs. namespace vs. project

| Dimension | Question | Example | Cardinality |
|-----------|----------|---------|-------------|
| `cluster` | Where is it deployed? | `prod-eu` | 1–50 |
| `namespace` | Which team boundary inside the cluster? | `payments` | 10–500 |
| `project` | What is it / who owns it? | `payment-service` | 50–5000 |

All three are `LowCardinality(String) DEFAULT ''` columns, none in `ORDER BY`.

---

## Non-Goals

- ❌ Custom Kubernetes Operator (Helm + ClickHouse Operator)
- ❌ In-tree VEX generation / LLM calls (stays in the VEXViper sidecar)
- ❌ Write APIs for license exceptions (frontend is public)
- ❌ Multi-repo split (monorepo is a hard constraint)
- ❌ Real-time streaming (batch + webhooks is sufficient)
- ❌ RBAC/multi-tenancy (auth is binary for now)
- ❌ Full OIDC in BOMHort (upstream proxy responsibility)
- ❌ Relational rewrite of `sbom_packages` (#254 informs the overlay only)

---

## Contributing

Want to pick up an issue from the roadmap? Check the [Project Board](https://github.com/orgs/seebom-labs/projects/1) for items in the **Todo** column. Issues labeled `help wanted` or `good first issue` — currently [#177](https://github.com/seebom-labs/BOMHort/issues/177), [#266](https://github.com/seebom-labs/BOMHort/issues/266), [#267](https://github.com/seebom-labs/BOMHort/issues/267) — are especially good for new contributors.

See [Development Guide](/docs/development/) for setup instructions.

