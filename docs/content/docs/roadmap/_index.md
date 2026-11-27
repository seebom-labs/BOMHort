---
title: "Roadmap"
linkTitle: "Roadmap"
type: docs
weight: 6
description: >
  Product roadmap for BOMHort — v0.8.0 contract, the v0.9.0 vulnerability register, the v1.0 freeze with the CRA dashboard, and what comes after.
---

{{% alert title="Last Updated" color="info" %}}
2026-10-17 · [Project Board →](https://github.com/orgs/seebom-labs/projects/1) · Milestones: [v0.8.0](https://github.com/seebom-labs/BOMHort/milestone/5) · [v0.9.0](https://github.com/seebom-labs/BOMHort/milestone/6) · [v1.0.0](https://github.com/seebom-labs/BOMHort/milestone/1) · [v1.1.0](https://github.com/seebom-labs/BOMHort/milestone/2) · [v1.2.0](https://github.com/seebom-labs/BOMHort/milestone/3)

This page summarises [`ROADMAP.md`](https://github.com/seebom-labs/BOMHort/blob/main/ROADMAP.md), which is authoritative and carries the full reasoning. Both are updated when a release is cut, not in feature pull requests.
{{% /alert %}}

## Vision

BOMHort is transitioning from a single-instance SBOM visualization tool into an **enterprise-grade, multi-cluster Software Supply Chain Security platform**. Phase 1 (foundation, auth, multi-cluster model, push ingestion) shipped in v0.4–v0.7.

The roadmap is organised around one hard deadline — the **v1.0.0 schema and API freeze** — and one regulatory fact: the **EU Cyber Resilience Act's vulnerability-reporting obligations are in force since 2026-09-11**, and customers already ask for a CRA-grade vulnerability register. The CRA scope therefore moved **into 1.0** (re-plan 2026-09-25), and 1.0 is reached in three steps:

| Release | Due | Theme |
|---------|-----|-------|
| **v0.8.0** ✅ | released 2026-10-17 | **Contract** — MCP server, project aggregation, `source_repo` fix, `values.yaml` shape, CVE ids, CSV export, license provenance |
| **v0.9.0** | 2026-11-30 | **Ingest correctness + vulnerability register** — audit fixes first, then CVSS, CWE, KEV, EPSS, remediation record, SLA due dates ([#414](https://github.com/seebom-labs/BOMHort/issues/414)) |
| **v1.0.0** | 2027-01-31 | **Freeze + CRA dashboard** — readiness score, MTTR, auditor report bundle, crypto-library inventory, versioned docs |
| v1.1.0 | 2027-04-30 | Automation, fleet & cryptography — VEXViper, fleet views, OSV mirror, attestations, CBOM |
| v1.2.0 | 2027-07-31 | Analytics — Scorecard, Lottery Factor, SBOM diff, tree view, blast radius, enriched export |

Two rules drive sequencing:

- **If it can't be back-filled, it lands before 1.0; if it's additive, it lands after.** The register work is additive and lands before 1.0 for *market* reasons, not contract reasons — the [Schema Change Register](#schema) says which is which.
- **Issues raised by the consumer side ship first.** [#398](https://github.com/seebom-labs/BOMHort/issues/398) and [#399](https://github.com/seebom-labs/BOMHort/issues/399) came from someone building *on* BOMHort; they opened v0.8.0.

---

## Phase 1: Foundation & Security ✅ {#phase-1}

**Q1–Q2 2026 · Complete.** Production-ready with real security requirements.

| Status | Issue | Description |
|:------:|-------|-------------|
| ✅ | ~~[#131](https://github.com/seebom-labs/BOMHort/issues/131)~~ Cluster-aware data model | `cluster` column on all core tables (migration `012`). |
| ✅ | ~~[#134](https://github.com/seebom-labs/BOMHort/issues/134)~~ API Authentication | Service token + API key modes. Gate for all write operations. |
| ✅ | ~~[#137](https://github.com/seebom-labs/BOMHort/issues/137)~~ Enhanced health checks | `/readyz`, `/livez` for K8s probes. |
| ✅ | ~~[#139](https://github.com/seebom-labs/BOMHort/issues/139)~~ Headless mode | API-only deployment without Angular UI. |
| ✅ | ~~[#59](https://github.com/seebom-labs/BOMHort/issues/59)~~ Expose API externally | Helm Ingress template + TLS. |
| ✅ | ~~[#8](https://github.com/seebom-labs/BOMHort/issues/8)~~ Project List View | Group SBOMs by project. |
| ✅ | ~~[#144](https://github.com/seebom-labs/BOMHort/issues/144)~~ SBOM Download | Download SBOM JSON from the platform. |
| ✅ | ~~[#55](https://github.com/seebom-labs/BOMHort/issues/55)~~ CycloneDX Support | Parse CycloneDX 1.4+ SBOMs. |
| ✅ | ~~[#37](https://github.com/seebom-labs/BOMHort/issues/37)~~ Version Skew Detection | Cross-org dependency consistency. |
| ✅ | ~~[#132](https://github.com/seebom-labs/BOMHort/issues/132)~~ / ~~[#133](https://github.com/seebom-labs/BOMHort/issues/133)~~ Cluster endpoints | `GET /api/v1/clusters`, per-cluster stats and SBOM lists. |
| ✅ | ~~[#135](https://github.com/seebom-labs/BOMHort/issues/135)~~ SBOM Upload (Push Model) | `POST /api/v1/sboms/upload` from CI/CD pipelines. |
| ✅ | ~~[#398](https://github.com/seebom-labs/BOMHort/issues/398)~~ Project-centric read model | `GET /api/v1/projects/{name}` + sub-resources, de-duplicated counts; the project identity rule is contract. Shipped in v0.8.0. |
| ✅ | ~~[#136](https://github.com/seebom-labs/BOMHort/issues/136)~~ Enhanced CORS | Complete: `CORS_ALLOW_CREDENTIALS`, configurable methods/headers, and max-age. |

**Schema wave `014`–`022` — complete:** `document_store` ([#256](https://github.com/seebom-labs/BOMHort/issues/256)), `namespace`/`project` ([#138](https://github.com/seebom-labs/BOMHort/issues/138), [#57](https://github.com/seebom-labs/BOMHort/issues/57)), `source_repo`/`source_ref` ([#332](https://github.com/seebom-labs/BOMHort/issues/332)), VEX provenance ([#334](https://github.com/seebom-labs/BOMHort/issues/334)), VEX SBOM scope ([#350](https://github.com/seebom-labs/BOMHort/issues/350)), OSV aliases, VEX `product_ref`, `document_version`, `tags` ([#357](https://github.com/seebom-labs/BOMHort/issues/357)). `023`–`026` followed in v0.8.0; the v0.9.0 register work starts at `027`.

**Delivered beyond the roadmap:** Global Search, Package Search, in-toto attestation unwrapping, protobom parsing backend, license resolution via GitHub + npm + NuGet with license-text classification, SPDX license *expression* evaluation ([#402](https://github.com/seebom-labs/BOMHort/issues/402)), dark mode, white-label theming, Prow chat-ops ([#405](https://github.com/seebom-labs/BOMHort/issues/405)).

---

## Phase 2: The road to 1.0 {#phase-2}

**Oct 2026 – Jan 2027 · Theme:** Freeze a contract that an external consumer has already exercised ([#399](https://github.com/seebom-labs/BOMHort/issues/399)), and ship a CRA-grade vulnerability register *inside* the frozen surface rather than bolting it on after.

### v0.8.0 — Contract ✅ (released 2026-10-17) {#v0-8}

| Status | Issue | Description |
|:------:|-------|-------------|
| ✅ | ~~[#399](https://github.com/seebom-labs/BOMHort/issues/399)~~ BOMHort MCP server | Five read-only tools over the REST API (`cmd/mcp-server`), no ClickHouse credentials. stdio by default; Streamable HTTP refuses to start without a bearer token and a non-wildcard Origin allow-list. See [MCP Server](/docs/mcp/). |
| ✅ | ~~[#58](https://github.com/seebom-labs/BOMHort/issues/58)~~ Aggregated SBOM View | The SBOM Explorer reads by project, not by document — same de-duplication as [#398](https://github.com/seebom-labs/BOMHort/issues/398). |
| ✅ | ~~[#355](https://github.com/seebom-labs/BOMHort/issues/355)~~ `source_repo` on real SBOMs | `documentNamespace` fallback, release/tag/commit URL handling, CycloneDX `distribution`. Existing rows need a re-parse. |
| ✅ | ~~[#397](https://github.com/seebom-labs/BOMHort/issues/397)~~ `existingConfigMap` | License policy and exceptions mount from an externally managed ConfigMap. |
| ✅ | ~~[#391](https://github.com/seebom-labs/BOMHort/issues/391)~~ Seed job removed | A leftover `seedJob` block fails `helm template` with a message naming the alternatives. |
| ✅ | ~~[#392](https://github.com/seebom-labs/BOMHort/issues/392)~~ ClickHouse floor | 24.8 LTS, pinned by digest; CI runs every query against 24.8 **and** 24.12. |
| ✅ | ~~[#344](https://github.com/seebom-labs/BOMHort/issues/344)~~ E + I | Project stats read only the selected projects' SBOMs; `apiGateway.queryLimits.*` bounds gateway queries (on by default). A–D, F–H stay post-1.0. |
| ✅ | ~~[#412](https://github.com/seebom-labs/BOMHort/issues/412)~~ CVE id + aliases | `cve_id` and `aliases` on findings, VEX statements and search; lookups by any alias. |
| ✅ | ~~[#266](https://github.com/seebom-labs/BOMHort/issues/266)~~ CSV export | `GET /api/v1/reports/vulnerabilities?format=csv`, streamed, formula-injection safe. |
| ✅ | ~~[#439](https://github.com/seebom-labs/BOMHort/issues/439)~~ License provenance | deps.dev/Packagist/PyPI resolvers, `unapproved` category, per-package license source (migration `024`). See [License Resolution](/docs/license-resolution/). |
| ✅ | ~~GHSA-943f-mm2v-j478~~ UI proxy write auth | The UI's nginx injects `SERVICE_TOKEN` on `GET`/`HEAD` only; uploads through the UI host need their own credential. Shipped in `v0.8.0-rc.3`. |

**Also shipped:** SPDX license expressions evaluated instead of reported as unknown ([#402](https://github.com/seebom-labs/BOMHort/issues/402)); license exceptions from a ConfigMap, URL or S3, reloaded live and applied retroactively ([#470](https://github.com/seebom-labs/BOMHort/issues/470)); summary mode for license compliance and bounded archived-packages memory ([#475](https://github.com/seebom-labs/BOMHort/issues/475)); installable release candidates.

### v0.9.0 — Vulnerability register {#v0-9}

**Due 2026-11-30.** The [#414](https://github.com/seebom-labs/BOMHort/issues/414) umbrella: CRA Annex I Part II made queryable — per finding and per deployed version: CVE, CWE, CVSS, EPSS, KEV status, remediation status, due date, and a timestamp proving it is current.

**First: ingest correctness.** The 2026-10-15 audit found ways to lose, hide or duplicate the rows the register is computed from. These land before the register columns; all except [#446](https://github.com/seebom-labs/BOMHort/issues/446) (migration) are backported to `release/v0.8` as v0.8.x patches.

| Status | Issue | Migration | Description |
|:------:|-------|-----------|-------------|
| 🔲 | [#480](https://github.com/seebom-labs/BOMHort/issues/480) Refresher findings without `cluster`/`namespace`/`project` | none | Newly disclosed CVEs are invisible in scoped views. Before [#459](https://github.com/seebom-labs/BOMHort/issues/459). |
| 🔲 | [#485](https://github.com/seebom-labs/BOMHort/issues/485) OSV stubs never refreshed | none | Precondition for the [#408](https://github.com/seebom-labs/BOMHort/issues/408)/[#409](https://github.com/seebom-labs/BOMHort/issues/409) backfill from `osv_json`. |
| 🔲 | [#482](https://github.com/seebom-labs/BOMHort/issues/482) + [#487](https://github.com/seebom-labs/BOMHort/issues/487) Half-ingested SBOMs never retried; watcher queries per file | none | `sboms` written last as commit marker; one bulk "already queued" query. |
| 🔲 | [#446](https://github.com/seebom-labs/BOMHort/issues/446) → [#483](https://github.com/seebom-labs/BOMHort/issues/483) Second-resolution queue timestamps; concurrent claims | `0xx` `DateTime64(3)` | Column-type change — must be pre-1.0. |
| 🔲 | [#481](https://github.com/seebom-labs/BOMHort/issues/481) + [#489](https://github.com/seebom-labs/BOMHort/issues/489) Resolver cache keeps transient failures forever | none | Shared cache type, "cache definite answers only". |
| 🔲 | [#484](https://github.com/seebom-labs/BOMHort/issues/484) Rate limit trusts client `X-Forwarded-For` | none | Security, small. |
| 🔲 | [#486](https://github.com/seebom-labs/BOMHort/issues/486) Refresher scans per PURL | none | Same binary as the KEV/EPSS feeds. |
| 🔲 | [#488](https://github.com/seebom-labs/BOMHort/issues/488) Search shows an older query's results | none | UI. |
| 🔲 | [#493](https://github.com/seebom-labs/BOMHort/issues/493) CNCF buckets: CycloneDX / SPDX 3 keys skipped, `_release_*` assets | none | Accept `_cdx.json`/`_spdx3.json`; skip `_release_*` keys — one SBOM per release. |
| 🔲 | [#447](https://github.com/seebom-labs/BOMHort/issues/447) `/licenses/compliance` unpaginated (10 MiB ingress cut) | none (shape) | `PaginatedResponse[T]` like every other list; before the freeze. |

**Second: runtime-scanner identity.** Raised by a Kubernetes runtime scanner: *how* was a document produced, *which image* does it describe, *which workload* runs it — and "do you already have this digest?". All additive columns; pre-1.0 because upload parameters and filters are contract. [#460](https://github.com/seebom-labs/BOMHort/issues/460) adds a Go dependency and is decided separately.

| Status | Issue | Migration | Description |
|:------:|-------|-----------|-------------|
| 🔲 | [#459](https://github.com/seebom-labs/BOMHort/issues/459) Ownership filters on `/vulnerabilities`, per-cluster/namespace vulnerability routes | none | After [#480](https://github.com/seebom-labs/BOMHort/issues/480); the columns exist already. |
| 🔲 | [#455](https://github.com/seebom-labs/BOMHort/issues/455) `origin` dimension (`cluster-scan`, `ci`, `registry`, `vendor`, `manual`) | `0xx` | Fixed vocabulary; upload param, per-bucket field, instance default. |
| 🔲 | [#458](https://github.com/seebom-labs/BOMHort/issues/458) Workload identity (`workload_kind`/`name`/`uid`) | `0xx` | Upload params + filters; `project` defaults to the workload name. |
| 🔲 | [#457](https://github.com/seebom-labs/BOMHort/issues/457) Image reference and digest; `?digest=`, `/images/{digest}` | `0xx` | Digest-based dedup is opt-in. |
| 🔲 | [#461](https://github.com/seebom-labs/BOMHort/issues/461) CycloneDX 1.6 / SPDX 3.0.1 fixtures; `k8s_*`/`image` identifiers from the document | `0xx` | Explicit config outranks the document; extracted values fill empty dimensions only. |
| 🔲 | [#456](https://github.com/seebom-labs/BOMHort/issues/456) Named, scoped API keys | `0xx` | Restrict a key to origins/clusters/namespaces/projects; flat `API_KEYS` keeps working. |
| 🔲 | [#460](https://github.com/seebom-labs/BOMHort/issues/460) Prometheus `/metrics` + ServiceMonitor | none | Needs the dependency decision first. |

**Then the register.**

| Status | Issue | Migration | Description |
|:------:|-------|-----------|-------------|
| 🔲 | [#408](https://github.com/seebom-labs/BOMHort/issues/408) CVSS score, vector, version (incl. v4) | `027` | Score is computed in `osvutil` today and discarded. Backfill from `osv_json`. |
| 🔲 | [#409](https://github.com/seebom-labs/BOMHort/issues/409) CWE ids | `027` | From OSV `database_specific.cwe_ids`. Enables crypto CWE filters. |
| 🔲 | [#410](https://github.com/seebom-labs/BOMHort/issues/410) CISA KEV status | `028_create_kev_catalog` | Daily feed; the public signal for "actively exploited" (CRA Art. 14, 24 h). Brings a due date. |
| 🔲 | [#64](https://github.com/seebom-labs/BOMHort/issues/64) EPSS scores | `029_create_epss_scores` | Pulled forward from v1.2.0; shares the refresher plumbing with KEV. |
| 🔲 | [#413](https://github.com/seebom-labs/BOMHort/issues/413) VEX action statement as remediation record | `030` | `action_statement_timestamp` on `vex_statements`. |
| 🔲 | [#411](https://github.com/seebom-labs/BOMHort/issues/411) Remediation SLA policy | none | `remediation-policy.json` → derived `due_date`, `overdue`, `remediation_status`. No write API. |
| 🔲 | [#414](https://github.com/seebom-labs/BOMHort/issues/414) Register umbrella | — | Docs page, `last_refreshed_at` on export and dashboard, final CSV column list. |

### v1.0.0 — Freeze + CRA dashboard {#v1}

**Due 2027-01-31**, after a four-week soak of v0.9.0 on the CNCF instance.

| Status | Issue | Description |
|:------:|-------|-------------|
| 🔲 | [#141](https://github.com/seebom-labs/BOMHort/issues/141) CRA compliance dashboard | Readiness score per project/cluster, computed from what v0.9.0 stores. [#140](https://github.com/seebom-labs/BOMHort/issues/140)/#143 become additional inputs in v1.1.0, not prerequisites. |
| 🔲 | [#7](https://github.com/seebom-labs/BOMHort/issues/7) CVE fix time (MTTR) | `031_create_vulnerability_resolutions`. Stretch — drops to v1.1.0 if the soak needs the time. |
| 🔲 | [#62](https://github.com/seebom-labs/BOMHort/issues/62) Auditor report bundle | CSV + JSON bundle with a manifest. PDF only after the library decision; not a blocker. |
| 🔲 | [#419](https://github.com/seebom-labs/BOMHort/issues/419) Crypto-library inventory | From existing SBOMs by PURL match (`032`); no CBOM needed. |
| 🔲 | [#145](https://github.com/seebom-labs/BOMHort/issues/145) Versioned documentation | Ships **with** the tag. |
| 🔲 | Migration guide + `values.yaml` review | Every key added since v0.7: `mcp.*`, `existingConfigMap`, `seedJob` removal, `apiGateway.queryLimits.*`, image pin, `kev.*`, `epss.*`, `remediationPolicy.*`, `cryptoLibraries.*`. |

### What v1.0 means

- **API contract frozen** — no endpoint removals or response shape changes without v2.0
- **ClickHouse schema stable** — no `ORDER BY` or column-type changes; `ADD COLUMN … DEFAULT` and new tables remain allowed
- **Helm values stable** — existing `values.yaml` keys won't be renamed
- **Supported ClickHouse floor** — 24.8 LTS, covered by CI ([#392](https://github.com/seebom-labs/BOMHort/issues/392)) ✅
- **Support policy active** — current release + 2 previous minors receive security patches (see [Support Policy](/docs/release/#support-policy))
- **A CRA-grade vulnerability register** is exportable per deployed version, and a readiness score is computed from it

All v0.x releases are development milestones and may contain breaking changes between minor versions — read the release notes before upgrading.

---

## Phase 3: Automation, Fleet & Cryptography {#phase-3}

**v1.1.0 · due 2027-04-30.**

### Epic [#338](https://github.com/seebom-labs/BOMHort/issues/338) — Automated VEX generation (VEXViper)

[VEXViper](https://github.com/seebom-labs/VEXViper) is an out-of-tree Go sidecar: it reads findings via the REST API, gathers evidence, asks a configurable LLM or rule engine, and uploads validated OpenVEX back. The correctness blockers ([#332](https://github.com/seebom-labs/BOMHort/issues/332), [#335](https://github.com/seebom-labs/BOMHort/issues/335), [#355](https://github.com/seebom-labs/BOMHort/issues/355)) have all landed.

| Status | Issue | Description |
|:------:|-------|-------------|
| 🔲 | [#336](https://github.com/seebom-labs/BOMHort/issues/336) Idempotent VEX upload + job status | Content-hash dedupe; `GET /api/v1/uploads/{job_id}`. New table `03x_create_upload_jobs`. |
| 🔲 | [#333](https://github.com/seebom-labs/BOMHort/issues/333) Incremental listing + `vex_status=missing` | `?since=&cursor=` on `/sboms`. Query-only. |
| 🔲 | [#334](https://github.com/seebom-labs/BOMHort/issues/334) Provenance UI | Automated vs. human badge, `status_notes`, `?vex_source=`. |
| 🔲 | [#337](https://github.com/seebom-labs/BOMHort/issues/337) Outbound webhooks | HMAC-signed `sbom.ingested`, `findings.updated`, `vex.applied`, `upload.rejected`. |

### Fleet operations

| Status | Issue | Description |
|:------:|-------|-------------|
| 🔲 | [#138](https://github.com/seebom-labs/BOMHort/issues/138) Namespace filtering (API + UI) | `?namespace=` on list endpoints, namespace chips. |
| 🔲 | [#267](https://github.com/seebom-labs/BOMHort/issues/267) → [#176](https://github.com/seebom-labs/BOMHort/issues/176) Cluster Picker | Query-param filter first (help wanted), then navbar dropdown. |
| 🔲 | [#140](https://github.com/seebom-labs/BOMHort/issues/140) Workload vulnerability summary | Image → posture; additional [#141](https://github.com/seebom-labs/BOMHort/issues/141) input. |
| 🔲 | [#57](https://github.com/seebom-labs/BOMHort/issues/57) Per-project policies | License policies, severity thresholds, exception scopes per project. |
| ✅ | ~~[#136](https://github.com/seebom-labs/BOMHort/issues/136)~~ CORS (remaining) | `CORS_ALLOW_CREDENTIALS`, configurable methods/headers. |
| 🔲 | [#490](https://github.com/seebom-labs/BOMHort/issues/490) Resolver response limits | Bounded bodies, deps.dev page cap; lands with the mirror's outbound feeds. |
| 🔲 | [#60](https://github.com/seebom-labs/BOMHort/issues/60) Local OSV mirror | Offline / air-gapped; KEV and EPSS feeds get the same treatment. |
| 🔲 | [#143](https://github.com/seebom-labs/BOMHort/issues/143) In-toto Witness integration | `03x_create_attestations`, signature verification; additional [#141](https://github.com/seebom-labs/BOMHort/issues/141) input. |

### Cryptography — [#420](https://github.com/seebom-labs/BOMHort/issues/420) (CBOM)

| Status | Issue | Description |
|:------:|-------|-------------|
| 🔲 | [#415](https://github.com/seebom-labs/BOMHort/issues/415) CycloneDX 1.6 crypto assets | `03x_create_crypto_assets`. |
| 🔲 | [#416](https://github.com/seebom-labs/BOMHort/issues/416) Cryptographic inventory | Algorithms, protocols, certificates, keys per project/fleet. |
| 🔲 | [#417](https://github.com/seebom-labs/BOMHort/issues/417) Crypto policy + exceptions | `crypto-policy.json`, BSI TR-02102 / NIST SP 800-131A example profiles. |
| 🔲 | [#418](https://github.com/seebom-labs/BOMHort/issues/418) PQC readiness | `quantum_vulnerable` / `hybrid` / `pqc` classification, readiness % per project. |

---

## Phase 4: Analytics {#phase-4}

**v1.2.0 · due 2027-07-31.** CRA scoring left this phase for 1.0; what remains is prioritisation and dependency-health depth.

| Status | Issue | Description |
|:------:|-------|-------------|
| 🔲 | [#255](https://github.com/seebom-labs/BOMHort/issues/255) Enriched SBOMs + enriched download | Overlay on the [#256](https://github.com/seebom-labs/BOMHort/issues/256) originals; companion VEX; in-toto re-sign. |
| 🔲 | [#254](https://github.com/seebom-labs/BOMHort/issues/254) protobom/storage schema evaluation | Research; informs [#255](https://github.com/seebom-labs/BOMHort/issues/255). Not a rewrite of `sbom_packages`. |
| 🔲 | [#38](https://github.com/seebom-labs/BOMHort/issues/38) SBOM Diff | Dependency tree divergence between versions. |
| 🔲 | [#56](https://github.com/seebom-labs/BOMHort/issues/56) Dependency Tree View | Hierarchical visualization of transitive chains. |
| 🔲 | [#63](https://github.com/seebom-labs/BOMHort/issues/63) Blast Radius Search | Version-constrained impact analysis. |
| 🔲 | [#61](https://github.com/seebom-labs/BOMHort/issues/61) OpenSSF Scorecard | Upstream project health per dependency. |
| 🔲 | [#82](https://github.com/seebom-labs/BOMHort/issues/82) Lottery Factor | Single-maintainer risk detection. |
| 🔲 | [#268](https://github.com/seebom-labs/BOMHort/issues/268) Official ClickHouse operator | Breaking `values.yaml` change → v2.0 candidate. |

---

## Schema Change Register {#schema}

Everything that touches `db/migrations/` or a frozen response shape. The authoritative register — including the "needs pre-1.0?" reasoning per row — is the one in [`ROADMAP.md`](https://github.com/seebom-labs/BOMHort/blob/main/ROADMAP.md#schema-change-register); check it, upstream `main` and open pull requests before claiming a number. After 1.0, `ORDER BY` and column-type changes are **never** allowed; `ADD COLUMN … DEFAULT` and new tables are fine at any time.

| Migration | Issue | Change | Pre/Post 1.0 |
|-----------|-------|--------|:------------:|
| `012_add_cluster_column` | [#131](https://github.com/seebom-labs/BOMHort/issues/131) | `ADD COLUMN cluster` | ✅ shipped |
| `013_create_registry_license_cache` | [#330](https://github.com/seebom-labs/BOMHort/issues/330) | New table | ✅ shipped |
| `014_create_document_store` | [#256](https://github.com/seebom-labs/BOMHort/issues/256) | New table | ✅ shipped (**pre**) |
| `015_add_namespace_project_columns` | [#138](https://github.com/seebom-labs/BOMHort/issues/138), [#57](https://github.com/seebom-labs/BOMHort/issues/57) | `ADD COLUMN namespace, project` (core tables + `document_store`) | ✅ shipped (**pre**) |
| `016_add_source_columns` | [#332](https://github.com/seebom-labs/BOMHort/issues/332) | `ADD COLUMN source_repo, source_ref` (`sboms` + `ingestion_queue`) | ✅ shipped (**pre**) |
| `017_add_vex_provenance` | [#334](https://github.com/seebom-labs/BOMHort/issues/334) | `ADD COLUMN author, role, tooling, status_notes` | ✅ shipped (**pre**) |
| `018_add_vex_sbom_scope` | [#350](https://github.com/seebom-labs/BOMHort/issues/350) | `ADD COLUMN sbom_id` on `vex_statements` + `target_sbom_id` on `ingestion_queue` — VEX scoped to its SBOM | ✅ shipped (**pre**) |
| `019_add_vulnerability_aliases` | — | `ADD COLUMN aliases` on `vulnerabilities` (GHSA ↔ CVE); VEX matches by alias | ✅ shipped (**pre**) |
| `020_add_vex_product_ref` | — | `ADD COLUMN product_ref` on `vex_statements` (VEX rescue pass) | ✅ shipped (**pre**) |
| `021_add_document_version` | — | `ADD COLUMN document_version` on `sboms` | ✅ shipped (**pre**) |
| `022_add_sbom_tags` | [#357](https://github.com/seebom-labs/BOMHort/issues/357) | `ADD COLUMN tags` on `sboms` + `ingestion_queue` | ✅ shipped (**pre**) |
| `023_add_project_parent` | — | `ADD COLUMN parent` on `sboms`/`ingestion_queue`, `root_purl`, `supplier` on `sboms` (project groups) | ✅ shipped (**pre**) |
| `024_add_package_license_sources` | [#439](https://github.com/seebom-labs/BOMHort/issues/439) | `ADD COLUMN package_license_sources` on `sbom_packages` — where each license came from or why it is missing ([License Resolution](/docs/license-resolution/)) | ✅ shipped (**pre**) |
| `025_add_dependency_depth` | — | `ADD COLUMN package_depths` on `sbom_packages`, `dependency_depth` on `vulnerabilities` (direct vs. transitive) | ✅ shipped (**pre**) |
| `026_add_queue_retry_after` | — | `ADD COLUMN retry_after` on `ingestion_queue` (defer jobs on a GitHub rate limit) | ✅ shipped (**pre**) |
| — | [#335](https://github.com/seebom-labs/BOMHort/issues/335) | Row semantics of `/sboms/{id}/vulnerabilities` | ✅ shipped (**pre**, API) |
| — | [#177](https://github.com/seebom-labs/BOMHort/issues/177) | `cluster` in `SBOMListItem` | ✅ shipped (**pre**, API) |
| — | [#398](https://github.com/seebom-labs/BOMHort/issues/398) | De-duplicated project counts; project identity rule is contract | ✅ shipped (**pre**, API) |
| — | [#399](https://github.com/seebom-labs/BOMHort/issues/399), [#397](https://github.com/seebom-labs/BOMHort/issues/397), [#391](https://github.com/seebom-labs/BOMHort/issues/391), [#392](https://github.com/seebom-labs/BOMHort/issues/392), [#344](https://github.com/seebom-labs/BOMHort/issues/344)-I | `mcp.*`, `existingConfigMap`, `seedJob` removed, ClickHouse image pin, `apiGateway.queryLimits.*` | ✅ shipped (**pre**, Helm values) |
| — | [#412](https://github.com/seebom-labs/BOMHort/issues/412), [#266](https://github.com/seebom-labs/BOMHort/issues/266) | `cve_id` + `aliases` on findings; CSV export endpoint | ✅ shipped (**pre**, API) |
| — | [#411](https://github.com/seebom-labs/BOMHort/issues/411) | `remediation-policy.json`; derived `due_date`/`overdue`, no storage | **pre** (v0.9.0, values) |
| — | [#141](https://github.com/seebom-labs/BOMHort/issues/141), [#62](https://github.com/seebom-labs/BOMHort/issues/62) | CRA readiness score; report bundle | **pre** (v1.0.0, API) |
| `0xx_ingestion_queue_created_at_datetime64` | [#446](https://github.com/seebom-labs/BOMHort/issues/446) | `MODIFY COLUMN created_at DateTime64(3)` on `ingestion_queue`; number assigned at merge | **pre** (v0.9.0, column type) |
| `0xx_add_origin` | [#455](https://github.com/seebom-labs/BOMHort/issues/455) | `ADD COLUMN origin` on the 7 data tables | **pre** (v0.9.0) |
| `0xx_add_workload_identity` | [#458](https://github.com/seebom-labs/BOMHort/issues/458) | `ADD COLUMN workload_kind, workload_name, workload_uid` on `sboms` | **pre** (v0.9.0) |
| `0xx_add_image_identity` | [#457](https://github.com/seebom-labs/BOMHort/issues/457) | `ADD COLUMN image_ref, image_digest` on `sboms` (+ skip index), `image_digest` on children | **pre** (v0.9.0) |
| `0xx_add_producer_identifiers` | [#461](https://github.com/seebom-labs/BOMHort/issues/461) | `ADD COLUMN producer_identifiers Map(String,String)` on `sboms` | **pre** (v0.9.0) |
| `0xx_add_uploaded_by` | [#456](https://github.com/seebom-labs/BOMHort/issues/456) | `ADD COLUMN uploaded_by` on `sboms` | **pre** (v0.9.0) |
| — | [#447](https://github.com/seebom-labs/BOMHort/issues/447) | `/licenses/compliance` → `PaginatedResponse[T]` | **pre** (v0.9.0, API) |
| `027_add_vulnerability_cvss_cwe` | [#408](https://github.com/seebom-labs/BOMHort/issues/408), [#409](https://github.com/seebom-labs/BOMHort/issues/409) | CVSS score/vector/version and CWE IDs on `vulnerabilities` | **pre** (v0.9.0) |
| `028_create_kev_catalog` | [#410](https://github.com/seebom-labs/BOMHort/issues/410) | New table | **pre** (v0.9.0) |
| `029_create_epss_scores` | [#64](https://github.com/seebom-labs/BOMHort/issues/64) | New table | **pre** (v0.9.0) |
| `030_add_vex_action_statement_timestamp` | [#413](https://github.com/seebom-labs/BOMHort/issues/413) | `ADD COLUMN action_statement_timestamp` on `vex_statements` | **pre** (v0.9.0) |
| `031_create_vulnerability_resolutions` | [#7](https://github.com/seebom-labs/BOMHort/issues/7) | New table | **pre** (v1.0.0, stretch) |
| `032_create_crypto_libraries` | [#419](https://github.com/seebom-labs/BOMHort/issues/419) | New table (or MV over `sbom_packages`) | **pre** (v1.0.0) |
| `03x_create_package_index_mv` | [#344](https://github.com/seebom-labs/BOMHort/issues/344)-C/D/E | MV + skip indexes | post |
| `03x_create_upload_jobs` | [#336](https://github.com/seebom-labs/BOMHort/issues/336) | New table | post |
| `03x_create_attestations` | [#143](https://github.com/seebom-labs/BOMHort/issues/143) | New table | post |
| `03x_create_crypto_assets`, `03x_create_crypto_compliance` | [#415](https://github.com/seebom-labs/BOMHort/issues/415), [#417](https://github.com/seebom-labs/BOMHort/issues/417) | New tables | post (v1.1.0) |
| `03x_*` | [#61](https://github.com/seebom-labs/BOMHort/issues/61), [#82](https://github.com/seebom-labs/BOMHort/issues/82), [#255](https://github.com/seebom-labs/BOMHort/issues/255), [#60](https://github.com/seebom-labs/BOMHort/issues/60) | New tables | post |
| — | [#268](https://github.com/seebom-labs/BOMHort/issues/268) | Operator swap | **v2.0** |

---

## Dependency Graph

```text
PRE-1.0 contract:
#398 ✅ ──┬── #58 ✅ (Aggregated SBOM View)                      v0.8.0
          └── #399 ✅ (MCP: get_project) ── post-1.0: write tools

REGISTER (#414):
#412 ✅ (cve_id/aliases) ── #410 (KEV, matched by alias) ──┐
#408 (CVSS) ─────────────────────────────────────────────┼── #411 (SLA due date; KEV due date overrides) ──┐
#409 (CWE) ──────────────────────────────────────────────┤                                                  ├── #141 (CRA score)  v1.0.0
#64  (EPSS) ─────────────────────────────────────────────┤                                                  ├── #62  (report bundle)
#413 (VEX action statement) ─────────────────────────────┘                                                  └── #7   (MTTR)
#266 ✅ (CSV) ── grows with every row above ── #62

CRYPTO (#420):
#419 (library inventory, SBOM-only)                         v1.0.0
#415 (CBOM ingest) ── #416 (inventory) ── #417 (policy) ── #418 (PQC)   v1.1.0
                                                 └── #409 (CWE-327 filter on the register)

RUNTIME-SCANNER IDENTITY (v0.9.0, after ingest correctness):
#455 (origin) ── #456 (scoped API keys)
#457 (image digest) ──┬── #461 (identifiers from the document)
#458 (workload) ──────┘
#460 (Prometheus) ── dependency decision first

VEXVIPER (#338):
#355 ── #336 (idempotent upload) ── #333 (since/cursor) ── #337 (webhooks) ── #334 UI

FLEET:
#131 ── #132/#133 ── #177 ── #267 ── #176
     └── #138 ── #140 ──┐
#143 (Witness) ─────────┴── additional #141 inputs (v1.1.0)

#60 (OSV/KEV/EPSS mirror) ── standalone
#61, #82 ── extend internal/github        #254 ── informs #255        #268 ── v2.0
```

---

## Prioritization

### Why the CRA moved into 1.0
The reporting obligation is **in force**, and its 24-hour clock for actively exploited vulnerabilities is exactly what KEV status (#410) makes visible. Customers ask for a register *now*, column by column. Every register item is additive, so this does not break the back-fill rule — it is pre-1.0 because 1.0 is the release adopters evaluate against the CRA.

### Why three releases instead of one
One milestone with 21 issues and a tag at the end slips. v0.8.0 kept its October date, v0.9.0 is the self-contained register, and v1.0.0 adds the score on top with a December soak.

### Why VEXViper after the register
The register is what VEX statements are written *against*: #413 fixes what a statement records, #411 defines what "open" means, #410/#64 define what to triage first.

### Cluster vs. namespace vs. project

| Dimension | Question | Example | Cardinality |
|-----------|----------|---------|-------------|
| `cluster` | Where is it deployed? | `prod-eu` | 1–50 |
| `namespace` | Which team boundary inside the cluster? | `payments` | 10–500 |
| `project` | What is it / who owns it? | `payment-service` | 50–5000 |

All three are `LowCardinality(String) DEFAULT ''` columns, none in `ORDER BY`. `tags` label projects across these dimensions; they do not replace them.

---

## Non-Goals

- ❌ Custom Kubernetes Operator (Helm + ClickHouse Operator)
- ❌ In-tree VEX generation / LLM calls (stays in the VEXViper sidecar; the MCP server is a transport)
- ❌ MCP write tools in 1.0 (read-only by design)
- ❌ Write APIs for policies or exceptions — license, remediation, crypto (frontend is public)
- ❌ Per-finding manual status or due dates (status from VEX, due dates from policy)
- ❌ CBOM generation or crypto scanning (BOMHort consumes CBOMs)
- ❌ CRA reporting to ENISA/CSIRTs (BOMHort tells you *what* and *when*; filing is your process)
- ❌ Multi-repo split (monorepo is a hard constraint)
- ❌ Real-time streaming (batch + webhooks is sufficient)
- ❌ RBAC/multi-tenancy (auth is binary for now)
- ❌ Full OIDC in BOMHort (upstream proxy responsibility)
- ❌ Relational rewrite of `sbom_packages` (#254 informs the overlay only)

---

## Contributing

Want to pick up an issue from the roadmap? Check the [Project Board](https://github.com/orgs/seebom-labs/projects/1) for items in the **Todo** column. Issues labeled `help wanted` or `good first issue` — for example #267 — are especially good for new contributors.

See [Development Guide](/docs/development/) for setup instructions.
