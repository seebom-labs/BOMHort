# BOMHort Product Roadmap

> Last updated: 2026-10-04
> Project Board: https://github.com/orgs/seebom-labs/projects/1
> Milestones: [v0.8.0](https://github.com/seebom-labs/BOMHort/milestone/5)  [v0.9.0](https://github.com/seebom-labs/BOMHort/milestone/6)  [v1.0.0](https://github.com/seebom-labs/BOMHort/milestone/1)  [v1.1.0](https://github.com/seebom-labs/BOMHort/milestone/2)  [v1.2.0](https://github.com/seebom-labs/BOMHort/milestone/3)  [v2.0.0](https://github.com/seebom-labs/BOMHort/milestone/4)

> ℹ️ **This file is updated when a release is cut, not in feature PRs.** Do not tick your own entry — every PR that does edits the same criteria line and the same milestone row, so two open PRs conflict on a checklist, and resolving that by picking a side silently un-ticks an issue that is already merged. See the release checklist in [`docs/RELEASE.md`](docs/RELEASE.md).

## Executive Summary

BOMHort is transitioning from a single-instance SBOM visualization tool into an **enterprise-grade, multi-cluster Software Supply Chain Security platform**. Phase 1 (foundation, auth, multi-cluster model, push ingestion) is complete and shipped in v0.4–v0.7.

The roadmap is organised around one hard deadline — the **v1.0.0 schema and API freeze** — and, since 2026-09-25, around one regulatory fact: the **EU Cyber Resilience Act's vulnerability-reporting obligations are in force since 2026-09-11**, and the first customer questionnaires asking for a CRA-grade vulnerability register have arrived. Consequently the CRA scope that Phase 4 had parked in 2027 H1 moves **into 1.0**, and 1.0 is reached in three steps:

1. **v0.8.0 — Contract (Oct 2026):** the consumer-facing contract and chart hygiene that were the 1.0 blockers: MCP server #399 first, project aggregation UI #58, `source_repo` fix #355, `values.yaml` shape (#397, #391, #392, #344-I), perf #344-E — plus the two cheapest register items (#412, #266).
2. **v0.9.0 — Vulnerability register (Nov 2026):** CRA Annex I Part II made queryable: CVSS #408, CWE #409, KEV #410, EPSS #64, remediation record #413, SLA due dates #411 — the #414 umbrella.
3. **v1.0.0 — Freeze + CRA dashboard (Jan 2027):** CRA readiness score #141 (re-scoped onto the register), MTTR #7, auditor report bundle #62, crypto-library inventory #419, versioned docs #145. Then freeze.
4. **v1.1.0 — Automation, Fleet & Cryptography (Apr 2027):** VEXViper epic #338, fleet views, OSV mirror, attestations #143, and the CBOM block #420 (#415–#418).
5. **v1.2.0 — Analytics (Jul 2027):** Scorecard, Lottery Factor, SBOM diff, tree view, blast radius, enriched export.

Two rules drive sequencing. The old one still holds: **if it can't be back-filled, it lands before 1.0; if it's additive, it lands after** — the register work is additive, it lands before 1.0 for *market* reasons, not contract reasons, and the schema register below says so per row. The new one: **issues raised by the consumer side ship first** — @jeefy's #398 (✅ v0.7.x) and #399 open every release they appear in, because they are the questions an external consumer of the contract actually asked.

> **Re-plan 2026-09-25.** Triggered by two customer security questionnaires
> (vulnerability register incl. CVE/CWE/CVSS/EPSS/KEV/remediation/due date → **#414**;
> cryptographic risk management incl. CBOM inventory, crypto policy, PQC → **#420**), each
> broken into sub-issues (#408–#413, #415–#419). Decisions:
> **(1)** the 1.0 milestone is split into `v0.8.0` (contract, 2026-10-31), `v0.9.0`
> (register, 2026-11-30) and `v1.0.0` (freeze + CRA dashboard, **2027-01-31**);
> **(2)** everything CRA-shaped moves into that 1.0 path: #414's sub-issues, #64 (from
> v1.2.0), #141 (from v1.2.0, re-scoped to not wait for #143/#140), #7 (from v1.2.0), #62
> and #266 (from v1.1.0), #419 (new);
> **(3)** the CBOM block #415–#418 lands in v1.1.0 — three new tables, all additive, not
> CRA-critical; **(4)** #399 is the first item of v0.8.0; **(5)** v1.1.0 → 2027-04-30,
> v1.2.0 → 2027-07-31. The previous re-plan (2026-09-24) is preserved below where its
> reasoning still applies.

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
| ~~#398~~ | ~~Project-centric read model~~ | ✅ v0.7.x (#401): `GET /api/v1/projects/{name}` + sub-resources, de-duplicated counts, project identity rule (`projectKeyExpr`) is contract. |
| #136 | Enhanced CORS | 🟡 **Functionally done** — `POST` on the upload route, `X-API-Key`/`X-Service-Token`/`X-Filename` headers, configurable origins. Remaining scope (`CORS_ALLOW_CREDENTIALS`, configurable methods/headers) is additive → v1.1.0. |

**Delivered beyond the roadmap:** Global Search (`GET /api/v1/search`), Package Search + detail page, in-toto attestation unwrapping, protobom parsing backend, license resolution via GitHub + npm + NuGet registries with license-text classification (`internal/licensetext`), SPDX license *expression* evaluation (#402), SPDX file-level filtering, dark mode, white-label theming, Prow chat-ops (#405).

**Schema wave `014`–`022` — complete** (`023` project parent and `024` license sources followed; the v0.9.0 register work starts at `025`). `document_store` (#256), `namespace`/`project` columns (#138, #57), `source_repo`/`source_ref` (#332), VEX provenance (#334), VEX SBOM scope (#350), OSV aliases (`019`), VEX `product_ref` (`020`), `document_version` (`021`), `tags` (#357). Every column the post-1.0 features were known to need exists; the register work below adds columns and tables of its own and is listed in the Schema Change Register.

---

## Phase 2: The road to 1.0 (Oct 2026 – Jan 2027)

**Theme:** Freeze a contract that an external consumer has already exercised (#399), and ship a CRA-grade vulnerability register *inside* the frozen surface rather than bolting it on after.

### 2a. v0.8.0 — Contract (due 2026-10-31)

Everything that was blocking 1.0 on 2026-09-24, minus the tag. Order within the release is the order of the table.

| # | Issue | Type | Why here |
|---|-------|------|----------|
| ~~#399~~ | ~~**BOMHort MCP server** — read-only tool surface over the REST API (`cmd/mcp-server`), SDK `>= v1.4.1`, stdio default~~ | New component + new `values.yaml` block (`mcp.*`) | ✅ Five read-only tools (`list_projects`, `get_project`, `search_packages`, `list_vulnerabilities`, `get_sbom`) over `internal/apiclient` — a REST consumer, no ClickHouse credentials. SDK on `v1.8.0`. stdio default; Streamable HTTP refuses to start (and `helm template` refuses to render) without a bearer token and a non-wildcard Origin allow-list. Full reasoning and the SDK advisory table are in [Prioritization Rationale](#why-399-mcp-server-before-the-freeze-when-its-purely-additive). |
| **#58** | Aggregated SBOM View — N versions of one project as one expandable row | UI + query | UI half of #398 (✅); same de-dup semantics. |
| ~~#355~~ | ~~`source_repo` extraction yields 0 % on real SBOMs — `documentNamespace` fallback~~ | Parser | ✅ `documentNamespace` last-resort fallback (strict: forge host or forge path shape only), release/tag/commit URL handling in `sourcerepo`, CycloneDX `distribution` counterpart. Existing rows need a re-parse to pick it up. |
| **#397** | `licenseExceptions.existingConfigMap` + `licensePolicy.existingConfigMap` | Helm values | Values shape; GitOps users otherwise inline ~180 KB into an Argo `Application` (cncf/automation#703). |
| **#391** | Seed job never seeds — gate (`seedJob.enabled`) or remove | Helm values | Ships broken since March, rendered by our own `values-production.yaml`. |
| **#392** | Chart ships ClickHouse 24.8, CI tests 24.12 — decide the supported floor | Helm values + CI matrix | Support policy starts at 1.0; the floor must be a written decision. |
| **#344** E + I | `enrichProjectStats` per page (E — lands on #398's semantics), ClickHouse `max_threads`/`max_memory_usage`/`max_execution_time` in values (I) | Query + Helm values | E was sequenced behind #398, which shipped; I is values shape. A–D, F–H stay additive (post-1.0 MVs/indexes). |
| **#412** | Expose the CVE id and OSV aliases in API, UI and lookups | DTO + query, **no migration** | Register item that costs nothing: `aliases` exist since `019`. Makes every finding answer "which CVE" before the register lands. |
| **#266** | CSV export for vulnerabilities (stdlib `encoding/csv`) | New endpoint | Register item, `good first issue`. Column list grows in v0.9.0 as fields arrive; the endpoint shape is set here. |
| **#439** | License resolution with provenance — deps.dev/Packagist/PyPI resolvers, `unapproved` category, per-package license source | Migration `024` + new endpoint + DTO field | `license_source` on dependency nodes and `GET /api/v1/licenses/sources` are contract surface, so they land before the freeze. Every heuristic is documented on the License Resolution docs page, which a test keeps in sync with the code. |

**Exit criteria:** an MCP client can ask `get_project` and get de-duplicated numbers; every `values.yaml` key 1.0 promises to keep exists; `source_repo` > 90 % on the CNCF corpus; a CSV of findings with CVE ids can be downloaded.

### 2b. v0.9.0 — Vulnerability register (due 2026-11-30)

The **#414** umbrella. CRA Annex I Part II (1)–(2) in one sentence: identify and document vulnerabilities, remediate without delay. A register that a security officer can hand to an auditor needs, per finding and per deployed version: CVE, CWE, CVSS, EPSS, KEV status, remediation status, due date, and a timestamp proving it is current. Order is dependency order.

| # | Issue | Migration | Notes |
|---|-------|-----------|-------|
| **#408** | CVSS score, vector, version (not only the bucket); v4 support | `025` `ADD COLUMN cvss_score, cvss_vector, cvss_version` on `vulnerabilities` | Score is already computed in `osvutil` and discarded. Backfill from `osv_json`. |
| **#409** | CWE ids from OSV `database_specific.cwe_ids` | `025` `ADD COLUMN cwe_ids Array(String)` (same migration) | Backfill from `osv_json`. Enables CRA/crypto CWE filters (CWE-327/-326/-328/-295/-916). |
| **#410** | CISA **KEV** catalogue status | `026_create_kev_catalog` (new table, keyed by CVE) | Daily feed in `cve-refresher`; matched via `aliases`. **CRA Art. 14: actively exploited vulnerabilities must be reported within 24 h** — KEV is the public signal for "actively exploited". Brings an externally set `dueDate`. |
| **#64** | **EPSS** scores | `027_create_epss_scores` (new table, keyed by CVE) | **Pulled forward from v1.2.0.** Same shape as #410 (daily bulk → side table); the two share refresher plumbing and the triage rule *KEV ∨ EPSS ≥ x ∨ CVSS ≥ 9*. |
| **#413** | VEX action statement as remediation record; `action_statement_timestamp` | `028` `ADD COLUMN action_statement_timestamp` on `vex_statements` | Surfaces what is stored; the remediation *status* column of the register. |
| **#411** | Remediation SLA policy → policy-derived `due_date`, `overdue`, `remediation_status` | none (computed at query time from `remediation-policy.json`) | The *estimated resolution date* column. Config-driven like `license-policy.json`; KEV due date overrides. No write API — public frontend. |
| **#414** | Umbrella: docs page "Using BOMHort as a vulnerability register", `last_refreshed_at` on export and dashboard, #266 column list finalised | — | Closes when the row above is complete. |

**Exit criteria:** `GET /api/v1/projects/{name}/vulnerabilities` and the CSV export carry `cve_id, aliases, cwe_ids, cvss_score, cvss_vector, epss_score, epss_percentile, kev_listed, kev_due_date, vex_status, remediation_status, action_statement, action_statement_timestamp, discovered_at, due_date, last_refreshed_at`; the dashboard shows overdue and KEV counts.

### 2c. v1.0.0 — Freeze + CRA dashboard (due 2027-01-31)

| # | Issue | Type | Notes |
|---|-------|------|-------|
| **#141** | **CRA compliance dashboard** — readiness score per project/cluster | New endpoint + UI, no migration | **Moved from v1.2.0 and re-scoped.** The 2026-09-24 plan made it wait for #140 (workloads), #143 (attestations) and #62. It no longer does: the score is computed from what v0.9.0 stores — SBOM coverage per project, register completeness (CVSS/CWE present), open KEV findings, overdue findings (#411), VEX coverage, refresh age. #140/#143 become *additional inputs* in v1.1.0, not prerequisites. |
| **#7** | CVE fix time (MTTR) per project | `029_create_vulnerability_resolutions` (new table) | **Moved from v1.2.0.** CRA "remediate without delay" needs the backwards-looking number next to #411's forward-looking one. Detection in `parsing-worker` (finding disappears between versions) and on VEX `fixed`/`not_affected`. *Stretch: if the December soak needs the time, #7 drops to v1.1.0 — the table is additive.* |
| **#62** | Auditor report bundle | Endpoint | **Moved from v1.1.0.** 1.0 scope: CSV + JSON bundle per project/fleet with a manifest (`sha256`, `generated_at`, `last_refreshed_at`, policy versions). **PDF only after the `gofpdf` vs `pdfcpu` decision** — not a 1.0 blocker. |
| **#419** | Cryptographic **library** inventory from existing SBOMs (`crypto-libraries.json`, PURL match) | `030_create_crypto_libraries` (new table) | New. Works on every SBOM already ingested, no CBOM needed; first defensible answer to "cryptographic inventory" (#420) and the CRA "state-of-the-art encryption" evidence. Small. The CBOM block stays in v1.1.0. |
| **#145** | Versioned documentation | Docs infra | Must ship **with** the tag. |
| — | Migration guide + `values.yaml` stability review | Process | Covers every new key since v0.7: `mcp.*` (#399), `existingConfigMap` (#397), `seedJob.enabled` (#391), ClickHouse limits (#344-I), image pin (#392), `kev.*`/`epss.*` feed URLs and skips (#410, #64), `remediationPolicy.*` (#411), `cryptoLibraries.*` (#419). |
| — | `AGENTS.md` dependency list | Docs | 5 → 6 direct dependencies (`modelcontextprotocol/go-sdk >= v1.4.1`). No further dependency for the register: KEV/EPSS are HTTP + JSON/CSV, stdlib. |
| — | December soak | Process | v0.9.0 runs on the CNCF instance for four weeks before the tag; register numbers are compared against the questionnaire answers given by hand. |

### 🎯 v1.0.0 Milestone

**Target: 2027-01-31** (was 2026-11-30; moved on 2026-09-25 to make room for v0.9.0 and a December soak).

- API contract frozen (no breaking changes without major version bump)
- ClickHouse schema stable (no `ORDER BY`/type changes; `ADD COLUMN` and new tables remain allowed)
- Helm chart values stable — including `mcp.*`, `existingConfigMap`, `seedJob.enabled`, ClickHouse limits, `kev.*`, `epss.*`, `remediationPolicy.*`, `cryptoLibraries.*`
- Supported ClickHouse version floor decided, written down and covered by CI (#392)
- Support policy (current − 2) takes effect
- Versioned documentation enabled (#145)
- **A CRA-grade vulnerability register is exportable per deployed version, and a readiness score is computed from it (#414, #141)**

**v1.0 Criteria:**
- [x] ~~Version Skew Detection~~ (#37) · ~~API Authentication~~ (#134) · ~~Cluster-aware schema~~ (#131) · ~~Cluster endpoints~~ (#132, #133) · ~~Upload~~ (#135) · ~~CycloneDX~~ (#55) · ~~Health probes~~ (#137)
- [x] ~~Schema wave `014`–`022`~~ (#256, #138, #332, #334, #57 column, #350, #357)
- [x] ~~One row per `(vuln_id, purl)` — latest VEX wins (#335)~~ · ~~`cluster` in `SBOMListItem` (#177)~~
- [x] ~~Project-centric read model + de-duplicated counts (#398)~~
- [ ] **v0.8.0:** ~~MCP server + `mcp.*` (#399)~~ ✅ · Aggregated SBOM View (#58) · ~~`source_repo` fallback (#355)~~ ✅ · `existingConfigMap` (#397) · seed job (#391) · ClickHouse floor (#392) · perf E + I (#344) · CVE id/aliases (#412) · CSV export (#266)
- [ ] **v0.9.0:** CVSS (#408) · CWE (#409) · KEV (#410) · EPSS (#64) · remediation record (#413) · SLA due dates (#411) · register docs (#414)
- [ ] **v1.0.0:** CRA dashboard (#141) · MTTR (#7, stretch) · report bundle (#62) · crypto-library inventory (#419) · versioned docs (#145) · migration guide + values review

### Milestone map

Every open issue carries a milestone — "no milestone" is not a valid state.

| Milestone | Due | Theme | Open issues |
|-----------|-----|-------|-------------|
| [v0.8.0](https://github.com/seebom-labs/BOMHort/milestone/5) | 2026-10-31 | Contract | ~~#399~~, #58, ~~#355~~, #397, #391, #392, #344, #412, #266, #439 |
| [v0.9.0](https://github.com/seebom-labs/BOMHort/milestone/6) | 2026-11-30 | Vulnerability register | #408, #409, #410, #64, #413, #411, #414 |
| [v1.0.0](https://github.com/seebom-labs/BOMHort/milestone/1) | 2027-01-31 | Freeze + CRA dashboard | #141, #7, #62, #419, #145 |
| [v1.1.0](https://github.com/seebom-labs/BOMHort/milestone/2) | 2027-04-30 | Automation, fleet & cryptography | #338, #336, #333, #337, #334 (UI), #138 (API/UI), #267, #176, #140, #57, #136, #60, #143, #420, #415, #416, #417, #418 |
| [v1.2.0](https://github.com/seebom-labs/BOMHort/milestone/3) | 2027-07-31 | Analytics | #61, #82, #38, #56, #63, #255, #254 |
| [v2.0.0](https://github.com/seebom-labs/BOMHort/milestone/4) | — | breaking only | #268 |

`v2.0.0` has no due date on purpose: per the major-version policy in `AGENTS.md` it is driven by accumulated breaking changes (earliest Q1/Q2 2028), not by a calendar.

**Exit criteria for Phase 2:** Every SBOM ingested from 1.0 onward can be reproduced byte-for-byte; a project can be answered for as a project, by a human and by an agent over MCP; **every finding in every deployed version can be exported with CVE, CWE, CVSS, EPSS, KEV status, remediation status and due date, and the export says when it was last refreshed.**

---

## Phase 3: Automation, Fleet Operations & Cryptography (v1.1.0, due 2027-04-30)

**Theme:** Make BOMHort a first-class platform for *automated* supply-chain workflows — starting with VEX generation — finish the fleet-scale views, and add the cryptographic dimension the register lacks.

### 3a. Epic #338 — Automated VEX generation (VEXViper integration)

[VEXViper](https://github.com/seebom-labs/VEXViper) is an out-of-tree Go sidecar that reads findings via the REST API, gathers evidence (govulncheck, version compare), asks a configurable LLM or rule engine and uploads go-vex-validated OpenVEX back. Sub-issues, in the order the sidecar needs them:

| # | Issue | Type | Notes |
|---|-------|------|-------|
| ~~#332~~ / ~~#335~~ / ~~#355~~ | Correctness blockers | — | All landed; #355 in v0.8.0. |
| **#336** | Idempotent VEX upload + `GET /api/v1/uploads/{job_id}` (applied / matched / unmatched) | New table `upload_jobs` (additive) + content-hash dedupe | Unblocks scale; surfaces PURL/vuln-id mismatches. |
| **#333** | Incremental listing (`since`/`cursor`) + `vex_status=missing` filter | Query-only, additive params | Cuts a 15 000-SBOM sweep from >25 min to seconds. |
| **#334** | VEX provenance UI: automated vs. human badge, `status_notes`, `?vex_source=` | Frontend + query (columns from `017`) | Auditors see *who/what* decided; #413 already shows the action statement. |
| **#337** | Outbound webhooks (`sbom.ingested`, `findings.updated`, `vex.applied`, `upload.rejected`) | New Helm values + `internal/webhook` (stdlib only) | Replaces polling; HMAC-signed payloads. |
| — | `docs/integrations/vexviper` | Docs | Once the above stabilises. |

### 3b. Fleet operations

| # | Issue | Rationale |
|---|-------|-----------|
| **#138** (API + UI) | `?namespace=` filters + namespace chips | Column landed in `015`; this is the consumer side. |
| **#267** → **#176** | Cluster filter via query param → full Cluster Picker | Backend ready since #132/#133; #267 is the help-wanted first step. |
| **#140** | Workload vulnerability summary | Image → posture cross-reference; becomes an additional input to the #141 score. |
| **#57** (policies) | Per-project license policies, severity thresholds, exception scopes | Project identity fixed by #398; policies have a stable key. |
| **#136** (rest) | `CORS_ALLOW_CREDENTIALS`, configurable methods/headers | Small, additive. |
| **#60** | Local OSV mirror | Offline / air-gapped; no rate limits. KEV/EPSS feeds (#410, #64) get the same mirror treatment here. |
| **#143** | In-toto Witness integration | New `attestations` table (additive), signature verification, provenance display. Additional #141 score input. Phase 1 no new deps; `sigstore-go` later. |
| **#399** (write tools) | MCP write/mutation tools, if ever wanted | The 1.0 server is read-only by design. |

### 3c. Cryptography — the #420 umbrella (CBOM)

The second questionnaire: cryptographic inventory, crypto agility, PQC migration, deprecated algorithms. #419 (library inventory from SBOMs) ships in 1.0 as the no-new-input answer; the CBOM-based block lands here. It is CycloneDX 1.6 — same pipeline, three new tables, all additive.

| # | Issue | Migration | Notes |
|---|-------|-----------|-------|
| **#415** | Ingest CycloneDX 1.6 `cryptographic-asset` components → `crypto_assets` | `03x_create_crypto_assets` | Base. Today a CBOM is mis-filed as packages without PURL. |
| **#416** | Cryptographic inventory — algorithms, protocols, certificates (expiry), keys per project/fleet | none | Fourth dimension next to packages/vulns/licenses. |
| **#417** | `crypto-policy.json` + `crypto-exceptions.json` — deprecated/forbidden algorithms, key sizes, protocol versions; BSI TR-02102 / NIST SP 800-131A example profiles | `03x_create_crypto_compliance` | Exact precedent: license policy. |
| **#418** | PQC readiness — `quantum_vulnerable` / `hybrid` / `pqc` classification, readiness % per project, migration list, trend | reuses `crypto_compliance` | Agility is reported as *indicators* only — see #420 for what is and is not claimed. |
| **#420** | Umbrella: docs page, exports | — | Closes with #418. |

**Exit criteria:** An external tool can discover new findings without polling, push VEX idempotently and see the result; cluster/namespace views exist in the UI; OSV/KEV/EPSS work offline; a CBOM ingested next to an SBOM yields an inventory, policy findings and a PQC readiness figure.

---

## Phase 4: Analytics (v1.2.0, due 2027-07-31)

**Theme:** Supply-chain intelligence on top of the mature data model. CRA scoring left this phase for 1.0; what remains is prioritisation and dependency-health depth.

| # | Issue | Rationale |
|---|-------|-----------|
| **#255** | Editable/enriched SBOMs + enriched download (+ companion VEX, in-toto re-sign) | Builds on #256 originals. Overlay table `ReplacingMergeTree`. |
| **#254** | Evaluate protobom/storage relational schema for ClickHouse | Research; informs #255's overlay; **not** a rewrite of `sbom_packages`. |
| **#38** | SBOM Diff (tree divergence) | "What changed between v1.7.1 and v1.7.2?" |
| **#56** | Dependency Tree View | Hierarchical visualization of transitive chains. |
| **#63** | Blast Radius Search | Extends Package Search with version constraints, vuln context, direct/transitive. |
| **#61** | OpenSSF Scorecard | Upstream project health; extends `internal/github`. |
| **#82** | Lottery Factor | Single-maintainer risk; extends `internal/github`. |
| **#268** | Evaluate official ClickHouse operator (vs. Altinity) | Breaking `values.yaml` → **major bump**; candidate for v2.0. |

**Exit criteria:** exploit-probability prioritisation is complemented by dependency-health metrics; SBOM diff and tree view exist; enriched export works.

---

## Schema Change Register

Everything that touches `db/migrations/` or a frozen response shape, in one place. Rule: **`ORDER BY` or column-type changes are never allowed after 1.0** (MergeTree can't alter them in place). `ADD COLUMN … DEFAULT` and new tables are fine at any time. "pre" below means *scheduled before the tag*; the "needs pre-1.0?" column is honest about which ones are there for contract reasons and which for market reasons.

| Migration | Issue | Change | Pre/Post 1.0 | Needs pre-1.0? |
|-----------|-------|--------|:------------:|---|
| `012`–`022` | #131 … #357 | see Phase 1 | ✅ shipped | contract |
| `023_add_project_parent` ✅ | project groups | `ADD COLUMN parent` on `sboms`/`ingestion_queue`, `root_purl`, `supplier` on `sboms` | ✅ shipped | market (additive) |
| `024_add_package_license_sources` | #439 | `ADD COLUMN package_license_sources Array(LowCardinality(String)) DEFAULT []` on `sbom_packages` | **pre** (v0.8.0) | market (additive; existing rows read as `unrecorded` until re-scan) |
| — (query only) ✅ | #335 | Row semantics of `/sboms/{id}/vulnerabilities` | ✅ | contract |
| — (DTO only) ✅ | #177 | `cluster` in `SBOMListItem` | ✅ | contract |
| — (query + DTO) ✅ | #398 | De-duplicated project counts; `projectKeyExpr` is contract | ✅ | contract |
| — (Helm values) ✅ | #399 | New `mcp.*` block | **pre** (v0.8.0) | contract (values) |
| — (Helm values) | #397, #391, #392, #344-I | `existingConfigMap`, `seedJob.enabled`, image pin, ClickHouse limits | **pre** (v0.8.0) | contract (values) |
| — (parser only) ✅ | #355 | `documentNamespace` fallback in `extractSourceRepo` | **pre** (v0.8.0) | makes #332 true |
| — (DTO + query) | #412 | `cve_id`, `aliases` on finding DTOs; lookups by alias | **pre** (v0.8.0) | market (additive) |
| — (endpoint) | #266 | CSV export | **pre** (v0.8.0) | market (additive) |
| `025_add_vulnerability_cvss_cwe` | #408, #409 | `ADD COLUMN cvss_score Float32, cvss_vector String, cvss_version LowCardinality(String), cwe_ids Array(String)` on `vulnerabilities` | **pre** (v0.9.0) | market (additive; backfill from `osv_json`) |
| `026_create_kev_catalog` | #410 | New table keyed by CVE id | **pre** (v0.9.0) | market (additive) |
| `027_create_epss_scores` | #64 | New table keyed by CVE id | **pre** (v0.9.0) | market (additive) |
| `028_add_vex_action_statement_timestamp` | #413 | `ADD COLUMN action_statement_timestamp` on `vex_statements` | **pre** (v0.9.0) | market — *but* automated VEX producers won't re-send, so capture early |
| — (query + config) | #411 | `remediation-policy.json`; derived fields, no storage | **pre** (v0.9.0) | market (values: `remediationPolicy.*`) |
| — (endpoint + UI) | #141 | CRA readiness score | **pre** (v1.0.0) | market |
| `029_create_vulnerability_resolutions` | #7 | New table | **pre** (v1.0.0, stretch) | market (additive) |
| — (endpoint) | #62 | Report bundle (CSV + JSON + manifest) | **pre** (v1.0.0) | market |
| `030_create_crypto_libraries` | #419 | New table (or MV over `sbom_packages`) | **pre** (v1.0.0) | market (additive; values: `cryptoLibraries.*`) |
| `03x_create_package_index_mv` | #344-C/D/E | MV + skip indexes | post | additive |
| `03x_create_upload_jobs` | #336 | New table | post | additive |
| `03x_create_attestations` | #143 | New table | post | additive |
| `03x_create_crypto_assets`, `03x_create_crypto_compliance` | #415, #417 | New tables | post (v1.1.0) | additive |
| `03x_*` | #61, #82, #255, #60 | Enrichment / overlay / mirror tables | post | additive |
| — | #268 | Operator swap (`values.yaml` breaking) | **v2.0** | breaking |

---

## Dependency Graph

```
PRE-1.0 contract:
#398 ✅ ──┬── #58 (Aggregated SBOM View)                        v0.8.0
          └── #399 ✅ (MCP: get_project) ── post-1.0: write tools

REGISTER (#414):
#412 (cve_id/aliases) ── #410 (KEV, matched by alias) ──┐
#408 (CVSS) ─────────────────────────────────────────────┼── #411 (SLA due date; KEV due date overrides) ──┐
#409 (CWE) ──────────────────────────────────────────────┤                                                  ├── #141 (CRA score)  v1.0.0
#64  (EPSS) ─────────────────────────────────────────────┤                                                  ├── #62  (report bundle)
#413 (VEX action statement) ─────────────────────────────┘                                                  └── #7   (MTTR)
#266 (CSV) ── grows with every row above ── #62

CRYPTO (#420):
#419 (library inventory, SBOM-only)                         v1.0.0
#415 (CBOM ingest) ── #416 (inventory) ── #417 (policy) ── #418 (PQC)   v1.1.0
                                                 └── #409 (CWE-327 filter on the register)

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

## Prioritization Rationale

### Why does CRA move into 1.0 after the 2026-09-24 plan put it in 2027 H1?

The earlier plan reasoned from the CRA calendar: reporting obligations from September 2026, full conformity December 2027, so H1 2027 "still gives adopters ~9 months". Two things changed within a day of writing that. First, the reporting obligation is no longer upcoming — it is **in force** — and its 24-hour clock for *actively exploited* vulnerabilities is exactly what KEV status (#410) makes visible. Second, the first customer questionnaires arrived, and they do not ask for a score in H1 2027; they ask for a register **now**, column by column (#414). A supply-chain governance tool that answers "planned for v1.2" to "do you know your CVSS scores" has failed the question.

The old sequencing rule is not violated. Every register item is additive (new columns with defaults, new side tables, derived fields), so nothing *had* to be pre-1.0 for contract reasons — the schema register says "market" for each of them on purpose. They are pre-1.0 because 1.0 is the release adopters will evaluate against the CRA, and evaluating a register that is not there is a short evaluation.

### Why split 1.0 into v0.8.0 / v0.9.0 / v1.0.0?

Because one milestone with 21 issues and a tag at the end is a milestone that slips. v0.8.0 is the 2026-09-24 scope with the same date it had, so no contract work is delayed by the register. v0.9.0 is the register, self-contained, with a hard exit criterion (the export column list). v1.0.0 then adds the score on top and gets a December soak on the CNCF instance — the register's numbers are compared against the questionnaire answers written by hand, which is the only test that matters for it. Two extra tags cost nothing; two extra months of an un-tagged 1.0 branch cost trust.

### Why do @jeefy's issues go first?

#398 and #399 are the only issues filed by someone building *on* BOMHort rather than *in* it. #398 found that the frozen project numbers were wrong; #399 will find whatever else an agent trips over. Consumers find contract holes internal callers never hit — that is the argument for building the MCP server before the freeze, and it is the argument for scheduling it first inside v0.8.0 rather than last. The rule generalises: an issue from a consumer of the contract outranks an issue from a maintainer of it, in the same release.

### Why #399 (MCP server) before the freeze, when it's purely additive?

The component is additive; its **Helm values are not**. `values.yaml` stability is an explicit 1.0 criterion, so an `mcp.*` block added in 1.1 is either a breaking reshuffle or a schema we guessed once and live with for a major cycle. The second reason: an MCP server is a *consumer* of the REST contract, and #398 exists because the UI could paper over bad aggregates with grouping logic in Angular while an agent calling `get_project` cannot. It stays read-only in 1.0 — write tools are additive.

**Dependency decision — approved 2026-09-24.** `github.com/modelcontextprotocol/go-sdk` is direct dependency **#6** (budget 5 → 6, `AGENTS.md:113` to update). **Minimum `v1.4.1`**: everything below carries four HIGH advisories that describe exactly the scenario a BOMHort MCP server runs in:

| Advisory | What it breaks |
|----------|----------------|
| CVE-2026-27896 | `encoding/json` case-insensitive key matching — a policy layer matching exact JSON-RPC field names can be walked past. Fixed in `v1.3.1`. |
| GHSA-q382-vc8q-7jhj | The `v1.3.1` fix itself: trailing `NUL` / duplicate keys → last-key-wins. Needs `segmentio/encoding v0.5.4`, pulled in by `v1.4.1`. |
| CVE-2026-33252 | Streamable-HTTP accepted cross-site `POST` without `Origin`/`Content-Type` validation. |
| CVE-2026-34742 | DNS-rebinding protection off by default for localhost HTTP. On by default from `v1.4.0`. |

Consequences, all `values.yaml` shape and therefore 1.0: pin `>= v1.4.1` and add to the CVE watch list; **stdio default**, HTTP opt-in and never without auth or an explicit allowed-origins list. Scope guard: read-only tools (`list_projects`, `get_project`, `search_packages`, `list_vulnerabilities`, `get_sbom`); no write tools, no LLM calls in-tree.

### Why break the 5-dependency rule for #399 — and why not again for the register?

The rule limits supply-chain exposure in a supply-chain tool. For MCP the hand-rolled alternative would reproduce the advisories above from scratch with nobody auditing it; taking the reviewed SDK on a pinned floor is the safer trade. The register needs **no** new dependency: KEV is one JSON file, EPSS one gzipped CSV, both stdlib; CVSS v3 is already computed in `osvutil`, v4 is a second small table of weights. #62's PDF is the only item that would need one, which is why PDF is gated on a separate decision and not a 1.0 blocker.

### Why is the CBOM block (#415–#418) in 1.1 and not with the rest of the crypto questionnaire?

Three reasons. It is not CRA-critical — Annex I asks for state-of-the-art encryption, not for a CBOM. It needs input almost nobody produces yet (CBOM generators are young), so shipping it in 1.0 would ship empty pages; #419 covers the same question from SBOMs everyone already has. And it is three new tables that are additive by construction — the exact profile the sequencing rule pushes past the freeze. Doing it in 1.1 also means the policy engine can reuse #411's derived-status pattern instead of inventing a third.

### Why did five "housekeeping" issues block a freeze — and still do?

Four of them add or change `values.yaml` keys (#397, #391, #392, #344-I); the fifth, #355, is the 1.0 criteria ticking off a feature with 0 % real-world coverage. Nothing about that changed; they keep their October date in v0.8.0.

### Why VEXViper before analytics, but after the register?

Automated VEX turns a wall of CVEs into a triaged queue, and every analytics feature is more useful once `not_affected` noise is gone — that reasoning stands, and #338 stays first in Phase 3. It comes *after* the register because the register is what VEX statements are written *against*: #413 fixes what a statement records, #411 defines what "open" means, #410/#64 define what to triage first. A sidecar generating VEX before those exist would be optimising a queue whose order is not yet defined.

### Cluster vs. project vs. namespace

Three orthogonal low-cardinality dimensions:

| Dimension | Question | Example | Cardinality | Owner |
|-----------|----------|---------|-------------|-------|
| `cluster` | Where is it deployed? | `prod-eu` | 1–50 | Platform |
| `namespace` | Which tenant/team boundary inside the cluster? | `payments` | 10–500 | Platform / team |
| `project` | What is it / who owns it? | `payment-service` | 50–5000 | Dev teams |

All three are `LowCardinality(String) DEFAULT ''` columns; none is in `ORDER BY`. Filtering is by `WHERE`. `tags` (`022`) label projects across these dimensions; they do not replace them.

---

## Success Metrics

| Release | Metric | Target |
|---------|--------|--------|
| v0.8.0 | MCP surface (#399) | All five read tools callable from a stock MCP client; SDK pinned `>= v1.4.1`; stdio default, HTTP never unauthenticated |
| v0.8.0 | Source attribution (#355) | `source_repo` populated for **> 90 %** of the 500-SBOM CNCF corpus (today: 0 %) |
| v0.8.0 | Chart honesty (#391, #392, #397) | `helm template` with our own `values-production.yaml` renders nothing that hangs; chart and CI pin the same ClickHouse version |
| v0.8.0 | UI latency (#344-E) | Projects page stops full-scanning `sbom_packages` + `vulnerabilities` for every project |
| v0.9.0 | Register completeness (#414) | On the CNCF corpus: `cvss_score` present for > 95 % of findings, `cve_id` for > 98 %, `cwe_ids` for > 80 %; every KEV-listed CVE in the corpus carries `kev_listed=true` |
| v0.9.0 | Register freshness | `last_refreshed_at` < 24 h on every export; KEV/EPSS feeds refreshed daily |
| v1.0.0 | CRA readiness (#141) | Score computed for every project with ≥ 1 SBOM; score > 80 % for the managed CNCF instance |
| v1.0.0 | Round-trip fidelity | 100 % of SBOMs ingested post-1.0 downloadable byte-identical |
| v1.0.0 | Questionnaire test | Both customer questionnaires (#414, #420 minus CBOM) answerable from the UI/export without a spreadsheet |
| v1.1.0 | Automated triage | VEXViper `watch` pass over 15 000 SBOMs < 60 s; 0 duplicate VEX rows |
| v1.1.0 | Cryptography | A cbomkit CBOM ingested next to its SBOM yields inventory, findings and a PQC figure |
| v1.2.0 | Prioritisation depth | Scorecard + Lottery Factor on every resolved upstream repo |

---

## Non-Goals (Explicitly Out of Scope)

- **Custom Kubernetes Operator**: Helm + ClickHouse Operator. No custom CRDs.
- **In-tree VEX generation / LLM calls**: stays in the VEXViper sidecar. The MCP server (#399) is a *transport*. BOMHort never calls an LLM itself.
- **MCP write tools in 1.0**: read-only by design. Mutation tools are additive → Phase 3.
- **Write APIs for policies or exceptions** (license, remediation, crypto): the frontend is public. Policy changes are config-file changes.
- **Per-finding manual status or due dates**: remediation status comes from VEX, due dates from policy (#411). Ticketing stays in the ticket system.
- **CBOM generation / crypto scanning of code or containers** (#420): BOMHort consumes CBOMs; `cbomkit`, `sonar-cryptography`, `cdxgen` produce them.
- **CRA reporting to ENISA/CSIRTs**: #141 tells you *what* to report and *when* the clock started (KEV, #410); filing the report is the manufacturer's process.
- **Multi-repo split**: Monorepo is a hard constraint for AI-assisted development.
- **Real-time streaming**: Batch ingestion (CronJob + queue) plus outbound webhooks (#337) is sufficient.
- **RBAC/multi-tenancy**: Auth is binary. Fine-grained RBAC is beyond this roadmap.
- **Full OIDC in BOMHort**: User authentication is the upstream proxy's responsibility.
- **Relational rewrite of the dependency model** (#254): protobom/storage's schema is evaluated for the *overlay* only.
- **A second project hierarchy** (#398): projects are grouped by `tags`, not by a new org/sub-project table.

