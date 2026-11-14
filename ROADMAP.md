# BOMHort Product Roadmap

> Last updated: 2026-10-17
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

Two rules drive sequencing. The old one still holds: **if it can't be back-filled, it lands before 1.0; if it's additive, it lands after** — the register work is additive, it lands before 1.0 for *market* reasons, not contract reasons, and the schema register below says so per row. The new one: **issues raised by the consumer side ship first** — @jeefy's #398 (✅ v0.8.0) and #399 open every release they appear in, because they are the questions an external consumer of the contract actually asked.

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
| ~~#398~~ | ~~Project-centric read model~~ | ✅ v0.8.0 (#401, after v0.7.1): `GET /api/v1/projects/{name}` + sub-resources, de-duplicated counts, project identity rule (`projectKeyExpr`) is contract. |
| #136 | Enhanced CORS | 🟡 **Functionally done** — `POST` on the upload route, `X-API-Key`/`X-Service-Token`/`X-Filename` headers, configurable origins. Remaining scope (`CORS_ALLOW_CREDENTIALS`, configurable methods/headers) is additive → v1.1.0. |

**Delivered beyond the roadmap:** Global Search (`GET /api/v1/search`), Package Search + detail page, in-toto attestation unwrapping, protobom parsing backend, license resolution via GitHub + npm + NuGet registries with license-text classification (`internal/licensetext`), SPDX license *expression* evaluation (#402), SPDX file-level filtering, dark mode, white-label theming, Prow chat-ops (#405).

**Schema wave `014`–`022` — complete** (`023` project parent, `024` license sources, `025` dependency depth and `026` job retry-after followed in v0.8.0; the v0.9.0 register work starts at `027`). `document_store` (#256), `namespace`/`project` columns (#138, #57), `source_repo`/`source_ref` (#332), VEX provenance (#334), VEX SBOM scope (#350), OSV aliases (`019`), VEX `product_ref` (`020`), `document_version` (`021`), `tags` (#357). Every column the post-1.0 features were known to need exists; the register work below adds columns and tables of its own and is listed in the Schema Change Register.

---

## Phase 2: The road to 1.0 (Oct 2026 – Jan 2027)

**Theme:** Freeze a contract that an external consumer has already exercised (#399), and ship a CRA-grade vulnerability register *inside* the frozen surface rather than bolting it on after.

### 2a. v0.8.0 — Contract ✅ (released 2026-10-17)

Everything that was blocking 1.0 on 2026-09-24, minus the tag. Order within the release is the order of the table.

| # | Issue | Type | Why here |
|---|-------|------|----------|
| ~~#399~~ | ~~**BOMHort MCP server** — read-only tool surface over the REST API (`cmd/mcp-server`), SDK `>= v1.4.1`, stdio default~~ | New component + new `values.yaml` block (`mcp.*`) | ✅ Five read-only tools (`list_projects`, `get_project`, `search_packages`, `list_vulnerabilities`, `get_sbom`) over `internal/apiclient` — a REST consumer, no ClickHouse credentials. SDK on `v1.8.0`. stdio default; Streamable HTTP refuses to start (and `helm template` refuses to render) without a bearer token and a non-wildcard Origin allow-list. Full reasoning and the SDK advisory table are in [Prioritization Rationale](#why-399-mcp-server-before-the-freeze-when-its-purely-additive). |
| ~~#58~~ | ~~Aggregated SBOM View — N versions of one project as one expandable row~~ | UI + query | ✅ The SBOM Explorer reads by project, not by document (#431); same de-dup semantics as #398. |
| ~~#355~~ | ~~`source_repo` extraction yields 0 % on real SBOMs — `documentNamespace` fallback~~ | Parser | ✅ `documentNamespace` last-resort fallback (strict: forge host or forge path shape only), release/tag/commit URL handling in `sourcerepo`, CycloneDX `distribution` counterpart. Existing rows need a re-parse to pick it up. |
| ~~#397~~ | ~~`licenseExceptions.existingConfigMap` + `licensePolicy.existingConfigMap`~~ | Helm values | ✅ Both rule files mount from a reviewed, externally managed ConfigMap; the chart renders no ConfigMap of its own then. GitOps users no longer inline ~180 KB into an Argo `Application` (cncf/automation#703). |
| ~~#391~~ | ~~Seed job never seeds — gate (`seedJob.enabled`) or remove~~ | Helm values | ✅ Removed, not gated: the job never seeded, so there was nothing to keep behind a flag. A leftover `seedJob` block in user values fails `helm template` with a message naming the alternatives, instead of being silently ignored. |
| ~~#392~~ | ~~Chart ships ClickHouse 24.8, CI tests 24.12 — decide the supported floor~~ | Helm values + CI matrix | ✅ Floor is the 24.8 LTS line: the chart pins `24.8.14.39` by digest, CI runs migrations and every query against 24.8 **and** 24.12, and a Helm test fails when chart, CI matrix and docker-compose drift. Written down on the deployment page (*Supported ClickHouse versions*). |
| ~~#344~~ E + I | ~~`enrichProjectStats` per page (E — lands on #398's semantics), ClickHouse `max_threads`/`max_memory_usage`/`max_execution_time` in values (I)~~ | Query + Helm values | ✅ E: project stats read only the selected projects' SBOMs. I: `apiGateway.queryLimits.*` (30 s / 512 MiB / unset threads by default), applied to the gateway only — workers and CronJobs stay unbounded. A–D, F–H stay additive (post-1.0 MVs/indexes); #344 stays open for them. |
| ~~#412~~ | ~~Expose the CVE id and OSV aliases in API, UI and lookups~~ | DTO + query, **no migration** | ✅ `cve_id` + `aliases` on findings, VEX statements and search results; affected-projects and global search accept any alias. UI leads with the CVE. |
| ~~#266~~ | ~~CSV export for vulnerabilities (stdlib `encoding/csv`)~~ | New endpoint | ✅ `GET /api/v1/reports/vulnerabilities?format=csv[&scope=]`, streamed, formula-injection safe, `cve_id` first. Column list grows in v0.9.0 as fields arrive; the endpoint shape is set here. |
| ~~#439~~ | ~~License resolution with provenance — deps.dev/Packagist/PyPI resolvers, `unapproved` category, per-package license source~~ | Migration `024` + new endpoint + DTO field | ✅ `license_source` on dependency nodes and `GET /api/v1/licenses/sources` are contract surface, so they land before the freeze. Every heuristic is documented on the License Resolution docs page, which a test keeps in sync with the code. |
| ~~GHSA-943f-mm2v-j478~~ | ~~UI nginx injected `SERVICE_TOKEN` on write requests — anonymous upload/PATCH through the public UI~~ | nginx config (image + chart) | ✅ Token injected on `GET`/`HEAD` only; shipped in `v0.8.0-rc.3`. Release notes: CI uploads through the UI host need their own credential. Found by the 2026-10-15 audit, like the v0.9.0 ingest-correctness block below. |

**Also shipped, unplanned:** SPDX license expressions (`AND`/`OR`/`WITH`) are evaluated instead of reported as unknown (#402); license exceptions from a ConfigMap, an `https://` URL or `s3://`, reloaded live and applied retroactively without re-ingest (#470); summary mode for `/projects/license-compliance` and bounded archived-packages memory (#475); installable release candidates cut from `release/vX.Y` branches.

**Exit criteria:** an MCP client can ask `get_project` and get de-duplicated numbers; every `values.yaml` key 1.0 promises to keep exists; `source_repo` > 90 % on the CNCF corpus; a CSV of findings with CVE ids can be downloaded.

### 2b. v0.9.0 — Vulnerability register (due 2026-11-30)

**First: ingest correctness (2026-10-15 audit).** A register is only as good as the rows under it, and the audit found ways to lose, hide or duplicate those rows silently. These land *before* the register columns, because every register column is computed from the rows they fix — #485's stubs have no `osv_json` for #408/#409 to backfill from, and #480's rows are invisible to every scoped view, including #459's. All are fixes, so each is backported to `release/v0.8` after merge (`make cherry-pick`) and ships as a v0.8.x patch; #446 is the exception (migration).

| # | Issue | Migration | Notes |
|---|-------|-----------|-------|
| **#480** | `cve-refresher` writes findings without `cluster`/`namespace`/`project` | none (+ one-off backfill `INSERT … SELECT`) | The newest CVEs are the ones scoped views miss. **Before #459**, which adds more such filters. Brings the first tests for `cmd/cve-refresher`. |
| **#485** | Un-hydrated OSV entries stored as stubs, never refreshed | none | Precondition for #408/#409 backfill. Moves the duplicated vulnerability builder into `osvutil` — #408/#409 then add their columns in one place, not two. |
| **#482** + **#487** | Failed jobs leave half-ingested SBOMs that are never retried; watcher queries per file | none | Write `sboms` last (commit marker), defer on shutdown, decide "already queued" on the latest status per job — in one bulk query (#487) instead of N. |
| **#446** → **#483** | `ingestion_queue.created_at` second resolution; workers claim the same jobs | `0xx` `MODIFY COLUMN created_at DateTime64(3)` on `ingestion_queue` | **Column-type change → must be pre-1.0** (Schema Change Register). #483's "keep only own claims" re-read needs #446's ordering. Not backported (migration). |
| **#481** + **#489** | Registry resolvers cache transient failures forever; cache plumbing copied 5× | none | #489's shared cache type first, so #481's rule ("cache definite answers only") lives in one place. Plus cleanup of poisoned `registry_license_cache` rows. |
| **#484** | Rate limit / auth logs trust client `X-Forwarded-For` | none | Small; security. |
| **#486** | `cve-refresher` scans `sbom_packages` once per new PURL | none | Same binary as the #410/#64 feeds; fix before adding to it. |
| **#488** | Search pages render results of an older query | none (UI) | Small. |
| **#493** | CNCF buckets: `ClassifyKey` skips `_cdx.json`/`_spdx3.json`; `_release_*` assets would duplicate a release | none | Consumer-raised (cncf/sbom), so first. Accept CycloneDX and SPDX 3 keys; **skip `_release_*` keys** — one SBOM per release, the per-binary asset is not it. |
| **#447** | `GET /api/v1/licenses/compliance` unpaginated, cut at 10 MiB by the ingress | none (response shape) | `PaginatedResponse[T]` like every other list. Shape change → before the freeze. Not backported. |

**Second: runtime-scanner identity (#455–#461, raised 2026-10-13 by a Kubernetes runtime scanner).** A scanner that walks pods needs to say *how* a document was produced, *which image* it describes and *which workload* runs it, and needs to ask "do you already have this digest?" before scanning again. Every column is `ADD COLUMN … DEFAULT ''`, so all of it is additive — it is pre-1.0 because the upload parameters and filters are contract, and because the register's "per deployed version" only means something once a finding can be scoped to a running workload. Order is dependency order; #460 adds the 7th direct Go dependency and is decided separately.

| # | Issue | Migration | Notes |
|---|-------|-----------|-------|
| **#459** | Ownership filters (`?cluster=`/`?namespace=`/`?project=`/`?tag=`) on `/vulnerabilities`, per-cluster/namespace vulnerability routes | none | **After #480** — until then the filters would hide every refresher finding. Columns already exist (`012`/`015`). |
| **#455** | `origin` dimension: `cluster-scan`, `ci`, `registry`, `vendor`, `manual` | `0xx` `ADD COLUMN origin` on the 7 data tables | Fixed vocabulary, `400` on anything else; upload param, per-bucket field, `ORIGIN` default — same plumbing as `cluster`. Prerequisite for #456. |
| **#458** | Workload identity: `workload_kind`, `workload_name`, `workload_uid` | `0xx` `ADD COLUMN` on `sboms` | Upload params + filters; `project` defaults to `workload_name`. One identity per SBOM — the `sbom_identities` table is a post-1.0 follow-up. |
| **#457** | Image reference and digest as SBOM identity; `?digest=`, `/images/{digest}`, `HEAD` existence check | `0xx` `ADD COLUMN image_ref, image_digest` on `sboms` (+ skip index), `image_digest` on children | Digest from upload param or `pkg:oci` purl. Digest-based dedup is **opt-in** (`DEDUP_BY_IMAGE_DIGEST`), off by default. |
| **#461** | CycloneDX 1.6 / SPDX 3.0.1 scanner fixtures; `k8s_*`/`image` identifiers read from the document | `0xx` `ADD COLUMN producer_identifiers Map(String,String)` on `sboms` | Explicit config still outranks the document; extracted values only fill empty dimensions, conflicts are logged and kept auditable. Needs #457/#458 for the target columns. |
| **#456** | Named, scoped API keys (`API_KEYS_JSON`, `auth.apiKeys[]`): restrict a key to origins/clusters/namespaces/projects | `0xx` `ADD COLUMN uploaded_by` on `sboms` | Flat `API_KEYS` keeps working unchanged. `403` with the key *name*; names in the startup log, never the secrets. Needs #455's `origin`. |
| **#460** | Prometheus `/metrics` + `ServiceMonitor`/`PodMonitor` in the chart | none | **Needs the dependency decision** (`prometheus/client_golang`). Labels bounded by config (`cluster`, `origin`), never `project`/`sbom_id`. |

**Then the register.**

The **#414** umbrella. CRA Annex I Part II (1)–(2) in one sentence: identify and document vulnerabilities, remediate without delay. A register that a security officer can hand to an auditor needs, per finding and per deployed version: CVE, CWE, CVSS, EPSS, KEV status, remediation status, due date, and a timestamp proving it is current. Order is dependency order.

| # | Issue | Migration | Notes |
|---|-------|-----------|-------|
| **#408** | CVSS score, vector, version (not only the bucket); v4 support | `027` `ADD COLUMN cvss_score, cvss_vector, cvss_version` on `vulnerabilities` | Score is already computed in `osvutil` and discarded. Backfill from `osv_json`. |
| **#409** | CWE ids from OSV `database_specific.cwe_ids` | `027` `ADD COLUMN cwe_ids Array(String)` (same migration) | Backfill from `osv_json`. Enables CRA/crypto CWE filters (CWE-327/-326/-328/-295/-916). |
| **#410** | CISA **KEV** catalogue status — plus ENISA's exploited list as a second source and **EUVD** ids in `aliases` | `028_create_kev_catalog` (new table, keyed by CVE, `source` column) + `euvd_aliases` | Daily feed in `cve-refresher`; matched via `aliases`. **CRA Art. 14: actively exploited vulnerabilities must be reported within 24 h** — KEV is the public signal for "actively exploited". Brings an externally set `dueDate`. NIS2 questionnaires ask for the EUVD id next to the CVE; same feed plumbing, one more table. |
| **#511** | Vulnerability **lifecycle**: the refresher re-hydrates OSV entries modified since the last run; withdrawn entries leave the counts | `0xx` `ADD COLUMN osv_modified, withdrawn_at` on `vulnerabilities` | A register with a fresh `last_refreshed_at` over stale rows is worse than none. After #485 (no stubs) and #486 (bulk refresher query); gives "register freshness" (Success Metrics) its meaning. |
| **#64** | **EPSS** scores | `029_create_epss_scores` (new table, keyed by CVE) | **Pulled forward from v1.2.0.** Same shape as #410 (daily bulk → side table); the two share refresher plumbing and the triage rule *KEV ∨ EPSS ≥ x ∨ CVSS ≥ 9*. |
| **#413** | VEX action statement as remediation record; `action_statement_timestamp` | `030` `ADD COLUMN action_statement_timestamp` on `vex_statements` | Surfaces what is stored; the remediation *status* column of the register. |
| **#411** | Remediation SLA policy → policy-derived `due_date`, `overdue`, `remediation_status` | none (computed at query time from `remediation-policy.json`) | The *estimated resolution date* column. Config-driven like `license-policy.json`; KEV due date overrides. Status vocabulary beyond open/fixed (`under investigation`, `pending upstream fix`, `fix not planned`, `fixed in`, `patched`) fed by #413 and #524. No write API — public frontend. |
| **#414** | Umbrella: docs page "Using BOMHort as a vulnerability register", `last_refreshed_at` on export and dashboard, #266 column list finalised | — | Closes when the row above is complete. |

**Exit criteria:** `GET /api/v1/projects/{name}/vulnerabilities` and the CSV export carry `cve_id, aliases, cwe_ids, cvss_score, cvss_vector, epss_score, epss_percentile, kev_listed, kev_due_date, vex_status, remediation_status, action_statement, action_statement_timestamp, discovered_at, osv_modified, due_date, last_refreshed_at`; withdrawn findings are excluded by default; the dashboard shows overdue and KEV counts.

### 2c. v1.0.0 — Freeze + CRA dashboard (due 2027-01-31)

| # | Issue | Type | Notes |
|---|-------|------|-------|
| **#141** | **CRA compliance dashboard** — readiness score per project/cluster | New endpoint + UI, no migration | **Moved from v1.2.0 and re-scoped.** The 2026-09-24 plan made it wait for #140 (workloads), #143 (attestations) and #62. It no longer does: the score is computed from what v0.9.0 stores — SBOM coverage per project, register completeness (CVSS/CWE present), open KEV findings, overdue findings (#411), VEX coverage, refresh age. #140/#143 become *additional inputs* in v1.1.0, not prerequisites. |
| **#7** | CVE fix time (MTTR) per project | `031_create_vulnerability_resolutions` (new table) | **Moved from v1.2.0.** CRA "remediate without delay" needs the backwards-looking number next to #411's forward-looking one. Detection in `parsing-worker` (finding disappears between versions) and on VEX `fixed`/`not_affected`. *Stretch: if the December soak needs the time, #7 drops to v1.1.0 — the table is additive.* |
| **#62** | Auditor report bundle | Endpoint | **Moved from v1.1.0.** 1.0 scope: CSV + JSON bundle per project/fleet with a manifest (`sha256`, `generated_at`, `last_refreshed_at`, policy versions). **PDF only after the `gofpdf` vs `pdfcpu` decision** — not a 1.0 blocker. |
| **#419** | Cryptographic **library** inventory from existing SBOMs (`crypto-libraries.json`, PURL match) | `032_create_crypto_libraries` (new table) | New. Works on every SBOM already ingested, no CBOM needed; first defensible answer to "cryptographic inventory" (#420) and the CRA "state-of-the-art encryption" evidence. Small. The CBOM block stays in v1.1.0. |
| **#512** | **SARIF** export (`?format=sarif`) next to CSV on the same endpoints | Endpoint, no migration | A second serialisation of a frozen shape → decided before the freeze. Same column list as #266; VEX `not_affected` becomes a SARIF suppression. The CI-gating path (#513, #521) consumes it in v1.1.0. |
| **#531** | Malicious-package findings (`MAL-`) and look-alike names as their own kind | `03x` `ADD COLUMN finding_kind` on `vulnerabilities`, `lookalike_of` on `sbom_packages` | OSV already delivers `MAL-` records; today they sort to the bottom as `UNKNOWN`. Forced `CRITICAL`, never globally VEX-suppressible, dashboard tile. Look-alike via deps.dev `GetSimilarlyNamedPackages`, hint not finding. Small, and the one finding kind that must not wait. |
| **#537** | SBOM **quality score** per document (NTIA / TR-03183 minimum elements), aggregated by producer tool and origin | `03x` `ADD COLUMN quality_score UInt8, quality_flags Array(LowCardinality(String))` on `sboms` | "Is this SBOM usable at all?" is the first procurement question; #493 observed the problem, this makes it a number. Report-only by default; #517 may gate on it. Parse-time, no new source. |
| **#536** | Migration **importer** (`cmd/bomhort-import`): CycloneDX `vulnerabilities[].analysis` and existing inventories → SBOM + OpenVEX through the public upload API | none (client of the API) | Lowers switching cost from days to an afternoon; suppression → VEX mapping is the valuable part. No ClickHouse dependency. |
| **#518** | **Trend over time** — findings, violations, versions as a series per fleet scope and per project | Query-time `GROUP BY toStartOfInterval`; decides the fate of `dashboard_stats_mv` (#344) | "Are we getting better?" is the first question an auditor asks of a register. No new storage; *stretch like #7 — drops to v1.1.0 if the soak needs the time.* Series: count by severity, net-new since previous version, fixed, mean days open; period selector and a second-project comparison line in the UI. |
| **#519** | SVG status **badges** per project | Endpoint, no migration | Cheap, public, stdlib `text/template`. Reads the project query; cached per TTL. |
| **#145** | Versioned documentation | Docs infra | Must ship **with** the tag. |
| — | Migration guide + `values.yaml` stability review | Process | Covers every new key since v0.7: `mcp.*` (#399), `existingConfigMap` (#397), `seedJob` **removed** (#391), `apiGateway.queryLimits.*` (#344-I), image pin (#392), `kev.*`/`epss.*` feed URLs and skips (#410, #64), `remediationPolicy.*` (#411), `cryptoLibraries.*` (#419). |
| — | `AGENTS.md` dependency list | Docs | 5 → 6 direct dependencies (`modelcontextprotocol/go-sdk >= v1.4.1`). No further dependency for the register: KEV/EPSS are HTTP + JSON/CSV, stdlib. |
| — | December soak | Process | v0.9.0 runs on the CNCF instance for four weeks before the tag; register numbers are compared against the questionnaire answers given by hand. |

### 🎯 v1.0.0 Milestone

**Target: 2027-01-31** (was 2026-11-30; moved on 2026-09-25 to make room for v0.9.0 and a December soak).

- API contract frozen (no breaking changes without major version bump)
- ClickHouse schema stable (no `ORDER BY`/type changes; `ADD COLUMN` and new tables remain allowed)
- Helm chart values stable — including `mcp.*`, `existingConfigMap`, `seedJob` removal, `apiGateway.queryLimits.*`, `kev.*`, `epss.*`, `remediationPolicy.*`, `cryptoLibraries.*`
- Supported ClickHouse version floor decided, written down and covered by CI (#392) ✅ 24.8 LTS
- Support policy (current − 2) takes effect
- Versioned documentation enabled (#145)
- **A CRA-grade vulnerability register is exportable per deployed version, and a readiness score is computed from it (#414, #141)**

**v1.0 Criteria:**
- [x] ~~Version Skew Detection~~ (#37) · ~~API Authentication~~ (#134) · ~~Cluster-aware schema~~ (#131) · ~~Cluster endpoints~~ (#132, #133) · ~~Upload~~ (#135) · ~~CycloneDX~~ (#55) · ~~Health probes~~ (#137)
- [x] ~~Schema wave `014`–`022`~~ (#256, #138, #332, #334, #57 column, #350, #357)
- [x] ~~One row per `(vuln_id, purl)` — latest VEX wins (#335)~~ · ~~`cluster` in `SBOMListItem` (#177)~~
- [x] ~~Project-centric read model + de-duplicated counts (#398)~~
- [x] **v0.8.0:** ~~MCP server + `mcp.*` (#399)~~ · ~~Aggregated SBOM View (#58)~~ · ~~`source_repo` fallback (#355)~~ · ~~`existingConfigMap` (#397)~~ · ~~seed job (#391)~~ · ~~ClickHouse floor (#392)~~ · ~~perf E + I (#344)~~ · ~~CVE id/aliases (#412)~~ · ~~CSV export (#266)~~ · ~~license provenance (#439)~~ · ~~UI proxy write auth (GHSA-943f-mm2v-j478)~~
- [ ] **v0.9.0:** ingest correctness (#480, #485, #482, #487, #446, #483, #481, #489, #484, #486, #488) · CVSS (#408) · CWE (#409) · KEV (#410) · EPSS (#64) · remediation record (#413) · SLA due dates (#411) · register docs (#414) · lifecycle (#511)
- [ ] **v1.0.0:** CRA dashboard (#141) · MTTR (#7, stretch) · report bundle (#62) · crypto-library inventory (#419) · SARIF (#512) · trend (#518, stretch) · badges (#519) · versioned docs (#145) · migration guide + values review

### Milestone map

Every open issue carries a milestone — "no milestone" is not a valid state.

| Milestone | Due | Theme | Open issues |
|-----------|-----|-------|-------------|
| [v0.8.0](https://github.com/seebom-labs/BOMHort/milestone/5) | ✅ 2026-10-17 | Contract | ~~#399~~, ~~#58~~, ~~#355~~, ~~#397~~, ~~#391~~, ~~#392~~, ~~#344~~ (E+I), ~~#412~~, ~~#266~~, ~~#439~~, ~~GHSA-943f-mm2v-j478~~ |
| [v0.9.0](https://github.com/seebom-labs/BOMHort/milestone/6) | 2026-11-30 | Ingest correctness + vulnerability register | #480, #485, #482, #487, #446, #483, #481, #489, #484, #486, #488, #408, #409, #410, #64, #511, #413, #411, #414 |
| [v1.0.0](https://github.com/seebom-labs/BOMHort/milestone/1) | 2027-01-31 | Freeze + CRA dashboard | #141, #7, #62, #419, #512, #531, #537, #536, #518, #519, #145 |
| [v1.1.0](https://github.com/seebom-labs/BOMHort/milestone/2) | 2027-04-30 | Automation, fleet & cryptography | #338, #336, #333, #337, #334 (UI), #138 (API/UI), #267, #176, #140, #57, #136, #60, #143, #420, #415, #416, #417, #418, #490, #513, #521, #520, #509, #514, #515, #524, #525, #527, #528, #529, #530, #533, #535, #538, #539 |
| [v1.2.0](https://github.com/seebom-labs/BOMHort/milestone/3) | 2027-07-31 | Analytics | #61, #82, #38, #56, #63, #532, #534, #255, #254, #510, #516, #517 |
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
| **#535** | Reachability **evidence** per finding (`reachability`, `evidence_source/ref/at`), govulncheck JSON ingest | `03x` columns on `vulnerabilities` | The generator's evidence gets a home instead of free text. Evidence never changes status by itself. |
| **#538** | **Upstream VEX subscriptions** — OpenVEX hubs (git, PURL layout), CSAF providers (ROLIE), OCI referrers; stored with `role = upstream`, local always outranks upstream | none (statements in `vex_statements`, one more precedence rung) | What the producer already said is not re-triaged downstream. Distinct from #524: that is "is it vulnerable", this is "does the producer say it matters". |
| **#533** | **VEX export** — consolidated OpenVEX / CSAF per project and SBOM, idempotent round trip, optional signing + OCI publish | Endpoint | The *distribute* step. Generate (#338) → manage (core) → distribute (#533, #534). Signing/OCI push share #525's dependency decision; unsigned export ships first. |
| — | `docs/integrations/vexviper` | Docs | Once the above stabilises. |

### 3b. Fleet operations

| # | Issue | Rationale |
|---|-------|-----------|
| **#138** (API + UI) | `?namespace=` filters + namespace chips | Column landed in `015`; this is the consumer side. |
| **#267** → **#176** | Cluster filter via query param → full Cluster Picker | Backend ready since #132/#133; #267 is the help-wanted first step. |
| **#140** | Workload vulnerability summary | Image → posture cross-reference; becomes an additional input to the #141 score. |
| **#57** (policies) | Per-project license policies, severity thresholds, exception scopes | Project identity fixed by #398; policies have a stable key. |
| **#136** (rest) | `CORS_ALLOW_CREDENTIALS`, configurable methods/headers | Small, additive. |
| **#490** | Bounded response sizes in the license resolvers, deps.dev page cap | Hardening; default registries are trusted, a configurable mirror is not. Lands with #60, which adds more outbound feeds. |
| **#60** | Local OSV mirror | Offline / air-gapped; no rate limits. KEV/EPSS feeds (#410, #64) get the same mirror treatment here. |
| **#143** | In-toto Witness integration | New `attestations` table (additive), signature verification, provenance display. Additional #141 score input. Phase 1 no new deps; `sigstore-go` later. |
| **#539** | **Reference cluster scanner** (own repository) + scanner conformance list in the docs | Out of tree; docs page in BOMHort | The v0.9.0 identity set (#455–#461) needs one thing that sends it. Generator stays syft/trivy; prefers the image's attestation (#525). Kind-tested against the chart. |
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

### 3d. Developer workflow and inventory depth

The register (v0.9.0) answers the auditor; this block answers the developer on a pull request and the operator whose inventory is full of their own code. Everything here is additive; the order is the dependency order of the CI path.

| # | Issue | Migration | Notes |
|---|-------|-----------|-------|
| **#513** | Stateless evaluation `POST /api/v1/scan` (`?fail_on=`) — parse, resolve, OSV, licenses; nothing persisted | none | Extracts the worker's evaluate step into `internal/evaluate`; the worker becomes "evaluate, then write". Returns the same finding shape as the stored endpoints, SARIF via #512. |
| **#521** | First-party composite GitHub Action (`.github/actions/upload-sbom`) + GitLab include | none | Six headers become six inputs with workflow defaults; `wait`/`fail-on`/`sarif` outputs. Shell + `curl`, tested against the Kind deployment. |
| **#520** | Workload-identity upload auth: OIDC / Kubernetes ServiceAccount tokens exchanged for a short-lived bearer, trust rules reuse #456's scope object | none (`uploaded_by` from #456) | Removes the last static secret from a CI → BOMHort path. Stdlib JWT verification; fails closed. *Upload* identity only — user login stays a Non-Goal. |
| **#509** | Outdated components: latest upstream version + version distance per package (`?outdated=`) | `0xx` `ADD COLUMN package_latest_versions, package_version_distance` on `sbom_packages` | Reuses the registry resolvers and their cache; `version-skew` compares projects with each other, this compares with upstream. Input to #517. |
| **#514** | First-party / internal component rules (`internal-components.json`): declared license, no public lookups, source `internal` | none (rules file, live-reloaded via `rulesource`, retroactive via `license_recheck`) | Removes the operator's own code from the `unknown` license number and from registry/GitHub rate limits. |
| **#515** | Private advisories (`private-vulnerabilities.json`, OSV schema) merged with public findings; `source` column | `0xx` `ADD COLUMN source LowCardinality(String) DEFAULT 'osv'` on `vulnerabilities` | Embargoed CVEs and vendor PSIRT bulletins reach the register before OSV does. Client-side OSV range matcher, same vocabulary as #60's mirror. |
| **#524** | Pluggable OSV-format advisory feeds (`ADVISORY_SOURCES`, PURL-prefix authority) + distro-aware matching: a feed hit suppresses the upstream range match for the same CVE; per-component status vocabulary and location stored | `0xx` `ADD COLUMN advisory_source, advisory_status, component_location` on `vulnerabilities` | Generalises #515 (a private feed is one `s3://`/`file://` entry) and #60 (a mirror is one more `all.json`). Fixes the backport false positives on `pkg:apk`/`deb`/`rpm`. Feed licence is the operator's check, documented. |
| **#525** | Ingest SBOM attestations from OCI registries by digest (`INGEST_REGISTRY_REFS`, empty-body upload with `?image=`); predicate type, SLSA builder id, EOL predicate, verification state recorded | `0xx` `ADD COLUMN attestation_predicate, attestation_verified, builder_id` on `sboms` | Fourth ingestion source after dir/S3/upload; envelope goes to the document store. Verification failure is recorded, not fatal. **Keyless verification needs sigstore libraries — explicit dependency decision before implementation.** Read side is #143's provenance tab. |

**Enrichment beyond OSV** — the register stores what OSV returns; these rows add the axes OSV does not carry. Every source below is free, pullable in bulk (git or daily dump, no key) and CC0/CC-BY/MIT/BSD — share-alike (CC-BY-SA) and non-redistributable feeds are deliberately not on the list, because stored derived data would inherit their terms.

| # | Issue | Migration | Notes |
|---|-------|-----------|-------|
| **#527** | Rich CVE record from the CVE List (`cvelistV5`, hourly git): SSVC decision points from the CISA ADP container, ADP CVSS/CWE fallback, `affected[].packageURL` | `03x_create_cve_records` (new table) | The decision axis next to EPSS (#64) and KEV (#410): Track / Attend / Act. CVE JSON 5.2 carries PURLs — long-term the CPE question answers itself. Same loader shape as #60/#524 (`CVELIST_SOURCE=file://` for air-gap). |
| **#528** | Public exploit-code signal per CVE (Nuclei, Metasploit, Exploit-DB references) | `03x_create_exploit_refs` (new table) + `exploit_available` on `vulnerabilities` | Three git clones, daily, MIT/BSD/GPL-data. The due-date override chain in #411 becomes KEV > exploit available > SSVC Attend/Act > EPSS threshold. |
| **#529** | Version publication status: `published_at`, deprecated / yanked / retracted / unlisted, build provenance (SLSA / Sigstore attestation) | `03x` `ADD COLUMN package_published_at, package_version_status, package_provenance` on `sbom_packages` | deps.dev `GetVersionBatch` (≤ 5000/call) + one more field from the packuments the registry resolvers already fetch. Input to #517 `cooldown`, to #516 (provenance judged there) and to a dashboard age histogram. |
| **#530** | Concluded vs. declared license + attribution NOTICE export (ClearlyDefined resolver, CC0) | `03x` `ADD COLUMN license_discrepancy` on `sbom_packages` | Declared still wins (AGENTS.md rule); a scan-derived disagreement is a flag, not an override. `GET …/notices` is the attribution row of #62. Decision-log entry + golden row before merge. |

**Exit criteria:** An external tool can discover new findings without polling, push VEX idempotently and see the result; cluster/namespace views exist in the UI; OSV/KEV/EPSS work offline; a CBOM ingested next to an SBOM yields an inventory, policy findings and a PQC readiness figure; **a pull request can be gated on an SBOM without a stored project or a static secret, and first-party packages stop counting as unknown; a distro-backported fix is not an open finding, and an image's signed SBOM is ingested from the registry without a scanner re-generating it; a finding shows SSVC, exploit-code and publication status next to CVSS, and a NOTICE file downloads per project.**

---

## Phase 4: Analytics (v1.2.0, due 2027-07-31)

**Theme:** Supply-chain intelligence on top of the mature data model. CRA scoring left this phase for 1.0; what remains is prioritisation and dependency-health depth.

| # | Issue | Rationale |
|---|-------|-----------|
| **#255** | Editable/enriched SBOMs + enriched download (+ companion VEX, in-toto re-sign) | Builds on #256 originals. Overlay table `ReplacingMergeTree`. |
| **#254** | Evaluate protobom/storage relational schema for ClickHouse | Research; informs #255's overlay; **not** a rewrite of `sbom_packages`. |
| **#38** | SBOM Diff: flat package/finding diff between two SBOMs or two image digests (#457) first — `added/removed/changed`, `fixed` findings — JSON + report export (#62); tree divergence view second | "What changed between v1.7.1 and v1.7.2?" — and "is the new base image actually better?" |
| **#56** | Dependency Tree View | Hierarchical visualization of transitive chains. |
| **#63** | Blast Radius Search | Extends Package Search with version constraints, vuln context, direct/transitive. |
| **#532** | **Base-image attribution** — findings classified `inherited`, aggregated per base image, `?inherited=false` | The noise killer: 34 images on one base show 212 findings once, with the upgrade that closes them. Needs digest/identifier data (#457, #461, #525) in the field first. |
| **#534** | **Transparency Exchange API** (TEA, Beta 2) read-only server over projects, releases and the document store | CRA Art. 13 "make available" as a standard surface; artefacts served by reference so hashes match the producer's. Spec version pinned; a spec bump is a new issue. |
| **#61** | OpenSSF Scorecard | Upstream project health; deps.dev `GetProjectBatch` (CC-BY) first, `api.scorecard.dev` fallback — not ecosyste.ms (CC-BY-SA). |
| **#82** | Lottery Factor | Single-maintainer risk; extends `internal/github`. |
| **#510** | End-of-life / end-of-support signal (endoflife.date feed, `eol-products.json` mapping) | The most predictable risk in an inventory has no CVE. New `eol_cycles` table; second source is a producer-attached EOL predicate via #525. Input to #517 and the #141 score. |
| **#516** | Component integrity — SBOM checksums verified against registry hashes (`verified` / `mismatch` / `unverifiable` / `unchecked`) | The checksums are already parsed and dropped. Same resolver plumbing as #509; `package_hashes` + `package_integrity` on `sbom_packages`. |
| **#517** | Component policy (`component-policy.json`): closed-vocabulary rules over packages — forbidden PURLs, version distance (#509), EOL (#510), integrity (#516), finding age without VEX, `cooldown` (version younger than N days), `support-window`, `pinned-digest` | Exact precedent: license policy + exceptions + recheck job. `policy_violations` table, `GET /api/v1/policy-violations`. Last, because its conditions are the three rows above. |
| **#268** | Evaluate official ClickHouse operator (vs. Altinity) | Breaking `values.yaml` → **major bump**; candidate for v2.0. |

**Exit criteria:** exploit-probability prioritisation is complemented by dependency-health metrics; SBOM diff and tree view exist; enriched export works; a fleet-wide rule like "nothing past end-of-life in production" is a config line and a page, not a script.

---

## Schema Change Register

Everything that touches `db/migrations/` or a frozen response shape, in one place. Rule: **`ORDER BY` or column-type changes are never allowed after 1.0** (MergeTree can't alter them in place). `ADD COLUMN … DEFAULT` and new tables are fine at any time. "pre" below means *scheduled before the tag*; the "needs pre-1.0?" column is honest about which ones are there for contract reasons and which for market reasons.

| Migration | Issue | Change | Pre/Post 1.0 | Needs pre-1.0? |
|-----------|-------|--------|:------------:|---|
| `012`–`022` | #131 … #357 | see Phase 1 | ✅ shipped | contract |
| `023_add_project_parent` ✅ | project groups | `ADD COLUMN parent` on `sboms`/`ingestion_queue`, `root_purl`, `supplier` on `sboms` | ✅ shipped | market (additive) |
| `024_add_package_license_sources` ✅ | #439 | `ADD COLUMN package_license_sources Array(LowCardinality(String)) DEFAULT []` on `sbom_packages` | ✅ shipped (v0.8.0) | market (additive; existing rows read as `unrecorded` until re-scan) |
| `025_add_dependency_depth` ✅ | dependency scope | `ADD COLUMN package_depths` on `sbom_packages`, `dependency_depth` on `vulnerabilities` (scope is derived from it) — direct vs. transitive on CVE and license views | ✅ shipped (v0.8.0) | market (additive; old rows read as `unknown` until re-scan) |
| `026_add_queue_retry_after` ✅ | GitHub rate limit | `ADD COLUMN retry_after` on `ingestion_queue` — a job hitting the GitHub rate limit is parked, not resolved with a guess | ✅ shipped (v0.8.0) | correctness (additive) |
| — (query only) ✅ | #335 | Row semantics of `/sboms/{id}/vulnerabilities` | ✅ | contract |
| — (DTO only) ✅ | #177 | `cluster` in `SBOMListItem` | ✅ | contract |
| — (query + DTO) ✅ | #398 | De-duplicated project counts; `projectKeyExpr` is contract | ✅ | contract |
| — (Helm values) ✅ | #399 | New `mcp.*` block | **pre** (v0.8.0) | contract (values) |
| — (Helm values) ✅ | #397, #391, #392, #344-I | `existingConfigMap`, `seedJob` removed, image pin, `apiGateway.queryLimits.*` | **pre** (v0.8.0) | contract (values) |
| — (parser only) ✅ | #355 | `documentNamespace` fallback in `extractSourceRepo` | **pre** (v0.8.0) | makes #332 true |
| — (DTO + query) ✅ | #412 | `cve_id`, `aliases` on finding DTOs; lookups by alias | **pre** (v0.8.0) | market (additive) |
| — (endpoint) ✅ | #266 | CSV export | **pre** (v0.8.0) | market (additive) |
| `0xx_ingestion_queue_created_at_datetime64` | #446 | `MODIFY COLUMN created_at DateTime64(3)` on `ingestion_queue` | **pre** (v0.9.0) | **contract** — a column-type change, not allowed after 1.0. Number assigned at merge; the planned numbers below shift if it lands first. |
| `0xx_add_origin` | #455 | `ADD COLUMN origin LowCardinality(String) DEFAULT ''` on the 7 data tables | **pre** (v0.9.0) | contract (upload param + filter), additive |
| `032_add_workload_identity` | #458 | `ADD COLUMN workload_kind, workload_name, workload_uid` on `sboms` | **pre** (v0.9.0) | contract (upload params), additive |
| `0xx_add_image_identity` | #457 | `ADD COLUMN image_ref, image_digest` on `sboms` (+ skip index), `image_digest` on `sbom_packages`/`vulnerabilities` | **pre** (v0.9.0) | contract (`/images/{digest}`), additive |
| `0xx_add_producer_identifiers` | #461 | `ADD COLUMN producer_identifiers Map(String,String)` on `sboms` | **pre** (v0.9.0) | additive (audit trail) |
| `0xx_add_uploaded_by` | #456 | `ADD COLUMN uploaded_by` on `sboms` | **pre** (v0.9.0) | additive (attribution) |
| — (response shape) | #447 | `/licenses/compliance` → `PaginatedResponse[T]` | **pre** (v0.9.0) | **contract** — shape change |
| `027_add_vulnerability_cvss_cwe` | #408, #409 | `ADD COLUMN cvss_score Float32, cvss_vector String, cvss_version LowCardinality(String), cwe_ids Array(String)` on `vulnerabilities` | **pre** (v0.9.0) | market (additive; backfill from `osv_json`) |
| `028_create_kev_catalog` | #410 | New table keyed by CVE id | **pre** (v0.9.0) | market (additive) |
| `029_create_epss_scores` | #64 | New table keyed by CVE id | **pre** (v0.9.0) | market (additive) |
| `0xx_add_vulnerability_lifecycle` | #511 | `ADD COLUMN osv_modified DateTime, withdrawn_at Nullable(DateTime)` on `vulnerabilities` | **pre** (v0.9.0) | correctness (additive; withdrawn rows excluded by default — a read-model change, so before the freeze) |
| `0xx_create_euvd_aliases` + `kev_catalog.source` | #410 (extension) | New table keyed by CVE; `source` column on `kev_catalog` from the start | **pre** (v0.9.0) | market (additive) |
| `030_add_vex_action_statement_timestamp` | #413 | `ADD COLUMN action_statement_timestamp` on `vex_statements` | **pre** (v0.9.0) | market — *but* automated VEX producers won't re-send, so capture early |
| — (query + config) | #411 | `remediation-policy.json`; derived fields, no storage | **pre** (v0.9.0) | market (values: `remediationPolicy.*`) |
| — (endpoint + UI) | #141 | CRA readiness score | **pre** (v1.0.0) | market |
| `031_create_vulnerability_resolutions` | #7 | New table | **pre** (v1.0.0, stretch) | market (additive) |
| — (endpoint) | #62 | Report bundle (CSV + JSON + manifest) | **pre** (v1.0.0) | market |
| `032_create_crypto_libraries` | #419 | New table (or MV over `sbom_packages`) | **pre** (v1.0.0) | market (additive; values: `cryptoLibraries.*`) |
| — (endpoint) | #512, #519 | SARIF export, SVG badges | **pre** (v1.0.0) | market (additive; `?format=` on a frozen shape is why SARIF is pre) |
| — (query only, MV decision) | #518 | Trend series; `dashboard_stats_mv` repointed or dropped | **pre** (v1.0.0, stretch) | market |
| `03x_create_package_index_mv` | #344-C/D/E | MV + skip indexes | post | additive |
| `03x_add_package_latest_version` | #509 | `ADD COLUMN package_latest_versions Array(String), package_version_distance Array(UInt8)` on `sbom_packages` | post (v1.1.0) | additive |
| `03x_add_vulnerability_source` | #515 | `ADD COLUMN source LowCardinality(String) DEFAULT 'osv'` on `vulnerabilities` | post (v1.1.0) | additive |
| `03x_add_advisory_feed_columns` | #524 | `ADD COLUMN advisory_source, advisory_status LowCardinality(String), component_location String` on `vulnerabilities` | post (v1.1.0) | additive; `advisory_source` may replace #515's `source` if #524 lands first |
| `03x_add_finding_kind` | #531 | `ADD COLUMN finding_kind LowCardinality(String) DEFAULT 'vulnerability'` on `vulnerabilities`, `lookalike_of Array(String)` on `sbom_packages` | post (v1.0.0) | additive |
| `03x_add_reachability` | #535 | `ADD COLUMN reachability LowCardinality(String), evidence_source, evidence_ref String, evidence_at DateTime` on `vulnerabilities` | post (v1.1.0) | additive |
| `03x_add_base_image` | #532 | `ADD COLUMN base_image_ref, base_image_digest` on `sboms`, `inherited_from` on `vulnerabilities` | post (v1.2.0) | additive |
| `03x_create_cve_records` | #527 | new table `cve_records` (cve_id, cna/adp cvss, ssvc_*, cwe_ids, affected_purls, modified) | post (v1.1.0) | new table |
| `03x_create_exploit_refs` | #528 | new table `exploit_refs` + `ADD COLUMN exploit_available UInt8, exploit_sources Array(String)` on `vulnerabilities` | post (v1.1.0) | additive |
| `03x_add_version_status` | #529 | `ADD COLUMN package_published_at Array(DateTime), package_version_status, package_provenance Array(LowCardinality(String))` on `sbom_packages` | post (v1.1.0) | additive, parallel arrays |
| `03x_add_license_discrepancy` | #530 | `ADD COLUMN license_discrepancy Array(String)` on `sbom_packages` | post (v1.1.0) | additive |
| `03x_add_attestation_columns` | #525 | `ADD COLUMN attestation_predicate, builder_id LowCardinality(String), attestation_verified UInt8` on `sboms` | post (v1.1.0) | additive |
| `03x_create_eol_cycles` | #510 | New table keyed by product + cycle | post (v1.2.0) | additive |
| `03x_add_package_integrity` | #516 | `ADD COLUMN package_hashes Map(String,String), package_integrity Array(LowCardinality(String))` on `sbom_packages` | post (v1.2.0) | additive |
| `03x_create_policy_violations` | #517 | New table, same shape as `license_compliance` | post (v1.2.0) | additive |
| `03x_create_upload_jobs` | #336 | New table | post | additive |
| `03x_create_attestations` | #143 | New table | post | additive |
| `03x_create_crypto_assets`, `03x_create_crypto_compliance` | #415, #417 | New tables | post (v1.1.0) | additive |
| `03x_*` | #61, #82, #255, #60 | Enrichment / overlay / mirror tables | post | additive |
| — | #268 | Operator swap (`values.yaml` breaking) | **v2.0** | breaking |

---

## Dependency Graph

```
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
#485 ── #511 (lifecycle: modified/withdrawn) ── #414 freshness        #410 ── EUVD/ENISA extension
#266 ✅ ── #512 (SARIF, same columns) ── #513 (stateless scan) ── #521 (GitHub Action)   v1.0.0 → v1.1.0
#518 (trend) ── decides #344 MV                                      #519 (badges) ── standalone

INVENTORY DEPTH (v1.1.0 → v1.2.0):
#489 (shared resolver cache) ──┬── #509 (latest version / distance) ──┐
                               └── #516 (integrity)  ─────────────────┼── #517 (component policy)   v1.2.0
#510 (EOL) ───────────────────────────────────────────────────────────┘
#514 (internal components) ── license_recheck        #515 (private advisories) ── #414, #60 vocabulary
#524 (advisory feeds) ──┬── #515, #60 (same loader)      #525 (registry attestations) ──┬── #457 (digest identity)
                        └── #411/#413 status vocabulary, #509 fixed-in                     ├── #143 provenance tab
                                                                                           └── #510 EOL predicate
#60 (OSV mirror loader) ──┬── #524 feeds ──┬── #527 CVE List (SSVC) ──┐
                          └── #531 MAL-    └── #528 exploit refs ─────┼── #411 due-date chain, #414 register
#64 EPSS ── #410 KEV ────────────────────────────────────────────────┘
#338 (generate) ── #535 evidence ── core (manage) ── #533 export ──┬── #534 TEA ── #256 document store
#538 (upstream VEX) ──┘                                             └── #525 OCI publish (shared dep decision)
#455–#461 identity ── #539 reference scanner ── #532 base-image attribution ── #518 trend
#529 (version status) ──┬── #517 cooldown      #530 (ClearlyDefined) ──┬── #62 NOTICE export
                        └── #516 provenance                             └── license decision log

CRYPTO (#420):
#419 (library inventory, SBOM-only)                         v1.0.0
#415 (CBOM ingest) ── #416 (inventory) ── #417 (policy) ── #418 (PQC)   v1.1.0
                                                 └── #409 (CWE-327 filter on the register)

INGEST CORRECTNESS (v0.9.0, before the register):
#480 (refresher ownership) ── #459 (ownership filters on vulnerabilities)
#485 (no OSV stubs) ── #408/#409 (backfill from osv_json)
#486 (refresher bulk query) ── #410/#64 (feeds in the same binary)
#446 (DateTime64) ── #483 (claim race)        #482 ── #487 (one bulk hash query)
#489 (shared resolver cache) ── #481 (cache definite answers only)

RUNTIME-SCANNER IDENTITY (v0.9.0, after ingest correctness):
#455 (origin) ── #456 (scoped API keys) ── #520 (workload identity, v1.1.0)
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
- **Full OIDC in BOMHort**: User authentication is the upstream proxy's responsibility. Verifying a *workload's* OIDC token for upload (#520) is not user login — it replaces a static key, not a session.
- **Relational rewrite of the dependency model** (#254): protobom/storage's schema is evaluated for the *overlay* only.
- **A second project hierarchy** (#398): projects are grouped by `tags`, not by a new org/sub-project table.
