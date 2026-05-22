# SeeBOM Product Roadmap

> Last updated: 2026-05-22
> Project Board: https://github.com/orgs/seebom-labs/projects/1

## Executive Summary

SeeBOM is transitioning from a single-instance SBOM visualization tool into an **enterprise-grade, multi-cluster Software Supply Chain Security platform**. This roadmap outlines three phases spanning Q1-Q3 2026, progressing from foundational infrastructure (authentication, multi-cluster data model) through fleet-scale operations (push ingestion, namespace isolation) to advanced analytics (CRA compliance scoring, exploit prediction, dependency health).

The sequencing is driven by dependency chains: multi-cluster support must land before fleet APIs, authentication must exist before write endpoints, and data enrichment (EPSS, Scorecard, Lottery Factor) builds on the mature query layer.

---

## Phase 1: Foundation & Security (Q1 2026 — Apr-Jun)

**Theme:** Make SeeBOM deployable in production environments with real security requirements.

| # | Issue | Rationale |
|---|-------|-----------|
| #131 | Cluster-aware data model | Foundational schema change — every multi-cluster feature depends on this. Non-destructive migration (ADD COLUMN DEFAULT). |
| #134 | API Authentication (Service Token + API Key) | Zero dependencies, highest organizational demand. Cannot expose API externally or accept uploads without auth. OIDC explicitly out of scope — handled by upstream proxy/gateway. |
| #137 | Enhanced health checks (/readyz, /livez) | Quick win. Production K8s deployments need proper probes before trusting traffic routing. |
| #136 | Enhanced CORS configuration | Required by upload endpoint and external dashboard embedding. Small change, large enablement. |
| #139 | Headless mode (API-only) | Helm-only change. Enables pure API consumers and reduces resource footprint for headless deployments. |
| #8 | Project List View | Existing priority:high. Groups SBOMs by project — foundational UX improvement. |
| #144 | SBOM Download | Small scope, high value. Users expect to download original SBOM JSON from the platform that aggregates them. Requires new API endpoint + UI button. |
| #59 | Expose API externally (Ingress) | Helm template + docs. Pairs with auth (#134) for secure external access. |
| #55 | CycloneDX Support | Already in progress (PR #110). Doubles the addressable market (Trivy, Grype users). |
| ~~#37~~ | ~~Version Skew Detection~~ | ✅ **Done** (PRs #103, #126, merged 2026-05-04). |

**Exit criteria:** SeeBOM can be deployed with authentication, multi-cluster tagging, and proper K8s health probes. CycloneDX SBOMs parse correctly.

---

## Phase 2: Multi-Cluster & Push Model (Q2 2026 — Jul-Sep)

**Theme:** Enable fleet-scale operations — multiple clusters, push ingestion, namespace isolation, and audit exports.

| # | Issue | Rationale |
|---|-------|-----------|
| #132 | Cluster listing endpoint | First consumer-visible multi-cluster feature. Enables cluster picker in frontend. |
| #133 | Cluster-detail endpoints | Per-cluster deep-links. Cleaner than query params for frontend routing. |
| #135 | SBOM Upload (Push Model) | Critical for CI/CD integration. Depends on auth (#134) and cluster model (#131). |
| #138 | Namespace filtering | Sub-cluster granularity. Enterprise teams operate in namespaces, not just clusters. |
| #140 | Workload vulnerability summary | The key cross-reference: image → posture. Powers compliance dashboards. |
| #62 | Exportable Auditor Reports (PDF/CSV) | CRA compliance requires offline documentation. Auditors don't use UIs. |
| #60 | Local OSV Mirror | Eliminates external dependency on osv.dev. Faster scans, offline capability, no rate limits. |
| #57 | Project-aware data model + per-project policies | **Expanded scope.** Add `project LowCardinality(String) DEFAULT ''` column to all core tables (same pattern as `cluster`). Resolution via per-bucket config, push API payload, or document-name convention. Includes per-project license policies, severity thresholds, and exception scopes. Powers Project List View (#8) and Aggregated SBOM View (#58). |
| #143 | In-toto Witness Integration | Supply chain attestation verification for ingested SBOMs. Provenance display, signature verification. Prerequisite for CRA compliance scoring (#141). |
| #58 | Aggregated SBOM View | UX fix: group 50 versions of containerd into one expandable row. Depends on project-aware data model (#57). |

**Exit criteria:** SeeBOM manages multiple clusters with namespace isolation, accepts SBOM pushes from CI/CD, generates PDF compliance reports, attestation verification, and doesn't depend on external OSV availability.

### 🎯 v1.0.0 Milestone (Target: October 2026)

After Phase 2 completes, SeeBOM reaches **v1.0.0** — the first stable release:

- API contract frozen (no breaking changes without major version bump)
- ClickHouse schema stable (no ORDER BY changes)
- Helm chart values stable
- Support policy (current − 2) takes effect
- Versioned documentation enabled (#145)

**v1.0 Criteria:**
- [x] ~~Version Skew Detection~~ (#37)
- [ ] API Authentication (#134)
- [ ] Cluster-aware schema (#131)
- [ ] All cluster/namespace endpoints finalized (#132, #133, #138)
- [ ] Upload endpoint stable (#135)
- [ ] CycloneDX parsing (#55)
- [ ] Health probes (#137)
- [ ] Versioned docs (#145)

---

## Phase 3: Analytics & Compliance (Q3 2026 — Oct-Dec)

**Theme:** Advanced analytics, regulatory compliance scoring, and supply chain intelligence.

| # | Issue | Rationale |
|---|-------|-----------|
| #141 | CRA Compliance Dashboard | EU Cyber Resilience Act goes live 2027. Organizations need readiness scoring NOW. |
| #38 | SBOM Diff (tree divergence) | "What changed between v1.7.1 and v1.7.2?" — critical for change review. |
| #56 | Dependency Tree View | Hierarchical visualization. Current flat list doesn't show transitive chains. |
| #63 | Blast Radius Search (delta) | Extends v0.4.0 Package Search with version constraints, vuln context, direct/transitive classification. |
| #64 | EPSS Scores | Exploit probability > CVSS severity for prioritization. Free daily bulk data from FIRST.org. |
| #61 | OpenSSF Scorecard Integration | Upstream project health scoring. "Is this dependency well-maintained?" |
| #82 | Lottery Factor | Single-maintainer risk detection. Supply chain resilience metric. |
| #7 | CVE Fix Time (MTTR) | Mean-time-to-remediate is a key security KPI for audits (SOC2, ISO 27001). |

**Exit criteria:** SeeBOM provides CRA readiness scoring, exploit-probability-based prioritization, dependency health metrics, and SBOM diff capabilities.

---

## Dependency Graph

```
#131 (Cluster Model) ─────┬── #132 (Cluster Listing)
                          ├── #133 (Cluster Detail)
                          ├── #138 (Namespace Filtering) ── #140 (Workload Summary) ── #141 (CRA Dashboard)
                          └── #135 (Upload)
                                    ↑
#134 (Auth) ──────────────────────────┘
#136 (CORS) ──────────────────────────┘

#57 (Project Model) ──────┬── #8  (Project List View)
                          ├── #58 (Aggregated SBOM View)
                          └── Per-project policies (license, severity, exceptions)

#143 (Witness) ── standalone (feeds into #141 CRA Dashboard)
#55 (CycloneDX) ── standalone
#144 (SBOM Download) ── standalone
#137 (Health Checks) ── standalone
#139 (Headless Mode) ── standalone
#60 (OSV Mirror) ── standalone
#64 (EPSS) ── standalone (extends cve-refresher)
#82 (Lottery Factor) ── extends internal/github
#61 (Scorecard) ── extends internal/github
```

---

## Prioritization Rationale

### Why multi-cluster before analytics?

Organizations evaluating SeeBOM for production ask: "Can it handle our 5 clusters?" before they ask "Does it have EPSS scores?" The cluster model is table-stakes for enterprise adoption.

### Why auth before upload?

A write endpoint without authentication is a security incident waiting to happen. Auth is the gate that unlocks all write operations safely. SeeBOM uses a lightweight service-token mode (shared secret with upstream proxy) rather than full OIDC — user authentication is the proxy's responsibility, not SeeBOM's.

### Why CRA compliance in Q3?

The EU Cyber Resilience Act enforcement begins 2027. Organizations need 6-12 months of tooling maturity before audits. Landing CRA scoring by end of 2026 gives early adopters a full year of runway.

### Why EPSS/Scorecard/Lottery Factor together?

These are all "data enrichment" features that follow the same pattern: fetch external data → store in ClickHouse → expose via API → display in frontend. Implementing them as a batch maximizes code reuse and architectural consistency.

### Why project model is separate from cluster model?

**Cluster** and **project** are orthogonal dimensions:

| Dimension | Cluster | Project |
|-----------|---------|---------|
| Question answered | Where is it deployed? | What is it / who owns it? |
| Example | `prod-eu`, `staging-us` | `payment-service`, `mobile-app` |
| Cardinality | Low (1-50) | High (50-5000) |
| Ownership | Platform team | Dev teams |
| Lifecycle | Stable (years) | Volatile |

A single SBOM can simultaneously belong to cluster `prod-eu` AND project `payment-service`. We model these as independent low-cardinality columns rather than overloading one field.

Cluster lands first (Phase 1, #131) because it's a smaller change with no UI implications. Project (#57) lands in Phase 2 because it requires UI work (project picker, per-project dashboards) and benefits from the Upload endpoint (#135) where the client can declare the project at push time.

---

## Success Metrics

| Phase | Metric | Target |
|-------|--------|--------|
| Phase 1 | API can be deployed with auth in production | Service token + API key modes working, health probes passing |
| Phase 2 | CI/CD pipeline pushes SBOM to SeeBOM | Upload endpoint processes 100 SBOMs/hour |
| Phase 3 | CRA readiness score > 80% for managed clusters | All 5 CRA conditions evaluable |

---

## Non-Goals (Explicitly Out of Scope)

- **Custom Kubernetes Operator**: We use standard Helm + ClickHouse Operator. No custom CRDs.
- **Write APIs for license exceptions**: Frontend is public. Policy changes require config file updates.
- **Multi-repo split**: Monorepo architecture is a hard constraint for AI-assisted development.
- **Real-time streaming**: Batch ingestion (CronJob + queue) is sufficient for SBOM use cases.
- **RBAC/multi-tenancy**: Auth is binary (authenticated or not). Fine-grained RBAC is a future consideration beyond this roadmap.
- **Full OIDC in SeeBOM**: User-facing authentication is the upstream proxy/gateway's responsibility. SeeBOM only validates service tokens from trusted proxies.





