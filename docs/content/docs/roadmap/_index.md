---
title: "Roadmap"
linkTitle: "Roadmap"
type: docs
weight: 6
description: >
  Product roadmap for SeeBOM — phased delivery from foundation to enterprise-grade supply chain security.
---

{{% alert title="Last Updated" color="info" %}}
2026-05-22 · [Project Board →](https://github.com/orgs/seebom-labs/projects/1)
{{% /alert %}}

## Vision

SeeBOM is transitioning from a single-instance SBOM visualization tool into an **enterprise-grade, multi-cluster Software Supply Chain Security platform**. The roadmap spans three phases (Q1–Q3 2026), each building on the previous:

1. **Foundation & Security** — authentication, multi-cluster model, production readiness
2. **Multi-Cluster & Push Model** — fleet operations, CI/CD integration, attestation verification
3. **Analytics & Compliance** — CRA scoring, exploit prediction, dependency health metrics

---

## Phase 1: Foundation & Security {#phase-1}

**Q1 2026 (Apr–Jun) · Theme:** Make SeeBOM production-ready with real security requirements.

| Status | Issue | Description |
|:------:|-------|-------------|
| 🔲 | [#131 — Cluster-aware data model](https://github.com/seebom-labs/seebom/issues/131) | Add `cluster_id` to all tables. Every multi-cluster feature depends on this. |
| 🔲 | [#134 — API Authentication](https://github.com/seebom-labs/seebom/issues/134) | Service token + API key modes. Gate for all write operations. |
| 🔲 | [#137 — Enhanced health checks](https://github.com/seebom-labs/seebom/issues/137) | `/readyz`, `/livez` with dependency verification for K8s probes. |
| 🔲 | [#136 — Enhanced CORS](https://github.com/seebom-labs/seebom/issues/136) | Support POST + custom headers for upload and cross-origin access. |
| 🔲 | [#139 — Headless mode](https://github.com/seebom-labs/seebom/issues/139) | API-only deployment without Angular UI (Helm toggle). |
| 🔲 | [#8 — Project List View](https://github.com/seebom-labs/seebom/issues/8) | Group SBOMs by project — foundational UX improvement. |
| 🔲 | [#144 — SBOM Download](https://github.com/seebom-labs/seebom/issues/144) | Download original SBOM JSON from the platform. |
| 🔲 | [#59 — Expose API externally](https://github.com/seebom-labs/seebom/issues/59) | Helm Ingress template for secure external access. |
| 🔲 | [#55 — CycloneDX Support](https://github.com/seebom-labs/seebom/issues/55) | Parse CycloneDX 1.4+ SBOMs (doubles addressable market). |
| ✅ | [~~#37 — Version Skew Detection~~](https://github.com/seebom-labs/seebom/issues/37) | Cross-org dependency consistency. Merged 2026-05-04. |

**Exit criteria:** SeeBOM deployable with authentication, multi-cluster tagging, proper K8s probes, and CycloneDX parsing.

---

## Phase 2: Multi-Cluster & Push Model {#phase-2}

**Q2 2026 (Jul–Sep) · Theme:** Enable fleet-scale operations — multiple clusters, push ingestion, attestation verification.

| Status | Issue | Description |
|:------:|-------|-------------|
| 🔲 | [#132 — Cluster listing endpoint](https://github.com/seebom-labs/seebom/issues/132) | First consumer-visible multi-cluster feature. |
| 🔲 | [#133 — Cluster-detail endpoints](https://github.com/seebom-labs/seebom/issues/133) | Per-cluster deep-links for frontend routing. |
| 🔲 | [#135 — SBOM Upload (Push Model)](https://github.com/seebom-labs/seebom/issues/135) | Accept SBOMs from CI/CD pipelines via POST API. |
| 🔲 | [#138 — Namespace filtering](https://github.com/seebom-labs/seebom/issues/138) | Sub-cluster granularity for enterprise teams. |
| 🔲 | [#140 — Workload vulnerability summary](https://github.com/seebom-labs/seebom/issues/140) | Image → posture cross-reference for compliance dashboards. |
| 🔲 | [#62 — Exportable Auditor Reports](https://github.com/seebom-labs/seebom/issues/62) | PDF/CSV compliance exports for CRA audits. |
| 🔲 | [#60 — Local OSV Mirror](https://github.com/seebom-labs/seebom/issues/60) | Clone osv.dev into ClickHouse — offline, no rate limits. |
| 🔲 | [#57 — Project-aware data model + per-project policies](https://github.com/seebom-labs/seebom/issues/57) | **Expanded scope.** Adds a `project` column to all core tables (same pattern as `cluster`), enabling per-project license policies, severity thresholds, and exception scopes. Powers Project List View (#8) and Aggregated SBOM View (#58). |
| 🔲 | [#143 — In-toto Witness Integration](https://github.com/seebom-labs/seebom/issues/143) | Supply chain attestation verification + provenance display. |
| 🔲 | [#58 — Aggregated SBOM View](https://github.com/seebom-labs/seebom/issues/58) | Group version history under project names. Depends on #57. |

**Exit criteria:** Multi-cluster management with namespace isolation, SBOM push from CI/CD, PDF compliance reports, attestation verification, no external OSV dependency.

---

## 🎯 v1.0.0 Milestone {#v1}

**Target: October 2026** · [GitHub Milestone →](https://github.com/seebom-labs/seebom/milestone/1)

After Phase 2 completes, SeeBOM reaches **v1.0.0** — the first stable release. From this point forward, the [Support Policy](/docs/release/#support-policy) (current − 2) takes effect and breaking changes require a major version bump.

### v1.0 Criteria

| Requirement | Status | Issue |
|-------------|:------:|-------|
| API Authentication (service token + API key) | 🔲 | [#134](https://github.com/seebom-labs/seebom/issues/134) |
| Cluster-aware data model (schema stable) | 🔲 | [#131](https://github.com/seebom-labs/seebom/issues/131) |
| Cluster listing + detail endpoints | 🔲 | [#132](https://github.com/seebom-labs/seebom/issues/132), [#133](https://github.com/seebom-labs/seebom/issues/133) |
| Namespace filtering | 🔲 | [#138](https://github.com/seebom-labs/seebom/issues/138) |
| SBOM Upload endpoint | 🔲 | [#135](https://github.com/seebom-labs/seebom/issues/135) |
| CycloneDX parsing | 🔲 | [#55](https://github.com/seebom-labs/seebom/issues/55) |
| Enhanced health probes | 🔲 | [#137](https://github.com/seebom-labs/seebom/issues/137) |
| Versioned documentation | 🔲 | [#145](https://github.com/seebom-labs/seebom/issues/145) |
| Version Skew Detection | ✅ | [~~#37~~](https://github.com/seebom-labs/seebom/issues/37) |

### What v1.0 means

- **API contract frozen** — no endpoint removals or response shape changes without v2.0
- **ClickHouse schema stable** — no ORDER BY or column type changes without migration tooling
- **Helm values stable** — existing `values.yaml` keys won't be renamed
- **Support policy active** — current release + 2 previous minors receive security patches
- **SemVer enforced** — features in minor bumps, fixes in patches, breaking = major

### Pre-1.0 releases

All v0.x releases are development milestones. They may contain breaking changes between any minor version. Do not assume backward compatibility.

---

## Phase 3: Analytics & Compliance {#phase-3}

**Q3 2026 (Oct–Dec) · Theme:** Advanced analytics, regulatory compliance scoring, and supply chain intelligence.

| Status | Issue | Description |
|:------:|-------|-------------|
| 🔲 | [#141 — CRA Compliance Dashboard](https://github.com/seebom-labs/seebom/issues/141) | EU Cyber Resilience Act readiness scoring. |
| 🔲 | [#38 — SBOM Diff](https://github.com/seebom-labs/seebom/issues/38) | Dependency tree divergence between versions. |
| 🔲 | [#56 — Dependency Tree View](https://github.com/seebom-labs/seebom/issues/56) | Hierarchical visualization of transitive chains. |
| 🔲 | [#63 — Blast Radius Search](https://github.com/seebom-labs/seebom/issues/63) | Version-constrained impact analysis with vuln context. |
| 🔲 | [#64 — EPSS Scores](https://github.com/seebom-labs/seebom/issues/64) | Exploit probability scoring for prioritization. |
| 🔲 | [#61 — OpenSSF Scorecard](https://github.com/seebom-labs/seebom/issues/61) | Upstream project health scoring per dependency. |
| 🔲 | [#82 — Lottery Factor](https://github.com/seebom-labs/seebom/issues/82) | Single-maintainer risk detection. |
| 🔲 | [#7 — CVE Fix Time (MTTR)](https://github.com/seebom-labs/seebom/issues/7) | Mean-time-to-remediate tracking per project. |

**Exit criteria:** CRA readiness scoring, EPSS-based prioritization, dependency health metrics, and SBOM diff.

---

## Dependency Graph

The following diagram shows blocking dependencies between issues:

```text
#131 (Cluster Model) ─────┬── #132 (Cluster Listing)
                          ├── #133 (Cluster Detail)
                          ├── #138 (Namespace) ── #140 (Workload Summary) ── #141 (CRA)
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

Key insight: **#131 (Cluster Model)**, **#134 (Auth)**, and **#57 (Project Model)** are the critical-path items — most Phase 2 features depend on them. Cluster and project are orthogonal dimensions (infrastructure vs. ownership) and intentionally modeled as separate low-cardinality columns.

---

## Success Metrics

| Phase | Metric | Target |
|-------|--------|--------|
| Phase 1 | Production deployment with auth | Service token + API key working, health probes passing |
| Phase 2 | CI/CD push integration | Upload endpoint processes 100 SBOMs/hour |
| Phase 3 | CRA compliance readiness | All 5 CRA conditions evaluable, score >80% |

---

## Prioritization Philosophy

### Multi-cluster before analytics
Organizations evaluating SeeBOM for production ask *"Can it handle our 5 clusters?"* before *"Does it have EPSS scores?"*

### Auth before upload
A write endpoint without authentication is a security incident. Auth gates all write operations.

### CRA compliance in Q3
EU CRA enforcement begins 2027. Landing scoring by end of 2026 gives adopters a full year of runway.

### Data enrichment as a batch
EPSS, Scorecard, and Lottery Factor share the same architecture pattern (fetch → store → expose → display). Implementing them together maximizes code reuse.

---

## Non-Goals

These items are **explicitly out of scope** for this roadmap:

- ❌ Custom Kubernetes Operator (we use Helm + ClickHouse Operator)
- ❌ Write APIs for license exceptions (frontend is public)
- ❌ Multi-repo split (monorepo is a hard constraint)
- ❌ Real-time streaming (batch ingestion is sufficient)
- ❌ RBAC/multi-tenancy (auth is binary for now)
- ❌ Full OIDC in SeeBOM (upstream proxy responsibility)

---

## Contributing

Want to pick up an issue from the roadmap? Check the [Project Board](https://github.com/orgs/seebom-labs/projects/1) for items in the **Todo** column. Issues labeled `help wanted` are especially good for new contributors.

See [Development Guide](/docs/development/) for setup instructions.


