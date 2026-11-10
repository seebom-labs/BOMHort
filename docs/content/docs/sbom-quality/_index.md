---
title: "SBOM Quality Score"
linkTitle: "Quality Score"
type: docs
weight: 7
description: >
  Deterministic SBOM quality evaluation based on NTIA minimum elements and TR-03183 criteria.
---

BOMHort evaluates each ingested SBOM document against industry quality benchmarks,
specifically the NTIA Minimum Elements for Software Bill of Materials and BSI TR-03183
guidelines.

Each SBOM receives a deterministic score from 0 to 100 alongside an array of quality
flags identifying specific deficiencies or omissions.

## Minimum Elements & Scoring Breakdown

A perfect score of 100 requires fulfilling all data completeness, freshness, and
identifiability requirements:

<!-- quality-weights:start -->
| Criterion | Points | Evaluation Rule |
|-----------|--------|-----------------|
| Root Component | 5 | Root component identifier or document name is specified |
| Author & Tooling | 10 | Creator tools or document authors are declared |
| Timestamp Freshness | 10 | Creation date is non-zero, not in the future, and not stale |
| Supplier Identity | 10 | Component or product supplier organization is provided |
| Component Names | 10 | At least 90% of packages declare a non-empty name |
| Component Versions | 10 | At least 80% of packages declare a valid version |
| PURL Coverage | 15 | Package URLs (pkg:) present for at least 80% of components |
| Dependency Graph | 15 | Explicit dependency relationships connect multi-component documents |
| License Coverage | 15 | Valid license expressions declared for at least 80% of components |
<!-- quality-weights:end -->

## Quality Deduction Flags

When an SBOM fails one or more criteria, deduction flags are attached to explain the
reasons for the lower score:

<!-- quality-flags:start -->
| Flag | Description |
|------|-------------|
| future-timestamp | Creation date is more than 24 hours in the future |
| low-license-coverage | Less than 80% of packages have declared licenses |
| low-purl-coverage | Between 1% and 79% of packages have Package URLs (PURLs) |
| missing-author | Document metadata contains no author or creator tool |
| missing-component-name | Over 10% of packages have missing or blank names |
| missing-supplier | No supplier or manufacturer organization was provided |
| missing-timestamp | Creation timestamp is missing or zero |
| missing-version | Over 20% of packages lack version information |
| no-dependency-graph | Multi-component document contains no dependency relationships |
| no-licenses | No package in the document has a declared license |
| no-purls | No package in the document has a valid Package URL |
| no-root-component | Document has no designated root component or document name |
| stale-document | Creation timestamp is older than two years |
| unsupported-spec-version | Document specification version is legacy or unsupported |
<!-- quality-flags:end -->

## Flat-List SBOMs and Vulnerability Scope

A common pattern in basic build tools is outputting a flat list of dependencies with
no dependency graph relationships. When this happens:

1. The document receives the `no-dependency-graph` flag and loses 15 quality points.
2. In the vulnerability listing (`/api/v1/vulnerabilities`), all findings from this
   document have `scope: "unknown"` with `scope_reason: "no-dependency-graph"`.
   This informs the security engineer that direct vs. transitive status cannot be
   determined due to generator limitations.

## Aggregation & Fleet Views

Corpus-wide quality metrics are aggregated via:
- `GET /api/v1/stats/dashboard`: displays `average_quality_score` and `low_quality_sboms`
  (documents scoring below 60).
- `GET /api/v1/stats/quality`: provides average corpus quality, score distribution, and
  breakdown grouped by SBOM generator tool.
- `GET /api/v1/sboms?min_quality=80`: filters the document inventory for SBOMs meeting
  compliance thresholds.

