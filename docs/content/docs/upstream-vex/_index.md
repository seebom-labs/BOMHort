---
title: "Upstream VEX Subscriptions"
linkTitle: "Upstream VEX"
type: docs
weight: 8
description: >
  Configure external OpenVEX hubs, CSAF providers, and OCI referrers to pull
  upstream VEX advisories and apply them to matching stored SBOM packages with
  upstream provenance.
---

Upstream VEX subscriptions allow BOMHort to automatically subscribe to external
security advisory and VEX repositories, pull statements that affect packages
present in your stored SBOMs, and apply suppressions with full upstream
provenance.

## Overview

Software supply-chain governance requires tracking vulnerability exploitability
assessments published by upstream maintainers, OS vendors, and foundation
ecosystems. Upstream VEX subscriptions enable:

1. **Automated ingestion**: Periodic polling of OpenVEX hubs, CSAF 2.0
   providers, and OCI 1.1 artifact referrers.
2. **PURL matching**: Upstream advisories are filtered against distinct package
   URLs (PURLs) already discovered and stored in BOMHort.
3. **Scoping**: When an advisory matches a package PURL, it is scoped to the
   exact SBOM(s) that contain that package.
4. **Precedence**: Local review statements strictly outrank upstream
   statements. An internal triage decision always beats an upstream advisory.
5. **Clear provenance**: Upstream advisories carry `role = "upstream"`, the
   publisher name in `author`, and the source URL in `tooling`.

## Supported Source Types

BOMHort supports three upstream VEX source types:

<!-- vex-source-types:start -->
| Type | Protocol | Description |
|------|----------|-------------|
| `openvex-hub` | HTTP / Git | OpenVEX Hub repository using `.vex/` and `pkg/` PURL-based layouts or direct lookups |
| `csaf-provider` | HTTP | CSAF 2.0 VEX profile via `provider-metadata.json` or RFC 8322 ROLIE feeds |
| `oci-referrers` | OCI / HTTP | OCI 1.1 referrers API querying image SBOMs for associated VEX artifacts |
<!-- vex-source-types:end -->

### OpenVEX Hub (`openvex-hub`)

An OpenVEX Hub is an HTTP-accessible repository hosting OpenVEX documents.
BOMHort checks candidate paths under:
- `pkg/<type>/<namespace>/<name>/<version>.openvex.json`
- `.vex/<purl-encoded>.json`

If the source is a local directory or Git repository clone, the engine walks
the directory tree looking for `.openvex.json` and `.vex.json` files.

### CSAF 2.0 Provider (`csaf-provider`)

Common Security Advisory Framework (CSAF) 2.0 providers publish machine-readable
vulnerability advisories conforming to the CSAF VEX profile. BOMHort discovers
documents via:
- Provider metadata document (`.well-known/csaf/provider-metadata.json`)
- RFC 8322 ROLIE feeds listed in the provider metadata
- Direct document URL

BOMHort maps CSAF product trees (`full_product_names` and `branches`) to
package URLs, and translates product status and flags to OpenVEX standards:

<!-- csaf-status-mapping:start -->
| CSAF Status | OpenVEX Status |
|-------------|----------------|
| `known_not_affected` | `not_affected` |
| `known_affected` | `affected` |
| `fixed` | `fixed` |
| `under_investigation` | `under_investigation` |
<!-- csaf-status-mapping:end -->

CSAF status flags are mapped to standard OpenVEX justifications:

<!-- csaf-justification-mapping:start -->
| CSAF Flag | OpenVEX Justification |
|-----------|----------------------|
| `component_not_present` | `component_not_present` |
| `vulnerable_code_not_present` | `vulnerable_code_not_present` |
| `vulnerable_code_not_in_execute_path` | `vulnerable_code_not_in_execute_path` |
| `vulnerable_code_cannot_be_controlled_by_adversary` | `vulnerable_code_cannot_be_controlled_by_adversary` |
| `inline_mitigations_already_exist` | `inline_mitigations_already_exist` |
<!-- csaf-justification-mapping:end -->

### OCI Referrers (`oci-referrers`)

For container image SBOMs, BOMHort queries the OCI 1.1 distribution specification
referrers API (`/v2/<name>/referrers/<digest>`) filtering for artifacts with
artifact type `application/vnd.dev.openvex+json` or `application/vnd.csaf+json`.

## Precedence and Conflict Resolution

When multiple VEX statements apply to the same `(vuln_id, purl)` pair in an
SBOM, BOMHort resolves conflicts using strict precedence tiers:

1. **Scoped beats global**: A statement scoped to the specific SBOM
   (`sbom_id != ''`) always beats an unscoped global statement.
2. **Local beats upstream**: A locally authored or uploaded statement
   (`role != 'upstream'`) strictly outranks any upstream statement
   (`role == 'upstream'`), regardless of timestamp.
3. **Newest timestamp wins**: Within the same tier (e.g. two upstream
   statements from different providers), the statement with the newest
   `vex_timestamp` wins.

The ClickHouse suppression query evaluates precedence using an integer tier
formula:

```sql
argMax(status, if(role != 'upstream', 1, 0) * 10000000000 + toUnixTimestamp(vex_timestamp))
```

This guarantees that an internal security decision to mark a package `affected`
will never be overturned by an upstream vendor marking it `not_affected`.

## Provenance and User Interface

Upstream VEX statements preserve complete provenance in the `vex_statements`
table:
- `author`: The upstream vendor or publisher name (e.g. Red Hat, Chainguard, Wolfi).
- `role`: Set to `upstream`.
- `tooling`: The subscription URL or endpoint that provided the document.
- `status_notes`: Context or reasoning provided by the upstream advisory.

In the BOMHort user interface:
- Suppressed findings originating from an upstream advisory display an
  `upstream` badge in both the global vulnerability list and SBOM detail view.
- The VEX statements tab in the SBOM detail explorer displays the `upstream`
  badge and provider metadata.

## Configuration

### Environment Variables

Configure upstream VEX subscriptions via environment variables:

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `VEX_SOURCES` | string | `""` | JSON array or comma-separated `type=url` list of upstream sources |
| `VEX_REFRESH_INTERVAL` | duration | `1h` | Polling interval for background worker refresh loop (0 disables periodic ticker) |

Example comma-separated string:
```bash
VEX_SOURCES="openvex-hub=https://raw.githubusercontent.com/openvex/vex-hub/main,csaf-provider=https://redhat.com/.well-known/csaf/provider-metadata.json"
```

Example JSON format:
```json
[
  {
    "type": "openvex-hub",
    "url": "https://raw.githubusercontent.com/openvex/vex-hub/main"
  },
  {
    "type": "csaf-provider",
    "url": "https://redhat.com/.well-known/csaf/provider-metadata.json"
  }
]
```

### Helm Values

In Kubernetes deployments, configure upstream VEX via `values.yaml`:

```yaml
vexSources:
  - type: openvex-hub
    url: https://raw.githubusercontent.com/openvex/vex-hub/main
  - type: csaf-provider
    url: https://redhat.com/.well-known/csaf/provider-metadata.json

vexRefreshInterval: 1h
```

## Refresh Mechanisms

Upstream VEX subscriptions are updated through three coordinated mechanisms:

1. **Daily CVE Refresher**: Step 5 of the daily `cve-refresher` CronJob pulls
   fresh advisories across all configured sources.
2. **Background Worker Loop**: The elected `parsing-worker` sync owner replica
   runs a background periodic ticker according to `VEX_REFRESH_INTERVAL`
   (0 disables the periodic ticker). Replicas coordinate leadership via
   Kubernetes Lease so work does not multiply with worker replicas.
3. **On-Demand API**: Administrators and CI/CD pipelines can trigger an
   immediate synchronization by sending `POST /api/v1/vex/upstream/sync`
   (requires authentication with `AUTH_ENABLED=true`).
