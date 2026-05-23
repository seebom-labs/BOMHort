---
title: "API Reference"
linkTitle: "API Reference"
type: docs
weight: 3
description: >
  Complete REST API reference for the SeeBOM API Gateway. Essential for headless deployments, CI/CD integrations, and custom tooling.
---

{{% alert title="Read-Only API" color="info" %}}
The SeeBOM API is currently **read-only** (GET endpoints only). Write endpoints (SBOM upload) are planned for Phase 2 — see [Roadmap](/docs/roadmap/).
{{% /alert %}}

## Base URL

```
http://<api-gateway-host>:8080/api/v1
```

In headless mode (Helm: `ui.enabled: false`), only the API Gateway is deployed. All endpoints remain the same.

## Authentication

Authentication is **fully optional** and disabled by default. Enable it via the `AUTH_ENABLED=true` environment variable on the API Gateway. See the [Deployment Guide](/docs/deployment/#6-api-authentication-optional) for full setup instructions.

### Two modes (combinable)

**Service Token** — single shared secret, typically used by upstream proxies (oauth2-proxy, Kong, custom auth gateways):

```bash
# Either header works:
curl -H "Authorization: Bearer <service-token>" \
  https://api.seebom.example.com/api/v1/stats/dashboard

curl -H "X-Service-Token: <service-token>" \
  https://api.seebom.example.com/api/v1/stats/dashboard
```

**API Keys** — multiple pre-shared keys for direct API consumers (CI/CD pipelines, scripts):

```bash
curl -H "X-API-Key: <api-key>" \
  https://api.seebom.example.com/api/v1/stats/dashboard
```

### Public endpoints (always accessible)

Even when authentication is enabled, the following endpoints bypass auth so Kubernetes probes and CORS preflight work:

| Endpoint | Reason |
|----------|--------|
| `/healthz` | K8s liveness/readiness probe |
| `/livez` | Reserved for liveness probe (#137) |
| `/readyz` | Reserved for readiness probe (#137) |
| `OPTIONS *` | CORS preflight |

### Responses

| Status | Condition |
|--------|-----------|
| `200 OK` | Auth disabled, or valid token/key presented |
| `401 Unauthorized` (with `WWW-Authenticate: Bearer realm="seebom"`) | Auth enabled, no credential sent |
| `401 Unauthorized` | Auth enabled, invalid token/key |

{{% alert title="Security" color="info" %}}
All credential comparisons are constant-time (`crypto/subtle.ConstantTimeCompare`) to prevent timing attacks. Failed auth attempts are logged with sanitized client IPs.
{{% /alert %}}

## Common Patterns

### Pagination

Paginated endpoints accept:

| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `page` | uint64 | 1 | — | Page number (1-based) |
| `page_size` | uint64 | 50 | 500 | Items per page |

Paginated responses return:

```json
{
  "data": [...],
  "total": 1234,
  "page": 1,
  "page_size": 50
}
```

### Error Responses

All errors return:

```json
{
  "error": "Human-readable error message"
}
```

| HTTP Status | Meaning |
|-------------|---------|
| 400 | Bad Request — invalid parameters (malformed UUID, missing required query param) |
| 429 | Too Many Requests — rate limit exceeded (100 req/10s per IP) |
| 500 | Internal Server Error — database or processing failure |

### Rate Limiting

- **100 requests per 10 seconds** per source IP
- Returns `429 Too Many Requests` when exceeded
- No `Retry-After` header (client should implement exponential backoff)

---

## Health

### `GET /healthz`

Health check endpoint for Kubernetes probes.

**Response:** `200 OK`
```json
{"status": "ok"}
```

---

## Dashboard & Statistics

### `GET /api/v1/stats/dashboard`

Aggregated platform statistics for the dashboard view.

**Response:** `200 OK`
```json
{
  "total_sboms": 142,
  "total_packages": 18743,
  "total_vulnerabilities": 892,
  "effective_vulnerabilities": 756,
  "suppressed_by_vex": 136,
  "critical_vulns": 23,
  "high_vulns": 187,
  "medium_vulns": 412,
  "low_vulns": 270,
  "license_breakdown": {
    "Apache-2.0": 8421,
    "MIT": 6234,
    "BSD-3-Clause": 2100
  },
  "exempted_packages": 14,
  "total_vex_statements": 42,
  "last_cve_refresh": "2026-05-20T03:00:00Z",
  "new_vulns_since_refresh": 3,
  "archived_repos_count": 7
}
```

### `GET /api/v1/stats/dependencies`

Top-N most used dependencies across all projects.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | uint64 | 50 | Number of top dependencies to return (max 500) |

**Response:** `200 OK`
```json
{
  "total_unique_deps": 4521,
  "top_dependencies": [
    {
      "package_name": "golang.org/x/net",
      "purl": "pkg:golang/golang.org/x/net",
      "project_count": 87,
      "versions": ["v0.23.0", "v0.24.0", "v0.25.0"],
      "vuln_count": 2
    }
  ]
}
```

### `GET /api/v1/stats/version-skew`

Packages with inconsistent versions across different projects (version skew detection).

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | uint64 | 1 | Page number |
| `page_size` | uint64 | 50 | Items per page (max 500) |
| `search` | string | — | Filter by package name (case-insensitive substring match) |

**Response:** `200 OK`
```json
{
  "total_skewed_packages": 234,
  "items": [
    {
      "package_name": "golang.org/x/crypto",
      "purl": "pkg:golang/golang.org/x/crypto",
      "version_count": 4,
      "project_count": 12,
      "is_direct_in_count": 8,
      "versions": [
        {
          "version": "v0.23.0",
          "project_count": 5,
          "projects": ["prometheus", "grafana", "etcd"]
        },
        {
          "version": "v0.21.0",
          "project_count": 3,
          "projects": ["containerd", "runc"]
        }
      ]
    }
  ],
  "page": 1,
  "page_size": 50
}
```

---

## SBOMs

### `GET /api/v1/sboms`

Paginated list of all ingested SBOMs.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | uint64 | 1 | Page number |
| `page_size` | uint64 | 50 | Items per page (max 500) |
| `search` | string | — | Filter by document name or source file (case-insensitive) |

**Response:** `200 OK`
```json
{
  "data": [
    {
      "sbom_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "source_file": "containerd-v1.7.2.spdx.json",
      "spdx_version": "SPDX-2.3",
      "document_name": "containerd-v1.7.2",
      "package_count": 245,
      "vuln_count": 12,
      "ingested_at": "2026-05-20T14:30:00Z"
    }
  ],
  "total": 142,
  "page": 1,
  "page_size": 50
}
```

### `GET /api/v1/sboms/{id}/detail`

Detailed SBOM information including vulnerability severity breakdown.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | UUID | SBOM identifier |

**Response:** `200 OK`
```json
{
  "sbom_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "source_file": "containerd-v1.7.2.spdx.json",
  "spdx_version": "SPDX-2.3",
  "document_name": "containerd-v1.7.2",
  "package_count": 245,
  "vuln_count": 12,
  "ingested_at": "2026-05-20T14:30:00Z",
  "critical_vulns": 1,
  "high_vulns": 3,
  "medium_vulns": 6,
  "low_vulns": 2
}
```

**Errors:**
- `400` — Invalid UUID format

### `GET /api/v1/sboms/{id}/vulnerabilities`

All vulnerabilities found in a specific SBOM, including VEX status.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | UUID | SBOM identifier |

**Response:** `200 OK`
```json
[
  {
    "vuln_id": "GHSA-xyz-abc-123",
    "severity": "HIGH",
    "purl": "pkg:golang/golang.org/x/net@v0.17.0",
    "summary": "HTTP/2 rapid reset vulnerability",
    "fixed_version": "v0.23.0",
    "source_file": "containerd-v1.7.2.spdx.json",
    "discovered_at": "2026-05-18T09:00:00Z",
    "vex_status": "not_affected"
  }
]
```

### `GET /api/v1/sboms/{id}/licenses`

License breakdown for a specific SBOM, grouped by license ID with package lists.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | UUID | SBOM identifier |

**Response:** `200 OK`
```json
[
  {
    "license_id": "Apache-2.0",
    "category": "permissive",
    "package_count": 120,
    "packages": ["github.com/containerd/containerd", "..."],
    "exempted_packages": [],
    "exemption_reason": ""
  },
  {
    "license_id": "GPL-2.0-only",
    "category": "copyleft",
    "package_count": 2,
    "packages": ["github.com/some/gpl-lib"],
    "exempted_packages": ["github.com/some/gpl-lib"],
    "exemption_reason": "System library, not linked"
  }
]
```

### `GET /api/v1/sboms/{id}/dependencies`

Dependency tree reconstructed as a flat array with parent→child index references.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | UUID | SBOM identifier |

**Response:** `200 OK`
```json
[
  {
    "index": 0,
    "spdx_id": "SPDXRef-Package-containerd",
    "name": "containerd",
    "version": "1.7.2",
    "purl": "pkg:golang/github.com/containerd/containerd@v1.7.2",
    "license": "Apache-2.0",
    "children": [1, 2, 3]
  },
  {
    "index": 1,
    "spdx_id": "SPDXRef-Package-runc",
    "name": "runc",
    "version": "1.1.12",
    "purl": "pkg:golang/github.com/opencontainers/runc@v1.1.12",
    "license": "Apache-2.0",
    "children": [4, 5]
  }
]
```

The UI reconstructs the tree by following `children` indices. Root nodes are those not referenced as children by any other node.

---

## Vulnerabilities

### `GET /api/v1/vulnerabilities`

Paginated list of all discovered vulnerabilities across all SBOMs.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | uint64 | 1 | Page number |
| `page_size` | uint64 | 50 | Items per page (max 500) |
| `vex_filter` | string | — | Filter mode: `effective` = exclude VEX-suppressed vulns |

**Response:** `200 OK` — `PaginatedResponse<VulnerabilityListItem>`

```json
{
  "data": [
    {
      "vuln_id": "CVE-2024-45338",
      "severity": "CRITICAL",
      "purl": "pkg:golang/golang.org/x/net@v0.21.0",
      "summary": "Denial of service in net/http",
      "fixed_version": "v0.23.0",
      "source_file": "etcd-v3.5.12.spdx.json",
      "discovered_at": "2026-05-15T00:00:00Z",
      "vex_status": ""
    }
  ],
  "total": 892,
  "page": 1,
  "page_size": 50
}
```

### `GET /api/v1/vulnerabilities/{id}/affected-projects`

All projects affected by a specific CVE, including transitive dependency information.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Vulnerability ID (CVE, GHSA, GO-*, PYSEC-*, etc.) |

**Response:** `200 OK`
```json
[
  {
    "sbom_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "source_file": "etcd-v3.5.12.spdx.json",
    "document_name": "etcd-v3.5.12",
    "purl": "pkg:golang/golang.org/x/net@v0.21.0",
    "package_name": "golang.org/x/net",
    "version": "v0.21.0",
    "severity": "CRITICAL",
    "vex_status": "",
    "is_direct": false
  }
]
```

**Errors:**
- `400` — Invalid vulnerability ID format

---

## Licenses

### `GET /api/v1/licenses/compliance`

Aggregated license compliance overview across all projects, with exemption details.

**Response:** `200 OK`
```json
[
  {
    "license_id": "GPL-3.0-only",
    "category": "copyleft",
    "package_count": 5,
    "sbom_count": 3,
    "non_compliant_packages": ["github.com/some/gpl3-lib"],
    "exempted_packages": ["github.com/some/gpl3-lib"],
    "exemption_reason": "Build tool only, not distributed",
    "affected_sboms": [
      {
        "sbom_id": "a1b2c3d4-...",
        "document_name": "my-project-v1.0"
      }
    ]
  }
]
```

### `GET /api/v1/projects/license-compliance`

Projects with copyleft or unknown license packages (filtered by active exceptions).

**Response:** `200 OK`
```json
[
  {
    "sbom_id": "a1b2c3d4-...",
    "source_file": "my-project.spdx.json",
    "document_name": "my-project-v2.1",
    "copyleft_count": 3,
    "unknown_count": 1,
    "violating_licenses": ["LGPL-2.1-only", "UNKNOWN"],
    "non_compliant_packages": ["github.com/some/lgpl-lib", "github.com/unknown/pkg"]
  }
]
```

### `GET /api/v1/license-exceptions`

Active license exceptions (read-only, loaded from config file).

**Response:** `200 OK`
```json
{
  "version": "1.0.0",
  "blanket_exceptions": [
    {
      "license": "ISC",
      "reason": "ISC is functionally equivalent to MIT"
    }
  ],
  "exceptions": [
    {
      "purl_prefix": "pkg:golang/github.com/some/gpl-lib",
      "license": "GPL-2.0-only",
      "reason": "Build tool only, not distributed with binary"
    }
  ]
}
```

### `GET /api/v1/license-policy`

Active license classification policy (permissive vs. copyleft lists).

**Response:** `200 OK`
```json
{
  "permissive": [
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense", "0BSD"
  ],
  "copyleft": [
    "GPL-2.0-only", "GPL-3.0-only", "LGPL-2.1-only", "AGPL-3.0-only", "MPL-2.0"
  ]
}
```

---

## VEX (Vulnerability Exploitability eXchange)

### `GET /api/v1/vex/statements`

Paginated list of all ingested VEX statements with affected SBOM cross-references.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | uint64 | 1 | Page number |
| `page_size` | uint64 | 50 | Items per page (max 500) |

**Response:** `200 OK` — `PaginatedResponse<VEXStatementItem>`

```json
{
  "data": [
    {
      "vex_id": "https://example.com/vex/2024-001",
      "document_id": "https://openvex.dev/docs/example/v1",
      "source_file": "golang-common.openvex.json",
      "product_purl": "pkg:golang/golang.org/x/net",
      "vuln_id": "CVE-2024-45338",
      "status": "not_affected",
      "justification": "vulnerable_code_not_present",
      "impact_statement": "The vulnerable HTTP/2 code path is not used",
      "action_statement": "",
      "vex_timestamp": "2024-12-01T00:00:00Z",
      "ingested_at": "2026-05-20T14:30:00Z",
      "affected_sboms": [
        {
          "sbom_id": "a1b2c3d4-...",
          "document_name": "etcd-v3.5.12"
        }
      ]
    }
  ],
  "total": 42,
  "page": 1,
  "page_size": 50
}
```

---

## Packages

### `GET /api/v1/packages/search`

Search packages by name across all ingested SBOMs.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `q` | string | ✅ | Search query (case-insensitive substring match) |
| `page` | uint64 | — | Page number (default 1) |
| `page_size` | uint64 | — | Items per page (default 50, max 500) |

**Response:** `200 OK`
```json
{
  "total_results": 15,
  "items": [
    {
      "package_name": "golang.org/x/crypto",
      "purl": "pkg:golang/golang.org/x/crypto",
      "project_count": 87,
      "versions": ["v0.21.0", "v0.22.0", "v0.23.0"],
      "projects": [
        {
          "project_name": "etcd-v3.5.12",
          "version": "v0.21.0",
          "sbom_id": "a1b2c3d4-..."
        }
      ]
    }
  ],
  "page": 1,
  "page_size": 50,
  "query": "crypto"
}
```

**Errors:**
- `400` — Missing required query parameter `q`

### `GET /api/v1/packages/detail`

Detailed information about a specific package, listing all projects that use it.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | ✅ | Exact package name |
| `page` | uint64 | — | Page number (default 1) |
| `page_size` | uint64 | — | Items per page (default 50, max 500) |

**Response:** `200 OK`
```json
{
  "package_name": "golang.org/x/crypto",
  "total_projects": 87,
  "projects": [
    {
      "project_name": "etcd-v3.5.12",
      "version": "v0.21.0",
      "sbom_id": "a1b2c3d4-..."
    }
  ],
  "page": 1,
  "page_size": 50
}
```

**Errors:**
- `400` — Missing required query parameter `name`

### `GET /api/v1/packages/archived`

Packages from archived/unmaintained GitHub repositories (supply chain risk indicator).

**Response:** `200 OK`
```json
[
  {
    "package_name": "github.com/abandoned/lib",
    "purl": "pkg:golang/github.com/abandoned/lib",
    "archived_since": "2023-06-15",
    "project_count": 4,
    "projects": ["etcd-v3.5.12", "containerd-v1.7.2"]
  }
]
```

---

## Security Headers

All responses include:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |

## CORS

Configured via `CORS_ALLOWED_ORIGINS` environment variable.

- Default: `*` (development)
- Production: Set to your frontend domain(s)
- Allowed methods: `GET`, `OPTIONS`
- Allowed headers: `Content-Type`, `Authorization`

---

## Headless Mode

When deployed with `ui.enabled: false` in Helm values, SeeBOM runs as a pure API service:

- All endpoints above remain available
- No UI container is deployed
- No Nginx, no static file serving
- Ideal for CI/CD integrations, custom dashboards, or aggregation by external tools

```yaml
# values-headless.yaml
ui:
  enabled: false

apiGateway:
  ingress:
    enabled: true
    hosts:
      - sbom-api.internal.example.com
```

---

## Usage Examples

### curl

```bash
# Get dashboard overview
curl -s http://localhost:8080/api/v1/stats/dashboard | jq .

# Search SBOMs
curl -s "http://localhost:8080/api/v1/sboms?search=containerd&page_size=10" | jq .

# Get vulnerabilities (effective only, VEX-filtered)
curl -s "http://localhost:8080/api/v1/vulnerabilities?vex_filter=effective&page_size=100" | jq .

# Check which projects are affected by a CVE
curl -s http://localhost:8080/api/v1/vulnerabilities/CVE-2024-45338/affected-projects | jq .

# Search packages
curl -s "http://localhost:8080/api/v1/packages/search?q=crypto" | jq .
```

### CI/CD Integration (GitHub Actions)

```yaml
- name: Check for critical vulnerabilities
  run: |
    CRITICAL=$(curl -sf "$SEEBOM_URL/api/v1/stats/dashboard" | jq '.critical_vulns')
    if [ "$CRITICAL" -gt 0 ]; then
      echo "::error::$CRITICAL critical vulnerabilities detected"
      exit 1
    fi
```

