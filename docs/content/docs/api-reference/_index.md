---
title: "API Reference"
linkTitle: "API Reference"
type: docs
weight: 3
description: >
  Complete REST API reference for the BOMHort API Gateway. Essential for headless deployments, CI/CD integrations, and custom tooling.
---

{{% alert title="Mostly Read-Only API" color="info" %}}
The BOMHort API is primarily **read-only** (GET endpoints). One write endpoint exists — [`POST /api/v1/sboms/upload`](#post-apiv1sbomsupload) for push-model CI/CD ingestion — and it is disabled unless `AUTH_ENABLED=true`, regardless of the global auth default.
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
  https://api.bomhort.example.com/api/v1/stats/dashboard

curl -H "X-Service-Token: <service-token>" \
  https://api.bomhort.example.com/api/v1/stats/dashboard
```

**API Keys** — multiple pre-shared keys for direct API consumers (CI/CD pipelines, scripts):

```bash
curl -H "X-API-Key: <api-key>" \
  https://api.bomhort.example.com/api/v1/stats/dashboard
```

### Public endpoints (always accessible)

Even when authentication is enabled, the following endpoints bypass auth so Kubernetes probes and CORS preflight work:

| Endpoint | Reason |
|----------|--------|
| `/healthz` | K8s health check (legacy, always 200) |
| `/livez` | Liveness probe (always 200 if process alive) |
| `/readyz` | Readiness probe (pings ClickHouse, 503 if unavailable) |
| `OPTIONS *` | CORS preflight |

### Responses

| Status | Condition |
|--------|-----------|
| `200 OK` | Auth disabled, or valid token/key presented |
| `401 Unauthorized` (with `WWW-Authenticate: Bearer realm="bomhort"`) | Auth enabled, no credential sent |
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

### `GET /livez`

Liveness probe. Returns `200 OK` as long as the API Gateway process is running. Used by Kubernetes to determine if the pod should be restarted.

**Response:** `200 OK`
```json
{"status": "ok"}
```

### `GET /readyz`

Readiness probe. Pings ClickHouse to verify database connectivity. Returns `503 Service Unavailable` if the database is unreachable. Kubernetes uses this to remove the pod from service endpoints until it recovers.

**Response (healthy):** `200 OK`
```json
{"status": "ok"}
```

**Response (unhealthy):** `503 Service Unavailable`
```json
{"error": "ClickHouse unavailable"}
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

### `POST /api/v1/sboms/upload`

Push an SBOM or VEX document directly instead of relying on a filesystem/S3 scan — designed for CI/CD pipelines. The upload is enqueued as a normal ingestion job; the parsing worker processes it exactly like any other job, so no ingestion logic is duplicated here.

**Storage backend:** the upload is routed to whichever push-storage backend is configured, resolved once at API Gateway startup:
- If one of the configured `S3_BUCKETS` entries has `"skipScan": true`, the upload is written there (`s3://<bucket>/<prefix>/pushed/<uuid>-<filename>`). That bucket is excluded from the ingestion watcher's periodic scan so the same object is never rediscovered and re-enqueued under a different dedup hash.
- Otherwise, it falls back to the local filesystem under `SBOM_DIR/pushed/` — this requires the API Gateway's `SBOM_DIR` mount to be writable (see the [Deployment Guide](/docs/deployment/) for the Helm `sbomSource.writable` flag).
- If neither is available, every request gets `503 Service Unavailable` rather than a confusing storage error.

{{% alert title="Requires authentication" color="warning" %}}
This endpoint refuses every request with `403 Forbidden` unless `AUTH_ENABLED=true` on the API Gateway — independent of whether the request would otherwise pass the global auth middleware. A write endpoint open by default is a materially different risk than a read-only API open by default, so this check is enforced by the handler itself.
{{% /alert %}}

**Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `X-Filename` | ✅ | Original filename. Must end in `.spdx.json`, `.cdx.json`, `.openvex.json`, `.vex.json`, or a generic `.json` (format auto-detected downstream, same as local scans). Only the base name is used — any directory components are stripped before the file is stored. |
| `X-Source-Repo` | — | Source repository URL for the product this SBOM describes (#332), e.g. `https://github.com/example-org/example-app`. Must be a plain `http(s)` URL without credentials — rejected with `400` otherwise. Overrides whatever the parser would extract from the document. Normalised before storage (`.git` suffix stripped, inline `@ref` split off). |
| `X-Source-Ref` | — | Commit SHA, tag or branch the SBOM was generated from. No whitespace, max 256 chars. An explicit value outranks a ref embedded in `X-Source-Repo`. |
| `Authorization` / `X-Service-Token` / `X-API-Key` | ✅ | Same credential options as the rest of the API — see [Authentication](#authentication). |

**Body:** Raw SBOM or VEX JSON content (not multipart form data). Max size is `MAX_UPLOAD_SIZE_MB` (Helm: `apiGateway.maxUploadSizeMB`, default 50 MB); larger bodies are rejected with `413`.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `cluster` | string | Overrides this instance's configured `CLUSTER_NAME` for the resulting ingestion job. |
| `namespace` | string | Overrides the configured `NAMESPACE` (#138). The deployment namespace the artifact belongs to, e.g. `payments`. |
| `project` | string | Overrides the configured `PROJECT` (#57), e.g. `payment-service`. |
| `sbom_id` | — | **VEX uploads only** (#350): scopes every statement in the document to this SBOM. Must be a valid SBOM UUID; rejected with `400` on SBOM uploads or malformed values. Without it, the worker resolves the statement's OpenVEX product `@id` against `sboms` (`source_repo`, `document_namespace`, `document_name`); if nothing matches the statement is stored **unscoped** and suppresses nothing. |

All three are optional and independent. A parameter that is absent **or blank** inherits the instance default — `?namespace=` and omitting it entirely mean the same thing, so a client cannot accidentally blank out a configured value. Values are trimmed.

Unlike the bucket/directory ingestion path, the server cannot infer these from an uploaded body, so a pushing CI job states them explicitly. They are stamped onto the ingestion job and copied onto every row the parsing worker writes (`sboms`, `sbom_packages`, `vulnerabilities`, `license_compliance`, `vex_statements`, `document_store`).

**Response (accepted):** `202 Accepted`
```json
{
  "status": "pending",
  "job_id": "d465b76c-5b91-48a1-b069-97069e9759a1",
  "sha256_hash": "3a7bd3e2360a3d4b1f8e...",
  "job_type": "sbom",
  "cluster": "production",
  "namespace": "payments",
  "project": "payment-service"
}
```

**Response (already ingested):** `200 OK`
```json
{
  "status": "duplicate",
  "sha256_hash": "3a7bd3e2360a3d4b1f8e...",
  "message": "Content already ingested, skipping"
}
```

**Errors:**
- `400` — Missing `X-Filename` header, unsupported file extension, empty body, malformed `X-Source-Repo`/`X-Source-Ref` header, or content that fails validation (SBOM uploads must be a single well-formed JSON object; VEX uploads must be a valid OpenVEX document — see below)
- `403` — `AUTH_ENABLED` is not `true` on this instance
- `413` — Body exceeds `MAX_UPLOAD_SIZE_MB`
- `500` — Storage (S3 or local) or ingestion-queue failure
- `503` — No push-storage backend is configured (no `skipScan` S3 bucket, and `SBOM_DIR` isn't writable)

{{% alert title="Content validation" color="info" %}}
VEX uploads are validated with the same OpenVEX parser the worker uses (a `@context` or at least one `statements` entry must be present) before anything is written to disk or enqueued. SBOM uploads must be a **single, well-formed JSON object** — bare scalars, `null`, top-level arrays, concatenated documents, and trailing data after the document are all rejected with `400`. Beyond that the shape is not constrained: format detection (`bomFormat`/`spdxVersion`/in-toto `predicateType`) and full parsing (package/component extraction) still happen in the parsing worker, so an unrecognized-but-well-formed object is accepted here and resolved downstream.
{{% /alert %}}

**Example:**
```bash
curl -X POST http://localhost:8080/api/v1/sboms/upload \
  -H "X-API-Key: <api-key>" \
  -H "X-Filename: my-service.spdx.json" \
  --data-binary @my-service.spdx.json
```

Tagging the upload with all three ownership dimensions:
```bash
curl -X POST "http://localhost:8080/api/v1/sboms/upload?cluster=prod-eu&namespace=payments&project=payment-service" \
  -H "X-API-Key: <api-key>" \
  -H "X-Filename: my-service.spdx.json" \
  --data-binary @my-service.spdx.json
```

Stating the source attribution from CI, where the pipeline knows the exact repo and commit (#332):
```bash
curl -X POST http://localhost:8080/api/v1/sboms/upload \
  -H "X-API-Key: <api-key>" \
  -H "X-Filename: my-service.spdx.json" \
  -H "X-Source-Repo: https://github.com/example-org/example-app" \
  -H "X-Source-Ref: ${GIT_COMMIT}" \
  --data-binary @my-service.spdx.json
```

---

### `GET /api/v1/sboms`

Paginated list of all ingested SBOMs.

**Document names:** `document_name` is the name stored at ingestion, also used by
the detail and other SBOM-related endpoints. Meaningful source names are preserved.
Empty or temporary names such as `tmp.ABC123xyz` fall back to a uniquely described
root package plus version (for example `example-org/widget v1.2.3`), then a source
label, finally `Unnamed SBOM`. See [the complete parser rules](/docs/development/parsers/#document-name-fallback).
Source bytes, hashes, SBOM IDs, and the original download are unchanged; the API
does not introduce a separate original-name field. Older rows retain their stored
names until re-processed. Project-scoped license exceptions match the exact resolved
`document_name`, including the version; old temporary names are not aliases.

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
      "ingested_at": "2026-05-20T14:30:00Z",
      "source_repo": "https://github.com/containerd/containerd",
      "source_ref": "v1.7.2",
      "cluster": "prod-eu",
      "namespace": "payments",
      "project": "payment-service"
    }
  ],
  "total": 142,
  "page": 1,
  "page_size": 50
}
```

`source_repo` / `source_ref` (#332) identify where the product's source lives — extracted from the document at ingest (SPDX root `downloadLocation` / vcs `ExternalRef`; CycloneDX `metadata.component.externalReferences[type=vcs]` and `pedigree.commits[0].uid`), overridable via the upload headers or `PATCH /api/v1/sboms/{id}`. Both are omitted from the JSON when unknown.

`cluster` / `namespace` / `project` (#177) are the three ownership dimensions the SBOM was tagged with at ingest (see [Ownership Data Model]({{< relref "/docs/architecture" >}}#ownership-data-model)). Each is omitted when unset, so single-instance deployments see the same payload as before. The same fields are returned by `GET /api/v1/clusters/{name}/sboms`.

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
  "source_repo": "https://github.com/containerd/containerd",
  "source_ref": "v1.7.2",
  "critical_vulns": 1,
  "high_vulns": 3,
  "medium_vulns": 6,
  "low_vulns": 2
}
```

**Errors:**
- `400` — Invalid UUID format


### `PATCH /api/v1/sboms/{id}`

Sets or clears `source_repo` / `source_ref` on an existing SBOM (#332) — the manual escape hatch for documents whose automatic extraction yielded nothing (Syft `dir:` scans, `pkg:generic` roots, monorepos). Requires `AUTH_ENABLED=true`, like the upload endpoint: an unauthenticated PATCH would let anyone redirect triage tooling to arbitrary repositories.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | UUID | SBOM identifier |

**Body:** JSON with one or both fields. This is a true PATCH — an **absent** field keeps its current value, an explicit `""` clears it:

```json
{
  "source_repo": "https://github.com/example-org/example-app",
  "source_ref": "v1.2.3"
}
```

`source_repo` must be a plain `http(s)` URL without credentials; `source_ref` a git ref without whitespace (max 256 chars). Values are normalised before storage exactly like extracted ones (`.git` suffix stripped, inline `@ref` split off), so the stored form is identical regardless of how it arrived.

**Response:** `200 OK` with the resulting attribution:
```json
{
  "sbom_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "source_repo": "https://github.com/example-org/example-app",
  "source_ref": "v1.2.3"
}
```

**Errors:**
- `400` — Invalid UUID, invalid JSON, empty body object, or a value that fails validation
- `403` — `AUTH_ENABLED` is not `true` on this instance
- `404` — No SBOM with this ID

**Example** — pin the repo for an SBOM whose extraction failed, keeping whatever ref is already stored:
```bash
curl -X PATCH http://localhost:8080/api/v1/sboms/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H "X-API-Key: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"source_repo": "https://github.com/example-org/example-app"}'
```

### `GET /api/v1/sboms/{id}/download`

Download the original SBOM JSON file. Streams the file from S3 or local filesystem depending on ingestion source.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | UUID | SBOM identifier |

**Response:** `200 OK` — Binary stream with `Content-Disposition: attachment`

| Header | Value |
|--------|-------|
| `Content-Type` | `application/json` |
| `Content-Disposition` | `attachment; filename="<original-filename>"` |

**Errors:**
- `400` — Invalid UUID format
- `404` — SBOM not found or source file no longer available in storage
- `503` — S3 not configured (source is S3 but API Gateway has no S3 credentials)

**Example:**
```bash
curl -O -J \
  http://localhost:8080/api/v1/sboms/a1b2c3d4-e5f6-7890-abcd-ef1234567890/download
```

### `GET /api/v1/sboms/{id}/vulnerabilities`

All vulnerabilities found in a specific SBOM, including the effective VEX statement.

**Row semantics (#335):** exactly **one row per `(vuln_id, purl)`**. When several VEX statements have been ingested for the pair (e.g. an automated `under_investigation` draft followed by a human `not_affected`), the statement with the newest `vex_timestamp` wins — the same OpenVEX conflict rule BOMHort applies for dashboard scoring. Clients never need to dedupe or re-implement OpenVEX semantics.

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
    "vex_status": "not_affected",
    "vex_justification": "vulnerable_code_not_present",
    "vex_timestamp": "2026-09-01T12:00:00Z",
    "vex_statement_id": "b3f1c2d4-5678-90ab-cdef-1234567890ab",
    "vex_author": "Example Org Security Team",
    "vex_tooling": "VEXViper/0.1.0"
  }
]
```

`vex_justification`, `vex_timestamp`, `vex_statement_id`, `vex_author` and `vex_tooling` describe the **winning** statement and are omitted (like `vex_status`) when no VEX statement covers the pair. `vex_author`/`vex_tooling` carry the provenance captured by migration `017` (#334) and are empty for statements ingested before it. `vex_timestamp` enables re-triage policies such as "re-open `under_investigation` older than 30 days" without paging through `/api/v1/vex/statements`.


### `GET /api/v1/sboms/{id}/vex`

VEX statements affecting one SBOM (#350): every statement **scoped to it**, newest first. Unscoped statements (`sbom_id = ''`, product unresolvable at ingest) are not returned — they apply to no SBOM.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | UUID | SBOM identifier |

**Response:** `200 OK` — array of `VEXStatementItem` (same shape as `/api/v1/vex/statements`, including provenance from #334). Every row carries this SBOM's `sbom_id`.

**Why scoping matters:** a VEX statement asserts a vulnerability status **for a product**. `vulnerable_code_not_in_execute_path` is a reachability claim about one product — another project with the identical library version may be exploitable. A statement therefore only suppresses findings in its own SBOM; a statement whose product could not be resolved suppresses nothing at all — there is no global/fleet-wide VEX scope.


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

### `GET /api/v1/projects`

Paginated list of projects grouped by source path or document name. Each project aggregates its SBOMs (versions), total packages, and vulnerability counts.

**Query parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `page_size` | integer | 50 | Items per page (max 500) |
| `search` | string | — | Filter projects by name (ILIKE) |

**Response:** `200 OK`
```json
{
  "data": [
    {
      "project_name": "cncf-project-sboms/containerd",
      "sbom_count": 12,
      "package_count": 1847,
      "vuln_count": 23,
      "latest_ingested": "2026-05-28T14:30:00Z",
      "latest_sbom_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    }
  ],
  "total": 142,
  "page": 1,
  "page_size": 50
}
```

---

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

Configured license exception document (read-only, loaded from config file).
Includes pending/revoked rules for inspection; only `approved` rules affect checks.
By default both arrays are empty. No CNCF approvals are automatically loaded.

**Response:** `200 OK`
```json
{
  "version": "1.0.0",
  "lastUpdated": "",
  "blanketExceptions": [],
  "exceptions": [
    {
      "id": "example-review-required",
      "package": "example.org/team/library",
      "license": "MPL-2.0",
      "project": "my-sbom-document-name",
      "status": "pending",
      "approvedDate": "",
      "comment": "Example only; requires organization approval"
    }
  ]
}
```

Field names are **camelCase**, and `package` is a package name, not a PURL prefix
or glob. A package rule retains its package restriction even when `project` is
empty or `"*"`. Otherwise `project` matches the exact SBOM document name.

**Configuration errors:** `500 Internal Server Error` for malformed or unreadable
exception files (also on `GET /api/v1/projects/license-compliance`). Missing optional
files return an empty document. An existing empty primary file takes precedence
over any fallback file. Configuration changes require re-processing existing SBOMs
for stored compliance results to become consistent across endpoints.

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
      "sbom_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "author": "Example Org Security Team",
      "role": "automated vulnerability triage",
      "tooling": "VEXViper/0.1.0",
      "status_notes": "confidence=0.94; vulnerable symbol not reachable",
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

`sbom_id` (#350) marks the SBOM the statement is scoped to; it is omitted for **unscoped** statements, whose product could not be resolved at ingest — those suppress findings in no SBOM. `author`, `role`, `tooling` and `status_notes` (#334) carry the statement's provenance, taken from the OpenVEX document (`author`/`role`/`tooling`) and statement (`status_notes`) at ingest. All four are omitted when the source document does not set them — including every statement ingested before migration `017`. Automated producers (VEXViper, #338) set `tooling` and write confidence + reasoning into `status_notes`; a `role`/`tooling`-based automated-vs-human badge and a `?vex_source=` filter follow in Phase 3.

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

---

## Global Search

### `GET /api/v1/search`

Faceted search across packages, projects, vulnerabilities, and licenses in a single request. Powers the navbar typeahead and the `/search` results page in the UI.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `q` | string | ✅ | Search query, minimum 2 characters (case-insensitive substring match) |
| `limit` | uint64 | — | Max results per facet (default 5, max 50) |

Vulnerabilities match on both the vulnerability ID and the summary text. Projects match on the derived project key (`org/repo` for S3 sources, document name otherwise).

**Response:** `200 OK`
```json
{
  "query": "grpc",
  "packages": [
    {
      "package_name": "google.golang.org/grpc",
      "purl": "pkg:golang/google.golang.org/grpc@v1.60.0",
      "project_count": 87
    }
  ],
  "total_packages": 3,
  "projects": [
    {
      "project_name": "grpc/grpc-go",
      "sbom_count": 4,
      "latest_sbom_id": "a1b2c3d4-..."
    }
  ],
  "total_projects": 1,
  "vulnerabilities": [
    {
      "vuln_id": "CVE-2024-9999",
      "severity": "HIGH",
      "summary": "gRPC denial of service",
      "affected_sboms": 7
    }
  ],
  "total_vulnerabilities": 1,
  "licenses": [
    {
      "license_id": "Apache-2.0",
      "category": "permissive",
      "sbom_count": 100
    }
  ],
  "total_licenses": 1
}
```

Facet arrays are always present (empty when no matches). Each facet returns at most `limit` items; the `total_*` fields report the full match counts.

**Errors:**
- `400` — Query parameter `q` missing or shorter than 2 characters

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

## Clusters

### `GET /api/v1/clusters`

List all known clusters with summary statistics. Returns an array of clusters sorted by SBOM count (descending).

**Response:** `200 OK`
```json
[
  {
    "name": "production",
    "sbom_count": 85,
    "package_count": 12400,
    "vuln_count": 423,
    "last_ingested": "2026-06-01T14:30:00Z"
  },
  {
    "name": "staging",
    "sbom_count": 42,
    "package_count": 6100,
    "vuln_count": 198,
    "last_ingested": "2026-06-01T12:00:00Z"
  }
]
```

{{% alert title="Note" color="info" %}}
Clusters with `name: ""` represent SBOMs ingested before multi-cluster support was enabled (migration 012). They appear as an empty string in the listing.
{{% /alert %}}

### `GET /api/v1/clusters/{name}/stats`

Per-cluster dashboard statistics including severity breakdown and license distribution.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Cluster name (max 200 chars) |

**Response:** `200 OK`
```json
{
  "cluster": "production",
  "total_sboms": 85,
  "total_packages": 12400,
  "total_vulnerabilities": 423,
  "critical_vulns": 12,
  "high_vulns": 89,
  "medium_vulns": 210,
  "low_vulns": 112,
  "license_breakdown": {
    "permissive": 9800,
    "copyleft": 340,
    "unknown": 2260
  },
  "last_ingested": "2026-06-01T14:30:00Z"
}
```

**Error Responses:**
- `400 Bad Request` — cluster name empty or exceeds 200 characters
- `404 Not Found` — no SBOMs exist for this cluster

### `GET /api/v1/clusters/{name}/sboms`

Paginated list of SBOMs for a specific cluster.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Cluster name (max 200 chars) |

**Query Parameters:** Standard pagination (`page`, `page_size`)

**Response:** `200 OK` — Standard `PaginatedResponse[SBOMListItem]`
```json
{
  "data": [
    {
      "sbom_id": "550e8400-e29b-41d4-a716-446655440000",
      "source_file": "s3://cncf-project-sboms/containerd/v1.7.spdx.json",
      "spdx_version": "SPDX-2.3",
      "document_name": "containerd-v1.7",
      "package_count": 245,
      "vuln_count": 12,
      "ingested_at": "2026-06-01T14:30:00Z"
    }
  ],
  "total": 85,
  "page": 1,
  "page_size": 50
}
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
- Allowed methods: `GET`, `OPTIONS` on every endpoint; `POST` is additionally advertised only on [`/api/v1/sboms/upload`](#post-apiv1sbomsupload)
- Allowed headers: `Content-Type`, `Authorization`, `X-Service-Token`, `X-API-Key`, `X-Filename`

---

## Headless Mode

When deployed with `ui.enabled: false` in Helm values, BOMHort runs as a pure API service:

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

# Get vulnerabilities (all findings, each with its VEX status attached)
curl -s "http://localhost:8080/api/v1/vulnerabilities?page_size=100" | jq .

# Check which projects are affected by a CVE
curl -s http://localhost:8080/api/v1/vulnerabilities/CVE-2024-45338/affected-projects | jq .

# Search packages
curl -s "http://localhost:8080/api/v1/packages/search?q=crypto" | jq .
```

### CI/CD Integration (GitHub Actions)

```yaml
- name: Check for critical vulnerabilities
  run: |
    CRITICAL=$(curl -sf "$BOMHORT_URL/api/v1/stats/dashboard" | jq '.critical_vulns')
    if [ "$CRITICAL" -gt 0 ]; then
      echo "::error::$CRITICAL critical vulnerabilities detected"
      exit 1
    fi
```

