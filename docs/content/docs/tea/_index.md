---
title: "Transparency Exchange API (TEA)"
linkTitle: "TEA Server"
type: docs
weight: 15
description: >
  Read-only Transparency Exchange API (TEA, ECMA TC54 / CycloneDX, Beta 2) server over projects, releases and stored supply chain documents.
---

BOMHort implements a native, read-only **Transparency Exchange API (TEA)** server surface directly on the API Gateway. TEA is the emerging open standard (developed by OWASP CycloneDX and standardised through Ecma International TC54-TG1) for automated discovery, consumption, and exchange of software supply chain transparency artefacts, including Software Bills of Materials (SBOMs), Vulnerability Exploitability eXchange (VEX) documents, and build attestations.

{{% alert title="Specification Version Pinned" color="info" %}}
This implementation strictly implements **TEA Beta 2 (Spec version 1.0.0)**. Any future protocol changes (e.g. Beta 3 or 1.1) will be tracked as distinct issues to maintain interface stability.
{{% /alert %}}

## Concept Mapping

BOMHort's data model maps directly onto the TEA entities:

| TEA Entity | BOMHort Concept | Description |
|---|---|---|
| **Product** | Project (`s.project` + `parent`) | Group of releases under a project boundary. Identified deterministically by UUID. |
| **Component** | Described Package (`root_purl`) | Top-level software component described by the SBOM. |
| **Product Release** | SBOM Version (`document_version`) | A specific release version of the product, identified by the SBOM UUID. |
| **Collection** | Document Set | Consolidated set of artefacts: original SBOM, consolidated OpenVEX, and attestation. |
| **Artifact** | Stored Document / Document Store Ref | Raw, byte-identical document served from `internal/docstore`. |

## Discovery & TEI Resolution

Consumers discover TEA endpoints by resolving the Transparency Exchange Identifier (TEI) domain via DNS and fetching the discovery document at `/.well-known/tea`.

### 1. Discovery Document (`/.well-known/tea`)

Publicly accessible even when `AUTH_ENABLED=true`:

```bash
curl https://bomhort.example.com/.well-known/tea
```

Response:

```json
{
  "schemaVersion": 1,
  "endpoints": [
    {
      "url": "https://bomhort.example.com/api/v1/tea",
      "versions": ["1.0.0"],
      "priority": 1.0
    }
  ]
}
```

### 2. Identifier Resolution (`/api/v1/tea/discovery`)

Resolves a canonical PURL or TEI into matching product releases:

```bash
# By canonical PURL:
curl "https://bomhort.example.com/api/v1/tea/discovery?purl=pkg:golang/github.com/seebom-labs/bomhort@v0.8.0"

# By TEI (tei:// or urn:tei:):
curl "https://bomhort.example.com/api/v1/tea/discovery?tei=urn:tei:purl:cGtnOm1hdmVuL2NvbW1vbnMtaW8vY29tbW9ucy1pb0AyLjIyLjA"
```

Response:

```json
[
  {
    "productReleaseUuid": "22222222-3333-4444-5555-666666666666",
    "servers": [
      {
        "rootUrl": "https://bomhort.example.com/api/v1/tea",
        "versions": ["1.0.0"],
        "priority": 1.0
      }
    ]
  }
]
```

## Endpoints

All TEA endpoints are mounted under `/api/v1/tea/` (and alias `/tea/`). When `AUTH_ENABLED=true`, authentication is required via `Authorization: Bearer <token>` or `X-API-Key: <key>`.

### Products & Components

- `GET /api/v1/tea/products` -- List products (paginated).
- `GET /api/v1/tea/product/{uuid}` -- Retrieve product details.
- `GET /api/v1/tea/product/{uuid}/releases` -- List releases belonging to a product.
- `GET /api/v1/tea/components` -- List components (paginated).
- `GET /api/v1/tea/component/{uuid}` -- Retrieve component details.
- `GET /api/v1/tea/component/{uuid}/releases` -- List releases of a component.

### Releases & Collections

- `GET /api/v1/tea/productReleases` -- List all product releases.
- `GET /api/v1/tea/productRelease/{uuid}` -- Retrieve product release details.
- `GET /api/v1/tea/productRelease/{uuid}/collections` -- List collections for a release.
- `GET /api/v1/tea/productRelease/{uuid}/collection/latest` -- Retrieve latest collection with artifacts.

Example collection response:

```json
{
  "uuid": "22222222-3333-4444-5555-666666666666",
  "version": 1,
  "createdDate": "2026-11-10T12:00:00Z",
  "belongsTo": "PRODUCT_RELEASE",
  "updateReason": {
    "type": "INITIAL_RELEASE"
  },
  "artifacts": [
    {
      "uuid": "22222222-3333-4444-5555-666666666666",
      "version": 1,
      "name": "payment-api.spdx.json",
      "type": "BOM",
      "createdDate": "2026-11-10T12:00:00Z",
      "formats": [
        {
          "mediaType": "application/spdx+json",
          "description": "Original SBOM",
          "checksums": [
            {
              "algType": "SHA-256",
              "algValue": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
          ]
        }
      ]
    }
  ]
}
```

### Artifact Downloads & Integrity

- `GET /api/v1/tea/artifact/{uuid}/latest` -- Retrieve artifact metadata.
- `GET /api/v1/tea/artifact/{uuid}/latest/download` -- Download artifact content.
- `GET /api/v1/tea/artifact/{uuid}/{version}/download` -- Download specific artifact revision.

{{% alert title="Exact Producer Byte Fidelity" color="success" %}}
Artefacts are served directly from BOMHort's original document store (`internal/docstore`) by reference and are **never re-serialised**. The SHA-256 hash of the downloaded stream is guaranteed to match the producer's original digest advertised in the artifact checksums.
{{% /alert %}}

Responses support:
- `ETag` and conditional validation (`If-None-Match` returns `304 Not Modified`).
- `Repr-Digest` (`RFC 9530`).
- Immutable caching headers on versioned revisions (`Cache-Control: public, max-age=31536000, immutable`).

## Configuration

| Environment Variable | Helm Value | Default | Description |
|---|---|---|---|
| `TEA_BASE_URL` | `apiGateway.teaBaseUrl` | `""` (auto-detected) | Explicit base URL advertised in discovery documents (e.g. `https://transparency.example.com/api/v1/tea`). |

