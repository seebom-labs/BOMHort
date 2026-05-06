---
title: "SBOM Parsers"
linkTitle: "Parsers"
type: docs
weight: 3
description: >
  Multi-format SBOM parsing: supported formats, parser backends, configuration, and trade-offs.
---

## Overview

SeeBOM supports multiple SBOM formats through a **format-detection dispatch layer** at `internal/sbom/parse.go`. When a file is processed, the dispatcher:

1. Reads the raw bytes
2. Probes JSON fields to identify the format
3. Routes to the appropriate parser backend
4. Returns a unified `ParseResult` (SBOM metadata + packages)

This happens transparently — the parsing worker simply calls `sbom.Parse(reader, sourceFile, hash)`.

## Supported Formats

| Format | File Extension | Detection Method |
|--------|---------------|-----------------|
| SPDX 2.3 JSON | `.spdx.json`, `.json` | `"spdxVersion"` field present |
| In-toto attestation (SPDX) | `.spdx.json`, `.json` | `"predicateType"` contains "spdx" |
| CycloneDX 1.0–1.7 JSON | `.cdx.json`, `.json` | `"bomFormat": "CycloneDX"` |

## Parser Backends

### Built-in (Default)

The default parsers use `goccy/go-json` for high-performance streaming and add **zero additional dependencies** beyond what SeeBOM already requires.

| Package | Format | Notes |
|---------|--------|-------|
| `internal/spdx` | SPDX 2.3 + in-toto | Streaming parser, handles Go temp module names |
| `internal/cyclonedx` | CycloneDX 1.0–1.7 | Maps `components` + `dependencies` to parallel arrays |

**Advantages:**
- ✅ Minimal memory footprint (no protobuf overhead)
- ✅ No additional transitive dependencies
- ✅ Optimized for the specific fields SeeBOM needs
- ✅ Handles in-toto attestation envelopes natively
- ✅ Handles Go-specific temp module name cleanup

**Limitations:**
- ❌ Only supports SPDX 2.3 and CycloneDX JSON
- ❌ No XML/protobuf format support
- ❌ Manual effort to support new format versions

### Protobom (Opt-in)

The [protobom](https://github.com/protobom/protobom) backend provides maximum format coverage through the community-maintained SBOM library. It supports all formats that protobom supports, including future additions.

| Package | Formats | Notes |
|---------|---------|-------|
| `internal/protobomparser` | SPDX 2.3 + CycloneDX 1.0–1.7 | Unified graph model |

**Advantages:**
- ✅ Broad format coverage (SPDX + CycloneDX all versions)
- ✅ Community-maintained — automatic support for new spec versions
- ✅ Unified protobuf data model for all formats
- ✅ Future-proof: new formats (SPDX 3.0, etc.) come "for free"

**Limitations:**
- ❌ Higher memory footprint (loads entire document into protobuf structs)
- ❌ Adds ~30 transitive dependencies (protobuf, grpc, etc.)
- ❌ Does not handle in-toto envelopes out-of-the-box
- ❌ Slight parsing overhead vs. the tuned built-in parsers

## Configuration

### Environment Variable

```bash
# Enable protobom backend (replaces built-in parsers)
USE_PROTOBOM=true
```

### Docker Compose (.env)

```dotenv
USE_PROTOBOM=true
```

### Helm Values

```yaml
parsingWorker:
  extraEnv:
    USE_PROTOBOM: "true"
```

### Programmatic (tests)

```go
import "github.com/seebom-labs/seebom/backend/internal/sbom"

sbom.SetUseProtobom(true)
result, err := sbom.Parse(reader, "file.cdx.json", "sha256hash")
```

{{% alert title="Note" color="info" %}}
When `USE_PROTOBOM=true`, **all** SBOM parsing is routed through protobom — including SPDX files. The built-in parsers are bypassed entirely.
{{% /alert %}}

## Architecture

```
                         ┌──────────────────────┐
                         │    sbom.Parse()       │
                         │  (Format Detection)   │
                         └──────────┬───────────┘
                                    │
               USE_PROTOBOM=false   │   USE_PROTOBOM=true
          ┌─────────────────────────┼─────────────────────┐
          │                         │                     │
          ▼                         ▼                     ▼
  ┌──────────────┐          ┌────────────┐       ┌──────────────┐
  │ SPDX Parser  │          │ CycloneDX  │       │  Protobom    │
  │ (internal/   │          │ (internal/ │       │ (internal/   │
  │  spdx)       │          │  cyclonedx)│       │  protobom-   │
  │              │          │            │       │  parser)     │
  │ goccy/json   │          │ goccy/json │       │              │
  └──────────────┘          └────────────┘       └──────────────┘
```

## CycloneDX Field Mapping

| CycloneDX Field | SeeBOM Model Field | Notes |
|-----------------|-------------------|-------|
| `specVersion` | `SBOM.SPDXVersion` | Stored as `"CycloneDX-1.5"` |
| `serialNumber` | `SBOM.DocumentNamespace` | URN format |
| `metadata.component.name` | `SBOM.DocumentName` | With version appended |
| `metadata.timestamp` | `SBOM.CreationDate` | RFC3339 |
| `metadata.tools[].name` | `SBOM.CreatorTools` | Prefixed with "Tool: " |
| `components[].bom-ref` | `PackageSPDXIDs` | Used as node identifier |
| `components[].name` | `PackageNames` | |
| `components[].version` | `PackageVersions` | |
| `components[].purl` | `PackagePURLs` | |
| `components[].licenses` | `PackageLicenses` | Expression or ID |
| `dependencies[].ref/dependsOn` | `RelSource/TargetIndices` | Type: `"DEPENDS_ON"` |

## Recommendation

| Scenario | Backend | Reason |
|----------|---------|--------|
| Production with CNCF S3 buckets | Built-in | All files are SPDX JSON, maximum performance |
| Mixed-format ingestion | Built-in | SPDX + CycloneDX covered with zero overhead |
| Unknown/exotic formats | Protobom | Broader format sniffing and parsing |
| Future SPDX 3.0 support | Protobom | Will be added by the protobom community |
| CI/CD with custom SBOMs | Built-in | Predictable behavior, no surprises |

## Adding a New Format

To add support for a new SBOM format:

1. Create a new parser package at `internal/<format>/parser.go`
2. Implement a `Parse(data []byte, sourceFile, sha256Hash string) (*ParseResult, error)` function
3. Add format detection logic to `internal/sbom/parse.go` (probe a distinguishing JSON field)
4. Add the file extension to `internal/repo/scanner.go`
5. Write tests in `internal/<format>/parser_test.go`
6. Update this documentation page

