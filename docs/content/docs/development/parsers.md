---
title: "SBOM Parsers"
linkTitle: "Parsers"
type: docs
weight: 3
description: >
  Multi-format SBOM parsing: supported formats, parser backends, configuration, and trade-offs.
---

## Overview

BOMHort supports multiple SBOM formats through a **format-detection dispatch layer** at `internal/sbom/parse.go`. When a file is processed, the dispatcher:

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

The default parsers use `goccy/go-json` for high-performance streaming and add **zero additional dependencies** beyond what BOMHort already requires.

| Package | Format | Notes |
|---------|--------|-------|
| `internal/spdx` | SPDX 2.3 + in-toto | Streaming parser, handles Go temp module names |
| `internal/cyclonedx` | CycloneDX 1.0–1.7 | Maps `components` + `dependencies` to parallel arrays |

**Advantages:**
- ✅ Minimal memory footprint (no protobuf overhead)
- ✅ No additional transitive dependencies
- ✅ Optimized for the specific fields BOMHort needs
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

## Document name fallback

Both parser backends share `internal/sbomname` for empty or temporary SBOM names.
For example, a source document named `tmp.ABC123xyz` describing
`example-org/widget` version `v1.2.3` is stored and displayed as
**`example-org/widget v1.2.3`**.

The conservative rules are:

1. Preserve a meaningful existing document name exactly, including existing formatting.
   Fallback detection recognizes whitespace-only names, `tmp`, and
   `tmp.` followed by at least six ASCII alphanumeric characters, including
   absolute filesystem paths ending in that pattern. It does not rewrite names
   merely containing `tmp`, such as `tmp-utils` or `org/tmp.tool`.
2. For SPDX JSON, use exactly one explicitly described package from
   `documentDescribes`, a `DESCRIBES` relationship originating at the document,
   or a `DESCRIBED_BY` relationship targeting the document. Append its version
   unless empty or `NOASSERTION`, `NONE`, or `UNKNOWN`.
3. Do not guess from package array order or dependency-graph roots. Multiple or
   dangling root references, duplicate package IDs, and temporary/empty root names
   use the source fallback instead. Redundant references to the same root are fine.
4. For CycloneDX JSON, use `metadata.component` name/version, then a usable
   `serialNumber`. Ordinary dependencies are not treated as metadata components.
5. Otherwise use the full S3 object key (preserving project/version context), or
   the basename of a local/HTTP source, removing `.spdx.json`, `_spdx.json`,
   `.cdx.json`, or `.json`. URL credentials, query strings, and fragments are not
   part of the label. If no usable source remains, use `Unnamed SBOM`.

The built-in in-toto parser applies the same rule to its SPDX predicate. This does
not add in-toto support to protobom. For already parsed XML without a name, the
shared helper uses the source fallback rather than attempting JSON root extraction.

Original SBOM bytes, source URI, hash/ID, namespace, and package identities are
unchanged. A bounded, quoted log entry records the original name, resolved name,
and fallback reason. The original name remains available in the source SBOM;
there is no new database column or raw-name API field.

**Upgrade note:** the resolved name is persisted in `document_name`. Deploying
new worker images does not rewrite existing rows: plan re-processing of existing
SBOMs, with backups before any destructive development reset helper. Re-running
the watcher alone skips unchanged files. Project-scoped license exceptions must
use the exact resolved document name (including the version), not the old `tmp.*`
name or the separately grouped S3 project label. No automatic scope aliases are added.

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
import "github.com/seebom-labs/BOMHort/backend/internal/sbom"

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

| CycloneDX Field | BOMHort Model Field | Notes |
|-----------------|-------------------|-------|
| `specVersion` | `SBOM.SPDXVersion` | Stored as `"CycloneDX-1.5"` |
| `serialNumber` | `SBOM.DocumentNamespace` | URN format |
| `metadata.component.name` | `SBOM.DocumentName` | With version appended; unusable names use the shared fallback above |
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
4. Write tests in `internal/<format>/parser_test.go`
5. Update this documentation page

{{% alert title="Note" color="info" %}}
No file extension changes are needed — the scanner accepts all `.json` files and format is detected at parse time by the dispatch layer.
{{% /alert %}}

