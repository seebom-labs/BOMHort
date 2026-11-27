---
title: "Private Vulnerability Advisories"
linkTitle: "Private Vulnerabilities"
type: docs
weight: 8
description: >
  Ingest internal security advisories and private zero-day findings in OSV
  schema, evaluate them alongside public feeds, and reconcile them across runs.
---

BOMHort evaluates package dependencies against public vulnerability databases
like [osv.dev](https://osv.dev) and distribution advisory feeds. Private
vulnerability advisories allow organizations to track internal security findings,
pre-disclosure flaws, proprietary component issues, and custom compliance findings
within the same dashboard and reporting surface, without submitting findings to
public registries.

Private findings carry `advisory_source = "private"` and are fully integrated with
ownership dimensions, reachability evidence, OpenVEX suppression, and CSV exports.

## Advisory File Format

Private advisories are authored in the [Open Source Vulnerability (OSV)](https://ossf.github.io/osv-schema/)
schema. The configuration accepts either:

1. A JSON array of vulnerability records:
   ```json
   [
     {
       "id": "ACME-2026-001",
       "summary": "Improper token validation in internal auth library",
       "details": "JWT verification fails to validate signature algorithm headers.",
       "database_specific": {
         "severity": "HIGH"
       },
       "affected": [
         {
           "package": {
             "name": "internal-auth",
             "ecosystem": "npm",
             "purl": "pkg:npm/internal-auth"
           },
           "ranges": [
             {
               "type": "SEMVER",
               "events": [
                 {"introduced": "0"},
                 {"fixed": "2.4.1"}
               ]
             }
           ]
         }
       ],
       "references": [
         {
           "type": "ADVISORY",
           "url": "https://security.example.internal/advisories/ACME-2026-001"
         }
       ]
     }
   ]
   ```

2. A JSON object with a `vulnerabilities` wrapper array:
   ```json
   {
     "version": "1.0.0",
     "vulnerabilities": [
       {
         "id": "ACME-2026-002",
         "summary": "SQL injection in reporting helper",
         "affected": [...]
       }
     ]
   }
   ```

### ID Rules and Public Prefix Protection

Advisory IDs identify flaws across the fleet. Every private advisory ID must match:

```text
^[A-Za-z0-9._-]{1,100}$
```

To prevent private advisories from colliding with or shadowing public advisories,
BOMHort rejects advisories starting with known public OSV namespace prefixes:

- `CVE-` (Common Vulnerabilities and Exposures)
- `GHSA-` (GitHub Security Advisories)
- `PYSEC-` (Python packaging advisories)
- `GO-` (Go vulnerability database)
- `RUSTSEC-` (Rust Security Advisory Database)
- `MAL-` (Malicious packages database)
- Distro and vendor prefixes: `DSA-`, `DLA-`, `DTSA-`, `USN-`, `CGA-`, `RHSA-`,
  `RHBA-`, `RHEA-`, `ALSA-`, `ALBA-`, `ALEA-`, `ELSA-`, `RLSA-`, `ALAS-`, `MGASA-`,
  `SUSE-SU-`, `OPENSUSE-SU-`, `UBUNTU-CVE-`, `DEBIAN-CVE-`, `ALPINE-CVE-`, `OSV-`,
  `BIT-`, `CURL-CVE-`, `PSF-`, `RSEC-`, `GSD-`, `ASB-A-`, `PUB-`, `HSEC-`, `OESA-`.

An advisory using any of these prefixes is rejected at load time with an error.

## Supported Range Types and Version Comparison

Private advisories support three matching strategies in `affected`:

1. **Exact versions:**
   ```json
   "versions": ["1.0.0", "1.0.1", "1.1.0-rc1"]
   ```
   Matches only the listed versions exactly.

2. **SEMVER ranges:**
   ```json
   "ranges": [
     {
       "type": "SEMVER",
       "events": [
         {"introduced": "1.0.0"},
         {"fixed": "1.4.2"}
       ]
     }
   ]
   ```
   Evaluates standard SemVer 2.0 expressions, with fallback to lenient comparison
   for dotted versions (`1.5.0.0`), release qualifiers (`1.5.0.Final`), and
   service pack identifiers (`1.5.1.SP1`).

3. **ECOSYSTEM ranges:**
   ```json
   "ranges": [
     {
       "type": "ECOSYSTEM",
       "events": [
         {"introduced": "0"},
         {"fixed": "4.19.0"}
       ]
     }
   ]
   ```
   For Linux distribution packages (`apk`, `deb`, `rpm`), native package manager
   comparators are used. For language ecosystems outside apk/deb/rpm (such as npm,
   PyPI, Maven, Go, or NuGet), ranges are compared with SemVer-like ordering.

### Version Comparison Ordering and Limits

When evaluating `SEMVER` ranges or non-distro `ECOSYSTEM` ranges:

- **Pre-release numbers:** Numeric suffixes in pre-release tags are compared
  numerically rather than alphabetically (`rc9 < rc10`, `alpha2 < alpha10`).
- **Post-releases:** Tags indicating post-release patches or service packs
  (`post`, `sp`, `patch`, `rev`) are ordered after the base release
  (`2.32.0.post1 > 2.32.0`, `1.5.1.SP1 > 1.5.1`).
- **PyPI Epochs:** Formats containing PyPI epoch prefixes (`1!1.0`) sort ahead
  of versions without an epoch (`1!1.0 > 2.0`).
- **Load-time warnings:** Versions containing epochs or unknown suffix qualifiers
  that cannot be ordered deterministically under standard ordering produce a
  warning in the worker and refresher logs at load time.
- **Versionless packages:** An unbounded range containing only `{"introduced": "0"}`
  matches versionless PURLs (such as internal Go packages referenced by import path
  without a tag). Bounded ranges require a version on the package.

## Sources

Private vulnerabilities can be supplied through three mechanisms:

| Source | Configuration | Use case |
|--------|---------------|----------|
| Chart-rendered ConfigMap | `privateVulnerabilities.custom` (Helm) | Advisories stored directly in Helm values |
| Dedicated ConfigMap | `privateVulnerabilities.existingConfigMap` (Helm) | GitOps pipeline or external manifest manages the ConfigMap |
| Remote URL or S3 object | `PRIVATE_VULNERABILITIES_SOURCE` (or Helm `privateVulnerabilities.source`) | Advisories hosted in an S3 bucket or internal security endpoint |

For standalone Docker Compose deployments, specify `PRIVATE_VULNERABILITIES_FILE`
pointing to the mounted JSON file (default: `/data/config/private-vulnerabilities.json`).

### Remote Authentication

When reading advisories from an `https://` source, set `PRIVATE_VULNERABILITIES_SOURCE_TOKEN`
to supply a Bearer authentication token. For S3 sources (`s3://bucket/key`),
configured S3 credentials (`S3_ACCESS_KEY`, `S3_SECRET_KEY`, or IAM role) are reused.

## Reload Behavior

The API Gateway, ingestion workers, and `cve-refresher` poll the configured source
every `PRIVATE_VULNERABILITIES_REFRESH_INTERVAL` (default: `60s`). Setting the
interval to `0` loads the file once at container startup.

- **Digest caching:** Reloads verify the SHA-256 digest of the source content.
  Unchanged documents require no index rebuild.
- **Fail-safe loading:** If a reload fails due to transient network issues or a
  malformed document, the service logs an error and continues serving the previous
  valid index. Active findings are not closed on transient errors.

## Ingestion and Reconciliation

Private vulnerability advisories participate in two stages of the pipeline:

### 1. Ingestion Worker (`parsing-worker`)

When an SBOM is ingested:
- The worker matches package PURLs against the active in-memory private index.
- Matches are recorded in ClickHouse with `advisory_source = "private"` and
  `advisory_status = "affected"`.
- Private vulnerabilities are evaluated even if OSV evaluation is disabled
  (`SKIP_OSV=true`).

### 2. Vulnerability Refresher (`cve-refresher`)

The scheduled `cve-refresher` job keeps private findings synchronized across runs:

- **Withdrawn or removed advisories:** If an advisory is marked `"withdrawn"` or
  removed from the file, existing findings for that advisory are closed across
  all affected SBOMs.
- **Missing or deleted file:** If the advisory file is deleted or emptied, the
  refresher closes stale private findings. If the file cannot be read due to an
  error, existing findings are preserved.
- **Metadata updates:** Edits to severity, summary, fixed version, or aliases are
  propagated to stored findings while preserving ownership dimensions (cluster,
  namespace, project) and image digest.
- **New findings:** When new private advisories are added, the refresher evaluates
  known package PURLs and records new findings for affected SBOMs.
