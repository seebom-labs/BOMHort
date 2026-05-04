# SeeBOM v0.1.3 – Release Notes

**Release Date:** 2026-03-12

This release introduces the official CNCF license policy as the default, significantly improves exception handling for CNCF-approved packages, fixes several bugs that blocked real-world usage with large SBOM repositories, and adds deployment examples for Kind and production Kubernetes clusters.

---

## 🚀 Features

### CNCF Allowed Third-Party License Policy as Default
The license policy now follows the official [CNCF Allowed Third-Party License Policy](https://github.com/cncf/foundation/blob/main/policies-guidance/allowed-third-party-license-policy.md). 18 licenses from the CNCF Allowlist (Apache-2.0, MIT, MIT-0, 0BSD, BSD-2-Clause, BSD-2-Clause-FreeBSD, BSD-3-Clause, ISC, PSF-2.0, Python-2.0, Python-2.0.1, PostgreSQL, UPL-1.0, X11, Zlib, OpenSSL, OpenSSL-standalone, SSLeay-standalone) are classified as permissive. All other licenses are flagged and require a CNCF Governing Board exception. The policy is fully customisable via `licensePolicy.custom` in Helm values.

### CNCF Exception Handling Improvements
- Exceptions with `"project": "All CNCF Projects"` are automatically promoted to **blanket exceptions** that apply to every SBOM — no per-project matching needed.
- **Compound license expressions** like `GPL-2.0-only, GPL-2.0-or-later` and `MPL-2.0 OR LGPL-3.0-or-later` are now split into individual SPDX IDs and matched correctly.
- **Substring package matching**: CNCF exception entries use short names like `cyphar/filepath-securejoin`, which now correctly match fully-qualified SBOM package names like `github.com/cyphar/filepath-securejoin`.

### License Exception Fallback Loading
Both the API Gateway and Parsing Worker now try loading exceptions from the ConfigMap path first, then fall back to `/data/sboms/license-exceptions.json` (the CNCF file downloaded by the seed job). Previously, workers would silently run without exceptions if the ConfigMap was empty.

### Deployment Examples (`examples/`)
New `examples/` directory with ready-to-use deployment configurations:
- **`examples/kind/`** — Kind cluster config, Helm values, secrets template, and step-by-step README
- **`examples/kubernetes/values-production.yaml`** — HA deployment with seed job (for large SBOM repos)
- **`examples/kubernetes/values-minimal.yaml`** — Single-replica deployment with git-sync (for small repos)
- Full documentation of all three SBOM ingestion methods (seed job, git-sync, manual PVC) with file placement rules

### New Makefile Targets
- `make kind-build` — Build all container images and load them into the Kind cluster
- `make kind-deploy` — Build, load, Helm upgrade, and restart pods in one command
- `make kind-reingest` — Truncate all data tables and re-queue all SBOMs from the PVC without re-downloading

### Configurable PVC Size
`sbomSource.storageSize` in Helm values now controls the SBOM PVC size. The CNCF SBOM repo requires ~15 Gi; the default remains 1 Gi for generic deployments.

### Pod Affinity for RWO Volumes
When using a PersistentVolumeClaim (`gitSync.enabled: false`), all pods that mount the SBOM PVC (Parsing Workers, API Gateway, Ingestion Watcher, Seed Job) are automatically co-scheduled on the same Kubernetes node via `podAffinity`. This prevents volume mount failures on multi-node clusters where the RWO volume is bound to a single node. The affinity is only applied in seed job mode — git-sync mode uses `emptyDir` volumes which don't need it.

---

## 🐛 Bug Fixes

### Archived Packages Query (HTTP 500)
Fixed a ClickHouse query error (`Expected equi-join ON condition`) in the `/api/v1/packages/archived` endpoint. The `JOIN` was replaced with a `CROSS JOIN` using a filtered subquery. The endpoint now returns results correctly instead of an HTTP 500 error.

### SBOM Seed Job File Deduplication
The CNCF SBOM repo contains 6559 files across deeply nested directories, but many share the same basename. The seed job now flattens directory paths into filenames (e.g. `cncf/kubernetes/v1.28/kubernetes.spdx.json` → `cncf_kubernetes_v1.28_kubernetes.spdx.json`), preserving all files. Previously only ~1105 of 6559 SBOMs were ingested.

### SBOM Detail Page Error Handling
Fixed an issue in the Angular UI where `forkJoin` cancelled all parallel API calls when the archived-packages endpoint returned an error. Added `catchError` with fallback defaults so the detail page loads even when individual API calls fail.

### Directory Scanner Crash on `lost+found`
On cloud block volumes (OCI, AWS EBS, etc.) with ext4 filesystems, the `lost+found` directory is root-owned and unreadable by the container user (`nobody`). The Ingestion Watcher crashed with `permission denied` instead of scanning any files. The scanner now gracefully skips unreadable child directories (logging a warning) and continues. `lost+found`, `.git`, and hidden directories are explicitly excluded from scanning.

---

## 🔧 Maintenance

- Removed stale compiled Go binaries (`backend/api-gateway`, `backend/parsing-worker`) from the repository and added them to `.gitignore`.
- Production Helm example (`values-production.yaml`) switched from git-sync to seed job — git-sync times out on large repos (>1 GB) like `cncf/sbom`.
- Fixed duplicate "Option B" headings in the README (now correctly labelled A/B/C).
- Updated all version references from 0.1.2 to 0.1.3 across Helm chart, values, examples, and documentation.
- Updated dates in all docs.

---

## 🧪 Tests

- 8 new tests for CNCF exception handling:
  - `TestBuildIndex_AllCNCFProjectsPromotedToBlanket`
  - `TestBuildIndex_CompoundLicenseOR`
  - `TestBuildIndex_CompoundLicenseAND`
  - `TestIsExempt_SubstringPackageMatch`
  - `TestIsExempt_SubstringPackageAnyLicense`
  - `TestSplitLicenses` (6 subtests)
  - `TestLoadExceptionsWithFallback_PrimaryPath`
  - `TestLoadExceptionsWithFallback_FallbackPath`
  - `TestLoadExceptionsWithFallback_AllMissing`
  - `TestLoadExceptionsWithFallback_EmptyPaths`
- Updated `TestCategorize` to cover BSD-3-Clause, ISC, and 0BSD under the CNCF Allowlist.
- Total test count: **87+** (up from 73+).

---

## 📦 Upgrade Notes

- The default license policy has changed. Licenses previously classified as permissive (e.g. `Unlicense`, `CC0-1.0`, `BSL-1.0`, `Artistic-2.0`, `JSON`, `WTFPL`, `CC-BY-3.0`, `CC-BY-4.0`) are now classified as **unknown** (not in either list) — they will be flagged for review unless covered by a CNCF exception. If you want the old behaviour, set `licensePolicy.custom` in your Helm values.
- To apply the new policy to existing data, run `make kind-reingest` (Kind) or truncate the `license_compliance` table and re-trigger the Ingestion Watcher.
- The `examples/kubernetes/values-production.yaml` now uses a seed job instead of git-sync. If you were using git-sync with a large repo, consider switching.

---

## Full Changelog

**Compare:** `v0.1.2...v0.1.3`

