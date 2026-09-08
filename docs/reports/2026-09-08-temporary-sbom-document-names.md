# Bug report: generated SPDX document names expose temporary checkout names

**Suggested issue title:** `fix: derive SPDX document names from repository identity, not temporary checkout directories`

**Observed:** 2026-09-08

## Summary

SPDX documents in `cncf-project-sboms` and `cncf-subproject-sboms` have meaningful
object keys and explicitly described root packages, but their top-level `name`
contains a random temporary-directory name such as `tmp.PM9IVSVGio`.

This value is present in the downloaded source JSON before BOMHort processes it.
Both BOMHort parser backends previously preserved it as the document title, making
individual SBOMs appear to be named `tmp.*` despite valid repository metadata.
Renaming the bucket object alone does not fix the JSON document name.

The producer metadata identifies Waybill 0.2.0 and 0.3.0. **The producer source code
and exact generator invocation were not inspected**, so it is not yet established
whether the incorrect name is set by Waybill itself or its calling pipeline.

## Evidence and scope

The checks were read-only: complete object listings, selected downloads, and local
parsing. No bucket objects, running deployments, or database records were changed.
Credentials and infrastructure-specific connection details are intentionally omitted.

| Bucket | Listed objects | Object keys containing `tmp` | Contents sampled | Top-level `name` matching `tmp.*` |
|---|---:|---:|---:|---:|
| `cncf-project-sboms` | 2,026 | 0 | 24 | 24/24 |
| `cncf-subproject-sboms` | 13,025 | 0 | 24 | 24/24 |

- All 48 sampled contents are plain SPDX 2.3 JSON, not in-toto envelopes.
- All have usable explicitly described root packages with repository names and versions.
- 35 samples identify `Tool: waybill-0.2.0`; 13 identify `Tool: waybill-0.3.0`.
- The sample includes objects updated on 2026-09-07, so it is not limited to old uploads.
- Sampling covered different source/project groups, selecting the latest object
  per chosen group, plus the first object and latest object overall in each bucket.
  Selection was deterministic; files larger than 16 MiB were excluded from content
  sampling. About 72.6 MB of sample content was downloaded.
- **All 15,051 object keys were listed, but not all 15,051 document contents were
  examined.** The 48/48 result is a sample finding, not a full-content census.

### Reproducible examples

| Bucket / object key | Actual document `name` | Described root package | Root version |
|---|---|---|---|
| `cncf-project-sboms/aeraki-mesh/1.0.5/aeraki-mesh_1_0_5_spdx.json` | `tmp.PM9IVSVGio` | `aeraki-mesh/aeraki` | `1.0.5` |
| `cncf-project-sboms/werf/3.3.1/werf_3_3_1_spdx.json` | `tmp.X3TNVswW6Y` | `werf/werf` | `v3.3.1` |
| `cncf-subproject-sboms/aeraki/meta-protocol-proxy/1.1.4/aeraki_meta-protocol-proxy_1_1_4_spdx.json` | `tmp.PxbREcw4zw` | `aeraki-mesh/meta-protocol-proxy` | `1.1.4` |
| `cncf-subproject-sboms/lima/socketvmnet/1.2.2/lima_socketvmnet_1_2_2_spdx.json` | `tmp.9agbSqURkZ` | `lima-vm/socket_vmnet` | `v1.2.2` |

These are observed source values, not proposed replacement package identities.

## Reproduction

1. Download one of the listed objects using the repository's normal authorized
   storage tooling. Do not paste access keys into an issue, script, or log.
2. Inspect its top-level name and explicitly described roots:

   ```bash
   jq '
     . as $doc |
     (($doc.documentDescribes // []) +
       [$doc.relationships[]? |
        select(.relationshipType == "DESCRIBES" and .spdxElementId == $doc.SPDXID) |
        .relatedSpdxElement]) | unique as $rootIDs |
     {name: $doc.name, creators: $doc.creationInfo.creators,
      roots: [$doc.packages[]? |
              select(.SPDXID as $id | $rootIDs | index($id)) |
              {SPDXID, name, versionInfo}]}
   ' downloaded.spdx.json
   ```

3. Compare the temporary document name to the meaningful root package and version.
4. To trace the producer defect, generate the same repository/ref in two differently
   named checkout directories and compare only the document names. This producer
   reproduction is a recommended next step; it was not run during the bucket test.

## Expected behavior

The document name should identify the software being described, independently of
the temporary working directory used to scan it. For example:

- `aeraki-mesh/aeraki 1.0.5`
- `werf/werf v3.3.1`
- `lima-vm/socket_vmnet v1.2.2`

A consistent producer naming convention can differ in formatting, but should be
stable for the same repository/ref and must not contain the temporary checkout name.

## Recommended producer fix

1. Trace where the top-level SPDX `name` is assigned. Check whether a temporary
   checkout basename is being used as the scan target/document title.
2. Supply the intended repository/project identity and the exact scanned ref/version
   when constructing the document. Prefer the existing explicit root metadata over
   guessing from arbitrary dependency names or replacing every occurrence of `tmp`.
3. Keep `documentDescribes` / document-to-package `DESCRIBES` references consistent
   with the actual root package. Do not assume `packages[0]` is always the root.
4. Change document-title metadata only as needed. Do not accidentally rename packages,
   rewrite PURLs, change dependency relationships, or broaden license statements.
   Normal document regeneration may of course change checksums and provenance.
5. Add a pre-upload validation gate that detects empty/temporary document titles
   and reports the affected repository/ref. Re-generate affected artifacts through
   the normal publication pipeline after reviewing its retention/versioning policy.

### Acceptance criteria

- [ ] The same repository/ref scanned in two different temporary directories yields
      the same meaningful document name.
- [ ] The generated name identifies the intended project and, when known, its version.
- [ ] Root selection is explicit and remains correct if package array order changes.
- [ ] Missing/multiple roots are handled deliberately; no arbitrary dependency is
      promoted to the document identity.
- [ ] Existing meaningful names and package/PURL/license/relationship data are preserved.
- [ ] The upload pipeline rejects or explicitly flags empty/temporary names.
- [ ] Representative project and subproject artifacts are re-generated and checked
      directly from object storage, not only through a consumer UI.

These are proposed upstream acceptance criteria, not claims that the producer has
already been patched.

## BOMHort mitigation implemented alongside this report

BOMHort now has a shared `internal/sbomname` fallback in its built-in SPDX,
CycloneDX, and protobom adapters:

- Preserve meaningful document names verbatim.
- For an empty or temporary SPDX name, choose a single explicitly described root
  package and append its known version. Duplicate references to that same root are
  allowed; multiple/dangling references and duplicate package IDs use a source label.
- Fall back to the S3 object key or local/HTTP basename if no usable root exists,
  and finally `Unnamed SBOM`. CycloneDX retains its metadata-component/serial-number
  preference. No package identity is changed by this document-name fallback.
- Log bounded, quoted original/resolved names for diagnosis while retaining the
  original source bytes and source identity. No database schema change is required.

### Consumer-side verification

| Parser | Before mitigation | After mitigation |
|---|---|---|
| Built-in | 48/48 samples retained `tmp.*` document names | 48/48 resolve to their expected root name and version |
| Protobom | 48/48 samples retained `tmp.*` document names | 48/48 resolve to their expected root name and version |

The post-fix check replayed the previously downloaded samples **offline**; no new
storage credentials or producer changes were required. Source files were unchanged.
Committed synthetic regression tests cover temporary/empty and valid names,
root ambiguity, in-toto (built-in), CycloneDX, source fallback, unchanged package
identity, and exact license-exception project scopes.

The mitigation is applied during ingestion, not solely in the UI. Existing BOMHort
rows require planned re-processing; a pod restart, Argo sync, or watcher-only run
does not bypass deduplication or rewrite stored results. Project-scoped license
exceptions must use the resolved document name including its version; old `tmp.*`
names are not implicitly granted aliases.

This consumer fallback is defensive handling and does **not** replace fixing the
producer metadata for other SBOM consumers.
