---
title: "Migration Importer"
linkTitle: "Migration Importer"
type: docs
weight: 7
description: >
  Move an existing SBOM inventory into BOMHort, keeping its triage decisions as OpenVEX.
---

`bomhort-import` is a one-shot command-line tool for teams that already run an
SBOM inventory. It reads CycloneDX documents with embedded
`vulnerabilities[].analysis`, uploads every SBOM, and turns the analyses into
one OpenVEX document per SBOM, so findings that were suppressed before are
suppressed in BOMHort too, with their original justification.

It talks only to the public upload API
([`POST /api/v1/sboms/upload`](/docs/api-reference/#post-apiv1sbomsupload)), so it
needs an instance URL and an API key, never database access. Running it again
imports nothing twice.

## Prerequisites

- An instance with uploads enabled: `apiGateway.auth.enabled: true` and upload
  storage configured (see [Push-Model Uploads](/docs/deployment/#option-e-push-model-uploads-cicd)).
- An API key from `apiGateway.auth.apiKeys`.
- A directory with the export: CycloneDX **JSON** documents (any depth of
  subdirectories). Most inventory tools can export a project's SBOM with its
  vulnerabilities and analysis included.

## Usage

Build and run it from a checkout:

```bash
make import ARGS="--dir /path/to/export --url https://bomhort.example.com --dry-run"
```

or directly with Go:

```bash
cd backend
go run ./cmd/bomhort-import --dir /path/to/export --dry-run
```

The API key is read from the `BOMHORT_API_KEY` environment variable, never from a
flag, so it does not end up in shell history or process listings. Redirects are
not followed, because they would send the key along: if the instance answers
with one, the error names the target, and you pass that as `--url`.

| Flag | Meaning |
|---|---|
| `--dir` | Directory of CycloneDX JSON documents, read recursively. |
| `--url` | Instance base URL, e.g. `https://bomhort.example.com` (default `$BOMHORT_URL`). |
| `--mapping` | JSON file assigning BOMHort projects and tags, see below. |
| `--dry-run` | Print the plan and upload nothing. Needs neither URL nor key. |
| `--timeout` | Timeout per upload request (default `2m`). |
| `--source` | Where to read from. Only `dir` exists today. |

Always start with `--dry-run`. For each SBOM it shows the project and tags it
will get, the VEX document it will generate with its statements per status, and
every analysis it cannot import and why:

```text
payments-api (team-a/payments.cdx.json)
  project: payments, tags: imported,team-payments
  SBOM: payments.cdx.json
  VEX:  payments.openvex.json, 2 statements (not_affected 1, under_investigation 1)

Dry run: 2 SBOMs and 2 VEX documents (3 statements) would be uploaded.
```

Then run it without `--dry-run`:

```bash
export BOMHORT_API_KEY=...
make import ARGS="--dir /path/to/export --url https://bomhort.example.com --mapping mapping.json"
```

The exit status is non-zero when an SBOM could not be read or uploaded; the
others are still imported. Fix the cause and run it again — what was already
uploaded is reported as `already imported`.

## Mapping projects and tags

Without a mapping, BOMHort derives the project from each document as it does
for any upload. A mapping file names the project per source project and adds
[tags](/docs/deployment/#tags):

```json
{
  "tags": ["imported"],
  "projects": {
    "payments-api": {"project": "payments", "tags": ["team-payments"]}
  }
}
```

The keys under `projects` are source project names: the document's
`metadata.component.name`, or the file name without `.cdx.json` when there is
none. Top-level `tags`
go on every SBOM and are merged with the project's own. Unknown fields are an
error, so a typo cannot silently import everything unmapped.

## How analyses become OpenVEX

Each analysis becomes one statement per affected component, matched on the
component's purl. The CycloneDX and OpenVEX vocabularies do not line up one to
one, so the closest value is used and the original state, justification and
response are kept in the statement's `status_notes`. The author is `imported`.

| CycloneDX `analysis.state` | OpenVEX `status` |
|---|---|
| `not_affected`, `false_positive` | `not_affected` |
| `resolved`, `resolved_with_pedigree` | `fixed` |
| `exploitable` | `affected` |
| `in_triage` | `under_investigation` |
| `not_set`, missing | not imported |

| CycloneDX `analysis.justification` | OpenVEX `justification` |
|---|---|
| `code_not_present` | `vulnerable_code_not_present` |
| `code_not_reachable` | `vulnerable_code_not_in_execute_path` |
| `requires_configuration`, `requires_dependency`, `requires_environment` | `vulnerable_code_cannot_be_controlled_by_adversary` |
| `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter`, `protected_by_mitigating_control` | `inline_mitigations_already_exist` |

`analysis.detail` becomes the impact statement of a `not_affected` statement and
the action statement of an `affected` one; for the other statuses it is added to
the notes. Only `not_affected` suppresses a finding.

Each statement carries its own time, taken from `analysis.lastUpdated` (or
`firstIssued`). The document itself has no timestamp, so a statement whose
analysis records no time never borrows another finding's date; it gets the time
BOMHort ingests it. As everywhere in BOMHort, the newest statement for a
finding wins.

## Linking VEX to its SBOM

The generated document names the SBOM by its `serialNumber`, which BOMHort
stores as the document namespace, so the statements apply to that SBOM only and
it does not matter which of the two is processed first.

An SBOM **without a `serialNumber`** is imported, but its VEX document is not:
the only other identifier, name and version, is not unique enough to attach
suppressions to. The plan lists these as `VEX: not generated`.

## Running it again

The generated OpenVEX is byte-for-byte the same for the same analyses, and the
upload endpoint skips content it already has, so a second run uploads nothing.
When an analysis changed in the source, its document changes too and is
imported as a newer statement.

## Limitations

- CycloneDX JSON only. SPDX and other JSON documents are skipped and listed in
  the output; files that do not end in `.json` (such as CycloneDX XML) are not
  read.
- Analyses whose affected component has no purl cannot be matched to a finding
  and are listed instead of imported.
- The directory is the only source so far. Adapters for inventory APIs plug in
  behind `importer.Source` in `backend/internal/importer`.
