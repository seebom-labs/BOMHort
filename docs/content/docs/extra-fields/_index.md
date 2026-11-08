---
title: "Extra SBOM Fields"
linkTitle: "Extra Fields"
type: docs
weight: 11
description: >
  Recognise producer-written fields in uploaded SBOMs, such as a team
  contact, with a config entry instead of a parser change.
---

BOMHort reads a fixed set of fields out of every SBOM: the source repository,
the document version, the grouping signals. Producers often write more
than that into CycloneDX `properties` and `externalReferences`, for example
which team answers for a component. That knowledge is only in the SBOM. BOMHort
used to drop it.

An **extra-fields file** declares which of these fields BOMHort should
recognise. The parsing worker stores the matches per SBOM
(`sboms.extra_fields`, migration `034`). The SBOM detail API and page show
them, and the SBOM list can be filtered by them. Adding a field takes a new
config entry, not a code change.

## Configuration

| Setting | Default | Notes |
|---------|---------|-------|
| `EXTRA_FIELDS_FILE` | `/data/config/extra-fields.json` | Read by the **parsing worker** at startup. A missing file turns the feature off. An invalid file stops the worker with an error, so a typo can't make it silently recognise nothing. |

Docker Compose mounts `sboms/extra-fields.json`. The directory scanner never
treats that file as an SBOM.

```json
{
  "fields": [
    {
      "name": "owner_contact",
      "description": "Team or person who answers for the component.",
      "from": [
        {"cyclonedx": "metadata.component.properties", "property": "bomhort:owner:contact"},
        {"cyclonedx": "metadata.properties", "property": "bomhort:owner:contact"}
      ]
    },
    {
      "name": "issue_tracker",
      "from": [
        {"cyclonedx": "metadata.component.externalReferences", "type": "issue-tracker"}
      ]
    }
  ]
}
```

- **`name`**: the key in the API and the label in the UI. It must match
  `^[a-z][a-z0-9_]{0,62}$` and be unique.
- **`from`**: where the field is read from, in priority order. Values from
  earlier sources come first, and duplicates collapse. Each entry names one of
  a fixed set of places. There is no general path language:

| `cyclonedx` | Selector | Value |
|-------------|----------|-------|
| `metadata.component.properties` | `property`: exact property name | the property's `value` |
| `metadata.properties` | `property`: exact property name | the property's `value` |
| `metadata.component.externalReferences` | `type`: reference type (case-insensitive) | the reference's `url` |

Unknown keys are rejected, such as a misspelt `propery` or an `spdx` source.
The file allows at most 32 fields and at most 8 sources per field.

CycloneDX documents inside an in-toto envelope are read too. The fields are
extracted from the raw document, so the result is the same with the built-in
parsers and with `USE_PROTOBOM=true`.

**SPDX is not supported yet.** SPDX 2.3 has no name–value properties, only
free-text annotations and package `externalRefs`, so mapping SPDX needs its
own design. SPDX 3.0 extensions are the more likely fit. SPDX documents simply
carry no extra fields.

## The team contact

The shipped config recognises one field, `owner_contact`, from the property
**`bomhort:owner:contact`**. It is read on the described component first, then
on the BOM metadata. Producers who want BOMHort to show who answers for a
component write:

```json
"metadata": {
  "component": {
    "name": "payments",
    "properties": [
      {"name": "bomhort:owner:contact", "value": "payments-team@example.com"}
    ]
  }
}
```

The value can be an e-mail address, a chat channel or an `https://` URL. Repeat
the property to name more than one contact.

## Untrusted values

Every value comes from whoever produced the SBOM. BOMHort therefore:

- **drops** values longer than 1024 bytes and values that aren't valid UTF-8,
  rather than truncating them, because a cut-off address would look right but
  be wrong;
- strips control characters (newlines included) and surrounding whitespace;
- keeps at most 16 values per field;
- never logs the values, only the names of the fields it recognised;
- in the UI, renders values as escaped text and links out only `http(s)` URLs.

API consumers should do the same.

## Reading and filtering

- `GET /api/v1/sboms/{id}/detail` returns `extra_fields`, keyed by field name
  (omitted when there are none). The MCP `get_sbom` tool returns it too.
- `GET /api/v1/sboms?extra_field=owner_contact` lists the SBOMs that carry the
  field; add `&extra_value=payments-team@example.com` for one exact value.
- On the SBOM detail page each value is a link to that filtered list.

See the [API reference]({{< relref "/docs/api-reference" >}}).

## Changing the config

The extra-fields file is read when the worker starts, and it applies to SBOMs
ingested **after** that. Rows that are already stored keep the fields they were
ingested with. A row ingested before migration `034`, or before a field was
configured, reports no extra fields.

A normal re-ingest does **not** change that. `make re-ingest`, or the next
ingestion-watcher run, only enqueues files it has not seen before, and the
parsing worker skips an SBOM whose ID already exists. An existing SBOM keeps
the extra fields it was stored with until it is rebuilt from scratch.

### Rebuilding existing SBOMs

{{% alert title="This deletes data" color="warning" %}}
A rebuild empties the `sboms`, `sbom_packages`, `vulnerabilities`,
`license_compliance`, `vex_statements` and `ingestion_queue` tables, then
re-ingests whatever the ingestion watcher can still read. Anything it cannot
read again is gone afterwards:

- SBOM and VEX documents uploaded to a `skipScan` push bucket: the watcher
  never scans that bucket;
- values given **at upload time** (`?cluster=`, `?namespace=`, `?project=`,
  `?parent=`, `?tags=`, `?origin=`, `?image=`, `X-Source-Repo`,
  `X-Source-Ref`) and later `PATCH` edits: they are not stored with the
  file, so a re-scanned upload in `SBOM_DIR/pushed/` is re-assigned from the
  instance, bucket and path configuration instead;
- files deleted from `SBOM_DIR` or the scanned buckets since they were first
  ingested.

Take a ClickHouse backup first, and do not rebuild if your SBOMs arrive
mainly through uploads you cannot repeat.
{{% /alert %}}

When the watcher's sources still hold every document:

1. Update the extra-fields file and restart the parsing worker so it loads it.
2. Rebuild:
   - **Docker Compose:** `make re-scan`. It stops the worker, empties the
     tables above, rebuilds the services and re-runs the watcher.
   - **Kind:** `make kind-reingest`.
   - **Other Kubernetes deployments:** scale the parsing worker to zero,
     `TRUNCATE` the six tables above, scale the worker back up, then start a
     watcher run (`kubectl create job --from=cronjob/<release>-ingestion-watcher …`).
     Stopping the worker first matters: one still busy with a job would write
     that SBOM after the truncate, and the rebuild would then skip it.
3. Wait for the queue to drain (`make dev-status`, or the parsing worker's
   log), then re-upload anything from the list above that you still need.

Re-applying a changed config to the stored originals in the document store,
without deleting anything, is planned as a follow-up.

## Relation to the owner map

An operator-maintained owner map covers SBOMs whose content the operator
doesn't control. Extra fields cover knowledge only the producer has. The two
combine: where both name a contact, the operator's map wins.
