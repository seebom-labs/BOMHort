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
(`sboms.extra_fields`, migration `032`). The SBOM detail API and page show
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
ingested with. A row ingested before migration `032`, or before a field was
configured, reports no extra fields. To apply a changed config to existing
SBOMs, re-process them (`make re-scan` locally, or re-ingest).

Applying a changed config to stored originals from the document store
automatically is planned as a follow-up.

## Relation to the owner map

An operator-maintained owner map covers SBOMs whose content the operator
doesn't control. Extra fields cover knowledge only the producer has. The two
combine: where both name a contact, the operator's map wins.
