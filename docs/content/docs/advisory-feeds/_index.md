---
title: "Advisory Feeds"
linkTitle: "Advisory Feeds"
type: docs
weight: 7
description: >
  OSV-format advisory feeds next to osv.dev: how a distro or vendor feed
  closes findings for fixes it has backported, which statuses it can report,
  and how to configure one.
---

BOMHort looks up every package in [osv.dev](https://osv.dev). That is the
right default for language ecosystems, but it has two blind spots:

- **Distro packages carry backports.** `pkg:apk/wolfi/openssl@3.1.4-r2` may
  contain the fix for a CVE whose *upstream* range still says 3.1.4 is
  vulnerable. Matching the upstream range reports a finding the distro has
  already fixed.
- **Vendor feeds are not all on osv.dev.** Hardened-image and library vendors
  publish advisories in the OSV schema on their own hosts, often with a status
  per component (`pending upstream fix`, `fix not planned`, …) and the location
  of the vulnerable file in the image.

An **advisory feed** adds such a source. OSV stays the only data model: a feed
is a set of OSV records.

## Configuring feeds

`ADVISORY_SOURCES` lists the feeds, comma-separated. Each entry is
`name|index[|purl-prefix…]`:

```bash
ADVISORY_SOURCES="wolfi|https://packages.example.dev/osv/all.json|pkg:apk/wolfi,private|s3://security-advisories/osv/all.json"
```

In the Helm chart:

```yaml
advisorySources:
  - name: wolfi
    index: https://packages.example.dev/osv/all.json
    prefixes: ["pkg:apk/wolfi"]
  - name: private
    index: s3://security-advisories/osv/all.json
```

| Field | Meaning |
|-------|---------|
| `name` | Lower-case letters, digits, `.`, `_`, `-`. Shown as the finding's `advisory_source` and as the author of the VEX statements the feed produces. `osv` is reserved. |
| `index` | The index document: `https://…`, `s3://bucket/key` (the bucket must be in `S3_BUCKETS`) or `file:///path`. Plain `http://` is refused. |
| `prefixes` | PURL prefixes the feed is **authoritative** for. A prefix matches at a path boundary: `pkg:apk/wolfi` covers `pkg:apk/wolfi/curl`, not `pkg:apk/wolfish/curl`. |

The parsing worker and the cve-refresher both read `ADVISORY_SOURCES`, and both
refuse to start on a malformed entry.

### Feed format

A feed is the layout osv.dev and several vendors already publish:

- an **index**: a JSON array of `{"id": "…", "modified": "RFC 3339"}`;
- one **OSV record** per id, next to the index: `<directory>/<id>.json`.

A local mirror of osv.dev, or a private feed of embargoed advisories, is the
same thing: one more index on `file://` or `s3://`.

### Sync

The **cve-refresher** syncs every feed into the `advisory_records` table before
its daily OSV pass, fetching only records that are new or whose `modified`
moved. A feed that cannot be fetched keeps the records of its last successful
sync; the OSV pass still runs. Run it once after enabling a feed so the worker
has records to match against:

```bash
make cve-refresh
```

Records that are withdrawn are ignored. Records whose id does not match their
file name are rejected. A record the index **no longer lists** is retired with
a tombstone row and stops matching; if the feed publishes it again it is
fetched again. An index that suddenly lists nothing while records are stored
is treated as a broken feed: the sync reports an error and keeps the records.

### Verdicts on findings already stored

Each refresh also re-evaluates the findings already stored for PURLs under a
feed's prefixes, so a verdict the feed publishes later applies without a
re-scan:

- **fixed** (the feed published the backport): the finding is removed from
  every SBOM that carries it.
- **not affected**: a VEX statement authored by the feed is recorded for every
  SBOM that carries the finding.

Only a feed authoritative for the PURL closes a stored finding, the same rule
as for new findings.

## How findings are decided

For each package, BOMHort evaluates the feed records that name its package
(`affected[].package.purl`, or an ecosystem it knows: Alpine, Wolfi,
Chainguard, Debian, Ubuntu, AlmaLinux, Rocky Linux, Red Hat, SUSE/openSUSE,
Mageia, openEuler, Azure Linux and the language ecosystems). A record whose
ecosystem names a release (`Alpine:v3.18`) only applies to a PURL whose
`distro` qualifier agrees; a PURL without the qualifier matches every release.

Versions are compared in the package's own order: **apk** (`-rN`, `_rc`,
`_p`), **dpkg** (epochs, `~`, `+deb12u1`) and **rpm** (`~`, `^`, `.el9_2`), plus
SemVer for `SEMVER` ranges. A record that cannot be evaluated (an `ECOSYSTEM`
range for an ecosystem without a comparator, an unparsable version) is
skipped and osv.dev decides — a version is never guessed.

Two records describe the same flaw when their ids, aliases or `related` ids
overlap. Feeds such as Wolfi's mint their own ids and list the CVE under
`related`; it is folded into the finding's aliases, so VEX statements and the
CVE column see it.

| Situation | Result |
|-----------|--------|
| Authoritative feed, version **in** the affected range | One finding, `advisory_source` = the feed, the feed's fixed version. Built on osv.dev's entry for the same flaw when there is one (severity, summary). |
| Authoritative feed, version **past** the fix (backport) | No finding. osv.dev's upstream match for the same flaw is dropped. |
| Authoritative feed says **not affected** | A finding with `advisory_status: not_affected` **and** a VEX statement authored by the feed (`role: advisory-feed`), so it is suppressed exactly like any OpenVEX statement. A newer statement of your own still wins. |
| Feed knows a flaw osv.dev does not | A finding under the feed's id. Severity is borrowed from osv.dev's record of the related CVE/GHSA when the feed has none. |
| Feed **without** prefixes | Only adds open findings (merged into osv.dev's when it is the same flaw). Its "fixed" and "not affected" verdicts are ignored. |
| Package no feed covers | osv.dev's result, unchanged. |

When two feeds speak about the same flaw, the one with the longest matching
prefix wins, then the one listed first.

## Status vocabulary

A feed may state a status per affected package or per component
(`affected[].ecosystem_specific.status`,
`affected[].ecosystem_specific.components[].status`, or the same under
`database_specific`). It is normalised (case, `_`/`-`/space) to:

| `advisory_status` | Accepted spellings | Effect |
|-------------------|--------------------|--------|
| `affected` | affected, vulnerable | Open finding. Also used when the version is in range and the feed states no status, or only `fixed` (a fix exists, this version lacks it). |
| `under_investigation` | under investigation, investigating | Open finding. |
| `pending_upstream_fix` | pending upstream fix | Open finding. |
| `fix_not_planned` | fix not planned, won't fix | Open finding. |
| `not_affected` | not affected, false positive | Suppressed via a feed-authored VEX statement. |
| `fixed` | fixed, resolved, patched | No finding, when the version is past the fix. |

An unrecognised status leaves the decision to the version range. A status on
an affected entry without ranges or versions applies to every version.

### Component location

`ecosystem_specific.components[]` entries with `purl`, `location` (or `path`)
and `architecture` (or `arch`) are stored with the finding and returned as
`advisory_components`, so the UI can say where in the image the vulnerable
file sits.

## API

`GET /api/v1/vulnerabilities`, `GET /api/v1/sboms/{id}/vulnerabilities` and
`GET /api/v1/projects/{name}/vulnerabilities` return `advisory_source` (`osv`
for findings osv.dev reported, including every finding stored before feeds
existed), `advisory_status` and `advisory_components`. See the
[API reference](../api-reference/).

## Licensing of feeds

Some vendor feeds carry a **non-commercial or otherwise restricted licence**.
BOMHort does not inspect or enforce it: enabling a feed is the operator's
decision, and checking its terms is the operator's responsibility.

## Limits

- Reconciliation only closes findings. A stored finding whose open status
  changes (`pending_upstream_fix` → `fix_not_planned`) keeps its first status,
  and a feed that later reverses a `not_affected` verdict leaves its earlier
  statement in place; `make re-scan` re-evaluates everything. Updating stored
  findings in place belongs to the vulnerability lifecycle work.
- Feeds are fetched without authentication; private feeds belong on `s3://`
  or `file://`.
