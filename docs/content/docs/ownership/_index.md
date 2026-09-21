---
title: "Fleet Views"
linkTitle: "Fleet Views"
type: docs
weight: 7
description: >
  Cluster, namespace and project views – what they look like, how to configure
  them, and a runnable example you can reproduce in one minute.
---

BOMHort tags every ingested record with three **orthogonal ownership
dimensions**:

| Dimension | Question it answers | Example | Typical cardinality |
|-----------|--------------------|---------|---------------------|
| `cluster` | Where is it deployed? | `prod-eu` | 1–50 |
| `namespace` | Which tenant / team boundary? | `payments` | 10–500 |
| `project` | What is it? | `payment-api` | 50–5000 |

All three are **optional** and default to `""` (*unassigned*). A single-instance
deployment works without configuring any of them — the fleet views simply show
one unassigned bucket.

{{% alert title="These are labels, not Kubernetes objects" color="info" %}}
BOMHort never talks to a Kubernetes API. `cluster` and `namespace` are plain
`LowCardinality(String)` columns that describe *where an artifact belongs*. They
happen to be named after Kubernetes concepts because that is how most fleets are
organised, but they work equally well for `region` / `business-unit` or any
other two-level ownership model.
{{% /alert %}}

## Tags: grouping projects

The three dimensions above all describe **where a workload runs**. That breaks
down for a *catalogue* instance — a foundation collecting SBOMs of its member
projects has no cluster and no namespace at all, yet still needs to say "these
40 projects are sandbox applications".

`tags` is that fourth, deployment-neutral dimension:

| | Answers | Example |
|---|---|---|
| `project` | *What is this?* | `k2s` |
| `tags` | *What kind of thing is it?* | `sandbox-applications` |

{{% alert title="Tags group projects — they do not replace them" color="warning" %}}
A tagged SBOM keeps its own `project`. If `k2s` has three SBOMs, `k2s` is one
project with three versions that additionally carries the
`sandbox-applications` label. The tag is how you find it; the project is still
what it is.

This is the distinction that makes a bucket laid out
`sandbox-applications/527/azure/unbounded.spdx.json` useful: without tags the
listing collapses the whole category into a single entry named after the
prefix. With them, the prefix becomes the grouping and the real projects stay
visible underneath it.
{{% /alert %}}

Tags are a **list**, because the groupings are genuinely many-to-many: a
project can be a sandbox application *and* an observability tool. They are also
**additive** across configuration levels, unlike the three dimensions above
which override — a bucket adding `sandbox-applications` does not contradict an
instance-wide `cncf`, so both are kept.

Values are normalised on ingestion (trimmed, lowercased, deduplicated), so
casing in configuration is not load-bearing.

### Configuring tags

```yaml
# Helm — every SBOM on this instance is a CNCF project
ownership:
  tags: ["cncf"]
```

```json
// S3_BUCKETS — one bucket per category, real projects from the path
[
  { "name": "cncf-sandbox",   "tags": ["sandbox-applications"], "pathLayout": "_/_/project" },
  { "name": "cncf-graduated", "tags": ["graduated"],            "pathLayout": "_/project"   }
]
```

```bash
# Push model — comma separated
curl -X POST "https://bomhort.example.com/api/v1/sboms/upload?project=k2s&tags=sandbox-applications" \
  -H "X-API-Key: $BOMHORT_API_KEY" --data-binary @sbom.spdx.json
```

Note how `pathLayout` and `tags` do different jobs in the bucket example:
`pathLayout` picks the **real project** out of the key, `tags` says **what kind
of project** it is.

### Reading tags back

```bash
# Which groupings exist? (empty on an untagged instance)
curl -s .../api/v1/tags
# [{"tag":"sandbox-applications","sbom_count":312,"project_count":41}]

# Projects within one grouping — still listed individually
curl -s ".../api/v1/projects?tag=sandbox-applications"
```

The UI derives its grouping filter from `/api/v1/tags`, so it renders whichever
groupings your data actually uses — and hides the filter entirely when nothing
is tagged.

### A grouping is a link

The filter lives in the URL, so it is something you can send to someone:

```
https://bomhort.example.com/projects?tag=sandbox-applications
https://bomhort.example.com/projects?tag=graduated&search=prom
```

Opening such a link comes up with the chip already selected and the listing
already filtered — "show me all sandbox applications" is a URL, not a click
path. Browser back/forward step through groupings, and a reload keeps the
filter. Clearing a filter drops the parameter rather than leaving `?tag=`
behind, so an unfiltered list is always a clean `/projects`.

Typing in the search box replaces the history entry instead of adding one,
otherwise a single back press would walk back one character at a time;
choosing a grouping is a deliberate act and does get its own entry.

### The Fleet tab appears only when it means something

The navigation asks `/api/v1/clusters` on load and shows the **Fleet** tab only
once at least one cluster is *named*. A catalogue instance — a foundation
publishing SBOMs for its projects, where nothing runs anywhere — reports a
single unnamed cluster and gets no Fleet tab at all, rather than a link into a
tree whose only root has no name. Ingest one SBOM carrying a cluster label and
the tab appears by itself, with no configuration change.

## What the views look like

### In the UI

The **Fleet** page (`/fleet`) renders the whole hierarchy as a tree:

```
prod-eu                            4 SBOMs   116 vulns
  payments                         2 SBOMs
    ledger                         1 SBOM     15 vulns
    payment-api                    1 SBOM     26 vulns
  platform                         1 SBOM
    ingress-gateway                1 SBOM     41 vulns
  search                           1 SBOM
    query-service                  1 SBOM     34 vulns
prod-us                            2 SBOMs    71 vulns
staging                            2 SBOMs    19 vulns
```

Selecting a cluster or namespace opens a detail panel with the severity
breakdown (critical / high / medium / low) and the license distribution for
exactly that scope. Clicking a project jumps into the SBOM explorer filtered to
that project. Unassigned dimensions are rendered as `(unassigned)` rather than
hidden — a large unassigned bucket is the clearest signal that the ingestion
labelling is misconfigured.

The SBOM list additionally shows each SBOM's cluster / namespace / project as
badges.

### Over the API

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/v1/fleet` | Full `cluster → namespace → project` tree in one response |
| GET | `/api/v1/clusters` | Cluster list with summary stats |
| GET | `/api/v1/clusters/{name}/stats` | Severity + license breakdown for one cluster |
| GET | `/api/v1/clusters/{name}/sboms` | Paginated SBOMs of one cluster |
| GET | `/api/v1/namespaces?cluster=` | Namespace list, optionally scoped to a cluster |
| GET | `/api/v1/namespaces/{name}/stats?cluster=` | Severity + license breakdown for one namespace |
| GET | `/api/v1/namespaces/{name}/sboms?cluster=` | Paginated SBOMs of one namespace |

See the [API Reference]({{< relref "/docs/api-reference" >}}#clusters) for full
request and response schemas.

{{% alert title="Why namespace endpoints take a cluster filter" color="warning" %}}
A cluster name is unique. A **namespace name is not** — `payments` exists in
`prod-eu`, `prod-us` and `staging` at the same time and usually belongs to the
same team, but not always. Without `?cluster=`, namespace endpoints aggregate
across the fleet and report `cluster_count` so you can see the ambiguity. With
`?cluster=`, you get exactly one cluster's slice. Pick the scope deliberately.
{{% /alert %}}

## How to configure it

There are four mechanisms. They can be combined, and are applied in this
precedence order — **the first match wins**:

| # | Mechanism | Use when |
|---|-----------|----------|
| 1 | Upload parameters: `POST /api/v1/sboms/upload?cluster=…&namespace=…&project=…` | Push model: the CI job knows where the artifact belongs |
| 2 | Per-bucket values in `S3_BUCKETS` JSON | One bucket per team or per cluster |
| 3 | Global `CLUSTER_NAME` / `NAMESPACE` / `PROJECT` | One BOMHort instance per cluster |
| 4 | Path derivation: `INGEST_PATH_LAYOUT` (or per-bucket `pathLayout`) | The source is already organised hierarchically |

Explicit configuration always outranks derivation. An operator who names a
dimension means it; silently overriding that from directory structure would be
impossible to debug.

### 1. Path derivation (`INGEST_PATH_LAYOUT`)

```bash
INGEST_PATH_LAYOUT="cluster/namespace/project"

# prod-eu/payments/payment-api/payment-api-1.4.2.spdx.json
#   → cluster=prod-eu  namespace=payments  project=payment-api
```

Rules:

* Segments map **positionally** onto the leading path segments, relative to the
  ingestion root (`SBOM_DIR`, or a bucket's `prefix`, which is stripped first —
  otherwise a bucket with prefix `k3s-io/` would label everything
  `cluster=k3s-io`).
* The **filename is never consumed**. A file directly at the root yields nothing.
* Valid tokens: `cluster`, `namespace`, `project`, and `_` to skip a level that
  carries no meaning (`cluster/_/project`).
* A duplicate or unknown token is a **startup error**, not a silent fallback.
* A path shallower than the layout fills what it can; a deeper path is matched
  from the left. One oddly-placed file must never fail an ingestion run.
* Unset (the default) means **no derivation at all**.

```bash
INGEST_PATH_LAYOUT="cluster/namespace/project"   # prod-eu/payments/svc/f.json
INGEST_PATH_LAYOUT="namespace/project"           # payments/svc/f.json
INGEST_PATH_LAYOUT="cluster/_/project"           # prod-eu/2026-09/svc/f.json
```

### 2. Static labels (global or per bucket)

```yaml
# Helm values — the whole instance is one cluster
ownership:
  cluster: prod-eu
  namespace: ""
  project: ""
```

```json
// S3_BUCKETS — one watcher, several teams
[
  { "name": "payments-sboms", "cluster": "prod-eu", "namespace": "payments" },
  { "name": "search-sboms",   "cluster": "prod-eu", "namespace": "search"  },
  { "name": "mixed-sboms",    "pathLayout": "cluster/namespace/project"    }
]
```

### 3. Push model (CI/CD)

```bash
curl -X POST "https://bomhort.example.com/api/v1/sboms/upload?cluster=prod-eu&namespace=payments&project=payment-api" \
  -H "X-API-Key: $BOMHORT_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @sbom.spdx.json
```

A parameter that is absent **or blank** inherits the instance default, so a
client cannot accidentally blank out a configured value.

### Docker Compose

All three services read the same variables:

```bash
# .env
CLUSTER_NAME=
NAMESPACE=
PROJECT=
INGEST_PATH_LAYOUT=cluster/namespace/project
SBOM_SOURCE_DIR=./examples/fleet
```

## Try it in one minute

The repository ships a runnable demo fleet at
[`examples/fleet/`](https://github.com/seebom-labs/bomhort/tree/main/examples/fleet):
three clusters, five namespaces, six projects, two SBOM formats, one OpenVEX
document and one deliberate copyleft violation.

```bash
make dev                  # stack up
make demo-fleet           # wipe all data + ingest examples/fleet with the layout set
make dev-status           # wait for the 9 jobs to reach "done"
make demo-fleet-verify    # print the cluster / namespace / fleet views
make demo-fleet-down      # back to your own .env configuration
```

Expected output of `make demo-fleet-verify`:

```
=== GET /api/v1/clusters ===
{"name":"prod-eu","sbom_count":4,"package_count":14,"vuln_count":116}
{"name":"prod-us","sbom_count":2,"package_count":6,"vuln_count":71}
{"name":"staging","sbom_count":2,"package_count":8,"vuln_count":19}

=== GET /api/v1/namespaces ===
{"name":"payments","cluster_count":3,"sbom_count":4,"vuln_count":89}
{"name":"platform","cluster_count":2,"sbom_count":2,"vuln_count":82}
{"name":"search","cluster_count":1,"sbom_count":1,"vuln_count":34}
{"name":"sandbox","cluster_count":1,"sbom_count":1,"vuln_count":1}
```

Vulnerability counts come from live OSV lookups and will drift over time; the
shape is what matters.

### …or the catalogue, if you have no cluster

The counterpart demo is [`examples/catalogue/`](https://github.com/seebom-labs/bomhort/tree/main/examples/catalogue):
seven SBOMs across six projects in three maturity tiers, with no cluster and no
namespace anywhere.

```bash
make dev                     # stack up
make demo-catalogue          # wipe + ingest all three tiers, each with its own tag
make demo-catalogue-verify   # print the tag / project views
make demo-catalogue-down     # back to your own .env configuration
```

Expected output of `make demo-catalogue-verify`:

```
=== GET /api/v1/tags ===
{"tag":"graduated","sbom_count":1,"project_count":1}
{"tag":"incubating","sbom_count":2,"project_count":2}
{"tag":"sandbox-applications","sbom_count":4,"project_count":3}

=== GET /api/v1/projects?tag=sandbox-applications ===
  k2s [2 SBOMs] tags=["sandbox-applications"]
  kuadrant [1 SBOMs] tags=["sandbox-applications"]
  kubewarden [1 SBOMs] tags=["sandbox-applications"]
```

Note `k2s`: it ships two SBOMs and is listed **once**, as one project. That is
the invariant — tags group projects, they never replace them. And
`/api/v1/clusters` returns a single unnamed entry, because on this instance
nothing runs in a cluster at all.

## How the labels reach the data

```
┌──────────────────────┐
│ ingestion-watcher    │  derives / applies ownership per file
│  ingestion_queue.{cluster,namespace,project}
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ parsing-worker       │  copies the job's labels onto every row it writes
│  sboms, sbom_packages, vulnerabilities,
│  license_compliance, vex_statements, document_store
└──────────────────────┘
```

Because the labels are carried on **every** table, a scope filter is a single
`WHERE` on a `LowCardinality` column — no joins, no post-filtering. A VEX
statement inherits the labels of the SBOM it is scoped to, so a suppression in
`prod-eu/payments` never silently hides a finding in `staging`.

Schema: `cluster` arrived with migration `012` (#131), `namespace` and `project`
with migration `015` (#138, #57). All three are
`LowCardinality(String) DEFAULT ''` and deliberately **not** part of any
`ORDER BY`, so adding them required no table rebuild.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Everything is `(unassigned)` | No labelling configured, or ingested before it was | Set the layout / static values and re-ingest (`make re-scan`) |
| One dimension is empty, the others are not | Layout too short, or the path is shallower than the layout | Check the layout against a real object key |
| Every SBOM has `cluster=<bucket prefix>` | Prefix not stripped — a stale BOMHort version | Upgrade; the prefix is stripped before the layout is applied |
| Namespace numbers look too high | Aggregated across clusters | Add `?cluster=` or look at `cluster_count` |
| Labels do not change after editing the config | The labels are written at ingest, not at query time | Re-ingest; `make re-scan` (Compose) or `make kind-reingest` (Kind) |
| Container startup fails with `invalid INGEST_PATH_LAYOUT` | Duplicate or unknown segment | Valid tokens are `cluster`, `namespace`, `project`, `_` |

## See also

* [Architecture – Ownership Data Model]({{< relref "/docs/architecture" >}}#ownership-data-model)
* [Deployment – Labelling SBOMs by Cluster, Namespace and Project]({{< relref "/docs/deployment" >}})
* [API Reference – Clusters & Namespaces]({{< relref "/docs/api-reference" >}}#clusters)

