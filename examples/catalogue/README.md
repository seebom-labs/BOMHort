# Demo Catalogue – Projects & Tags in Action

This directory is a **runnable example** of BOMHort's second operating mode:
a *catalogue* of projects that do not run anywhere in particular.

It is the counterpart to [`../fleet/`](../fleet/). Both are real, ingestible
data — they differ in which dimensions carry meaning.

## Two modes, two sets of dimensions

|                        | Fleet (`../fleet/`)                | Catalogue (this directory)          |
|------------------------|------------------------------------|-------------------------------------|
| Who runs it            | Companies operating on Kubernetes  | Foundations, vendors, product lines |
| Question answered      | *Where does this workload run?*    | *What kind of project is this?*     |
| `cluster` / `namespace`| The core of the model              | Structurally empty, forever         |
| `project`              | A workload inside a namespace      | The unit of the catalogue           |
| `tags`                 | Optional extra labelling           | The grouping dimension              |

A foundation publishing SBOMs for its projects has no cluster to speak of.
Forcing its maturity levels into `namespace` would overload Kubernetes
semantics with something that is not Kubernetes at all — so grouping gets its
own dimension: **tags**.

## Tags group projects, they do not replace them

This is the invariant the example exists to demonstrate, and `k2s` is here to
make it visible:

```
examples/catalogue/
├── sandbox/
│   ├── k2s/                                       ← ONE project …
│   │   ├── k2s-0.3.0.spdx.json                    ←   … with two SBOMs
│   │   └── k2s-0.4.0.spdx.json                    ←   (x/net v0.17.0 → v0.23.0)
│   ├── kuadrant/
│   │   └── kuadrant-1.0.2.spdx.json
│   └── kubewarden/
│       └── kubewarden-1.11.0.spdx.json
├── incubating/
│   ├── keda/keda-2.14.0.spdx.json
│   └── cilium/cilium-1.15.3.spdx.json
└── graduated/
    └── prometheus/prometheus-2.51.0.spdx.json
```

After ingestion `k2s` is **one project with two SBOMs** — not two projects, and
not a project named "sandbox". It additionally carries the tag
`sandbox-applications`, which is what lets you ask for "all sandbox
applications" without changing what `k2s` *is*.

## The layout is the configuration

Nothing inside the SBOM files names the project or the maturity level. Both are
assigned at ingest:

```bash
INGEST_PATH_LAYOUT="project"   # sandbox/k2s/k2s-0.4.0.spdx.json → project=k2s
TAGS="sandbox-applications"    # applied to every document in this run
```

Note what is *not* in the layout: no `cluster`, no `namespace`. They stay `''`,
which is a valid steady state — the fleet views simply have nothing to show,
and a catalogue instance can hide them entirely.

## Why one watcher run per tier

`TAGS` is instance-wide, so the demo ingests each maturity level in its own
run, each with its own `SBOM_SOURCE_DIR` and `TAGS`. That mirrors how this
looks in production, where each tier is typically its own bucket:

```json
S3_BUCKETS='[
  {"name":"cncf-sandbox",    "pathLayout":"project", "tags":["sandbox-applications"]},
  {"name":"cncf-incubating", "pathLayout":"project", "tags":["incubating"]},
  {"name":"cncf-graduated",  "pathLayout":"project", "tags":["graduated"]}
]'
```

Per-bucket tags are **merged** with the instance-wide `TAGS`, not overridden —
a bucket saying "these are sandbox apps" does not contradict an instance-wide
"all of this is CNCF". Tags are many-to-many by nature: a project can be both
`graduated` and `security-critical`.

## Run it

```bash
make demo-catalogue          # wipe, ingest all three tiers
make demo-catalogue-verify   # print the tag and project views
```

## What to look at

```bash
# Which groupings exist, and how far each reaches.
curl -s localhost:8080/api/v1/tags | jq
# → [{"tag":"sandbox-applications","sbom_count":4,"project_count":3}, …]

# All sandbox applications — three separate projects, k2s with 2 SBOMs.
curl -s 'localhost:8080/api/v1/projects?tag=sandbox-applications' | jq '.data[].project_name'
# → "k2s", "kuadrant", "kubewarden"
```

The tag list is **data-driven**: an instance that sets no tags gets `[]` back,
and the UI hides the grouping affordance entirely rather than showing an empty
filter. Nothing about "sandbox-applications" is hardcoded anywhere — it is just
what this demo happens to put in `TAGS`.

