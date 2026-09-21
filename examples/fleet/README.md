# Demo Fleet – Cluster, Namespace & Project in Action

This directory is a **runnable example** of BOMHort's three ownership
dimensions (`cluster` → `namespace` → `project`). It exists so you can see the
fleet views with real data in under a minute, without a Kubernetes cluster and
without your own SBOMs.

## The layout is the configuration

The directory structure *is* the metadata:

```
examples/fleet/
├── prod-eu/                                   ← cluster
│   ├── payments/                              ← namespace
│   │   ├── payment-api/                       ← project
│   │   │   ├── payment-api-1.4.2.spdx.json    ← SPDX 2.3
│   │   │   └── payment-api.openvex.json       ← OpenVEX (not_affected)
│   │   └── ledger/
│   │       └── ledger-2.0.1.cdx.json          ← CycloneDX 1.5
│   ├── search/
│   │   └── query-service/
│   │       └── query-service-0.9.0.spdx.json  ← Python deps
│   └── platform/
│       └── ingress-gateway/
│           └── ingress-gateway-3.1.0.spdx.json
├── prod-us/
│   ├── payments/payment-api/payment-api-1.3.9.spdx.json      ← older version
│   └── platform/ingress-gateway/ingress-gateway-3.0.4.spdx.json
└── staging/
    ├── payments/payment-api/payment-api-1.5.0-rc.1.spdx.json ← newest version
    └── sandbox/legacy-report-tool/legacy-report-tool-0.2.0.spdx.json ← GPL/LGPL
```

Nothing inside the SBOM files carries the cluster or namespace. BOMHort derives
them at ingest from the object's position in the source, driven by one setting:

```bash
INGEST_PATH_LAYOUT="cluster/namespace/project"
```

The final path segment is always the filename and is never consumed by the
layout. Use `_` to skip a directory level that carries no meaning
(`cluster/_/project`). Unset — the default — means nothing is derived and every
dimension stays `""` (*unassigned*).

## What the fixtures deliberately cover

| Aspect | Where | Why it is in here |
|--------|-------|-------------------|
| Three clusters | `prod-eu`, `prod-us`, `staging` | The cluster list is only interesting with more than one |
| A namespace reused across clusters | `payments` in all three | Proves namespace names are **not** globally unique, which is why namespace endpoints take `?cluster=` |
| A namespace unique to one cluster | `search`, `sandbox` | Shows `cluster_count: 1` vs `cluster_count: 3` |
| Same project, three versions | `payment-api` 1.3.9 / 1.4.2 / 1.5.0-rc.1 | Feeds the Version Skew view; also shows the drift between prod and staging |
| Two SBOM formats | SPDX 2.3 + CycloneDX 1.5 | Format detection is automatic; ownership works the same for both |
| Real vulnerable versions | `lodash@4.17.15`, `golang.org/x/net@v0.17.0`, `gin@v1.6.0`, `urllib3@1.26.4` | OSV returns actual CVEs, so severity breakdowns are non-empty |
| Copyleft violation | `legacy-report-tool` (GPL-3.0-only, LGPL-3.0-or-later, GPL-2.0-only) | Puts a `copyleft` entry into the license breakdown of exactly one cluster |
| VEX with provenance | `payment-api.openvex.json` | Suppression inherits the ownership labels of the SBOM it is scoped to |
| Automated VEX (tool-generated) | `ledger-2.0.1.vexviper.openvex.json` | Real [VEXViper](https://github.com/seebom-labs/VEXViper) output (heuristic provider): `tooling`/`role` set, so the UI shows the *automated* badge; covers `under_investigation` and `fixed` |
| Human review supersedes automation | `ledger-2.0.1.review.openvex.json` | Newer timestamp, same `(vuln, purl)` as the VEXViper draft — latest-wins flips gin `GHSA-h395-qcrw-5vmq` to `not_affected` and the badge from automated to human |
| Alias matching | same pair | Alice's `GHSA-h395-qcrw-5vmq` statement also settles the `GO-2021-0052` row (same CVE) |
| `affected` + action statement | `ingress-gateway-ssh-advisory.openvex.json` | One document scoping the same advisory to *two* SBOMs (prod-eu 3.1.0 and prod-us 3.0.4) via product IRI + `subcomponents` |
| `fixed` status | `payment-api-1.5.0-rc.1.review.openvex.json` | Backported patch on the staging RC; also `GO-2024-2606`/`GHSA-mrww-27vc-gghv` in the VEXViper doc |
| Unassigned SBOM | `dev-workstation-scan-0.1.0.spdx.json` (repo root) | No leading directories, so the layout derives nothing — all three dimensions stay `""` and the SBOM lands in the *unassigned* bucket of every fleet view |
| Partially assigned SBOM | `prod-eu/toolbox-cli-1.1.0.spdx.json` | Only one path level: `cluster=prod-eu`, namespace and project stay `""` — a path shallower than the layout fills what it can |

Together the VEX fixtures exercise all four statuses (`not_affected`,
`affected`, `fixed`, `under_investigation`), SBOM-scoped resolution via
product IRIs and `subcomponents`, latest-wins collapsing, alias matching and
the automated-vs-human provenance badge. For the live upload path
(`POST /api/v1/sboms/upload?sbom_id=…`), point VEXViper at the stack:

```bash
vexviper generate --bomhort http://localhost:8080 \
  --sbom prod-eu/payments/ledger/ledger-2.0.1.cdx.json \
  --provider heuristic --upload --wait
```

Every file has unique content on purpose: the ingestion watcher deduplicates by
SHA256, so byte-identical copies in two clusters would be ingested **once**.

## Run it

```bash
make dev           # stack must be up
make demo-fleet    # wipes all data, then ingests examples/fleet with the layout set
make dev-status    # wait until the 15 jobs are "done"
make demo-fleet-verify
```

`make demo-fleet` blanks the S3 variables for this run, so it works even when
your `.env` points at real buckets. `make demo-fleet-down` puts the stack back
on your `.env` configuration.

Then open the **Fleet** tab at <http://localhost:8090/fleet>.

## What you get

`GET /api/v1/clusters` — "where is it deployed":

```json
{"name":"prod-eu","sbom_count":4,"package_count":14,"vuln_count":116}
{"name":"prod-us","sbom_count":2,"package_count":6,"vuln_count":71}
{"name":"staging","sbom_count":2,"package_count":8,"vuln_count":19}
```

`GET /api/v1/namespaces` — "who owns it", aggregated across the fleet. Note
`cluster_count`, which tells you `payments` is the same name in three clusters:

```json
{"name":"payments","cluster_count":3,"sbom_count":4,"vuln_count":89}
{"name":"platform","cluster_count":2,"sbom_count":2,"vuln_count":82}
{"name":"search","cluster_count":1,"sbom_count":1,"vuln_count":34}
{"name":"sandbox","cluster_count":1,"sbom_count":1,"vuln_count":1}
```

`GET /api/v1/namespaces?cluster=prod-eu` — the same view scoped to one cluster:

```json
{"name":"payments","cluster":"prod-eu","cluster_count":1,"sbom_count":2,"vuln_count":41}
{"name":"platform","cluster":"prod-eu","cluster_count":1,"sbom_count":1,"vuln_count":41}
{"name":"search","cluster":"prod-eu","cluster_count":1,"sbom_count":1,"vuln_count":34}
```

`GET /api/v1/fleet` — the whole hierarchy in one request (this is what the UI
tree renders):

```
prod-eu [4 SBOMs, 116 vulns]
  payments [2 SBOMs]
    ledger [1 SBOMs, 15 vulns]
    payment-api [1 SBOMs, 26 vulns]
  platform [1 SBOMs]
    ingress-gateway [1 SBOMs, 41 vulns]
  search [1 SBOMs]
    query-service [1 SBOMs, 34 vulns]
prod-us [2 SBOMs, 71 vulns]
  ...
staging [2 SBOMs, 19 vulns]
  payments [1 SBOMs]
    payment-api [1 SBOMs, 18 vulns]
  sandbox [1 SBOMs]
    legacy-report-tool [1 SBOMs, 1 vulns]
```

The copyleft violation only shows up where it actually runs — in `staging`:

```bash
curl -s http://localhost:8080/api/v1/clusters/staging/stats | jq .license_breakdown
# { "copyleft": 3, "permissive": 3 }
```

And the same namespace looks different depending on the scope you ask for:

```bash
curl -s http://localhost:8080/api/v1/namespaces/payments/stats | jq '{clusters, total_sboms}'
# { "clusters": ["staging","prod-us","prod-eu"], "total_sboms": 4 }

curl -s "http://localhost:8080/api/v1/namespaces/payments/stats?cluster=staging" | jq '{clusters, total_sboms}'
# { "clusters": ["staging"], "total_sboms": 1 }
```

## Other ways to label the same data

Path derivation is one of four mechanisms; they can be combined and are applied
in a fixed precedence order (first match wins):

1. Upload parameters — `POST /api/v1/sboms/upload?cluster=…&namespace=…&project=…`
2. Per-bucket values in `S3_BUCKETS` JSON (`"cluster"`, `"namespace"`, `"project"`)
3. Global `CLUSTER_NAME` / `NAMESPACE` / `PROJECT`
4. Path derivation via `INGEST_PATH_LAYOUT` (or per-bucket `pathLayout`)

Explicit configuration always outranks derivation — an operator who names a
dimension means it. See
[Ownership – Labelling SBOMs](../../docs/content/docs/deployment/_index.md)
for the full matrix, and the
[Fleet Views walkthrough](../../docs/content/docs/ownership/_index.md) for a
step-by-step guide including troubleshooting.

## Reproducing this without the bundled files

Point the stack at your own tree and declare its shape:

```bash
SBOM_SOURCE_DIR=/path/to/my-sboms \
INGEST_PATH_LAYOUT="cluster/namespace/project" \
docker compose up -d --force-recreate ingestion-watcher parsing-worker api-gateway
```

For S3, the layout applies to the object key **after** the bucket prefix is
stripped, so a bucket with `prefix: k3s-io/` does not label everything
`cluster=k3s-io`.

