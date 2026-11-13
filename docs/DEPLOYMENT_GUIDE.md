# BOMHort – Kubernetes Deployment Guide

> **Updated:** 2026-03-13

## Prerequisites

- Kubernetes cluster (1.27+)
- [ClickHouse Operator](https://github.com/Altinity/clickhouse-operator) installed
- Helm 3.x
- Container images pushed to a registry (e.g. `ghcr.io/your-org/bomhort/*`)

### Supported ClickHouse versions

The supported floor is the **ClickHouse 24.8 LTS** line (#392). The chart installs `clickhouse/clickhouse-server:24.8.14.39`, pinned by digest so a re-pushed tag cannot change what gets installed. LTS because production should run a release that keeps receiving fixes.

CI runs the migrations and every API query against that exact image and against 24.12, the version `docker-compose.yml` uses for local development. A query that only works on the newer version fails CI instead of production. `deploy/helm/tests/test_clickhouse_version.py` fails if the chart, the CI matrix and docker-compose drift apart.

Running a newer ClickHouse via `clickhouse.installation.podTemplate.containerImage` works, but only 24.8 and 24.12 are tested. Older than 24.8 is unsupported.

### Chart source: published release or working tree

The examples below install from the working tree (`deploy/helm/bomhort/`). For a published release use the OCI chart — it deploys the images of exactly that release (leave `image.tag` unset):

```bash
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort --version 0.8.0 -n bomhort -f my-values.yaml
# Release candidate, for testing an upcoming release (installed only when asked for the exact version):
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort --version 0.8.0-rc.1 -n bomhort -f my-values.yaml
```

See [RELEASE.md](RELEASE.md#installing-a-release-candidate).

---

## 1. SBOMs – Getting Data Into the Cluster

BOMHort supports multiple SBOM ingestion methods. **S3 bucket ingestion** is the default and recommended approach — it requires no PVCs, no volume scheduling, and scales to any number of SBOMs. Volume-based alternatives are available for environments without S3.

### Option A: S3 Buckets (default, recommended)

Ingest SBOMs directly from S3-compatible buckets (AWS S3, MinIO, GCS). The Ingestion Watcher streams object listings with pagination (no full listing in memory) and the Parsing Workers fetch objects on-demand. No PVCs or git-sync sidecars required.

**Single public bucket:**

```yaml
s3:
  buckets: '[{"name":"my-org-sboms","region":"us-east-1"}]'
```

**Multiple buckets:**

```yaml
s3:
  buckets: '[{"name":"my-org-sboms","region":"us-east-1"},{"name":"platform-sboms","region":"us-east-1"}]'
```

**Private buckets with credentials:**

```yaml
s3:
  buckets: '[{"name":"my-private-bucket","region":"eu-west-1"}]'
  accessKey: ""   # pass via --set or K8s Secret
  secretKey: ""   # pass via --set or K8s Secret
```

```bash
helm install bomhort deploy/helm/bomhort/ -n bomhort -f my-values.yaml \
  --set s3.accessKey="AKIA..." \
  --set s3.secretKey="..."
```

**Per-bucket credentials** (different keys for different buckets):

```yaml
s3:
  buckets: '[{"name":"bucket-a","accessKey":"AKIA_A","secretKey":"..."},{"name":"bucket-b","accessKey":"AKIA_B","secretKey":"..."}]'
```

**MinIO (local S3-compatible):**

```yaml
s3:
  buckets: '[{"name":"sboms","endpoint":"minio.minio.svc:9000","usePathStyle":true,"useSSL":false}]'
  accessKey: "minioadmin"
  secretKey: "minioadmin"
```

**Advantages:**
- No PVC, no volume scheduling, no pod affinity constraints
- Streams object listings — handles 100k+ SBOMs without memory issues
- Jobs are enqueued in batches of 500 for efficient ClickHouse inserts
- SHA256 deduplication via streaming hash (object is never fully loaded into memory)
- Workers fetch objects on-demand — no shared filesystem needed
- Works with any S3-compatible storage (AWS, GCS, MinIO, Ceph, DigitalOcean Spaces)
- Can run alongside local filesystem ingestion

**Supported file patterns in S3:**

| Pattern | Type |
|---------|------|
| `*.spdx.json` | SPDX SBOM |
| `*_spdx.json` | SPDX SBOM (underscore variant) |
| `*.cdx.json`, `*_cdx.json` | CycloneDX SBOM |
| `*.spdx3.json`, `*_spdx3.json` | SPDX 3 JSON-LD SBOM (parsed via protobom) |
| `*.openvex.json` | OpenVEX statement |
| `*.vex.json` | OpenVEX statement |

Nested keys are fully supported (e.g. `k3s-io/helm-controller/0.16.14/k3s-io_helm-controller_0_16_14_spdx.json`).
Keys whose basename contains `_release_` (e.g. `cosign_3_1_3_release_spdx.json`) are skipped: that is the
layout the CNCF pipeline uses for a project's own per-binary release assets, which would otherwise appear as a
second SBOM with the same name for the same release.

### Option B: Seed Job (removed in 0.8.0)

Charts up to 0.7.x rendered a seed job whenever git-sync was disabled. Its
`git clone` had been commented out since March 2026, so it cloned nothing and
waited forever for a file nothing created — blocking `helm install --wait` for
S3 users too. It was removed in 0.8.0
([#391](https://github.com/seebom-labs/BOMHort/issues/391)).

Values that still contain a `seedJob` block now **fail the render** with a
message pointing here. Remove the block and pick one of the other options: S3
(Option A) for any size, git-sync (Option C) for small repos, or a PVC you
populate yourself (Option D) for large Git repos without S3.

> **Note:** When using a PVC, the SBOM volume is `ReadWriteOnce` (RWO). The Helm chart automatically adds pod affinity to co-schedule all workloads on the same node.

### Option C: git-sync (alternative for small repos < 1 GB)

A [git-sync](https://github.com/kubernetes/git-sync) sidecar continuously pulls SBOMs from a Git repo. Only suitable for small repos under ~1 GB.

```yaml
s3:
  buckets: ""    # disable S3

gitSync:
  enabled: true
  repo: "https://github.com/your-org/sbom-repo.git"
  branch: main
  depth: 1
  period: "6h"
  timeout: 120
```

> **⚠️  Limitation:** git-sync struggles with large repos. Past a few GB it times out or gets OOM-killed. Use S3 or a pre-populated PVC instead.

### Option D: Pre-populated PVC (manual / CI pipeline)

If your SBOMs are not in S3 or a Git repo:

```yaml
s3:
  buckets: ""
gitSync:
  enabled: false

sbomSource:
  pvcName: my-preloaded-sbom-pvc
```

Populate the PVC however you prefer, then trigger the Ingestion Watcher:
```bash
kubectl create job --from=cronjob/bomhort-ingestion-watcher manual-ingest -n bomhort
```

### Supported File Types

| Pattern | Type |
|---------|------|
| `*.spdx.json` / `*_spdx.json` | SPDX SBOM |
| `*.openvex.json` | OpenVEX statement |
| `*.vex.json` | OpenVEX statement |

Files are **deduplicated by SHA256 hash** — uploading the same file twice will not create duplicates.

> **Note:** VEX files are never truncated by `SBOM_LIMIT`.

---

## 2. Ownership – Labelling SBOMs by Cluster, Namespace and Project

Every ingested row carries three orthogonal ownership labels. All default to
`""` (unassigned), so an existing deployment that sets none of them keeps
behaving exactly as before.

| Label | Question it answers | Example | Typical cardinality | Owned by |
|-------|---------------------|---------|---------------------|----------|
| `cluster` | Where is it deployed? | `prod-eu` | 1–50 | Platform |
| `namespace` | Which tenant/team boundary inside the cluster? | `payments` | 10–500 | Platform / team |
| `project` | What is it / who owns it? | `payment-service` | 50–5000 | Dev teams |

They are stored as `LowCardinality(String)` columns on every core table
(`sboms`, `sbom_packages`, `vulnerabilities`, `license_compliance`,
`ingestion_queue`, `vex_statements`, `document_store`) by migrations `012`
(cluster) and `015` (namespace, project).

### Static values

The simplest setup: one BOMHort instance per cluster, everything labelled the
same.

```yaml
ownership:
  cluster: prod-eu
  namespace: ""
  project: ""
```

Per bucket, for the bucket-per-team case:

```yaml
s3:
  buckets:
    - name: team-payments-sboms
      region: eu-central-1
      cluster: prod-eu
      namespace: payments
    - name: team-search-sboms
      region: eu-central-1
      cluster: prod-eu
      namespace: search
```

### Deriving labels from the ingestion path

If your buckets are already organised by cluster/team/service, declare that
layout instead of repeating it per bucket:

```yaml
ownership:
  pathLayout: "cluster/namespace/project"
```

```
prod-eu/payments/payment-service/app.spdx.json
  -> cluster=prod-eu  namespace=payments  project=payment-service
```

Segments map **positionally** onto the leading path segments, relative to the
ingestion root — `SBOM_DIR` for local files, or a bucket's configured `prefix`
for S3 (the prefix is stripped first, so a bucket with `prefix: k3s-io/` does
not end up with `cluster=k3s-io`). The filename itself is never consumed.

| Segment | Meaning |
|---------|---------|
| `cluster` / `namespace` / `project` | Assign this path level to that dimension |
| `_` | Skip this level (it carries no meaning) |

Examples:

```yaml
pathLayout: "cluster/namespace/project"   # prod-eu/payments/svc/f.json
pathLayout: "namespace/project"           # payments/svc/f.json
pathLayout: "cluster/_/project"           # prod-eu/ignored/svc/f.json
pathLayout: "project/cluster"             # reordering is fine, it is positional
```

Per-bucket override, for fleets where one bucket is nested and another flat:

```yaml
s3:
  buckets:
    - name: nested-sboms
      pathLayout: "cluster/namespace/project"
    - name: flat-sboms
      namespace: legacy          # no layout: label it statically instead
```

{{% alert title="Explicit configuration always wins" color="info" %}}
Derivation only fills dimensions that are still empty after upload params,
per-bucket config and the instance defaults have been applied. If you set
`cluster: prod-eu` and the path also yields a cluster segment, the configured
value is kept — an operator who names a dimension means it, and silently
overriding that from directory structure would be impossible to debug.
{{% /alert %}}

**Tolerant on data, strict on config.** A path shallower than the layout fills
what it can and leaves the rest empty; a deeper one is matched from the left.
One oddly-placed file therefore cannot fail an ingestion run. A *malformed
layout* is the opposite — it is rejected at startup, because accepting it would
ingest the whole fleet unlabelled, and `DEFAULT ''` makes that mistake
indistinguishable from "genuinely unassigned". Only a full re-ingest would fix
it.

### Push-model uploads

The server cannot infer ownership from an uploaded body, so a pushing CI job
states it per request:

```bash
curl -X POST "https://bomhort.example.com/api/v1/sboms/upload?cluster=prod-eu&namespace=payments&project=payment-service" \
  -H "X-API-Key: $BOMHORT_API_KEY" \
  -H "X-Filename: payment-service.spdx.json" \
  --data-binary @payment-service.spdx.json
```

Any parameter you omit falls back to the instance default. A blank parameter
(`?namespace=`) is treated as omitted, so a client cannot accidentally blank
out a configured value.

### Applying the change

These are ingestion-time labels, not query-time ones: they are written when an
SBOM is parsed. Changing them affects **new** ingests only.

Run migration `015` before deploying the new images — the columns must exist
before any writer references them:

```bash
# The migrate Job runs automatically on helm upgrade; to apply manually:
kubectl exec -it deploy/bomhort-clickhouse -- \
  clickhouse-client --database=bomhort --multiquery \
  < db/migrations/015_add_namespace_project_columns.up.sql
```

{{% alert title="Rolling upgrades" color="warning" %}}
`ingestion_queue` is append-only — a status change is a new row, not an update
— so during a rolling upgrade an **old** parsing worker can claim a job that a
**new** ingestion watcher enqueued, and write the status row back without the
`namespace`/`project` columns it doesn't know about. Those rows land with
`''`, exactly as if the labels had never been set.

This is transient and harmless (the data is merely unlabelled, never wrong),
but if you care about complete labelling from the first ingest, let the worker
rollout finish before the next watcher run — or simply re-ingest afterwards.
The same applied to `cluster` when #131 shipped.
{{% /alert %}}

```bash
helm upgrade bomhort ./deploy/helm/bomhort -f my-values.yaml

# Re-label existing data by re-ingesting it:
kubectl create job --from=cronjob/bomhort-ingestion-watcher reingest-$(date +%s)
```

---

## 3. License Exceptions – Whitelisting Known Violations

License exceptions suppress specific license violations. They come from one
source: a chart-rendered ConfigMap (`licenseExceptions.custom`), your own
ConfigMap (`licenseExceptions.existingConfigMap`), or an https URL / `s3://`
object (`licenseExceptions.source`). The API Gateway and the workers re-read
them every `licenseExceptions.refreshInterval` (default `60s`), and stored
results of SBOMs already ingested are re-checked when they change. See
[License Exceptions](content/docs/license-exceptions/_index.md).

### Configure reviewed exceptions through Helm

The default list is **empty**. No CNCF approvals are downloaded or implied.
Use the [inactive example and migration guide](../examples/license-exceptions/README.md)
as a structure to adapt, not as pre-approved policy.

```bash
helm upgrade --install bomhort deploy/helm/bomhort -n bomhort \
  -f my-values.yaml --set-file licenseExceptions.custom=./my-exceptions.json
```

Alternatively, supply a YAML object in your values. To explicitly disable all approvals:

```yaml
licenseExceptions:
  enabled: true
  custom:
    version: "1.0.0"
    blanketExceptions: []
    exceptions: []
```

Both arrays are required. An empty file is authoritative; only a missing file
permits fallback to `SBOM_DIR/license-exceptions.json`. Malformed configuration
stops the worker and causes exception-related API requests to return HTTP 500.
`enabled: false` disables only the Helm mount, not the legacy file fallback.

Only rules with `status: "approved"` apply. Package rules match exact names or
complete slash-delimited suffixes. `project` is the exact SBOM document name;
empty or `"*"` means all projects. It never turns a package rule into a blanket
rule. Use `blanketExceptions` only for genuinely organization-wide approvals.
`scope` and dates are informational, not executable conditions.

### Apply changes and migrate

No rollout is needed: ConfigMaps are mounted as a directory, so edits reach
the running pods, which reload them. Direct ConfigMap edits work the same way
but are overwritten by the next Helm upgrade.

Remove the former `seedJob.cncfExceptionsURL` setting from existing values;
the chart rejects it with instructions to use `licenseExceptions.custom` instead.
Review old `"All CNCF Projects"` rules explicitly: that value now has only literal
project-name semantics, not global approval semantics.

**No re-scan is needed.** When the rules change, a worker enqueues a
`license_recheck` job that re-evaluates every stored compliance result and
rewrites the ones whose outcome changed — revoked approvals included. See
[Retroactive application](content/docs/license-exceptions/_index.md#retroactive-application).
License *policy* changes still need a re-scan.

### Argo CD (GitOps)

Set `cleanBatchJobs: false` and ignore the server-added Job labels
(`.spec.selector`, `.spec.template.metadata.labels`), otherwise Argo keeps
recreating the finished Jobs. The schema-migration Job is named after the hash of
its migrations, so a release with new migrations creates a new Job that runs,
and the old one is pruned. Charts up to 0.8.0-rc.1 named it after the Helm
revision, which is always `1` under Argo, so new migrations never ran. See the
[Argo CD Application example](content/docs/deployment/_index.md#argo-cd).

Store `licenseExceptions.custom` in Git-backed Helm values referenced by your
Application's `helm.valueFiles` or `helm.valuesObject`. For multi-source
Applications, configure the entry that renders the Helm chart.
See the [Argo CD example and deployment checklist](content/docs/license-exceptions/_index.md#argo-cd-gitops).

Argo only needs to render and sync the chart: changed exceptions alter the
ConfigMap only, the pods reload it, and stored results are re-checked. No Helm
upgrade hook, restart or re-scan is required. Keep edits in Git rather than
modifying the live ConfigMap.

Deploy a chart revision and API/worker images that include the fixes, and remove
`seedJob.cncfExceptionsURL` from all Argo values/parameters.

To keep a large reviewed file out of the Application, set
`licenseExceptions.existingConfigMap` (and/or `licensePolicy.existingConfigMap`)
to a ConfigMap managed by a second source; the chart then mounts it instead of
rendering its own. It is mutually exclusive with `custom`; content changes are
reloaded like the chart's own ConfigMap. See the [multi-source example](content/docs/license-exceptions/_index.md#reviewed-rules-from-their-own-source-existingconfigmap).

---

## 4. License Policy – Defining Permissive vs. Copyleft

The license policy defines which SPDX IDs are classified as **permissive** or **copyleft**. A declared license that is not listed is **unapproved** (a policy violation, not necessarily copyleft); only a missing license (`NOASSERTION`, `NONE`, empty) is **unknown**.

### Edit the default ConfigMap

```bash
kubectl edit configmap bomhort-license-policy
```

The format:

```json
{
  "permissive": [
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "Unlicense", "0BSD", "CC0-1.0", "Zlib"
  ],
  "copyleft": [
    "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only",
    "LGPL-2.1-only", "MPL-2.0", "EPL-2.0"
  ]
}
```

### Apply changes

After editing, restart **both** the API Gateway and Workers:

```bash
kubectl rollout restart deployment bomhort-api-gateway bomhort-parsing-worker
```

> **Note:** Policy changes affect new ingestions. To reclassify existing data,
> trigger a full re-scan (truncate tables + re-ingest).

---

## 5. Custom Theme – Rebranding the UI

The entire UI color scheme is defined via 60+ CSS Custom Properties and can be overridden **without rebuilding Angular**.

### Enable the theme ConfigMap

```yaml
# values-production.yaml
ui:
  customTheme:
    enabled: true
```

### Apply a custom theme

```bash
kubectl create configmap bomhort-custom-theme \
  --from-file=custom-theme.css=./my-theme.css \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment bomhort-ui
```

### Example theme file

```css
/* my-theme.css – override any CSS variable */
:root {
  --accent: #0066cc;
  --nav-bg: #002244;
  --nav-brand: #ff9900;
  --severity-critical: #ff4444;
  --license-permissive: #22c55e;
}
```

See `ui/src/assets/custom-theme.example.css` for all available variables.

> **Note:** The UI also includes a built-in **Dark Mode toggle** (top right of navbar). It persists the user's preference in `localStorage` and respects `prefers-color-scheme`.

---

## 6. Site Configuration – Customising UI Texts

All UI text content — brand name, page title, dashboard title/subtitle, description banner, and disclaimer — can be overridden **without rebuilding Angular** via a JSON config file (`ui-config.json`).

The Angular app loads `/ui-config.json` at startup. Missing keys gracefully fall back to the built-in BOMHort defaults.

### Enable the site config ConfigMap

```yaml
# values-production.yaml
ui:
  siteConfig:
    enabled: true
    content:
      brandName: "My Platform"
      pageTitle: "My Platform"
      dashboard:
        title: "Overview"
        subtitle: "Software Supply Chain Governance"
        description: "<strong>Welcome</strong> to our internal SBOM governance dashboard."
        disclaimer: "Internal use only. Data is provided as-is."
      footer:
        enabled: true
        text: "© 2026 My Company"
```

### Configurable fields

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `brandName` | string | `BOMHort` | Navbar brand text (top left) |
| `pageTitle` | string | `BOMHort` | Browser tab title (`<title>`) |
| `dashboard.title` | string | `Dashboard` | Dashboard page heading |
| `dashboard.subtitle` | string | `Software Bill of Materials — Governance Overview` | Dashboard subheading |
| `dashboard.description` | HTML string | *(BOMHort description)* | Description banner on dashboard. Supports HTML (links, bold, etc.) |
| `dashboard.disclaimer` | HTML string | *(default disclaimer)* | Disclaimer text at bottom of dashboard. Supports HTML. |
| `footer.enabled` | boolean | `false` | Show a footer bar below the main content |
| `footer.text` | string | `""` | Footer text content |

All fields are **optional**. Omitted keys use the built-in defaults.

### Apply changes

After editing the ConfigMap, restart the UI deployment:

```bash
kubectl rollout restart deployment bomhort-ui
```

### Local development (Docker Compose)

Edit the default config file directly:

```bash
vim ui/public/ui-config.json
docker compose up -d --force-recreate ui
```

Or point to a custom file via the `UI_CONFIG` environment variable:

```bash
UI_CONFIG=./my-ui-config.json docker compose up -d --force-recreate ui
```

> **Note:** The config file is served with `Cache-Control: no-cache` by nginx, so changes take effect on the next browser reload without clearing caches.

---

## 7. Full Deployment Example

### S3-based (recommended)

```bash
# 1. Install with S3 ingestion
helm install bomhort ./deploy/helm/bomhort \
  -f values-production.yaml \
  --set 's3.buckets=[{"name":"my-org-sboms","region":"us-east-1"},{"name":"platform-sboms","region":"us-east-1"}]' \
  --set s3.accessKey="AKIA..." \
  --set s3.secretKey="..." \
  --set parsingWorker.replicas=10 \
  --set ui.customTheme.enabled=true

# 2. Override license exceptions from a local file
kubectl create configmap bomhort-license-exceptions \
  --from-file=license-exceptions.json=./my-exceptions.json \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Override license policy from a local file
kubectl create configmap bomhort-license-policy \
  --from-file=license-policy.json=./my-policy.json \
  --dry-run=client -o yaml | kubectl apply -f -

# 4. Apply a custom theme
kubectl create configmap bomhort-custom-theme \
  --from-file=custom-theme.css=./my-theme.css \
  --dry-run=client -o yaml | kubectl apply -f -

# 5. Restart to pick up new configs
kubectl rollout restart deployment bomhort-api-gateway bomhort-parsing-worker bomhort-ui

# 6. Trigger initial ingestion manually
kubectl create job --from=cronjob/bomhort-ingestion-watcher bomhort-initial-ingest
```

### Volume-based (alternative)

```bash
helm install bomhort ./deploy/helm/bomhort \
  -f values-production.yaml \
  --set gitSync.repo=https://github.com/your-org/sbom-repo.git \
  --set parsingWorker.replicas=10
```

---

### API query limits

The API gateway sends three ClickHouse session settings with every query it runs, so one expensive request — a search over a large fleet, a project page over thousands of SBOMs — fails with an error instead of starving every other page and the ingestion pipeline (#344):

```yaml
apiGateway:
  queryLimits:
    maxExecutionTime: 30        # seconds per query (max_execution_time)
    maxMemoryUsage: 536870912   # bytes per query (max_memory_usage), 512 MiB
    maxThreads: 0               # threads per query (max_threads); 0 = server default
```

`0` leaves a setting unset, so the ClickHouse server or user-profile default applies. `maxMemoryUsage` is a plain byte count — `512Mi` fails the render — and the default is half of the chart's 1Gi ClickHouse memory limit: raise it together with `clickhouse.installation.podTemplate.resources.limits.memory`. A query that hits a limit returns `500` to that one caller; everything else keeps working.

Only the gateway is limited. The parsing workers, the CVE refresher and the migration job read the same ClickHouse but get none of these variables: their long inserts and full-table refreshes are the job, not an accident, and a limit sized for interactive pages would make them fail on large instances. If legitimate pages start hitting the limit, scale ClickHouse and raise the limit rather than removing it — and `apiGateway.replicas` adds request capacity, not per-query headroom.

Outside Helm, set `CLICKHOUSE_MAX_EXECUTION_TIME`, `CLICKHOUSE_MAX_MEMORY_USAGE` and `CLICKHOUSE_MAX_THREADS` on the gateway only. An invalid or negative value stops the gateway at startup.

## 8. Verifying the Deployment

```bash
# Check all pods are running
kubectl get pods -l app.kubernetes.io/name=bomhort

# Check ingestion progress
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/component=api-gateway -o name | head -1) \
  -- wget -qO- http://localhost:8080/api/v1/stats/dashboard

# View loaded policy
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/component=api-gateway -o name | head -1) \
  -- wget -qO- http://localhost:8080/api/v1/license-policy

# View active exceptions
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/component=api-gateway -o name | head -1) \
  -- wget -qO- http://localhost:8080/api/v1/license-exceptions
```

---

## 9. Local Development

Copy `.env.example` to `.env` and adjust:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `S3_BUCKETS` | *(empty)* | JSON array of S3 bucket configs (recommended). See `.env.example` for format. |
| `S3_BUCKET` | *(empty)* | Single S3 bucket name (simpler alternative to `S3_BUCKETS`). |
| `S3_ENDPOINT` | `s3.amazonaws.com` | S3 endpoint URL. |
| `S3_REGION` | `us-east-1` | AWS region. |
| `S3_ACCESS_KEY` | *(empty)* | Shared S3 access key. Leave empty for public buckets. |
| `S3_SECRET_KEY` | *(empty)* | Shared S3 secret key. |
| `SBOM_SOURCE_DIR` | `./sboms` | Path to local SBOM files (used alongside or instead of S3). |
| `SBOM_LIMIT` | `0` | Max SBOMs to enqueue per watcher run. `0` = unlimited. VEX files are never limited. |
| `SBOM_IGNORE_PREFIX` | `_` | Local files starting with this prefix are skipped during scanning. Empty = no skip. |
| `WORKER_REPLICAS` | `1` | Number of parallel parsing worker containers. Keep `1`: only Kubernetes serialises claims across workers |
| `WORKER_BATCH_SIZE` | `50` | Jobs claimed per polling cycle per worker |
| `SKIP_OSV` | `false` | Skip OSV vulnerability API calls. Set `true` for fast initial bulk load. |
| `ADVISORY_SOURCES` | — | OSV-format advisory feeds, comma-separated `name\|index[\|purl-prefix…]` entries (worker + cve-refresher). See [Advisory Feeds](content/docs/advisory-feeds/_index.md); check each feed's licence before enabling it. |
| `SKIP_GITHUB_RESOLVE` | `false` | Skip GitHub license resolution for packages with unknown licenses. |
| `SKIP_NPM_RESOLVE` | `false` | Skip npm registry license resolution for npm packages with unknown licenses. |
| `SKIP_NUGET_RESOLVE` | `false` | Skip NuGet license resolution for NuGet packages with unknown licenses. |
| `SKIP_DEPSDEV_RESOLVE` | `false` | Skip deps.dev fallback license resolution for supported package registries. |
| `SKIP_PACKAGIST_RESOLVE` | `false` | Skip Packagist license resolution for Composer packages with unknown licenses. |
| `SKIP_PYPI_RESOLVE` | `false` | Skip PyPI license resolution for Python packages deps.dev could not resolve. |
| `LICENSE_EXPRESSION_MODE` | *(empty → `strict`)* | Classification of compound SPDX expressions (`A AND B`, `A OR B`): `strict`, `permissive-wins` or `off`. Overrides `expressionMode` in `license-policy.json`. Re-scan after changing. |
| `EXCEPTIONS_FILE` | `/data/config/license-exceptions.json` | License exceptions file (falls back to `SBOM_DIR/license-exceptions.json` only if missing). |
| `EXCEPTIONS_SOURCE` | *(empty)* | Read the exceptions from an `https://` URL or `s3://bucket/key` instead of `EXCEPTIONS_FILE`. A missing remote document is an error; an unreachable one keeps the last rules that loaded. |
| `EXCEPTIONS_SOURCE_TOKEN` | *(empty)* | Bearer token sent to an `https://` `EXCEPTIONS_SOURCE` (private repositories). |
| `EXCEPTIONS_REFRESH_INTERVAL` | `60s` | How often the exceptions are re-read (Go duration, `0` = only at startup). Changes are re-applied to the stored results of all ingested SBOMs, no re-scan needed. |
| `EXTRA_FIELDS_FILE` | `/data/config/extra-fields.json` | Parsing worker: producer-written SBOM fields to recognise, e.g. a team contact. Missing file = off; invalid file = startup error. Compose mounts `sboms/extra-fields.json`. See the *Extra SBOM Fields* docs page. |
| `CUSTOM_THEME` | (example file) | Path to a custom CSS theme file for the UI |
| `UI_CONFIG` | `./ui/public/ui-config.json` | Path to a JSON file with UI text overrides (brand, titles, disclaimer) |

### Useful Make targets

| Command | Description |
|---------|-------------|
| `make dev` | Start full stack via Docker Compose |
| `make dev-down` | Stop all containers |
| `make dev-restart` | Restart with new `.env` values (keeps data) |
| `make dev-reset` | Destroy data volumes and restart fresh |
| `make re-ingest` | Re-trigger the Ingestion Watcher (scans for new files) |
| `make re-scan` | Wipe all data and re-process everything (e.g. after enabling OSV) |
| `make dev-status` | Show container status + ingestion progress |
| `make ch-shell` | Open a ClickHouse CLI |

---

## 10. Ingress – Exposing the API Externally

BOMHort includes an optional Ingress resource to expose the API Gateway (and optionally the UI) outside the cluster. The template is controller-agnostic — it works with any Ingress controller that implements the Kubernetes Ingress spec (Envoy Gateway, Contour, AWS ALB, etc.).

> **Note:** For the newer [Gateway API](https://gateway-api.sigs.k8s.io/), configure Gateway/HTTPRoute resources separately. The Helm chart provides the classic Ingress resource.

### Basic (HTTP only, Envoy Gateway)

```yaml
ingress:
  enabled: true
  className: eg
  hosts:
    - host: bomhort.example.com
      paths:
        - path: /api
          pathType: Prefix
        - path: /
          pathType: Prefix
          serviceSuffix: ui
```

### With TLS (cert-manager)

```yaml
ingress:
  enabled: true
  className: eg
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: bomhort.example.com
      paths:
        - path: /api
          pathType: Prefix
        - path: /
          pathType: Prefix
          serviceSuffix: ui
  tls:
    - secretName: bomhort-tls
      hosts:
        - bomhort.example.com
```

### Contour Example

```yaml
ingress:
  enabled: true
  className: contour
  annotations:
    projectcontour.io/tls-cert-namespace: cert-manager
  hosts:
    - host: bomhort.example.com
      paths:
        - path: /api
          pathType: Prefix
        - path: /
          pathType: Prefix
          serviceSuffix: ui
  tls:
    - secretName: bomhort-tls
      hosts:
        - bomhort.example.com
```

### API-only (headless, no UI)

```yaml
ingress:
  enabled: true
  className: eg
  hosts:
    - host: api.bomhort.example.com
      paths:
        - path: /
          pathType: Prefix
```

> **Security Note:** When exposing the API externally, ensure `apiGateway.auth.enabled: true` is set. Without authentication, all SBOM data is publicly accessible.

### AWS ALB Example

```yaml
ingress:
  enabled: true
  className: alb
  annotations:
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:...
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTPS":443}]'
  hosts:
    - host: bomhort.example.com
      paths:
        - path: /api
          pathType: Prefix
        - path: /
          pathType: Prefix
          serviceSuffix: ui
```

---

## Summary

| What | Where | How to Change |
|---|---|---|
| **SBOMs (S3)** | S3-compatible buckets | Configure `s3.buckets` in Helm values, CronJob streams objects |
| **SBOMs (volume)** | PVC via git-sync or populated by you | Push to Git (git-sync re-syncs) or copy into the PVC |
| **VEX files** | Same S3 bucket or directory as SBOMs | Place `*.openvex.json` or `*.vex.json` alongside SBOMs |
| **License Exceptions** | `bomhort-license-exceptions` ConfigMap, your own via `licenseExceptions.existingConfigMap`, or a URL / S3 object via `licenseExceptions.source` | Update the rules → pods reload within `refreshInterval` → stored results re-checked automatically |
| **License Policy** | `bomhort-license-policy` ConfigMap, or your own via `licensePolicy.existingConfigMap` | `kubectl edit configmap` → restart API + Workers |
| **Custom Theme** | `bomhort-custom-theme` ConfigMap | `kubectl create configmap` → restart UI |
| **Site Config** | `bomhort-ui-config` ConfigMap | Helm values `ui.siteConfig.content.*` → restart UI |
| **Dark Mode** | Built-in toggle (navbar) | User preference, stored in browser localStorage |
| **ClickHouse password** | `bomhort-secret` Secret | `kubectl edit secret` |
| **S3 credentials** | `bomhort-secret` Secret | `--set s3.accessKey=...` or `kubectl edit secret` |
| **Ingress** | `bomhort-ingress` Ingress resource | `ingress.enabled: true` + configure hosts/tls in Helm values |
