---
title: "Deployment"
linkTitle: "Deployment"
type: docs
weight: 3
description: >
  Kubernetes deployment guide — S3 ingestion, Helm configuration, license governance, theming, and operations.
---

{{% pageinfo %}}
This guide covers deploying BOMHort to a Kubernetes cluster using Helm.
{{% /pageinfo %}}

## Prerequisites

- Kubernetes cluster (1.27+)
- [ClickHouse Operator](https://github.com/Altinity/clickhouse-operator) installed
- Helm 3.x
- Container images pushed to a registry (e.g. `ghcr.io/seebom-labs/bomhort/*`)

---

## 1. SBOMs – Getting Data Into the Cluster

BOMHort supports multiple SBOM ingestion methods. **S3 bucket ingestion** is the default and recommended approach — it requires no PVCs, no volume scheduling, and scales to any number of SBOMs.

### Option A: S3 Buckets (default, recommended)

Ingest SBOMs directly from S3-compatible buckets (AWS S3, MinIO, GCS). The Ingestion Watcher streams object listings with pagination and the Parsing Workers fetch objects on-demand.

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

**Private buckets with an existing Kubernetes Secret (recommended for production):**

Instead of passing credentials as plain Helm values, you can reference a pre-existing Kubernetes Secret — the same pattern used for ClickHouse and GitHub credentials:

```yaml
s3:
  buckets: '[{"name":"my-private-bucket","region":"eu-west-1"}]'
  credentialsSecret:
    enabled: true
    secretName: "my-s3-credentials"
    accessKeyKey: "S3_ACCESS_KEY"   # key inside the Secret
    secretKeyKey: "S3_SECRET_KEY"   # key inside the Secret
```

Create the Secret first:

```bash
kubectl create secret generic my-s3-credentials \
  --from-literal=S3_ACCESS_KEY="AKIA..." \
  --from-literal=S3_SECRET_KEY="..." \
  -n bomhort
```

This avoids storing credentials in Helm values files or command history.

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
- Works with any S3-compatible storage (AWS, GCS, MinIO, Ceph, DigitalOcean Spaces)

### Multi-Cluster Ingestion

BOMHort supports tagging data by **cluster** for multi-cluster visibility from a single instance. This is fully optional — omit all cluster config for single-instance mode.

{{% alert title="Changed in v0.7.0" color="warning" %}}
Earlier versions of this page showed `ingestionWatcher.env.CLUSTER_NAME`. That
key was **never read by the chart** — the watcher template has no `env`
passthrough, so the setting silently did nothing and all data stayed untagged.
Use the `ownership` block below, which is wired into the ConfigMap that every
workload consumes. If you were relying on the old snippet, re-ingest after
switching so existing rows pick up the label.
{{% /alert %}}

**Option 1: Global cluster name (one instance per cluster)**

```yaml
# values-prod-eu.yaml
ownership:
  cluster: "prod-eu"
```

Deploy one BOMHort instance per cluster, each with its own `cluster` value.

**Option 2: Per-bucket cluster assignment (one instance, multiple clusters)**

```yaml
# values.yaml — single watcher, multiple clusters
ownership:
  cluster: "default"   # fallback for buckets without explicit cluster

s3:
  buckets: |
    [
      {"name": "prod-eu-sboms", "region": "eu-west-1", "cluster": "prod-eu"},
      {"name": "prod-us-sboms", "region": "us-east-1", "cluster": "prod-us"},
      {"name": "staging-sboms", "cluster": "staging"},
      {"name": "shared-sboms"}
    ]
```

In this example:
- `prod-eu-sboms` → all SBOMs tagged as `prod-eu`
- `prod-us-sboms` → tagged as `prod-us`
- `staging-sboms` → tagged as `staging`
- `shared-sboms` → inherits `ownership.cluster` = `default`

**Priority:** per-bucket `cluster` > global `ownership.cluster` > empty (untagged)

Cluster is only one of the ownership dimensions — see
[Ownership](#2-ownership--labelling-sboms-by-cluster-namespace-project-and-tags)
for `namespace`, `project`, `tags` and deriving the triple from the ingestion
path.

### Option B: Seed Job

```yaml
s3:
  buckets: ""

gitSync:
  enabled: false

seedJob:
  sbomRepo: "https://github.com/my-org/sboms.git"
  sbomBranch: main
```

### Option C: git-sync (small repos < 1 GB)

```yaml
s3:
  buckets: ""

gitSync:
  enabled: true
  repo: "https://github.com/your-org/sbom-repo.git"
  branch: main
```

> **⚠️** git-sync struggles with large repos (multi-GB). Use S3 or the seed job instead.

### Option D: Pre-populated PVC

```yaml
s3:
  buckets: ""
gitSync:
  enabled: false

sbomSource:
  pvcName: my-preloaded-sbom-pvc
```

### Option E: Push-Model Uploads (CI/CD)

In addition to the pull-based methods above, CI/CD pipelines can push SBOM/VEX content directly via `POST /api/v1/sboms/upload` (see the [API Reference](/docs/api-reference/#post-apiv1sbomsupload)). This endpoint always requires `apiGateway.auth.enabled: true` — it self-enforces this independent of the global auth default, since a write endpoint open by default is a materially different risk than the read-only default.

**Recommended: dedicated S3 bucket.** Mark one bucket `"skipScan": true` — it becomes the upload target and is excluded from the ingestion watcher's periodic scan, so pushed objects are never rediscovered and double-enqueued:

```yaml
apiGateway:
  auth:
    enabled: true

s3:
  buckets: '[{"name":"my-org-sboms","region":"us-east-1"},{"name":"bomhort-pushed","region":"us-east-1","skipScan":true}]'
```

**Fallback: local filesystem.** If no `skipScan` bucket is configured, uploads fall back to `SBOM_DIR/pushed/` — this needs the API Gateway's `sbom-data` volume mounted read-write:

```yaml
apiGateway:
  auth:
    enabled: true

gitSync:
  enabled: false   # PVC mode required for a writable mount

sbomSource:
  writable: true
  # Only if apiGateway.replicas > 1 — ReadWriteOnce lets just one pod mount
  # read-write at a time, so every replica but one would fail to persist
  # uploads. Requires a storage class that supports ReadWriteMany (EFS,
  # Azure Files, most NFS-backed provisioners).
  accessMode: ReadWriteMany
```

If neither a `skipScan` bucket nor a writable `SBOM_DIR` is configured, the API Gateway logs a startup warning and `POST /api/v1/sboms/upload` returns `503 Service Unavailable` for every request rather than failing with a confusing storage error.

**Sizing the write budget.** The gateway's rate limit is request-based (100 requests / 10s per IP), not byte-based, so the effective per-IP write budget is `100 × MAX_UPLOAD_SIZE_MB` per 10 seconds — 5 GB at the 50 MB default. Set `apiGateway.maxUploadSizeMB` to the smallest value that fits your largest SBOM, especially if the endpoint is reachable from untrusted networks:

```yaml
apiGateway:
  maxUploadSizeMB: 25
```

### Original Document Store (Tier-2 Fidelity) {#original-document-store}

From v0.7 the parsing worker keeps the **original bytes** of every ingested SBOM so it can be reproduced byte-for-byte later (download, enriched export, re-signing — see [Architecture](/docs/architecture/#original-document-store-tier-2-fidelity)). ClickHouse only stores a reference and `sha256`; the bytes go to a blob store selected by `originalStore.backend`:

| `backend` | Where originals go | When to use |
|-----------|-------------------|-------------|
| `auto` (default) | `s3` if `s3.buckets` is set, else `fs` if `originalStore.fs.enabled`, else `none` | Almost always — follows your ingestion setup. |
| `s3` | `originalStore.s3.bucket` (default: first non-`skipScan` bucket) under `originalStore.s3.prefix` (default `_bomhort/originals/`) | Any deployment with object storage. Anything under `_bomhort/` is ignored by the ingestion watcher, so originals are never re-ingested. |
| `fs` | A dedicated PVC (`originalStore.fs.pvcName`) mounted read-write into the workers and read-only into the API gateway | Air-gapped / filesystem-only deployments. |
| `none` | Nowhere | Only deliberately — SBOMs ingested while disabled can **never** be recovered byte-for-byte. |

**S3 (default with buckets configured) — nothing to do.** Optionally pin a dedicated archive bucket:

```yaml
s3:
  buckets: '[{"name":"my-org-sboms","region":"us-east-1"},{"name":"bomhort-archive","region":"us-east-1","skipScan":true}]'

originalStore:
  s3:
    bucket: bomhort-archive
    prefix: originals/
```

**Filesystem (no S3):**

```yaml
originalStore:
  backend: fs
  fs:
    enabled: true
    storageSize: 20Gi
    # Required if parsingWorker.replicas > 1 (they all write) — needs a
    # ReadWriteMany-capable storage class (EFS, Azure Files, NFS, …).
    accessMode: ReadWriteMany
    storageClassName: nfs
```

Sizing: originals are **gzip-compressed** and stored once per `sbom_id` (a re-ingest replaces the previous blob instead of adding a second one). SBOM JSON typically shrinks 6–10×, so budget roughly **10–15 % of the raw size of your SBOM corpus** plus growth — a 50 GB corpus needs about 5–8 GB. `document_store.stored_size_bytes` tells you the exact footprint per SBOM (`SELECT sum(stored_size_bytes), sum(size_bytes) FROM document_store FINAL`). A worker that cannot reach the blob store fails the job (it is retried later) rather than ingesting without the original.

Performance: compression runs at `gzip.BestSpeed` and costs a few milliseconds per document on the worker; the gateway never decompresses for clients that accept gzip (all browsers, `curl --compressed`) — it passes the stored bytes through with `Content-Encoding: gzip`, so downloads of stored originals are usually *faster* than reading the source file.

**Volume ownership.** The images run as `nobody` (uid/gid 65534). A freshly provisioned PVC is normally root-owned, so the chart sets `podSecurityContext.fsGroup: 65534` (with `fsGroupChangePolicy: OnRootMismatch`) on the worker and gateway pods by default. The worker also probes the directory at startup and refuses to start with a `not writable by uid 65534 … set fsGroup / chown` error instead of failing every job. If your cluster forbids `fsGroup` (e.g. a restrictive admission policy) set `podSecurityContext: null` and make the volume writable for uid 65534 yourself. The same applies to `sbomSource.writable` for push uploads.

The download endpoint advertises a served original with `X-BOMHort-Original: true` and its digest in `ETag` / `X-BOMHort-SHA256` (always the sha256 of the *decoded* document, regardless of transfer encoding); SBOMs ingested before this feature fall back to the source file transparently.

---

## 2. Ownership – Labelling SBOMs by Cluster, Namespace, Project and Tags

{{% alert title="See it before you configure it" color="info" %}}
[Fleet Views]({{< relref "/docs/ownership" >}}) shows what the cluster and
namespace views look like, and ships a runnable demo fleet: `make demo-fleet`
wipes the database and ingests `examples/fleet/` (three clusters, five
namespaces, six projects) with `INGEST_PATH_LAYOUT=cluster/namespace/project`.
For the tag dimension there is `make demo-catalogue`, which ingests
`examples/catalogue/` (six projects across three tiers) with `TAGS` instead.
{{% /alert %}}

Every ingested row carries three orthogonal ownership labels, plus a list of
free-form [tags](#tags). All default to `""` / `[]` (unassigned), so an
existing deployment that sets none of them keeps behaving exactly as before.

| Label | Question it answers | Example | Typical cardinality | Owned by |
|-------|---------------------|---------|---------------------|----------|
| `cluster` | Where is it deployed? | `prod-eu` | 1–50 | Platform |
| `namespace` | Which tenant/team boundary inside the cluster? | `payments` | 10–500 | Platform / team |
| `project` | What is it / who owns it? | `payment-service` | 50–5000 | Dev teams |
| `tags` | Which grouping does it belong to? | `sandbox-applications` | 5–100 | Curator |

Stored as `LowCardinality(String)` columns on every core table (`sboms`,
`sbom_packages`, `vulnerabilities`, `license_compliance`, `ingestion_queue`,
`vex_statements`, `document_store`) by migrations `012` (cluster) and `015`
(namespace, project). `tags` is an `Array(String)` on `sboms` and
`ingestion_queue` (migration `022`).

### Static values

The simplest setup — one BOMHort instance per cluster, everything labelled the
same:

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
  → cluster=prod-eu  namespace=payments  project=payment-service
```

Segments map **positionally** onto the leading path segments, relative to the
ingestion root — `SBOM_DIR` for local files, or a bucket's configured `prefix`
for S3 (the prefix is stripped first, so a bucket with `prefix: k3s-io/` does
not end up with `cluster=k3s-io`). The filename itself is never consumed.

| Segment | Meaning |
|---------|---------|
| `cluster` / `namespace` / `project` | Assign this path level to that dimension |
| `_` | Skip this level (it carries no meaning) |

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

### Tags – grouping projects {#tags}

The three dimensions above describe where a workload *runs*. On a
catalogue-style instance — a foundation collecting SBOMs of its member
projects, a vendor publishing SBOMs for its product portfolio — nothing runs
in a cluster at all, so `cluster` and `namespace` stay structurally empty. That
instance still needs to say *"these 40 projects are sandbox applications"*.
Tags (#357) are that fourth, orthogonal dimension.

**Tags group projects, they do not replace them.** A project with three SBOMs
stays one project named after itself and merely carries the label — so a
catalogue keeps its per-project view *and* gains the grouping.

```yaml
# values.yaml
ownership:
  project: ""                                  # left to pathLayout / per-bucket
  tags: ["sandbox-applications", "platform"]
```

A list rather than a single value, because the groupings are genuinely
many-to-many: one project can be a sandbox application *and* an observability
tool. Per bucket and per upload:

```yaml
s3:
  buckets:
    - name: sandbox-sboms
      tags: ["sandbox-applications"]
    - name: graduated-sboms
      tags: ["graduated"]
```

```bash
curl -X POST "https://bomhort.example.com/api/v1/sboms/upload?tags=sandbox-applications,observability" \
  -H "X-API-Key: $BOMHORT_API_KEY" \
  -H "X-Filename: k2s.spdx.json" \
  --data-binary @k2s.spdx.json
```

{{% alert title="Tags merge, they do not override" color="info" %}}
This is the one place where tags deliberately break the ownership precedence
rules. `cluster`/`namespace`/`project` are *answers* — a more specific level
overrides a less specific one, because a document has exactly one owner. Tags
are *memberships*: a bucket adding `sandbox-applications` does not contradict
an instance-wide `platform`, so the document ends up with both. Values are
normalised on ingestion (trimmed, lowercased, deduplicated, sorted), so casing
in your values file is not load-bearing.
{{% /alert %}}

Read the groupings back data-driven — never hard-code a tag vocabulary, the
API reports exactly the tags that exist in the data:

```bash
curl -s https://bomhort.example.com/api/v1/tags
# [{"tag":"graduated","sbom_count":89,"project_count":12},
#  {"tag":"sandbox-applications","sbom_count":312,"project_count":41}]

curl -s "https://bomhort.example.com/api/v1/projects?tag=sandbox-applications"
```

Tags need migration `022`. See
[Fleet Views]({{< relref "/docs/ownership" >}}) for the full model and
`make demo-catalogue` for a runnable three-tier catalogue.

### Applying the change

These are ingestion-time labels, not query-time ones: they are written when an
SBOM is parsed. Changing them affects **new** ingests only.

Run migration `015` before deploying the new images — the columns must exist
before any writer references them. The `migrate` Job does this automatically on
`helm upgrade`.

```bash
helm upgrade bomhort ./deploy/helm/bomhort -f my-values.yaml

# Re-label existing data by re-ingesting it:
kubectl create job --from=cronjob/bomhort-ingestion-watcher reingest-$(date +%s)
```

{{% alert title="Rolling upgrades" color="warning" %}}
`ingestion_queue` is append-only — a status change is a new row, not an update
— so during a rolling upgrade an **old** parsing worker can claim a job that a
**new** ingestion watcher enqueued, and write the status row back without the
`namespace`/`project` columns it doesn't know about. Those rows land with `''`,
exactly as if the labels had never been set.

This is transient and harmless (the data is merely unlabelled, never wrong),
but if you care about complete labelling from the first ingest, let the worker
rollout finish before the next watcher run — or simply re-ingest afterwards.
The same applied to `cluster` when #131 shipped.
{{% /alert %}}

---

## 3. License Exceptions

License exceptions suppress specific license violations. They are stored in a **ConfigMap** that is mounted read-only into the API Gateway and Workers.

**No exceptions are enabled or downloaded by default.** Adapt the inactive
`examples/license-exceptions/license-exceptions.example.json` structure to your
organization and approve only reviewed rules. Configure it with your normal values:

```bash
helm upgrade --install bomhort deploy/helm/bomhort -n bomhort \
  -f my-values.yaml --set-file licenseExceptions.custom=./my-exceptions.json
```

`licenseExceptions.custom` also accepts a YAML object. An explicit empty template is:

```yaml
licenseExceptions:
  enabled: true
  custom:
    version: "1.0.0"
    blanketExceptions: []
    exceptions: []
```

Use camelCase `blanketExceptions` and `package` (not `blanket_exceptions` or
`purl_prefix`). Both arrays are required. Only `status: "approved"` or
`"allowlisted"` activates a rule — every other value, including `denied`,
`not-eligible` and typos, leaves the entry inactive. Package names match exactly
or as complete slash-delimited suffixes; `project` is an exact SBOM document
name (omit it, use `"*"`, or phrase it as `all <qualifier> projects` for all
projects). A project scope never removes a rule's package restriction. Files
exported from a published exception registry load as-is: the provenance fields
`results`, `issueUrl` and `packageUrl` are accepted and kept as audit metadata.
Audit fields such as `scope` and dates are informational, not automatically
enforced conditions.

Empty lists are authoritative and never load old approvals from the SBOM directory.
Fallback is allowed only when the primary file is absent. Invalid configuration
stops the worker and returns HTTP 500 from exception-related API endpoints.
Keep the ConfigMap enabled with empty lists to disable approvals; disabling the
mount alone does not disable the legacy SBOM-directory fallback.

Helm changes restart **both** API and workers via checksums. Direct ConfigMap
edits require manually restarting both deployments because of `subPath` mounts.
**Re-process existing SBOMs** to update stored compliance data, especially after
revoking approvals; a watcher run alone skips unchanged hashes. Back up data
before a full re-scan; development reset helpers delete ingested data.

For upgrades, remove `seedJob.cncfExceptionsURL` (also from retained Helm values)
and supply reviewed rules explicitly. `"All CNCF Projects"` is now a literal
project name, not a global approval. The default license classification policy
is unchanged.

### Argo CD (GitOps)

License exception updates also work when Argo CD renders the chart with
`helm template`: the rollout mechanism does **not** depend on running
`helm upgrade` or on a Helm upgrade hook.

Keep exceptions in your GitOps repository, either in a Helm values file referenced
by `spec.source.helm.valueFiles` or directly in `spec.source.helm.valuesObject`.
The following is a **fragment to merge into your existing Application**, not a
complete deployment manifest. For multi-source Applications, use the Helm chart
entry under `spec.sources[]` instead of `spec.source`.

```yaml
spec:
  source:
    helm:
      valuesObject:
        licenseExceptions:
          enabled: true
          custom:
            version: "1.0.0"
            blanketExceptions: []
            exceptions:
              - id: example-review-required
                package: example.org/your-team/your-library
                license: MPL-2.0
                project: your-exact-sbom-document-name
                status: pending
                approvedDate: ""
                comment: "Example only; requires organization approval."
```

This example grants **no approval**. Replace the placeholders, review the rule,
then explicitly set `status: approved` only after approval. To remove all
approvals, keep `enabled: true` and set both arrays to `[]`.

If your Argo CD Application CRD does not support `valuesObject`, use a committed
values file or the equivalent YAML in `helm.values`. Do not rely on a workstation's
local `--set-file` invocation: Argo must receive the configuration through its own
Git-backed Helm inputs. Avoid defining the same exceptions in multiple layers;
`valuesObject` overrides `valueFiles`, and Helm `parameters` override both.

**What happens on a change:**

1. Commit the reviewed values and let Argo refresh the desired manifests.
2. The rendered ConfigMap data changes, together with
   `spec.template.metadata.annotations.checksum/license-exceptions` on **both**
   the API Gateway and parsing-worker Deployments. Checksums are deterministic:
   unchanged configuration does not cause repeated rollouts.
3. At the next sync (manual or automated according to your Application policy),
   Argo applies the ConfigMap and both Deployment changes. Kubernetes rolls out
   new pods, refreshing the read-only `subPath` mounts. No manual restart is needed.

**Deployment checklist:**

- Point Argo at a chart revision **and API/worker image versions containing these
  fixes**. Updating only the chart does not update the matching/loading behavior
  in older binaries. Local, unpushed changes are not available to Argo.
- Remove `seedJob.cncfExceptionsURL` from all GitOps values and parameter overrides;
  the chart rejects this retired option with a migration hint.
- For an exception-only change, check the Argo diff for the ConfigMap and both
  Deployment checksum annotations. Sync all affected resources, not just the
  ConfigMap, and do not configure diff/sync rules that suppress the checksum changes.
- Wait for both Deployments to become healthy. Verify the configured rules through
  `GET /api/v1/license-exceptions` or the UI's **Configured Exceptions** tab.
- **Re-process existing SBOMs separately** to update stored compliance results.
  Argo syncing and pod rollouts do not perform a license re-scan; the ingestion
  watcher skips unchanged hashes. Plan and back up any full re-scan, particularly
  when revoking old approvals.

Do not edit the managed ConfigMap with `kubectl edit` as a normal configuration
workflow: the next Argo sync or self-heal can overwrite the change. Git is the
source of truth for the exceptions and their review history.

---

## 4. License Policy

The license policy defines which SPDX IDs are classified as **permissive**, **copyleft**, or **unknown**.

```bash
kubectl edit configmap bomhort-license-policy
kubectl rollout restart deployment bomhort-api-gateway bomhort-parsing-worker
```

---

## 5. Custom Theme

```yaml
ui:
  customTheme:
    enabled: true
```

```bash
kubectl create configmap bomhort-custom-theme \
  --from-file=custom-theme.css=./my-theme.css \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment bomhort-ui
```

---

## 6. Site Configuration

```yaml
ui:
  siteConfig:
    enabled: true
    content:
      brandName: "My Platform"
      pageTitle: "My Platform"
      dashboard:
        title: "Overview"
        subtitle: "Software Supply Chain Governance"
```

---

## 7. API Authentication (Optional)

API authentication is **fully optional and disabled by default**. When you expose the API Gateway externally (e.g. via Ingress), enable it to prevent unauthenticated access.

### When you need it

- ✅ API Gateway exposed via Ingress / public endpoint
- ✅ CI/CD pipelines pushing data (when upload endpoint lands in #135)
- ✅ Multi-tenant or shared deployments

### When you don't need it

- ❌ Internal cluster-only deployments (network policy is enough)
- ❌ Local development (`make dev`)
- ❌ Air-gapped environments behind a corporate VPN

### Two authentication modes (combinable)

**Mode 1: Service Token** — a single shared secret, ideal for upstream proxy/gateway integrations (Kong, oauth2-proxy, custom auth) **and** for letting the bundled UI authenticate against the API Gateway:

```yaml
apiGateway:
  auth:
    enabled: true
    serviceToken: "your-strong-random-secret-here"
```

> **UI ⇄ API Gateway:** When you deploy the bundled Angular UI alongside the API Gateway, the chart automatically injects the same `SERVICE_TOKEN` into the UI's nginx container. Nginx adds the `Authorization: Bearer …` header on every `/api/` proxy call before forwarding to the API Gateway, so the browser never sees the token. No extra configuration is required — flip `auth.enabled` to `true` and both sides are wired up.

Clients send the token via either header:

```bash
curl -H "Authorization: Bearer your-strong-random-secret-here" \
  https://bomhort.example.com/api/v1/stats/dashboard

# Or:
curl -H "X-Service-Token: your-strong-random-secret-here" \
  https://bomhort.example.com/api/v1/stats/dashboard
```

**Mode 2: API Keys** — multiple pre-shared keys for direct consumers (CI/CD pipelines, scripts):

```yaml
apiGateway:
  auth:
    enabled: true
    apiKeys: "ci-cd-pipeline-key,monitoring-key,backup-script-key"
```

Clients send the key via:

```bash
curl -H "X-API-Key: ci-cd-pipeline-key" \
  https://bomhort.example.com/api/v1/stats/dashboard
```

**Both modes can be enabled at the same time** — useful when a proxy uses the service token while direct CI/CD jobs use API keys.

### Using Kubernetes Secrets (recommended for production)

Reference a pre-existing Secret instead of inlining the token in Helm values — same pattern as `s3.credentialsSecret` and `clickhouse.userPasswordSecret`:

```bash
kubectl create secret generic bomhort-api-auth \
  --from-literal=SERVICE_TOKEN="$(openssl rand -hex 32)" \
  --from-literal=API_KEYS="key1,key2,key3" \
  -n bomhort
```

```yaml
apiGateway:
  auth:
    enabled: true
    existingSecret:
      enabled: true
      secretName: "bomhort-api-auth"
      serviceTokenKey: "SERVICE_TOKEN"   # key inside the Secret
      apiKeysKey: "API_KEYS"
```

Both the API Gateway and the UI nginx container automatically read `SERVICE_TOKEN` from this Secret. To rotate the token, update the Secret and restart both Deployments:

```bash
kubectl rollout restart deployment bomhort-api-gateway bomhort-ui
```

### Public endpoints (always accessible)

Even when authentication is enabled, the following endpoints are always reachable without credentials:

| Endpoint | Purpose |
|----------|---------|
| `/healthz` | Kubernetes health check (legacy, always 200) |
| `/livez` | Liveness probe (always 200 if process running) |
| `/readyz` | Readiness probe (pings ClickHouse, 503 if DB unavailable) |
| `OPTIONS *` | CORS preflight |

### Security notes

- Use **at least 32 random bytes** for the service token: `openssl rand -hex 32`
- Rotate tokens by restarting the API Gateway pod after updating the secret
- All comparisons are **constant-time** to prevent timing attacks
- Failed auth attempts are logged with sanitized client IPs
- The frontend UI bundle is publicly served by Nginx — auth applies to the API Gateway only

### Failure scenarios

| Scenario | Response |
|----------|----------|
| No credentials sent (auth enabled) | `401 Unauthorized` with `WWW-Authenticate: Bearer realm="bomhort"` |
| Invalid token/key | `401 Unauthorized` |
| `AUTH_ENABLED=true` but no `SERVICE_TOKEN` and no `API_KEYS` configured | All requests rejected (misconfiguration warning logged at startup) |

---

## 8. GitHub Token (License Resolution)

BOMHort resolves unknown package licenses (`NOASSERTION`) by querying the GitHub API. Without a token, you are limited to **60 requests per hour**. With a token, the limit increases to **5,000 req/h**.

**We strongly recommend setting a GitHub token for any production deployment.**

Create a [Personal Access Token (classic)](https://github.com/settings/tokens) with **no scopes required**.

```yaml
github:
  token: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

Or pass it securely via `--set`:

```bash
helm install bomhort deploy/helm/bomhort/ -n bomhort -f values.yaml \
  --set github.token="ghp_..."
```

See [FAQ: Should I use a GitHub token?](/docs/faq/#should-i-use-a-github-token) for more details and how to re-ingest after adding a token.

Licenses that are still unknown after the GitHub pass are looked up in the public package registries for **npm** (`registry.npmjs.org`) and **NuGet** (`api.nuget.org`). These lookups need no credentials and are rate-limited client-side (5 req/s per worker). They can be disabled individually, e.g. in air-gapped environments:

```yaml
parsingWorker:
  skipGitHubResolve: false
  skipNPMResolve: false
  skipNuGetResolve: false
```

See [Architecture: License Resolution](/docs/architecture/#license-resolution) for the exact resolution strategy.

---

## 9. Full Deployment Example

### S3-based (recommended)

```bash
helm install bomhort ./deploy/helm/bomhort \
  -f values-production.yaml \
  --set 's3.buckets=[{"name":"my-org-sboms","region":"us-east-1"}]' \
  --set s3.accessKey="AKIA..." \
  --set s3.secretKey="..." \
  --set parsingWorker.replicas=10
```

---

## 10. Headless Mode (API-Only)

For CI/CD integrations, custom dashboards, or environments where the Angular UI is not needed, BOMHort can be deployed in **headless mode**. This skips all UI-related resources (Deployment, Service, nginx ConfigMap) and reduces the cluster's resource footprint.

```yaml
# values-headless.yaml
ui:
  enabled: false

apiGateway:
  auth:
    enabled: true
    serviceToken: "my-ci-token"
```

With `ui.enabled: false`:
- No UI Deployment, Service, or ConfigMaps are rendered
- All 25 API endpoints remain fully functional
- The API Gateway is the only externally exposed component
- Pair with `apiGateway.auth.enabled: true` to secure access

This is ideal for:
- **CI/CD pipelines** that push SBOMs and query results programmatically
- **Grafana/custom dashboards** that consume the REST API directly
- **Resource-constrained clusters** where every pod counts
- **Air-gapped deployments** where the UI is served separately

---

## 11. Ingress – Exposing the API Externally

BOMHort includes an optional Ingress resource to expose the API Gateway (and optionally the UI) outside the cluster. The template is controller-agnostic — it works with any Ingress controller that implements the Kubernetes Ingress spec (Envoy Gateway, Contour, AWS ALB, etc.).

{{% alert title="Gateway API" color="info" %}}
For the newer [Gateway API](https://gateway-api.sigs.k8s.io/), configure Gateway/HTTPRoute resources separately. The Helm chart provides the classic Ingress resource.
{{% /alert %}}

### Basic (Envoy Gateway)

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

### Contour

```yaml
ingress:
  enabled: true
  className: contour
  hosts:
    - host: bomhort.example.com
      paths:
        - path: /api
          pathType: Prefix
        - path: /
          pathType: Prefix
          serviceSuffix: ui
```

### AWS ALB

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

### API-only (headless)

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

{{% alert title="Security" color="warning" %}}
When exposing the API externally, ensure `apiGateway.auth.enabled: true` is set. Without authentication, all SBOM data is publicly accessible.
{{% /alert %}}

---

## 12. Upgrading from v0.5.0 or Earlier (SeeBOM → BOMHort)

Starting with v0.6.0, the project was renamed from **SeeBOM** to **BOMHort**. This affects the Helm chart name, namespace, ClickHouse database name, and container image paths. Existing deployments running v0.5.0 or earlier need a one-time data migration.

### What changed

| Resource | v0.5.0 (old) | v0.6.0+ (new) |
|----------|--------------|----------------|
| Helm chart | `seebom` | `bomhort` |
| Namespace | `seebom` | `bomhort` |
| ClickHouse database | `seebom` | `bomhort` |
| ClickHouse host | `chi-seebom-clickhouse-seebom-cluster-0-0` | `chi-bomhort-clickhouse-bomhort-cluster-0-0` |
| Image repository | `ghcr.io/seebom-labs/seebom/*` | `ghcr.io/seebom-labs/bomhort/*` |
| PVC name | `seebom-sbom-data` | `bomhort-sbom-data` |
| OCI chart URL | `oci://ghcr.io/seebom-labs/seebom/charts/seebom` | `oci://ghcr.io/seebom-labs/bomhort/charts/bomhort` |

### Migration steps

The chart includes a built-in **data migration hook** that copies all ClickHouse tables from the old `seebom` instance to the new `bomhort` instance using ClickHouse's `remote()` function. It runs as a Helm post-install/post-upgrade Job.

#### 1. Keep the old deployment running

Do **not** delete the `seebom` namespace yet. The migration Job connects to the old ClickHouse cross-namespace.

#### 2. Create the password Secret in the new namespace

The migration Job needs access to the old ClickHouse password:

```bash
kubectl create namespace bomhort

# Copy the old ClickHouse password into the new namespace
OLD_PW=$(kubectl get secret clickhouse-password -n seebom -o jsonpath='{.data.password}' | base64 -d)
kubectl create secret generic clickhouse-migration-source \
  --from-literal=password="$OLD_PW" \
  -n bomhort
```

#### 3. Add the `cluster` column to the old database

v0.6.0 introduces a `cluster` column (migration 012). The data migration Job uses `SELECT * FROM remote(...)`, which requires matching schemas. Add the column to the source tables first:

```bash
kubectl exec -n seebom chi-seebom-clickhouse-seebom-cluster-0-0-0 -c clickhouse -- \
  clickhouse-client --database=seebom --password="$OLD_PW" --multiquery <<'EOF'
ALTER TABLE sboms ADD COLUMN IF NOT EXISTS cluster LowCardinality(String) DEFAULT '';
ALTER TABLE sbom_packages ADD COLUMN IF NOT EXISTS cluster LowCardinality(String) DEFAULT '';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cluster LowCardinality(String) DEFAULT '';
ALTER TABLE license_compliance ADD COLUMN IF NOT EXISTS cluster LowCardinality(String) DEFAULT '';
ALTER TABLE ingestion_queue ADD COLUMN IF NOT EXISTS cluster LowCardinality(String) DEFAULT '';
ALTER TABLE vex_statements ADD COLUMN IF NOT EXISTS cluster LowCardinality(String) DEFAULT '';
EOF
```

This is safe and non-destructive — existing rows get an empty default value.

#### 4. Deploy with migration enabled

```bash
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --version 0.7.0 \
  -n bomhort \
  -f your-values.yaml \
  --set dataMigration.enabled=true \
  --set dataMigration.source.host=chi-seebom-clickhouse-seebom-cluster-0-0.seebom.svc.cluster.local \
  --set dataMigration.source.port=9000 \
  --set dataMigration.source.database=seebom \
  --set dataMigration.source.user=default \
  --set dataMigration.source.passwordSecret.secretName=clickhouse-migration-source \
  --set dataMigration.source.passwordSecret.key=password
```

Or add this to your values file:

```yaml
dataMigration:
  enabled: true
  source:
    host: chi-seebom-clickhouse-seebom-cluster-0-0.seebom.svc.cluster.local
    port: 9000
    database: seebom
    user: default
    passwordSecret:
      secretName: clickhouse-migration-source
      key: password
```

#### 5. Monitor the migration

```bash
kubectl logs -n bomhort job/bomhort-data-migration-1 -f
```

The Job migrates these tables (skipping any that are empty or already populated in the target):
- `sboms`, `sbom_packages`, `vulnerabilities`, `license_compliance`
- `ingestion_queue`, `vex_statements`, `cve_refresh_log`
- `github_license_cache`, `github_repo_metadata`, `registry_license_cache`, `document_store`

Stored originals themselves (the blobs referenced by `document_store`) are not moved by the Job — they stay in their S3 prefix or PVC; make sure the new release points at the same bucket / volume.

The `dashboard_stats_mv` materialized view repopulates automatically.

#### 6. Verify and clean up

```bash
# Verify row counts match
kubectl exec -n bomhort $(kubectl get pod -n bomhort -l app.kubernetes.io/component=api-gateway -o name | head -1) \
  -- wget -qO- http://localhost:8080/api/v1/stats/dashboard

# Once satisfied, disable migration for future upgrades
helm upgrade bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  -n bomhort -f your-values.yaml \
  --set dataMigration.enabled=false

# Delete the old deployment when ready
kubectl delete namespace seebom
```

{{% alert title="Important" color="warning" %}}
The migration Job is **idempotent** — it skips tables that already contain data in the target database. It is safe to re-run, but it will not merge partial data. If you need to re-migrate a specific table, truncate it in the new database first.
{{% /alert %}}

### ArgoCD users

If you manage deployments via ArgoCD, create a new Application resource pointing to the new chart:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: bomhort
  namespace: argocd
spec:
  source:
    repoURL: ghcr.io/seebom-labs/bomhort/charts
    chart: bomhort
    targetRevision: "0.7.0"
    helm:
      values: |
        dataMigration:
          enabled: true
          source:
            host: chi-seebom-clickhouse-seebom-cluster-0-0.seebom.svc.cluster.local
            port: 9000
            database: seebom
            user: default
            passwordSecret:
              secretName: clickhouse-migration-source
              key: password
  destination:
    namespace: bomhort
```

After confirming data integrity, set `dataMigration.enabled: false` and remove the old `seebom` Application.

---

## 13. Verifying the Deployment

```bash
kubectl get pods -l app.kubernetes.io/name=bomhort

kubectl exec -it $(kubectl get pod -l app.kubernetes.io/component=api-gateway -o name | head -1) \
  -- wget -qO- http://localhost:8080/api/v1/stats/dashboard
```

---

## Summary

| What | Where | How to Change |
|---|---|---|
| **SBOMs (S3)** | S3-compatible buckets | Configure `s3.buckets` in Helm values |
| **SBOMs (volume)** | PVC via seed job or git-sync | Push to Git, seed job clones |
| **SBOMs (push/CI-CD)** | `skipScan` S3 bucket, or PVC | `POST /api/v1/sboms/upload` — see [Option E](#option-e-push-model-uploads-cicd) |
| **VEX files** | Same S3 bucket or directory | Place `*.openvex.json` alongside SBOMs |
| **License Exceptions** | ConfigMap | `licenseExceptions.custom` in Git → Helm upgrade / [Argo sync](#argo-cd-gitops) → API + worker rollout → re-process existing SBOMs |
| **License Policy** | ConfigMap | `kubectl edit configmap` → restart API + Workers |
| **Custom Theme** | ConfigMap | `kubectl create configmap` → restart UI |
| **Site Config** | ConfigMap | Helm values `ui.siteConfig.content.*` → restart UI |
| **S3 credentials** | Secret | `--set s3.accessKey=...` or `s3.credentialsSecret` (existing K8s Secret) |
| **API Authentication** | Env vars (Secret recommended) | `AUTH_ENABLED=true` + `SERVICE_TOKEN` and/or `API_KEYS`; off by default |
| **Headless Mode** | Helm value | `ui.enabled: false` — skips UI Deployment/Service/ConfigMaps |
| **Ingress** | Ingress resource | `ingress.enabled: true` + configure hosts/tls in Helm values |
