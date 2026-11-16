# BOMHort – Kubernetes Deployment Examples

Example Helm values for deploying BOMHort to a real Kubernetes cluster
(EKS, GKE, AKS, self-hosted, etc.).

## Prerequisites

- Kubernetes ≥ 1.27
- Helm ≥ 3.12
- [Altinity ClickHouse Operator](https://github.com/Altinity/clickhouse-operator) installed

## Quick Start

```bash
# 1. Install ClickHouse Operator
kubectl apply -f https://raw.githubusercontent.com/Altinity/clickhouse-operator/master/deploy/operator/clickhouse-operator-install-bundle.yaml

# 2. Create namespace + secret
kubectl create namespace bomhort
kubectl create secret generic bomhort-secret -n bomhort \
  --from-literal=CLICKHOUSE_PASSWORD='<your-password>' \
  --from-literal=GITHUB_TOKEN='<your-github-pat>'

# 3. Customise values
cp examples/kubernetes/values-production.yaml my-values.yaml
vi my-values.yaml

# 4. Install (with S3 ingestion)
helm install bomhort deploy/helm/bomhort/ \
  -n bomhort -f my-values.yaml \
  --set 's3.buckets=[{"name":"my-org-sboms","region":"us-east-1"}]'

# Or from the OCI registry:
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --version 0.7.0 -n bomhort -f my-values.yaml
```

## Values Files

| File | SBOM Source | Best For |
|------|-------------|----------|
| `values-production.yaml` | **S3 buckets** (default) or a pre-populated PVC (fallback) | Production, large-scale ingestion |
| `values-minimal.yaml` | **S3 buckets** (default) or git-sync (PVC fallback) | Small repos (< 1 GB), CI/staging |
| `values-headless.yaml` | S3 buckets | API-only deployments without the UI |
| `values-cncf.yaml` | S3 bucket (CNCF project SBOMs) | The public CNCF catalogue instance: no auth, CNCF branding, `licensePolicy.expressionMode: permissive-wins`, foundation exceptions via `--set-file` |

---

## License Classification of Compound Expressions

SBOM generators frequently emit SPDX expressions rather than single
identifiers — `Apache-2.0 AND BSD-3-Clause AND MIT`, `MIT OR GPL-2.0-only`,
`GPL-2.0-only WITH Classpath-exception-2.0`. BOMHort evaluates these operand
by operand against the policy. `licensePolicy.expressionMode` (injected as
`LICENSE_EXPRESSION_MODE`, overriding the policy file's `expressionMode`)
selects the rule:

| Mode | `Apache-2.0 AND MIT` | `MIT AND GPL-3.0-only` | `MIT OR GPL-3.0-only` |
|------|----------------------|------------------------|-----------------------|
| `strict` (default) | permissive | copyleft | permissive |
| `permissive-wins` | permissive | permissive | permissive |
| `off` | unknown | unknown | unknown |

`strict` follows SPDX semantics: AND binds you to every operand, OR lets you
choose. `permissive-wins` is for catalogues whose generators join a package's
licenses with AND regardless of whether it is dual-licensed. `off` restores
the pre-evaluation behaviour. A policy entry that lists a whole expression
verbatim always wins. Changing the mode only affects newly processed SBOMs —
re-process to update stored results.

---

## How SBOMs Are Loaded

BOMHort supports multiple ingestion methods. **S3 is the default and recommended approach** — no PVCs, no volume scheduling, scales to any repo size. Volume-based methods are available as alternatives.

### Method 1: S3 Buckets (default, recommended)

The Ingestion Watcher streams `ListObjects` from each configured S3 bucket (paginated, memory-efficient). The Parsing Workers fetch objects on-demand via `s3://bucket/key` URIs. No PVC required.

```yaml
s3:
  buckets: '[{"name":"my-org-sboms","region":"us-east-1"},{"name":"platform-sboms","region":"us-east-1"}]'
  accessKey: ""   # pass via --set for private buckets
  secretKey: ""
```

With `gitSync.enabled: false` the chart still creates the `sbom-data` PVC and pins the watcher, the workers and the gateway to one node for it. To run S3-only without either, as `values-cncf.yaml` does, add:

```yaml
gitSync:
  enabled: false

sbomSource:
  enabled: false
```

Supports any S3-compatible storage: AWS S3, MinIO, GCS, Ceph, DigitalOcean Spaces.

Supported file patterns: `*.spdx.json`, `*_spdx.json`, `*.openvex.json`, `*.vex.json`.

Nested keys like `k3s-io/helm-controller/0.16.14/k3s-io_helm-controller_0_16_14_spdx.json` are fully supported.

### Method 2: git-sync (alternative, for small repos)

Used by `values-minimal.yaml` when `s3.buckets` is empty.

A [git-sync](https://github.com/kubernetes/git-sync) sidecar runs alongside the Ingestion Watcher and continuously pulls from your Git repo.

```yaml
s3:
  buckets: ""              # disable S3

gitSync:
  enabled: true
  repo: "https://github.com/your-org/sbom-repo.git"
  branch: main
  depth: 1
  period: "6h"             # re-sync every 6 hours
  timeout: 120             # seconds for git operations
```

**⚠️  Limitation:** git-sync struggles with very large repos (multi-GB). Use S3 or a pre-populated PVC for repos in the multi-GB range.

### Method 3: Pre-populated PVC (manual / CI pipeline)

Used by `values-production.yaml` when `s3.buckets` is empty. With git-sync
disabled the chart creates the PVC empty; populating it is up to you (a CI job,
`kubectl cp`, or push uploads with `sbomSource.writable`). Earlier charts
shipped a `seedJob` for this, but its clone had been disabled since March 2026
and it only ever waited; it was removed in 0.8.0 (#391), and values that still
set `seedJob` now fail the render.

```yaml
s3:
  buckets: ""
gitSync:
  enabled: false

sbomSource:
  pvcName: bomhort-sbom-data
  mountPath: /data/sboms
  storageSize: 10Gi
```

After populating the PVC, trigger the Ingestion Watcher:
```bash
kubectl create job --from=cronjob/bomhort-ingestion-watcher manual-ingest -n bomhort
```

---

## File Placement Rules

The Ingestion Watcher scans the SBOM directory **recursively** for:

| Pattern | Type | Example |
|---------|------|---------|
| `*.spdx.json` | SPDX SBOM | `my-project.spdx.json` |
| `*.openvex.json` | OpenVEX statement | `my-project.openvex.json` |
| `*.vex.json` | OpenVEX statement | `my-project.vex.json` |

`license-exceptions.json` and `license-policy.json` are configuration files and
are **not ingested as SBOMs**. Use their ConfigMaps to configure them — or,
for the exceptions, an `https://` / `s3://` source (`licenseExceptions.source`,
shown commented out in `values-production.yaml`). Either way the pods reload the
exceptions every `refreshInterval` and apply a change to every SBOM already
ingested; see the [License Exceptions](../../docs/content/docs/license-exceptions/_index.md) page.
The legacy exception-file fallback in the SBOM directory is used only if the
primary file is absent; an empty ConfigMap is authoritative.

Files are **deduplicated by SHA256 hash** — uploading the same file twice will not create duplicate entries.

Nested directories are fine:
```
/data/sboms/
├── org-a/
│   ├── project-1/v1.0/project-1.spdx.json
│   └── project-2/v2.3/project-2.spdx.json
├── org-b/
│   └── service-x.spdx.json
├── license-exceptions.json
└── my-project.openvex.json
```

---

## Exposing the UI

Both values files use `ClusterIP` services. To expose them:

### Option A: Ingress (recommended)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: bomhort
  namespace: bomhort
spec:
  ingressClassName: nginx
  rules:
    - host: bomhort.example.com
      http:
        paths:
          - path: /api
            pathType: Prefix
            backend:
              service:
                name: bomhort-api-gateway
                port: { number: 80 }
          - path: /
            pathType: Prefix
            backend:
              service:
                name: bomhort-ui
                port: { number: 80 }
```

### Option B: kubectl port-forward

```bash
kubectl port-forward -n bomhort svc/bomhort-ui 8090:80 &
kubectl port-forward -n bomhort svc/bomhort-api-gateway 8080:80 &
```
