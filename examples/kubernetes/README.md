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
  --set 's3.buckets=[{"name":"cncf-subproject-sboms","region":"us-east-1"}]'

# Or from the OCI registry:
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --version 0.1.3 -n bomhort -f my-values.yaml
```

## Values Files

| File | SBOM Source | Best For |
|------|-------------|----------|
| `values-production.yaml` | **S3 buckets** (default) or seed job (PVC fallback) | Production, large-scale ingestion |
| `values-minimal.yaml` | **S3 buckets** (default) or git-sync (PVC fallback) | Small repos (< 1 GB), CI/staging |

---

## How SBOMs Are Loaded

BOMHort supports multiple ingestion methods. **S3 is the default and recommended approach** — no PVCs, no volume scheduling, scales to any repo size. Volume-based methods are available as alternatives.

### Method 1: S3 Buckets (default, recommended)

The Ingestion Watcher streams `ListObjects` from each configured S3 bucket (paginated, memory-efficient). The Parsing Workers fetch objects on-demand via `s3://bucket/key` URIs. No PVC required.

```yaml
s3:
  buckets: '[{"name":"cncf-subproject-sboms","region":"us-east-1"},{"name":"cncf-project-sboms","region":"us-east-1"}]'
  accessKey: ""   # pass via --set for private buckets
  secretKey: ""
```

Supports any S3-compatible storage: AWS S3, MinIO, GCS, Ceph, DigitalOcean Spaces.

Supported file patterns: `*.spdx.json`, `*_spdx.json`, `*.openvex.json`, `*.vex.json`.

Nested keys like `k3s-io/helm-controller/0.16.14/k3s-io_helm-controller_0_16_14_spdx.json` are fully supported.

### Method 2: Seed Job (alternative, for environments without S3)

Used by `values-production.yaml` when `s3.buckets` is empty.

A Kubernetes Job runs once at install time and:
1. Does a **shallow `git clone`** of your SBOM repo into a temp directory
2. **Flat-copies** all `.spdx.json` and `.openvex.json` files into the PVC (flattening nested directory paths into filenames to avoid collisions)
3. Optionally downloads the [CNCF license exceptions](https://github.com/cncf/foundation/blob/main/license-exceptions/exceptions.json) into the PVC

```yaml
s3:
  buckets: ""              # disable S3

gitSync:
  enabled: false           # disable git-sync

seedJob:
  sbomRepo: "https://github.com/cncf/sbom.git"
  sbomBranch: main
  cncfExceptionsURL: "https://raw.githubusercontent.com/cncf/foundation/main/license-exceptions/exceptions.json"

sbomSource:
  storageSize: 20Gi        # must be large enough for the full repo
```

**Refreshing:** Delete the seed job and re-run Helm upgrade:
```bash
kubectl delete job -n bomhort -l app.kubernetes.io/component=seed-sboms
helm upgrade bomhort deploy/helm/bomhort/ -n bomhort -f my-values.yaml
```

> **Note:** Requires a `ReadWriteOnce` PVC. All pods are automatically co-scheduled on the same node via pod affinity.

### Method 3: git-sync (alternative, for small repos)

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

**⚠️  Limitation:** git-sync struggles with very large repos (multi-GB). Use S3 or the seed job for repos like `cncf/sbom` (~14 GB).

### Method 4: Pre-populated PVC (manual / CI pipeline)

If your SBOMs are not in S3 or a Git repo, you can populate the PVC yourself:

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
| `license-exceptions.json` | CNCF exceptions file | (auto-downloaded by seed job) |
| `license-policy.json` | Custom license policy | (optional, overrides ConfigMap) |

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
