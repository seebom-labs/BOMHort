# BOMHort – Deployment Examples

This directory contains ready-to-use example configurations for deploying BOMHort.

| Directory | Description |
|-----------|-------------|
| [`kind/`](kind/) | Local development with [Kind](https://kind.sigs.k8s.io/) (Kubernetes in Docker) |
| [`kubernetes/`](kubernetes/) | Production / staging deployment on a real Kubernetes cluster |
| [`fleet/`](fleet/) | Runnable demo data for the cluster / namespace / project views (`make demo-fleet`) |
| [`catalogue/`](catalogue/) | Runnable demo data for the project / tag views, for instances with no cluster (`make demo-catalogue`) |
| [`license-exceptions/`](license-exceptions/) | Example license exception file to adapt and review |

## Which demo data fits your instance?

BOMHort is run in two shapes, and the demo directories mirror them:

| | [`fleet/`](fleet/) | [`catalogue/`](catalogue/) |
|---|---|---|
| For | Companies running workloads on Kubernetes | Foundations, vendors, product lines |
| Answers | *Where does this workload run?* | *What kind of project is this?* |
| Dimensions | `cluster` → `namespace` → `project` | `project` + `tags` |
| `cluster`/`namespace` | The core of the model | Structurally empty, and that is fine |

## SBOM Ingestion Methods

| Method | Config | Best For |
|--------|--------|----------|
| **S3 buckets** (default) | `s3.buckets` JSON array | Any scale, no PVC needed, AWS/MinIO/GCS |
| **Seed job** (alternative) | `gitSync.enabled: false` + `seedJob` | Large Git repos (cncf/sbom ~14 GB), environments without S3 |
| **git-sync** (alternative) | `gitSync.enabled: true` | Small Git repos (< 1 GB), continuous auto-pull |
| **Manual PVC** (alternative) | `gitSync.enabled: false`, no seedJob | Custom CI, pre-built SBOMs |

See [`kubernetes/README.md`](kubernetes/README.md) for full details on each method.

## Quick Start (Kind)

```bash
# 1. Copy the example and fill in your secrets
cp examples/kind/secrets.env.example local/secrets.env
vi local/secrets.env

# 2. Deploy
make kind-up

# 3. Open
#    UI:  http://localhost:8090
#    API: http://localhost:8080/healthz
```

## Production Deployment

```bash
# 1. Copy and customise values
cp examples/kubernetes/values-production.yaml my-values.yaml
vi my-values.yaml

# 2. Install via Helm
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --version 0.1.3 \
  -f my-values.yaml
```

See [`docs/DEPLOYMENT_GUIDE.md`](../docs/DEPLOYMENT_GUIDE.md) for the full guide.

