# BOMHort – Local Kind Deployment

Deploy BOMHort to a local [Kind](https://kind.sigs.k8s.io/) cluster for development and testing.

## Prerequisites

- [Kind](https://kind.sigs.k8s.io/) ≥ v0.20
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- [Helm](https://helm.sh/docs/intro/install/) ≥ 3.12
- Docker (or Podman with Docker compat)

## Setup

### 1. Create secrets

```bash
cp examples/kind/secrets.env.example local/secrets.env
vi local/secrets.env
```

Fill in:
- `CLICKHOUSE_PASSWORD` — pick any password for local dev
- `GITHUB_TOKEN` — (optional) GitHub PAT for license resolution (increases rate limit from 60 → 5000 req/h)
- `S3_ACCESS_KEY` / `S3_SECRET_KEY` — (optional) for private S3 buckets

### 2. Configure SBOM source

Edit `local/values-local.yaml` to set your S3 bucket(s):

```yaml
s3:
  buckets: '[{"name":"cncf-subproject-sboms","region":"us-east-1"}]'
```

Or keep the default seed job (PVC-based) if you don't have S3 access.

### 3. Deploy

```bash
make kind-up
```

This will:
1. Create a Kind cluster named `seebom` (see [`kind-config.yaml`](kind-config.yaml))
2. Install the [Altinity ClickHouse Operator](https://github.com/Altinity/clickhouse-operator)
3. Deploy BOMHort via Helm with [`values-kind.yaml`](values-kind.yaml)
4. If S3 is configured: Ingestion Watcher streams SBOMs from your buckets
5. If S3 is not configured: Seed job clones the CNCF SBOM repo into a PVC (6500+ SBOMs, ~14 GB)

### 4. Access

| Service | URL |
|---------|-----|
| UI | http://localhost:8090 |
| API | http://localhost:8080/healthz |

### 5. Monitor

```bash
# Watch pods
kubectl get pods -n seebom -w

# Check ingestion progress
curl -s http://localhost:8080/api/v1/stats/dashboard | jq .total_sboms

# Worker logs
kubectl logs -n seebom -l app.kubernetes.io/component=parsing-worker --tail=20
```

### 6. Re-ingest (without re-downloading)

If you change the license policy or want to re-process all SBOMs:

```bash
make kind-reingest
```

This truncates all data tables and re-queues all SBOMs from the PVC.

### 7. Tear down

```bash
make kind-down
```

## File Reference

| File | Description |
|------|-------------|
| `kind-config.yaml` | Kind cluster config (ports, labels) |
| `values-kind.yaml` | Helm values for Kind (smaller resources, NodePort, seed job) |
| `secrets.env.example` | Template for `local/secrets.env` (NEVER commit the real file) |

## Architecture (Kind)

```
                    ┌─────────────────────┐
                    │  S3 Buckets (AWS,   │
                    │  MinIO, GCS)        │
                    │  ← default source   │
                    └────────┬────────────┘
                             │ s3://
┌────────────────────────────┼────────────────────────────────┐
│  Kind Cluster (seebom)     │                                │
│                            ▼                                │
│  ┌──────────┐  ┌───────────────┐  ┌──────────────────┐     │
│  │ ClickHouse│  │Parsing Workers│  │  API Gateway     │     │
│  │ (Operator)│  │  (2 replicas) │  │  :8080 → :30081  │     │
│  └──────────┘  └───────────────┘  └──────────────────┘     │
│                                                             │
│  ┌──────────┐  ┌───────────────┐  ┌──────────────────┐     │
│  │ Ingestion│  │  CVE Refresher│  │  UI (Angular)    │     │
│  │ Watcher  │  │  (CronJob)    │  │  :8090 → :30080  │     │
│  │ (CronJob)│  └───────────────┘  └──────────────────┘     │
│  └──────────┘                                               │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  PVC: seebom-sbom-data (optional, fallback only)   │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
     :8090 (UI)          :8080 (API)
       ↕                    ↕
    localhost             localhost
```

