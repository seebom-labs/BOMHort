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
  buckets: '[{"name":"cncf-subproject-sboms","region":"us-east-1"}]'
```

**Multiple buckets:**

```yaml
s3:
  buckets: '[{"name":"cncf-subproject-sboms","region":"us-east-1"},{"name":"cncf-project-sboms","region":"us-east-1"}]'
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

**Option 1: Global cluster name (one instance per cluster)**

```yaml
# values-prod-eu.yaml
ingestionWatcher:
  env:
    CLUSTER_NAME: "prod-eu"
```

Deploy one BOMHort instance per cluster, each with its own `CLUSTER_NAME`.

**Option 2: Per-bucket cluster assignment (one instance, multiple clusters)**

```yaml
# values.yaml — single watcher, multiple clusters
ingestionWatcher:
  env:
    CLUSTER_NAME: "default"   # fallback for buckets without explicit cluster

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
- `shared-sboms` → inherits `CLUSTER_NAME` = `default`

**Priority:** per-bucket `cluster` > global `CLUSTER_NAME` > empty (untagged)

### Option B: Seed Job

```yaml
s3:
  buckets: ""

gitSync:
  enabled: false

seedJob:
  sbomRepo: "https://github.com/cncf/sbom.git"
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

---

## 2. License Exceptions

License exceptions suppress specific license violations. They are stored in a **ConfigMap** that is mounted read-only into the API Gateway and Workers.

```bash
kubectl edit configmap bomhort-license-exceptions
kubectl rollout restart deployment bomhort-api-gateway
```

---

## 3. License Policy

The license policy defines which SPDX IDs are classified as **permissive**, **copyleft**, or **unknown**.

```bash
kubectl edit configmap bomhort-license-policy
kubectl rollout restart deployment bomhort-api-gateway bomhort-parsing-worker
```

---

## 4. Custom Theme

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

## 5. Site Configuration

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

## 6. API Authentication (Optional)

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

## 7. GitHub Token (License Resolution)

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

---

## 8. Full Deployment Example

### S3-based (recommended)

```bash
helm install bomhort ./deploy/helm/bomhort \
  -f values-production.yaml \
  --set image.tag=0.1.3 \
  --set 's3.buckets=[{"name":"cncf-subproject-sboms","region":"us-east-1"}]' \
  --set s3.accessKey="AKIA..." \
  --set s3.secretKey="..." \
  --set parsingWorker.replicas=10
```

---

## 9. Headless Mode (API-Only)

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
- All 24 API endpoints remain fully functional
- The API Gateway is the only externally exposed component
- Pair with `apiGateway.auth.enabled: true` to secure access

This is ideal for:
- **CI/CD pipelines** that push SBOMs and query results programmatically
- **Grafana/custom dashboards** that consume the REST API directly
- **Resource-constrained clusters** where every pod counts
- **Air-gapped deployments** where the UI is served separately

---

## 10. Ingress – Exposing the API Externally

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

## 11. Upgrading from v0.5.0 or Earlier (SeeBOM → BOMHort)

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

#### 3. Deploy with migration enabled

```bash
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --version 0.6.0 \
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

#### 4. Monitor the migration

```bash
kubectl logs -n bomhort job/bomhort-data-migration-1 -f
```

The Job migrates these tables (skipping any that are empty or already populated in the target):
- `sboms`, `sbom_packages`, `vulnerabilities`, `license_compliance`
- `ingestion_queue`, `vex_statements`, `cve_refresh_log`
- `github_license_cache`, `github_repo_metadata`

The `dashboard_stats_mv` materialized view repopulates automatically.

#### 5. Verify and clean up

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
    targetRevision: "0.6.0"
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

## 12. Verifying the Deployment

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
| **VEX files** | Same S3 bucket or directory | Place `*.openvex.json` alongside SBOMs |
| **License Exceptions** | ConfigMap | `kubectl edit configmap` → restart API |
| **License Policy** | ConfigMap | `kubectl edit configmap` → restart API + Workers |
| **Custom Theme** | ConfigMap | `kubectl create configmap` → restart UI |
| **Site Config** | ConfigMap | Helm values `ui.siteConfig.content.*` → restart UI |
| **S3 credentials** | Secret | `--set s3.accessKey=...` or `s3.credentialsSecret` (existing K8s Secret) |
| **API Authentication** | Env vars (Secret recommended) | `AUTH_ENABLED=true` + `SERVICE_TOKEN` and/or `API_KEYS`; off by default |
| **Headless Mode** | Helm value | `ui.enabled: false` — skips UI Deployment/Service/ConfigMaps |
| **Ingress** | Ingress resource | `ingress.enabled: true` + configure hosts/tls in Helm values |
