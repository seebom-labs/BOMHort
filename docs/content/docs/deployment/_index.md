---
title: "Deployment"
linkTitle: "Deployment"
type: docs
weight: 3
description: >
  Kubernetes deployment guide — S3 ingestion, Helm configuration, license governance, theming, and operations.
---

{{% pageinfo %}}
This guide covers deploying SeeBOM to a Kubernetes cluster using Helm.
{{% /pageinfo %}}

## Prerequisites

- Kubernetes cluster (1.27+)
- [ClickHouse Operator](https://github.com/Altinity/clickhouse-operator) installed
- Helm 3.x
- Container images pushed to a registry (e.g. `ghcr.io/seebom-labs/seebom/*`)

---

## 1. SBOMs – Getting Data Into the Cluster

SeeBOM supports multiple SBOM ingestion methods. **S3 bucket ingestion** is the default and recommended approach — it requires no PVCs, no volume scheduling, and scales to any number of SBOMs.

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
helm install seebom deploy/helm/seebom/ -n seebom -f my-values.yaml \
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
  -n seebom
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

SeeBOM supports tagging data by **cluster** for multi-cluster visibility from a single instance. This is fully optional — omit all cluster config for single-instance mode.

**Option 1: Global cluster name (one instance per cluster)**

```yaml
# values-prod-eu.yaml
ingestionWatcher:
  env:
    CLUSTER_NAME: "prod-eu"
```

Deploy one SeeBOM instance per cluster, each with its own `CLUSTER_NAME`.

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
kubectl edit configmap seebom-license-exceptions
kubectl rollout restart deployment seebom-api-gateway
```

---

## 3. License Policy

The license policy defines which SPDX IDs are classified as **permissive**, **copyleft**, or **unknown**.

```bash
kubectl edit configmap seebom-license-policy
kubectl rollout restart deployment seebom-api-gateway seebom-parsing-worker
```

---

## 4. Custom Theme

```yaml
ui:
  customTheme:
    enabled: true
```

```bash
kubectl create configmap seebom-custom-theme \
  --from-file=custom-theme.css=./my-theme.css \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment seebom-ui
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
  https://seebom.example.com/api/v1/stats/dashboard

# Or:
curl -H "X-Service-Token: your-strong-random-secret-here" \
  https://seebom.example.com/api/v1/stats/dashboard
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
  https://seebom.example.com/api/v1/stats/dashboard
```

**Both modes can be enabled at the same time** — useful when a proxy uses the service token while direct CI/CD jobs use API keys.

### Using Kubernetes Secrets (recommended for production)

Reference a pre-existing Secret instead of inlining the token in Helm values — same pattern as `s3.credentialsSecret` and `clickhouse.userPasswordSecret`:

```bash
kubectl create secret generic seebom-api-auth \
  --from-literal=SERVICE_TOKEN="$(openssl rand -hex 32)" \
  --from-literal=API_KEYS="key1,key2,key3" \
  -n seebom
```

```yaml
apiGateway:
  auth:
    enabled: true
    existingSecret:
      enabled: true
      secretName: "seebom-api-auth"
      serviceTokenKey: "SERVICE_TOKEN"   # key inside the Secret
      apiKeysKey: "API_KEYS"
```

Both the API Gateway and the UI nginx container automatically read `SERVICE_TOKEN` from this Secret. To rotate the token, update the Secret and restart both Deployments:

```bash
kubectl rollout restart deployment seebom-api-gateway seebom-ui
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
| No credentials sent (auth enabled) | `401 Unauthorized` with `WWW-Authenticate: Bearer realm="seebom"` |
| Invalid token/key | `401 Unauthorized` |
| `AUTH_ENABLED=true` but no `SERVICE_TOKEN` and no `API_KEYS` configured | All requests rejected (misconfiguration warning logged at startup) |

---

## 7. GitHub Token (License Resolution)

SeeBOM resolves unknown package licenses (`NOASSERTION`) by querying the GitHub API. Without a token, you are limited to **60 requests per hour**. With a token, the limit increases to **5,000 req/h**.

**We strongly recommend setting a GitHub token for any production deployment.**

Create a [Personal Access Token (classic)](https://github.com/settings/tokens) with **no scopes required**.

```yaml
github:
  token: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

Or pass it securely via `--set`:

```bash
helm install seebom deploy/helm/seebom/ -n seebom -f values.yaml \
  --set github.token="ghp_..."
```

See [FAQ: Should I use a GitHub token?](/docs/faq/#should-i-use-a-github-token) for more details and how to re-ingest after adding a token.

---

## 8. Full Deployment Example

### S3-based (recommended)

```bash
helm install seebom ./deploy/helm/seebom \
  -f values-production.yaml \
  --set image.tag=0.1.3 \
  --set 's3.buckets=[{"name":"cncf-subproject-sboms","region":"us-east-1"}]' \
  --set s3.accessKey="AKIA..." \
  --set s3.secretKey="..." \
  --set parsingWorker.replicas=10
```

---

## 9. Headless Mode (API-Only)

For CI/CD integrations, custom dashboards, or environments where the Angular UI is not needed, SeeBOM can be deployed in **headless mode**. This skips all UI-related resources (Deployment, Service, nginx ConfigMap) and reduces the cluster's resource footprint.

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
- All 19 API endpoints remain fully functional
- The API Gateway is the only externally exposed component
- Pair with `apiGateway.auth.enabled: true` to secure access

This is ideal for:
- **CI/CD pipelines** that push SBOMs and query results programmatically
- **Grafana/custom dashboards** that consume the REST API directly
- **Resource-constrained clusters** where every pod counts
- **Air-gapped deployments** where the UI is served separately

---

## 10. Ingress – Exposing the API Externally

SeeBOM includes an optional Ingress resource to expose the API Gateway (and optionally the UI) outside the cluster. The template is controller-agnostic — it works with any Ingress controller that implements the Kubernetes Ingress spec (Envoy Gateway, Contour, AWS ALB, etc.).

{{% alert title="Gateway API" color="info" %}}
For the newer [Gateway API](https://gateway-api.sigs.k8s.io/), configure Gateway/HTTPRoute resources separately. The Helm chart provides the classic Ingress resource.
{{% /alert %}}

### Basic (Envoy Gateway)

```yaml
ingress:
  enabled: true
  className: eg
  hosts:
    - host: seebom.example.com
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
    - host: seebom.example.com
      paths:
        - path: /api
          pathType: Prefix
        - path: /
          pathType: Prefix
          serviceSuffix: ui
  tls:
    - secretName: seebom-tls
      hosts:
        - seebom.example.com
```

### Contour

```yaml
ingress:
  enabled: true
  className: contour
  hosts:
    - host: seebom.example.com
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
    - host: seebom.example.com
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
    - host: api.seebom.example.com
      paths:
        - path: /
          pathType: Prefix
```

{{% alert title="Security" color="warning" %}}
When exposing the API externally, ensure `apiGateway.auth.enabled: true` is set. Without authentication, all SBOM data is publicly accessible.
{{% /alert %}}

---

## 11. Verifying the Deployment

```bash
kubectl get pods -l app.kubernetes.io/name=seebom

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
