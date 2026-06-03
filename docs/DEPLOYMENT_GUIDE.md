# SeeBOM – Kubernetes Deployment Guide

> **Updated:** 2026-03-13

## Prerequisites

- Kubernetes cluster (1.27+)
- [ClickHouse Operator](https://github.com/Altinity/clickhouse-operator) installed
- Helm 3.x
- Container images pushed to a registry (e.g. `ghcr.io/your-org/seebom/*`)

---

## 1. SBOMs – Getting Data Into the Cluster

SeeBOM supports multiple SBOM ingestion methods. **S3 bucket ingestion** is the default and recommended approach — it requires no PVCs, no volume scheduling, and scales to any number of SBOMs. Volume-based alternatives are available for environments without S3.

### Option A: S3 Buckets (default, recommended)

Ingest SBOMs directly from S3-compatible buckets (AWS S3, MinIO, GCS). The Ingestion Watcher streams object listings with pagination (no full listing in memory) and the Parsing Workers fetch objects on-demand. No PVCs, git-sync sidecars, or seed jobs required.

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
| `*_spdx.json` | SPDX SBOM (CNCF naming convention) |
| `*.openvex.json` | OpenVEX statement |
| `*.vex.json` | OpenVEX statement |

Nested keys are fully supported (e.g. `k3s-io/helm-controller/0.16.14/k3s-io_helm-controller_0_16_14_spdx.json`).

### Option B: Seed Job (alternative for environments without S3)

A Kubernetes Job runs at install time, does a shallow `git clone`, and flat-copies all SBOM files into a PVC. Suitable when your SBOMs live in a Git repo and S3 is not available.

```yaml
s3:
  buckets: ""    # disable S3

gitSync:
  enabled: false

seedJob:
  sbomRepo: "https://github.com/cncf/sbom.git"
  sbomBranch: main
  cncfExceptionsURL: "https://raw.githubusercontent.com/cncf/foundation/main/license-exceptions/exceptions.json"

sbomSource:
  storageSize: 20Gi
```

The seed job flattens nested directory structures (`org/project/version/file.spdx.json` → `org_project_version_file.spdx.json`) to avoid filename collisions.

**To refresh SBOMs**, delete the seed job and re-run Helm upgrade:
```bash
kubectl delete job -n seebom -l app.kubernetes.io/component=seed-sboms
helm upgrade seebom deploy/helm/seebom/ -n seebom -f my-values.yaml
```

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

> **⚠️  Limitation:** git-sync struggles with large repos (multi-GB). For repos like `cncf/sbom` (~14 GB), it times out or OOM-kills. Use S3 or the seed job instead.

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
kubectl create job --from=cronjob/seebom-ingestion-watcher manual-ingest -n seebom
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

## 2. License Exceptions – Whitelisting Known Violations

License exceptions suppress specific license violations. They are stored in a **ConfigMap** that is mounted read-only into the API Gateway and Workers.

### Edit the default ConfigMap

After `helm install`, edit the ConfigMap directly:

```bash
kubectl edit configmap seebom-license-exceptions
```

The JSON format follows the [CNCF exceptions format](https://github.com/cncf/foundation/blob/main/license-exceptions/exceptions.json):

```json
{
  "version": "1.0.0",
  "lastUpdated": "2026-03-07",
  "blanketExceptions": [
    {
      "id": "blanket-mpl-2.0",
      "license": "MPL-2.0",
      "status": "approved",
      "approvedDate": "2026-03-07",
      "comment": "MPL-2.0 is file-level copyleft, acceptable for unmodified deps."
    }
  ],
  "exceptions": [
    {
      "id": "exc-001",
      "package": "github.com/hashicorp/golang-lru",
      "license": "MPL-2.0",
      "status": "approved",
      "approvedDate": "2026-03-07",
      "comment": "Widely used LRU cache, unmodified."
    }
  ]
}
```

### Apply changes

After editing, restart the API Gateway to pick up changes:

```bash
kubectl rollout restart deployment seebom-api-gateway
```

> **Note:** Violations are filtered at query time, so no re-ingestion is needed.

---

## 3. License Policy – Defining Permissive vs. Copyleft

The license policy defines which SPDX IDs are classified as **permissive**, **copyleft**, or **unknown**. Any license not listed falls into `unknown`.

### Edit the default ConfigMap

```bash
kubectl edit configmap seebom-license-policy
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
kubectl rollout restart deployment seebom-api-gateway seebom-parsing-worker
```

> **Note:** Policy changes affect new ingestions. To reclassify existing data,
> trigger a full re-scan (truncate tables + re-ingest).

---

## 4. Custom Theme – Rebranding the UI

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
kubectl create configmap seebom-custom-theme \
  --from-file=custom-theme.css=./my-theme.css \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment seebom-ui
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

## 5. Site Configuration – Customising UI Texts

All UI text content — brand name, page title, dashboard title/subtitle, description banner, and disclaimer — can be overridden **without rebuilding Angular** via a JSON config file (`ui-config.json`).

The Angular app loads `/ui-config.json` at startup. Missing keys gracefully fall back to the built-in SeeBOM defaults.

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
| `brandName` | string | `SeeBOM` | Navbar brand text (top left) |
| `pageTitle` | string | `SeeBOM` | Browser tab title (`<title>`) |
| `dashboard.title` | string | `Dashboard` | Dashboard page heading |
| `dashboard.subtitle` | string | `Software Bill of Materials — Governance Overview` | Dashboard subheading |
| `dashboard.description` | HTML string | *(SeeBOM description)* | Description banner on dashboard. Supports HTML (links, bold, etc.) |
| `dashboard.disclaimer` | HTML string | *(default disclaimer)* | Disclaimer text at bottom of dashboard. Supports HTML. |
| `footer.enabled` | boolean | `false` | Show a footer bar below the main content |
| `footer.text` | string | `""` | Footer text content |

All fields are **optional**. Omitted keys use the built-in defaults.

### Apply changes

After editing the ConfigMap, restart the UI deployment:

```bash
kubectl rollout restart deployment seebom-ui
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

## 6. Full Deployment Example

### S3-based (recommended)

```bash
# 1. Install with S3 ingestion
helm install seebom ./deploy/helm/seebom \
  -f values-production.yaml \
  --set image.tag=0.1.3 \
  --set 's3.buckets=[{"name":"cncf-subproject-sboms","region":"us-east-1"},{"name":"cncf-project-sboms","region":"us-east-1"}]' \
  --set s3.accessKey="AKIA..." \
  --set s3.secretKey="..." \
  --set parsingWorker.replicas=10 \
  --set ui.customTheme.enabled=true

# 2. Override license exceptions from a local file
kubectl create configmap seebom-license-exceptions \
  --from-file=license-exceptions.json=./my-exceptions.json \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Override license policy from a local file
kubectl create configmap seebom-license-policy \
  --from-file=license-policy.json=./my-policy.json \
  --dry-run=client -o yaml | kubectl apply -f -

# 4. Apply a custom theme
kubectl create configmap seebom-custom-theme \
  --from-file=custom-theme.css=./my-theme.css \
  --dry-run=client -o yaml | kubectl apply -f -

# 5. Restart to pick up new configs
kubectl rollout restart deployment seebom-api-gateway seebom-parsing-worker seebom-ui

# 6. Trigger initial ingestion manually
kubectl create job --from=cronjob/seebom-ingestion-watcher seebom-initial-ingest
```

### Volume-based (alternative)

```bash
helm install seebom ./deploy/helm/seebom \
  -f values-production.yaml \
  --set image.tag=0.1.3 \
  --set gitSync.repo=https://github.com/your-org/sbom-repo.git \
  --set parsingWorker.replicas=10
```

---

## 7. Verifying the Deployment

```bash
# Check all pods are running
kubectl get pods -l app.kubernetes.io/name=seebom

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

## 8. Local Development

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
| `WORKER_REPLICAS` | `1` | Number of parallel parsing worker containers |
| `WORKER_BATCH_SIZE` | `50` | Jobs claimed per polling cycle per worker |
| `SKIP_OSV` | `false` | Skip OSV vulnerability API calls. Set `true` for fast initial bulk load. |
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

## 9. Ingress – Exposing the API Externally

SeeBOM includes an optional Ingress resource to expose the API Gateway (and optionally the UI) outside the cluster. The template is controller-agnostic — it works with any Ingress controller that implements the Kubernetes Ingress spec (Envoy Gateway, Contour, AWS ALB, etc.).

> **Note:** For the newer [Gateway API](https://gateway-api.sigs.k8s.io/), configure Gateway/HTTPRoute resources separately. The Helm chart provides the classic Ingress resource.

### Basic (HTTP only, Envoy Gateway)

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

### Contour Example

```yaml
ingress:
  enabled: true
  className: contour
  annotations:
    projectcontour.io/tls-cert-namespace: cert-manager
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

### API-only (headless, no UI)

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
    - host: seebom.example.com
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
| **SBOMs (volume)** | PVC via seed job or git-sync | Push to Git, seed job clones or git-sync re-syncs |
| **VEX files** | Same S3 bucket or directory as SBOMs | Place `*.openvex.json` or `*.vex.json` alongside SBOMs |
| **License Exceptions** | `seebom-license-exceptions` ConfigMap | `kubectl edit configmap` → restart API |
| **License Policy** | `seebom-license-policy` ConfigMap | `kubectl edit configmap` → restart API + Workers |
| **Custom Theme** | `seebom-custom-theme` ConfigMap | `kubectl create configmap` → restart UI |
| **Site Config** | `seebom-ui-config` ConfigMap | Helm values `ui.siteConfig.content.*` → restart UI |
| **Dark Mode** | Built-in toggle (navbar) | User preference, stored in browser localStorage |
| **ClickHouse password** | `seebom-secret` Secret | `kubectl edit secret` |
| **S3 credentials** | `seebom-secret` Secret | `--set s3.accessKey=...` or `kubectl edit secret` |
| **Ingress** | `seebom-ingress` Ingress resource | `ingress.enabled: true` + configure hosts/tls in Helm values |
