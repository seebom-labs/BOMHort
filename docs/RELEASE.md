# BOMHort – Release & Publishing Guide

> **Updated:** 2026-05-05

---


## Container Images

All container images are published to **GitHub Container Registry (ghcr.io)**:

| Image | Description |
|-------|-------------|
| `ghcr.io/seebom-labs/bomhort/ingestion-watcher` | CronJob: scans SBOM/VEX files, enqueues jobs |
| `ghcr.io/seebom-labs/bomhort/parsing-worker` | Stateless worker: parses SBOMs, queries OSV, checks licenses |
| `ghcr.io/seebom-labs/bomhort/api-gateway` | REST API (16 endpoints) |
| `ghcr.io/seebom-labs/bomhort/cve-refresher` | CronJob: daily incremental CVE checks against OSV |
| `ghcr.io/seebom-labs/bomhort/ui` | Angular frontend (Nginx) |

Images are built for **linux/amd64** and **linux/arm64**.

---

## How to Release

### 1. Scan for vulnerabilities and update dependencies

Before tagging, ensure all dependencies are clean:

```bash
# Go backend
cd backend && govulncheck ./... && go get -u ./... && go mod tidy && go build ./... && go test ./...

# Angular UI
cd ui && npm audit fix && npx ng build

# Hugo docs
cd docs && npm audit fix
```

Fix any reported vulnerabilities before proceeding. Check all three ecosystems (Go, UI npm, docs npm).

### 2. Tag the release

```bash
git tag v0.1.2
git push origin v0.1.2
```

### 3. What happens automatically

The GitHub Actions workflow (`.github/workflows/release.yml`) triggers on any `v*` tag and:

1. **Builds all 5 container images** (multi-arch: amd64 + arm64)
2. **Pushes them to ghcr.io** with two tags each:
   - `ghcr.io/seebom-labs/bomhort/<component>:0.1.2` (version)
   - `ghcr.io/seebom-labs/bomhort/<component>:latest`
3. **Packages the Helm chart** with the matching version
4. **Pushes the Helm chart** as an OCI artifact to `oci://ghcr.io/seebom-labs/bomhort/charts`
5. **Creates a GitHub Release** with:
   - Auto-generated release notes from commits since the last tag
   - `docker pull` commands for all 5 images
   - `helm install` command for the chart
   - Pre-release flag for `-rc`, `-alpha`, `-beta` tags

Release notes are grouped by PR labels (see `.github/release.yml`):
- 🚀 Features (`enhancement`, `feature`)
- 🐛 Bug Fixes (`bug`, `fix`)
- 📖 Documentation (`docs`)
- 🧪 Tests (`test`)
- 🔧 Maintenance (`chore`, `dependencies`, `ci`)
- 🔒 Security (`security`)

### 4. Verify the release

```bash
# Check images exist
docker pull ghcr.io/seebom-labs/bomhort/api-gateway:0.1.2

# Check Helm chart
helm show chart oci://ghcr.io/seebom-labs/bomhort/charts/bomhort --version 0.1.2
```

---

## Installing from a Release

### Helm (recommended)

```bash
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --version 0.1.2 \
  -f values-production.yaml
```

### Override image tag

```bash
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --version 0.1.2 \
  --set image.tag=0.1.2
```

---

## CI Workflows

| Workflow | File | Trigger | What it does |
|----------|------|---------|-------------|
| **CI** | `.github/workflows/ci.yml` | Push/PR to `main` | Go build + test + vet, Angular build, Helm lint |
| **Release** | `.github/workflows/release.yml` | Git tag `v*` | Build + push 5 images (multi-arch), Helm chart, GitHub Release |
| **Pre-Release** | `.github/workflows/pre-release.yml` | Manual (`workflow_dispatch`) | Build images from any branch, create pre-release |
| **Sync Labels** | `.github/workflows/sync-labels.yml` | Push to `main` (labels.yml changed) or manual | Sync `.github/labels.yml` to GitHub repo labels |
| **Auto-Label** | `.github/workflows/labeler.yml` | PR opened/updated | Auto-assigns labels based on changed files (`.github/labeler.yml`) |

---

## Fork-Based Workflow

If you contribute via a fork:

1. **Develop in your fork** — push branches, open PRs against the main repo
2. **Merge the PR** into `main` of the main repo
3. **Tag in the main repo** (not in the fork):
   ```bash
   git tag v0.1.2
   git push origin v0.1.2
   ```

> **Do not tag releases in your fork.** The `GITHUB_TOKEN` in a fork cannot push images to the main repo's GHCR, and the GitHub Release would be created in the fork instead of the main repo.

### Testing a pre-release from any branch

Use the manual **Pre-Release** workflow to build and publish test images without merging to `main`:

1. Go to **Actions → Pre-Release (manual)** in your repo
2. Click **Run workflow**
3. Select the branch and enter a version (e.g. `0.2.0-rc1`)
4. Images are pushed to your repo's GHCR with that version tag
5. A GitHub Pre-Release is created automatically

---

## Building Images Locally

For testing before a release:

```bash
# Build all 5 images with tag "dev"
make images

# Build with a specific tag
make images TAG=0.2.0-rc1

# Build and push to GHCR (requires: docker login ghcr.io)
make images-push TAG=0.2.0-rc1
```

### Manual docker build (single image)

```bash
# Backend images (multi-target Dockerfile)
docker build -t my-registry/bomhort/api-gateway:test \
  --target api-gateway backend/

docker build -t my-registry/bomhort/parsing-worker:test \
  --target parsing-worker backend/

docker build -t my-registry/bomhort/ingestion-watcher:test \
  --target ingestion-watcher backend/

# UI image
docker build -t my-registry/bomhort/ui:test ui/
```

---

## Image Architecture

The backend uses a **single multi-stage Dockerfile** (`backend/Dockerfile`) with three named targets:

```
golang:1.24-alpine (builder)
  ├── go build → /bin/ingestion-watcher
  ├── go build → /bin/parsing-worker
  ├── go build → /bin/api-gateway
  └── go build → /bin/cve-refresher

alpine:3.21 (ingestion-watcher)  ← FROM builder, COPY binary
alpine:3.21 (parsing-worker)     ← FROM builder, COPY binary
alpine:3.21 (api-gateway)        ← FROM builder, COPY binary
alpine:3.21 (cve-refresher)      ← FROM builder, COPY binary
```

The UI uses a separate Dockerfile (`ui/Dockerfile`):

```
node:22-alpine (builder)
  └── ng build → /app/dist/

nginx:1.27-alpine
  └── COPY dist/ → /usr/share/nginx/html/
```

All runtime images run as `nobody:nobody` (backend) or `nginx` (UI) for security.

---

## Versioning

- **Git tags**: `v0.1.2`, `v0.2.0`, etc. (SemVer)
- **Image tags**: `0.1.3` (without `v` prefix) + `latest`
- **Helm chart version**: Matches the Git tag (auto-updated by CI)
- `values.yaml` defaults to the latest released tag

---

## Private Registry

To use a different registry, override in Helm:

```bash
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --set image.registry=my-registry.example.com \
  --set image.repository=my-org/bomhort \
  --set image.tag=0.1.3
```

Or build + push locally:

```bash
make images-push REGISTRY=my-registry.example.com REPO=my-org/bomhort TAG=0.1.3
```

