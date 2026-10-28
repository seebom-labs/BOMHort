# BOMHort – Release & Publishing Guide

> **Updated:** 2026-10-14

---


## Container Images

All container images are published to **GitHub Container Registry (ghcr.io)**:

| Image | Description |
|-------|-------------|
| `ghcr.io/seebom-labs/bomhort/ingestion-watcher` | CronJob: scans SBOM/VEX files, enqueues jobs |
| `ghcr.io/seebom-labs/bomhort/parsing-worker` | Stateless worker: parses SBOMs, queries OSV, checks licenses |
| `ghcr.io/seebom-labs/bomhort/api-gateway` | REST API (37 endpoints) |
| `ghcr.io/seebom-labs/bomhort/cve-refresher` | CronJob: daily incremental CVE checks against OSV |
| `ghcr.io/seebom-labs/bomhort/mcp-server` | Read-only MCP server over the REST API (`mcp.enabled`) |
| `ghcr.io/seebom-labs/bomhort/ui` | Angular frontend (Nginx) |

Images are built for **linux/amd64** and **linux/arm64**.

---

## Release Branches

Every minor version gets a release branch `release/vX.Y`. **All release tags — RCs, the final release and every patch — are cut from it**; the release workflow rejects a tag that is not on its release branch.

```
main           ●──●──●──●──●──●──●──●──●──●──●──▶   next minor continues here
               │        │           │        │
          branch cut  fix #501    fix #507  fix #512   merged on main first,
               │        ↓           ↓        ↓         then make cherry-pick
release/v0.8   ●────────●───────────●────────●──▶
            v0.8.0-rc.1 rc.2      v0.8.0   v0.8.1
```

- **Branch cut** — the first `make release-rc VERSION=X.Y.0` creates `release/vX.Y` from `main` and tags `-rc.1` on it. From that moment `main` is open for the next minor; nothing merged there reaches X.Y by itself.
- **Fixes land on `main` first**, always — then are backported to the release branch as a pull request: `make cherry-pick PR=<n> BRANCH=X.Y`. Never commit to a release branch directly; a fix only on the branch is lost again in the next minor. PRs are rebase-merged, so the script asks GitHub which commits on `main` belong to the PR and picks all of them; this needs the [GitHub CLI](https://cli.github.com/) (`gh`, or `GH=/path/to/gh`).
- **Only fixes are backported**: bug fixes, security fixes, dependency bumps for CVEs, docs corrections. No features.
- Backport PRs run the full CI (CI, CodeQL, fuzz trigger on `release/**`) and go through review and merge like any other PR.
- **Minors released before release branches existed** (≤ 0.7) have no branch. To patch one, create it from its latest release, backport, then release: `make release-branch VERSION=0.7`, `make cherry-pick ...`, `make release VERSION=0.7.2`.

> **Repository settings (once, by an admin):** protect `release/**` like `main` — require pull requests, the CI status checks and review; disallow force pushes and deletion. The release scripts only *create* the branch; everything after that arrives through pull requests. Dependabot only targets `main`; security updates reach release branches by cherry-pick.

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

### 2. Reconcile `ROADMAP.md`

Feature PRs deliberately **do not** tick their own roadmap entry — see `AGENTS.md`. Two PRs that both edit the v0.8.0 criteria line conflict on a checklist, and resolving such a conflict by picking a side silently un-ticks an issue that is already merged. So the roadmap is reconciled once, here, by one author who can see the whole set.

List what actually landed since the previous tag:

```bash
git log v0.6.0..HEAD --oneline | grep -oE '#[0-9]+' | sort -u
```

Then, for each merged issue, update **all four** places it appears — missing one leaves the roadmap self-contradicting:

1. the register table row (`| #58 | … |` → `| ~~#58~~ | … | ✅ what shipped |`),
2. the release criteria checklist (`- [ ] **v0.8.0:** …`),
3. the milestone map row,
4. the dependency graph at the bottom.

Tick the release's own `- [ ]` box only when every item on that line is done. If items slipped, move them to the next milestone rather than quietly dropping them — the roadmap is the thing people read to find out what BOMHort promised.

### 3. Cut a release candidate

Every minor release goes through at least one release candidate. An RC runs the **same** pipeline as the final release — same images, signing, provenance, Helm chart — so whatever breaks in packaging breaks on the RC, not on the release.

```bash
make release-rc VERSION=0.8.0 DRY_RUN=1   # preview: tag, branch, commit, #commits since last release
make release-rc VERSION=0.8.0             # first run: cuts release/v0.8 from main + tags v0.8.0-rc.1
```

The script ([`hack/cut-release.sh`](../hack/cut-release.sh)):

- works on the **remote's** branches only (never your local checkout, so unpushed commits cannot slip in),
- cuts `release/vX.Y` from `main` if it does not exist yet, and pushes branch and tag in one atomic push,
- otherwise tags the head of `release/vX.Y`; refuses when nothing changed since the last RC,
- picks the next RC number from the existing tags (`-rc.N`, numeric — `rc.10` sorts after `rc.9`),
- pushes to the remote pointing at `seebom-labs/*` (override with `REMOTE=...`), and asks before pushing (`YES=1` skips the prompt).

Then **install the RC and test it** (see [Installing a release candidate](#installing-a-release-candidate)). If something is wrong: fix it on `main`, backport it (`make cherry-pick PR=<n> BRANCH=0.8`), merge the backport PR, cut the next RC (`make release-rc VERSION=0.8.0` → `-rc.2`).

### 4. Cut the final release

```bash
make release VERSION=0.8.0 DRY_RUN=1
make release VERSION=0.8.0
```

The script warns if no RC exists for this version, or if `release/v0.8` has moved past the last RC — the final release would then ship commits nobody tested as a candidate. To release exactly what was tested, tag the RC's commit:

```bash
make release VERSION=0.8.0 REF=v0.8.0-rc.2
```

### Patch releases

Backport the fixes to `release/vX.Y` (above), then:

```bash
make release VERSION=0.8.1 DRY_RUN=1
make release VERSION=0.8.1           # or first make release-rc VERSION=0.8.1 for a risky patch
```

The script refuses when nothing was backported since the last release of that minor.

### 5. What happens automatically

The GitHub Actions workflow (`.github/workflows/release.yml`) triggers on any `v*` tag and:

1. **Validates the version**: `X.Y.Z` or `X.Y.Z-rc.N` (also `-alpha.N`, `-beta.N`), and that the tagged commit is on `release/vX.Y`. Anything else fails the run before anything is published.
2. **Builds all 6 container images** (multi-arch: amd64 + arm64), signs them with cosign and attests SLSA provenance
3. **Pushes them to ghcr.io**:
   - `ghcr.io/seebom-labs/bomhort/<component>:0.8.0` (version) — always
   - `ghcr.io/seebom-labs/bomhort/<component>:latest` — **final releases only**; an RC never moves `latest`
4. **Packages the Helm chart** with `version` and `appVersion` set to the release version, so the chart deploys exactly the images of its own release
5. **Pushes the Helm chart** as an OCI artifact to `oci://ghcr.io/seebom-labs/bomhort/charts`
6. **Publishes the npm packages** `@bomhort/api-client`, `@bomhort/elements`, `@bomhort/react` to npmjs.org with the release version stamped in (the repo keeps `0.0.0`) and npm provenance. Final releases get the `latest` dist-tag, pre-releases `next`. Auth is npm **trusted publishing** (OIDC, no token secret): the `@bomhort` org on npmjs.com must list this repo + `release.yml` as trusted publisher for each package — a one-time setup per package, done by hand (the first publish of a new package also has to be manual, trusted publishing only covers existing packages).
7. **Creates a GitHub Release** with:
   - Release notes generated against the **previous final release** (not the previous tag), so `v0.8.0` lists everything since `v0.7.1`, not only what changed since `v0.8.0-rc.2`
   - `helm install` / `helm upgrade` and `docker pull` commands for all 6 images
   - SPDX SBOM of the repository, signed, with provenance
   - **Pre-release** flag for `-rc`, `-alpha`, `-beta` versions

Release notes are grouped by the PR's `kind/*` label (see `.github/release.yml`), which
`.github/workflows/kind-label.yml` derives from the conventional-commit prefix of the title
(leading `[...]` tags such as a backport's `[release/v0.8]` are skipped):
- 🔒 Security (`kind/security` — set by hand, listed first)
- 🚀 Features (`kind/feature` ← `feat:`)
- 🐛 Bug Fixes (`kind/bug` ← `fix:`, `revert:`)
- ⚡ Performance (`kind/performance` ← `perf:`)
- 📖 Documentation (`kind/docs` ← `docs:`)
- 🧪 Tests (`kind/test` ← `test:`)
- 🔧 Maintenance (`kind/cleanup` ← `chore:`, `ci:`, `build:`, `refactor:`; plus `dependencies`)

Dependabot PRs are excluded. Before cutting a release, check that every PR in the range has a
`kind/*` label (`gh pr list --state merged --search 'merged:>YYYY-MM-DD -label:kind/feature …'`)
— a PR without one lands under "Other Changes".

### 6. Verify the release

```bash
# Check images exist
docker pull ghcr.io/seebom-labs/bomhort/api-gateway:0.8.0

# Check Helm chart
helm show chart oci://ghcr.io/seebom-labs/bomhort/charts/bomhort --version 0.8.0

# Check npm packages
npm view @bomhort/elements@0.8.0 version
```

---

## Installing from a Release

### Helm (recommended)

```bash
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --version 0.8.0 \
  -f values-production.yaml
```

### Installing a release candidate

RC charts are SemVer pre-releases. Helm never picks them on its own (not for `helm install` without `--version`, not for ranges like `~0.8`), so production installs cannot drift onto an RC — you have to ask for one explicitly:

```bash
# Fresh install
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --version 0.8.0-rc.1 \
  -f values-production.yaml

# Upgrade a test installation from the previous release to the RC
helm upgrade bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --version 0.8.0-rc.1 \
  --reuse-values
```

The chart's `appVersion` is the RC version and `image.tag` defaults to it, so the RC chart deploys the RC images. If your values pin `image.tag`, unset it (`--set image.tag=`) or set it to the RC.

Into the local Kind cluster (chart + images from GHCR, nothing built locally; upgrades whatever `make kind-up` installed, so it exercises the upgrade path too):

```bash
make kind-deploy-release VERSION=0.8.0-rc.1
# an RC published by a fork:
make kind-deploy-release VERSION=0.8.0-rc.1 RELEASE_REPO=<owner>/<repo>
```

### Override image tag

```bash
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --version 0.8.0 \
  --set image.tag=0.8.0
```

---

## CI Workflows

| Workflow | File | Trigger | What it does |
|----------|------|---------|-------------|
| **CI** | `.github/workflows/ci.yml` | Push/PR to `main` | Go build + test + vet, Angular build, Helm lint |
| **Release** | `.github/workflows/release.yml` | Git tag `v*`, or manual (`workflow_dispatch`, pre-releases only) | Build + sign + push 6 images (multi-arch), Helm chart, GitHub (pre-)release |
| **Prow** | `.github/workflows/prow.yml` | Issues, comments, PRs, hourly | Chat-ops (`/lgtm`, `/approve`, `/hold`, `/label`, ...), OWNERS-based path labels + review requests, auto-merge, label sync from `.github/prow.yaml` ([cncf/prow-github-actions](https://github.com/cncf/prow-github-actions)) |

---

## Fork-Based Workflow

If you contribute via a fork:

1. **Develop in your fork** — push branches, open PRs against the main repo
2. **Merge the PR** into `main` of the main repo
3. **Tag in the main repo** (not in the fork) — `make release-rc` / `make release` push to the `seebom-labs` remote automatically.

> **Do not tag releases in your fork.** The `GITHUB_TOKEN` in a fork cannot push images to the main repo's GHCR, and the GitHub Release would be created in the fork instead of the main repo.

### Release candidate from a branch

To let someone install a branch that is not merged yet, run the release workflow manually:

1. Go to **Actions → Release** (in the main repo, or in your fork to publish to your fork's GHCR)
2. Click **Run workflow**, select the branch
3. Enter a pre-release version, e.g. `0.8.0-rc.1` — final versions are rejected; those are only cut by pushing a tag
4. The workflow builds, signs and pushes the 6 images and the Helm chart, then creates the tag at the built commit and a GitHub pre-release

Install it as described in [Installing a release candidate](#installing-a-release-candidate). A fork publishes to `ghcr.io/<owner>/<repo>`, which is private by default — make the packages public or `helm registry login ghcr.io` first.

---

## Building Images Locally

For testing before a release:

```bash
# Build all 6 images with tag "dev"
make images

# Build with a specific tag
make images TAG=0.8.0-rc.1

# Build and push to GHCR (requires: docker login ghcr.io)
make images-push TAG=0.8.0-rc.1
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
golang:1.26-alpine (builder)
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

- **Git tags**: `v0.8.0` (final), `v0.8.0-rc.1`, `v0.8.0-rc.2`, ... (release candidates) — SemVer. The `.` before the RC number is required: SemVer compares `rc.10` > `rc.9` numerically, while `rc10` would sort before `rc9`. The release workflow rejects any other shape.
- **Image tags**: `0.8.0` / `0.8.0-rc.1` (without `v` prefix); `latest` follows final releases only
- **Helm chart version**: Matches the Git tag (auto-updated by CI); `appVersion` too
- `values.yaml` leaves `image.tag` empty, so a chart always deploys the images of its own `appVersion`

---

## Private Registry

To use a different registry, override in Helm:

```bash
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --set image.registry=my-registry.example.com \
  --set image.repository=my-org/bomhort \
  --set image.tag=0.7.0
```

Or build + push locally:

```bash
make images-push REGISTRY=my-registry.example.com REPO=my-org/bomhort TAG=0.6.0
```

