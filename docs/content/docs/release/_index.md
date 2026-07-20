---
title: "Release"
linkTitle: "Release"
type: docs
weight: 5
description: >
  Release process, support policy, versioning, CI workflows, and container images.
---

## Support Policy

{{% alert title="Effective from v1.0" color="info" %}}
This support policy applies starting with the first stable release (v1.0.0). All pre-1.0 releases are development milestones without backward-compatibility guarantees.
{{% /alert %}}

BOMHort supports the **current stable release plus the two previous minor versions** (current − 2).

### Support Matrix (example)

| Version | Status | Security Fixes | Bug Fixes | Docs |
|---------|--------|:--------------:|:---------:|:----:|
| v1.3.x (main) | Development | ✅ | ✅ | `latest` |
| **v1.2.x** | **Current Stable** | ✅ | ✅ | `/v1.2/` |
| v1.1.x | Supported | ✅ | Critical only | `/v1.1/` |
| v1.0.x | Supported (last) | ✅ | Critical only | `/v1.0/` |
| v0.x | **End of Life** | ❌ | ❌ | `/v0.x/` (archived) |

When a new minor version is released (e.g., v1.3.0):
- The oldest supported version (v1.0.x) moves to **End of Life**
- Its docs remain accessible but display an "unsupported version" banner
- No further patches are backported

### What "supported" means

- **Security fixes**: CVEs in BOMHort's own code or critical dependency updates are backported
- **Bug fixes (current stable)**: All confirmed bugs are fixed
- **Bug fixes (older supported)**: Only critical/data-loss bugs are backported
- **Features**: Only land in `main` (next release), never backported

---

## Versioning

BOMHort follows [Semantic Versioning](https://semver.org/):

| Component | Format | Example |
|-----------|--------|---------|
| Git tag | `vMAJOR.MINOR.PATCH` | `v1.2.3` |
| Container image tag | `MAJOR.MINOR.PATCH` (no `v`) + `latest` | `1.2.3` |
| Helm chart version | Matches Git tag | `1.2.3` |

### Version types

- **Major** (v2.0.0) — Breaking changes to API, schema, or configuration
- **Minor** (v1.3.0) — New features, backward-compatible
- **Patch** (v1.2.1) — Bug fixes, security patches, no new features

### Major Version Philosophy

BOMHort plans for **one major version bump every 2–3 years**, driven by accumulated breaking changes — not by calendar. We do not stay on 1.x forever, but we also don't bump majors for marketing reasons.

**Triggers for a major version:**
- ClickHouse schema redesign (ORDER BY changes, table splits/merges)
- API contract breaks (`/api/v2/` introduction)
- Fundamental architecture shifts (e.g., multi-tenant RBAC, new ingestion protocol)
- Helm values restructuring that breaks existing `values.yaml` files

**What a major version provides:**
- Clean slate for accumulated tech debt and design lessons
- Clear migration window for enterprise adopters (migration guide required)
- Marketing momentum for significant capability jumps

**Constraints:**
- The previous major version receives security patches for **12 months** after the new major GA
- A **migration guide** with automated tooling (schema migration scripts, Helm values converter) is mandatory before tagging any major release
- Major versions are announced **at least 3 months** in advance via the roadmap

**Projected timeline:**
- v1.0 — October 2026 (first stable)
- v2.0 — Earliest Q1/Q2 2028 (after 12–18 months of production feedback on 1.x)

---

## How to Release

### Minor / Major Release

```bash
# 1. Ensure main is clean and CI passes
git checkout main && git pull

# 2. Tag the release
git tag v1.3.0
git push origin v1.3.0

# 3. CI automatically:
#    - Builds all 5 images (multi-arch: amd64 + arm64)
#    - Signs images with cosign (keyless)
#    - Attests provenance (SLSA)
#    - Packages and pushes Helm chart
#    - Creates GitHub Release with SBOM + changelog

# 4. Create release branch for future patches
git checkout -b release/v1.3
git push origin release/v1.3
```

### Minor Release Checklist

- [ ] All planned features for this milestone merged to `main`
- [ ] CI passes on `main`
- [ ] `govulncheck ./...` (backend), `npm audit` (ui + docs) clean
- [ ] **`ROADMAP.md` updated**: move completed items to "Done", adjust phase timelines if needed
- [ ] `docs/ARCHITECTURE_PLAN.md` reflects any new services or schema changes
- [ ] Tag created (`vX.Y.0`) and pushed
- [ ] Release branch created (`release/vX.Y`) and pushed
- [ ] Release notes written (features, breaking changes, upgrade notes)
- [ ] Helm chart version matches Git tag

### Patch Release

Patches are cherry-picked onto the release branch:

```bash
# 1. Fix the bug on main first (always)
git checkout main
# ... make fix, get PR merged ...

# 2. Cherry-pick to release branch
git checkout release/v1.2
git cherry-pick <commit-sha>
git push origin release/v1.2

# 3. Tag the patch
git tag v1.2.4
git push origin v1.2.4

# CI builds and publishes automatically
```

### Patch Release Checklist

- [ ] Fix merged to `main` first (never patch-only)
- [ ] Cherry-picked cleanly to `release/vX.Y` branch
- [ ] No new features included (patches are bug/security fixes only)
- [ ] CI passes on the release branch
- [ ] Tag follows existing sequence (v1.2.3 → v1.2.4)
- [ ] Release notes mention the fix and affected versions

---

## Documentation for Releases

Docs are versioned at the **minor** level (not per patch):

```
docs.bomhort.dev/           ← latest (main)
docs.bomhort.dev/v1.2/      ← v1.2.0, v1.2.1, v1.2.2, ... share these docs
docs.bomhort.dev/v1.1/      ← v1.1.x docs (frozen at last patch)
docs.bomhort.dev/v1.0/      ← v1.0.x docs (frozen)
```

### When releasing a new minor version:

1. Create `release/vX.Y` branch (docs freeze point)
2. Update `docs/hugo.toml` on the release branch: add versioned `baseURL`
3. Add new version to `params.versions` on both `main` and release branch
4. Mark the oldest supported version's docs with "unsupported" banner

### Doc fixes for patches:

- Fix docs on `main` first
- Cherry-pick to the release branch if the fix is relevant for that version
- Deploy triggers automatically on push to release branches

See [#145](https://github.com/seebom-labs/BOMHort/issues/145) for the full versioned docs implementation plan.

---

## Container Images

All images are published to **GitHub Container Registry (ghcr.io)**.

Images are built for **linux/amd64** and **linux/arm64**.

| Image | Purpose |
|-------|---------|
| `ghcr.io/seebom-labs/bomhort/api-gateway` | REST API server |
| `ghcr.io/seebom-labs/bomhort/parsing-worker` | SBOM processing worker |
| `ghcr.io/seebom-labs/bomhort/ingestion-watcher` | File scanner / queue enqueuer |
| `ghcr.io/seebom-labs/bomhort/cve-refresher` | Daily CVE refresh |
| `ghcr.io/seebom-labs/bomhort/ui` | Angular frontend (Nginx) |

All images are:
- Signed with [cosign](https://github.com/sigstore/cosign) (keyless via Fulcio)
- Attested with SLSA provenance (`actions/attest-build-provenance`)

### Verifying signatures

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/seebom-labs/BOMHort" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/seebom-labs/bomhort/api-gateway:1.2.3
```

## Installing from a Release

```bash
helm install bomhort oci://ghcr.io/seebom-labs/bomhort/charts/bomhort \
  --version 1.2.3 \
  -f values-production.yaml
```

## CI Workflows

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| CI | Push/PR to main | Go build + test + vet, Angular build, Helm lint |
| Release | Git tag `v*` | Build + push images, sign, attest, Helm chart, GitHub Release |
| Pre-Release | Manual | Build from any branch, create pre-release |
| Fuzz | Weekly + PRs touching `backend/` | SPDX and VEX parser fuzz tests |
| CodeQL | Push/PR | SAST for Go and TypeScript |
| Scorecard | Weekly | OpenSSF Scorecard analysis |

## Building Images Locally

```bash
make images            # Build all 5 images with tag "dev"
make images TAG=0.2.0  # Build with a specific tag
make images-push       # Build and push to GHCR
```
