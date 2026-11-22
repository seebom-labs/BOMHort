# Executable Commands

These are command references, not permission to execute destructive operations.
For reviews use [the isolated-stack procedure](review.md); never reset shared
data, stop another user's stack or run formatting commands that edit tracked
files. Resolve paths from the repository root. Release commands still require
explicit authorization under [workflow.md](workflow.md).

## Development (Docker Compose)
```
make dev             # Start full stack (alias for dev-up, prints URLs)
make dev-up          # Start full stack (ClickHouse + Backend + UI)
make dev-down        # Stop and remove containers
make dev-reset       # Wipe ClickHouse data and restart from scratch
make dev-restart     # Restart with new .env values (keeps data)
make dev-status      # Show container status + ingestion progress + data summary
make dev-logs        # Follow Docker Compose logs
make re-ingest       # Re-trigger the Ingestion Watcher
make re-scan         # Wipe vulns/licenses and re-process all SBOMs
make demo-fleet      # Wipe all data and ingest examples/fleet (cluster/namespace/project demo)
make demo-fleet-verify # Print the cluster / namespace / fleet-tree API views
make cve-refresh     # Run CVE refresh (check all PURLs for new CVEs)
make migrate         # Run all pending database migrations
make ch-shell        # Open ClickHouse SQL shell
```

## Local Development (without Docker for backend)
```
make ch-only         # Start only ClickHouse in Docker
make ch-migrate      # Run migrations against running ClickHouse
make api             # Run API Gateway locally (needs ClickHouse)
make ingest          # Run Ingestion Watcher once locally
make worker          # Run Parsing Worker locally
make mcp             # Run the MCP server locally on stdio (needs a running API gateway)
make ui-dev          # Start Angular dev server (hot-reload, proxies to localhost:8080)
```

## Kind (Local Kubernetes)
```
make kind-up         # Deploy BOMHort to a local Kind cluster
make kind-down       # Destroy the local Kind cluster
make kind-stop       # Stop the Kind cluster without losing data (docker stop)
make kind-start      # Resume a stopped Kind cluster (all data intact)
make kind-status     # Show Kind cluster and pod status
make kind-build      # Build dev images and load into Kind
make kind-deploy     # Build, load, and upgrade Helm release
make kind-reingest   # Truncate data and re-trigger ingestion in Kind
make kind-deploy-release VERSION=0.8.0-rc.1   # Upgrade Kind to a published release/RC from GHCR (no local build)
```

## Releases
```
make release-rc VERSION=0.8.0 DRY_RUN=1   # Preview the next RC; the first one also cuts release/v0.8 from main
make release-rc VERSION=0.8.0             # Tag + push it → release.yml publishes images, chart, pre-release
make release    VERSION=0.8.0             # Final release from release/v0.8 (patches: VERSION=0.8.1)
make cherry-pick PR=431 BRANCH=0.8        # Backport a PR merged on main → PR against release/v0.8
make release-branch VERSION=0.7           # Create a branch for a minor released before release branches
```
Release tags live on release branches `release/vX.Y` only (release.yml rejects others). Tags and branches are pushed to the `seebom-labs` remote — only with explicit approval (see Boundaries). Details: `docs/RELEASE.md`.

## Build & Test
```
Backend Build:   cd backend && go build ./...
Backend Test:    cd backend && go test ./... -v -count=1
Backend Vet:     cd backend && go fmt ./... && go vet ./...
Frontend Install: cd ui && npm install
Frontend Build:  cd ui && npx ng build --configuration=production
Frontend Test:   cd ui && npx ng test            # uses Vitest
Helm Test:       python3 -B -m unittest discover -s deploy/helm/tests -v   # needs helm
Release Tooling: python3 -B -m unittest discover -s hack/tests -v          # cut-release / cherry-pick vs. throwaway repos
```
