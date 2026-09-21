.PHONY: help dev dev-up dev-down dev-logs dev-reset
.PHONY: demo-fleet demo-fleet-verify demo-fleet-down
.PHONY: demo-catalogue demo-catalogue-verify demo-catalogue-down
.PHONY: ch-shell ch-migrate
.PHONY: backend-build backend-test backend-vet
.PHONY: ui-build ui-dev
.PHONY: ingest worker api
.PHONY: images images-push
.PHONY: sync-labels
.PHONY: kind-up kind-down kind-reingest kind-build kind-deploy kind-stop kind-start kind-status
.PHONY: docs-serve docs-build docs-deps

SHELL := /bin/bash
REGISTRY ?= ghcr.io
REPO     ?= seebom-labs/bomhort
TAG      ?= dev

# ─── Help ────────────────────────────────────────────────────────────────────
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ─── Docker Compose (full stack) ────────────────────────────────────────────
dev: dev-up ## Start entire stack (ClickHouse + all services + UI)
	@echo "🚀 BOMHort running at:"
	@echo "   UI:          http://localhost:8090"
	@echo "   API:         http://localhost:8080/healthz"
	@echo "   ClickHouse:  http://localhost:8123 (HTTP) / localhost:9000 (TCP)"

dev-up: ## docker compose up --build -d
	docker compose up --build -d

dev-down: ## docker compose down
	docker compose down

dev-restart: ## Restart with new .env values (keeps data)
	docker compose up -d --force-recreate

sync-migrations: ## Copy db/migrations into the Helm chart (they must not drift)
	@echo "⏳ Syncing db/migrations -> deploy/helm/bomhort/migrations..."
	@cp db/migrations/*.sql deploy/helm/bomhort/migrations/
	@echo "✅ In sync."

check-migrations: ## Fail if the Helm chart's migrations have drifted from db/migrations
	@for f in db/migrations/*.sql; do \
		b=$$(basename "$$f"); \
		if [ ! -f "deploy/helm/bomhort/migrations/$$b" ]; then \
			echo "❌ Missing from Helm chart: $$b"; \
			echo "   Run 'make sync-migrations'."; exit 1; \
		fi; \
		if ! cmp -s "$$f" "deploy/helm/bomhort/migrations/$$b"; then \
			echo "❌ Content differs: $$b"; \
			echo "   Run 'make sync-migrations'."; exit 1; \
		fi; \
	done
	@echo "✅ Helm migrations in sync."

migrate: ## Run all pending database migrations
	@echo "⏳ Running migrations..."
	@for f in db/migrations/*.sql; do \
		echo "  → $$f"; \
		docker compose exec -T clickhouse clickhouse-client --database=bomhort --multiquery < "$$f" 2>/dev/null || true; \
	done
	@echo "✅ Migrations complete."

cve-refresh: migrate ## Run a CVE refresh (check all PURLs for new vulnerabilities)
	@echo "🔍 Starting CVE refresh..."
	@docker compose --profile cve-refresh up --build --force-recreate cve-refresher
	@echo "✅ CVE refresh complete."

re-ingest: ## Re-trigger the Ingestion Watcher (scans for new files)
	docker compose up --force-recreate ingestion-watcher

re-scan: ## Reset all data + queue, then re-ingest (e.g. after enabling OSV)
	@echo "⏳ Running pending migrations..."
	@for f in db/migrations/*.sql; do \
		echo "  → $$f"; \
		docker compose exec -T clickhouse clickhouse-client --database=bomhort --multiquery < "$$f" 2>/dev/null || true; \
	done
	@echo "🗑️  Clearing all data tables and queue..."
	@docker compose exec -T clickhouse clickhouse-client --database=bomhort \
		--query "TRUNCATE TABLE ingestion_queue"
	@docker compose exec -T clickhouse clickhouse-client --database=bomhort \
		--query "TRUNCATE TABLE vulnerabilities"
	@docker compose exec -T clickhouse clickhouse-client --database=bomhort \
		--query "TRUNCATE TABLE license_compliance"
	@docker compose exec -T clickhouse clickhouse-client --database=bomhort \
		--query "TRUNCATE TABLE sbom_packages"
	@docker compose exec -T clickhouse clickhouse-client --database=bomhort \
		--query "TRUNCATE TABLE sboms"
	@docker compose exec -T clickhouse clickhouse-client --database=bomhort \
		--query "TRUNCATE TABLE vex_statements" 2>/dev/null || true
	@echo "♻️  Rebuilding services with latest code..."
	@docker compose up --build -d api-gateway parsing-worker
	@echo "♻️  Re-triggering ingestion..."
	@docker compose up --force-recreate ingestion-watcher
	@echo "✅ Full re-scan started. Workers will process all SBOMs from scratch."
	@echo "   Monitor: make dev-status"

dev-logs: ## docker compose logs -f
	docker compose logs -f

# --- Ownership demo (cluster / namespace / project) --------------------------
# examples/fleet/ is laid out as {cluster}/{namespace}/{project}/file.json, so
# INGEST_PATH_LAYOUT derives all three dimensions from the path. The S3 vars are
# blanked on purpose: the shell environment wins over .env in Compose, so this
# runs against the bundled files even when .env points at real buckets.
DEMO_FLEET_ENV = SBOM_SOURCE_DIR=./examples/fleet \
	INGEST_PATH_LAYOUT=cluster/namespace/project \
	S3_BUCKETS= S3_BUCKET= S3_ENDPOINT= S3_ACCESS_KEY= S3_SECRET_KEY= \
	SBOM_LIMIT=0

demo-fleet: ## Wipe all data and ingest the bundled multi-cluster demo fleet (examples/fleet)
	@echo "Running pending migrations..."
	@for f in db/migrations/*.sql; do \
		docker compose exec -T clickhouse clickhouse-client --database=bomhort --multiquery < "$$f" 2>/dev/null || true; \
	done
	@echo "Clearing all data tables and queue..."
	@docker compose exec -T clickhouse clickhouse-client --database=bomhort --multiquery --query \
		"TRUNCATE TABLE ingestion_queue; TRUNCATE TABLE vulnerabilities; TRUNCATE TABLE license_compliance; TRUNCATE TABLE sbom_packages; TRUNCATE TABLE sboms; TRUNCATE TABLE vex_statements; TRUNCATE TABLE document_store;"
	@echo "Starting stack against examples/fleet with INGEST_PATH_LAYOUT=cluster/namespace/project..."
	@$(DEMO_FLEET_ENV) docker compose up --build -d --force-recreate api-gateway parsing-worker ui
	@$(DEMO_FLEET_ENV) docker compose up --build --force-recreate ingestion-watcher
	@echo "Demo fleet queued. Progress: make dev-status   Views: make demo-fleet-verify"

demo-fleet-verify: ## Print the cluster / namespace / fleet-tree views of the demo data
	@echo "=== GET /api/v1/clusters ==="
	@curl -sf http://localhost:8080/api/v1/clusters | jq -c '.[]' || echo "(API not reachable)"
	@echo ""
	@echo "=== GET /api/v1/namespaces ==="
	@curl -sf http://localhost:8080/api/v1/namespaces | jq -c '.[]' || true
	@echo ""
	@echo "=== GET /api/v1/namespaces?cluster=prod-eu ==="
	@curl -sf "http://localhost:8080/api/v1/namespaces?cluster=prod-eu" | jq -c '.[]' || true
	@echo ""
	@echo "=== GET /api/v1/fleet (cluster -> namespace -> project) ==="
	@curl -sf http://localhost:8080/api/v1/fleet | \
		jq -r '.[] | "\(.name) [\(.sbom_count) SBOMs, \(.vuln_count) vulns]", (.namespaces[] | "  \(.name) [\(.sbom_count) SBOMs]", (.projects[] | "    \(.name) [\(.sbom_count) SBOMs, \(.vuln_count) vulns]"))' || true

demo-fleet-down: ## Return the stack to the configuration in .env (keeps ingested data)
	docker compose up -d --force-recreate api-gateway parsing-worker ui

# --- Catalogue demo (project / tags) ----------------------------------------
# The counterpart to demo-fleet: a catalogue of projects that run nowhere in
# particular, so cluster/namespace stay empty and TAGS carries the grouping.
# Layout is {project}/file.json per tier, hence INGEST_PATH_LAYOUT=project.
#
# One watcher run per tier because TAGS is instance-wide. The parsing worker is
# recreated with the same SBOM_SOURCE_DIR for each run and the queue is drained
# before moving on: source_file is stored relative to the watcher's root, so a
# worker mounted at a different root cannot resolve it.
#
# In production none of this is needed — each tier is its own S3 bucket with
# its own "tags", and one worker serves them all (see examples/catalogue/README.md).
DEMO_CATALOGUE_ENV = INGEST_PATH_LAYOUT=project \
	S3_BUCKETS= S3_BUCKET= S3_ENDPOINT= S3_ACCESS_KEY= S3_SECRET_KEY= \
	SBOM_LIMIT=0

demo-catalogue: ## Wipe all data and ingest the bundled project catalogue (examples/catalogue)
	@echo "Running pending migrations..."
	@for f in db/migrations/*.sql; do \
		docker compose exec -T clickhouse clickhouse-client --database=bomhort --multiquery < "$$f" 2>/dev/null || true; \
	done
	@echo "Clearing all data tables and queue..."
	@docker compose exec -T clickhouse clickhouse-client --database=bomhort --multiquery --query \
		"TRUNCATE TABLE ingestion_queue; TRUNCATE TABLE vulnerabilities; TRUNCATE TABLE license_compliance; TRUNCATE TABLE sbom_packages; TRUNCATE TABLE sboms; TRUNCATE TABLE vex_statements; TRUNCATE TABLE document_store;"
	@$(DEMO_CATALOGUE_ENV) docker compose up --build -d --force-recreate api-gateway ui
	@for tier in sandbox:sandbox-applications incubating:incubating graduated:graduated; do \
		dir=$${tier%%:*}; tag=$${tier##*:}; \
		echo ""; \
		echo "── Ingesting $$dir with TAGS=$$tag ──────────────────────────"; \
		$(DEMO_CATALOGUE_ENV) SBOM_SOURCE_DIR=./examples/catalogue/$$dir TAGS=$$tag \
			docker compose up --build -d --force-recreate parsing-worker; \
		$(DEMO_CATALOGUE_ENV) SBOM_SOURCE_DIR=./examples/catalogue/$$dir TAGS=$$tag \
			docker compose up --build --force-recreate ingestion-watcher; \
		printf "   draining queue"; \
		for i in $$(seq 1 60); do \
			left=$$(docker compose exec -T clickhouse clickhouse-client --database=bomhort -q \
				"SELECT count() FROM (SELECT job_id, argMax(status, created_at) s FROM ingestion_queue GROUP BY job_id) WHERE s IN ('pending','processing')" 2>/dev/null || echo 1); \
			[ "$$left" = "0" ] && break; \
			printf "."; sleep 2; \
		done; \
		echo " done"; \
	done
	@echo ""
	@echo "Demo catalogue ingested. Views: make demo-catalogue-verify"

demo-catalogue-verify: ## Print the tag / project views of the catalogue demo data
	@echo "=== GET /api/v1/tags (the groupings that exist — data-driven) ==="
	@curl -sf http://localhost:8080/api/v1/tags | jq -c '.[]' || echo "(API not reachable)"
	@echo ""
	@echo "=== GET /api/v1/projects?tag=sandbox-applications ==="
	@echo "    (k2s must appear ONCE with 2 SBOMs — tags group projects, not replace them)"
	@curl -sf "http://localhost:8080/api/v1/projects?tag=sandbox-applications" | \
		jq -r '.data[] | "  \(.project_name) [\(.sbom_count) SBOMs, \(.vuln_count) vulns] tags=\(.tags)"' || true
	@echo ""
	@echo "=== GET /api/v1/projects (unfiltered: every tier) ==="
	@curl -sf "http://localhost:8080/api/v1/projects?page_size=50" | \
		jq -r '.data[] | "  \(.project_name) [\(.sbom_count) SBOMs] tags=\(.tags)"' || true
	@echo ""
	@echo "=== GET /api/v1/clusters (one unnamed bucket — nothing runs in a cluster) ==="
	@echo "    (a catalogue has no cluster dimension; the UI renders this as \"(unassigned)\")"
	@curl -sf http://localhost:8080/api/v1/clusters | jq -c '.' || true

demo-catalogue-down: ## Return the stack to the configuration in .env (keeps ingested data)
	docker compose up -d --force-recreate api-gateway parsing-worker ui


dev-reset: dev-down ## Destroy volumes and restart fresh
	docker compose down -v
	docker compose up --build -d

dev-status: ## Show status of all containers + ingestion progress
	@docker compose ps
	@echo ""
	@echo "=== Ingestion Progress ==="
	@docker compose exec -T clickhouse clickhouse-client --database=bomhort \
		--query "SELECT latest_status AS status, count() AS cnt FROM (SELECT argMax(status, created_at) AS latest_status FROM ingestion_queue GROUP BY job_id) GROUP BY latest_status ORDER BY latest_status" \
		--format=PrettyCompact 2>/dev/null || echo "(ClickHouse not ready)"
	@echo ""
	@echo "=== Data Summary ==="
	@docker compose exec -T clickhouse clickhouse-client --database=bomhort \
		--query "SELECT 'sboms' AS tbl, count() AS cnt FROM sboms FINAL UNION ALL SELECT 'packages', count() FROM sbom_packages FINAL UNION ALL SELECT 'vulns', count() FROM vulnerabilities FINAL UNION ALL SELECT 'licenses', count() FROM license_compliance FINAL" \
		--format=PrettyCompact 2>/dev/null || echo "(ClickHouse not ready)"

# ─── ClickHouse ──────────────────────────────────────────────────────────────
ch-shell: ## Open a ClickHouse client shell
	docker compose exec clickhouse clickhouse-client --database=bomhort

ch-migrate: ## Manually run all migrations against running ClickHouse
	@for f in db/migrations/*.sql; do \
		echo "⏳ Running $$f ..."; \
		docker compose exec -T clickhouse clickhouse-client --database=bomhort --multiquery < "$$f"; \
	done
	@echo "✅ All migrations applied."

# ─── Local dev (without Docker for backend) ──────────────────────────────────
# Start only ClickHouse, then run Go services locally.

ch-only: ## Start only ClickHouse in Docker
	docker compose up -d clickhouse
	@echo "⏳ Waiting for ClickHouse to be healthy..."
	@until docker compose exec clickhouse clickhouse-client --query "SELECT 1" > /dev/null 2>&1; do sleep 1; done
	@echo "✅ ClickHouse ready at localhost:9000"

backend-build: ## Build all Go binaries
	cd backend && go build ./...

backend-test: ## Run all Go tests
	cd backend && go test ./... -v -count=1

backend-vet: ## Run go vet + go fmt
	cd backend && go fmt ./... && go vet ./...

api: ## Run API Gateway locally (needs ClickHouse)
	cd backend && go run ./cmd/api-gateway/

ingest: ## Run Ingestion Watcher once locally (needs ClickHouse)
	cd backend && go run ./cmd/ingestion-watcher/

worker: ## Run Parsing Worker locally (needs ClickHouse)
	cd backend && go run ./cmd/parsing-worker/

# ─── Angular UI ──────────────────────────────────────────────────────────────
ui-dev: ## Start Angular dev server (hot-reload, proxies to localhost:8080)
	cd ui && npx ng serve --proxy-config proxy.conf.json

ui-build: ## Build Angular for production
	cd ui && npx ng build --configuration=production

# ─── Container Images ────────────────────────────────────────────────────────
images: ## Build all container images locally (TAG=dev)
	docker build -t $(REGISTRY)/$(REPO)/ingestion-watcher:$(TAG) --target ingestion-watcher backend/
	docker build -t $(REGISTRY)/$(REPO)/parsing-worker:$(TAG)    --target parsing-worker    backend/
	docker build -t $(REGISTRY)/$(REPO)/api-gateway:$(TAG)       --target api-gateway       backend/
	docker build -t $(REGISTRY)/$(REPO)/cve-refresher:$(TAG)     --target cve-refresher     backend/
	docker build -t $(REGISTRY)/$(REPO)/ui:$(TAG) ui/
	@echo "✅ Built 5 images with tag $(TAG)"

images-push: images ## Build and push all images to GHCR (TAG=dev)
	docker push $(REGISTRY)/$(REPO)/ingestion-watcher:$(TAG)
	docker push $(REGISTRY)/$(REPO)/parsing-worker:$(TAG)
	docker push $(REGISTRY)/$(REPO)/api-gateway:$(TAG)
	docker push $(REGISTRY)/$(REPO)/cve-refresher:$(TAG)
	docker push $(REGISTRY)/$(REPO)/ui:$(TAG)
	@echo "✅ Pushed 5 images to $(REGISTRY)/$(REPO) with tag $(TAG)"


# ─── GitHub ──────────────────────────────────────────────────────────────────
sync-labels: ## Sync GitHub labels from .github/labels.yml (requires gh + yq)
	.github/scripts/sync-labels.sh

# ─── Kind (local Kubernetes) ─────────────────────────────────────────────────
kind-up: ## Deploy BOMHort to a local Kind cluster (see local/secrets.env)
	./local/setup.sh

kind-down: ## Destroy the local Kind cluster (deletes everything)
	./local/teardown.sh

kind-stop: ## Stop the Kind cluster without losing data (docker stop)
	@echo "⏸️  Stopping Kind cluster 'bomhort'..."
	@docker stop bomhort-control-plane 2>/dev/null || echo "Cluster not running"
	@echo "✅ Cluster stopped. Data and volumes preserved."
	@echo "   Resume with: make kind-start"

kind-start: ## Resume a stopped Kind cluster (docker start)
	@echo "▶️  Starting Kind cluster 'bomhort'..."
	@docker start bomhort-control-plane 2>/dev/null || { echo "❌ No stopped cluster found. Run: make kind-up"; exit 1; }
	@echo "⏳ Waiting for API server..."
	@until kubectl --context kind-bomhort cluster-info >/dev/null 2>&1; do sleep 2; done
	@echo "✅ Cluster running. All pods and volumes intact."
	@echo "   UI:   http://localhost:8090"
	@echo "   API:  http://localhost:8080/healthz"
	@echo "   Pods: kubectl get pods -n bomhort"

kind-status: ## Show Kind cluster and pod status
	@echo "=== Kind Cluster ==="
	@docker ps -a --filter "name=bomhort-control-plane" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "No Kind cluster found"
	@echo ""
	@echo "=== Pods ==="
	@kubectl get pods -n bomhort 2>/dev/null || echo "(cluster not reachable)"

kind-reingest: ## Re-ingest all SBOMs in Kind (no re-download, truncates data + re-queues)
	@echo "🗑️  Truncating data tables..."
	@source local/secrets.env 2>/dev/null; \
	kubectl exec -n bomhort chi-bomhort-clickhouse-bomhort-cluster-0-0-0 -c clickhouse -- \
		clickhouse-client --database=bomhort --password="$${CLICKHOUSE_PASSWORD:-bomhort}" --multiquery \
		--query "TRUNCATE TABLE ingestion_queue; TRUNCATE TABLE license_compliance; TRUNCATE TABLE vulnerabilities; TRUNCATE TABLE sbom_packages; TRUNCATE TABLE sboms; TRUNCATE TABLE vex_statements;"
	@echo "♻️  Triggering ingestion watcher..."
	@kubectl create job --from=cronjob/bomhort-ingestion-watcher bomhort-reingest-$$(date +%s) -n bomhort
	@echo "✅ Re-ingest started. Workers will re-process all SBOMs from the PVC."
	@echo "   Monitor: curl -s http://localhost:8080/api/v1/stats/dashboard | jq .total_sboms"

kind-build: images ## Build dev images and load them into the Kind cluster
	@echo "📦 Loading images into Kind cluster..."
	kind load docker-image $(REGISTRY)/$(REPO)/ingestion-watcher:$(TAG) --name bomhort
	kind load docker-image $(REGISTRY)/$(REPO)/parsing-worker:$(TAG)    --name bomhort
	kind load docker-image $(REGISTRY)/$(REPO)/api-gateway:$(TAG)       --name bomhort
	kind load docker-image $(REGISTRY)/$(REPO)/cve-refresher:$(TAG)     --name bomhort
	kind load docker-image $(REGISTRY)/$(REPO)/ui:$(TAG)                --name bomhort
	@echo "✅ Loaded 5 images into Kind (tag: $(TAG))"

kind-deploy: kind-build ## Build images, load into Kind, and upgrade Helm release
	@source local/secrets.env 2>/dev/null; \
	helm upgrade bomhort deploy/helm/bomhort/ \
		-n bomhort \
		-f local/values-local.yaml \
		--set clickhouse.password="$${CLICKHOUSE_PASSWORD:-bomhort}" \
		--set github.token="$${GITHUB_TOKEN:-}" \
		--set s3.accessKey="$${S3_ACCESS_KEY:-}" \
		--set s3.secretKey="$${S3_SECRET_KEY:-}"
	@kubectl rollout restart deployment/bomhort-api-gateway deployment/bomhort-parsing-worker -n bomhort
	@echo "✅ Deployed. Pods restarting with new images."

# ─── Documentation (Hugo + Docsy) ────────────────────────────────────────────
docs-deps: ## Install Hugo docs dependencies (npm + Go modules)
	cd docs && npm install && hugo mod get

docs-serve: ## Start Hugo dev server with live reload (http://localhost:1313)
	cd docs && hugo server --buildDrafts --buildFuture

docs-build: ## Build Hugo documentation site (output in docs/public/)
	cd docs && hugo --minify
