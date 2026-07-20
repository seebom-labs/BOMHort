---
title: "Getting Started"
linkTitle: "Getting Started"
type: docs
weight: 1
description: >
  Quick start guide for running BOMHort locally or on Kubernetes.
---

<img src="/images/dashboard-screenshot.png" alt="BOMHort Dashboard" style="width: 100%; border-radius: 8px; border: 1px solid var(--sb-border); margin-bottom: 2rem;">

{{% alert title="Project rename" color="info" %}}
BOMHort is the new project name (formerly known as BOMHort). Details: [Why we renamed BOMHort to BOMHort](/docs/getting-started/rename/).
{{% /alert %}}

## Prerequisites

| Tool | Minimum Version |
|------|----------------|
| Docker + Docker Compose | v2.20+ |
| Go | 1.24+ (only for local dev) |
| Node.js | 22+ (only for local dev) |

## Option A: Full Stack via Docker Compose (Recommended)

```bash
# 1. Clone the repo
git clone https://github.com/seebom-labs/BOMHort.git && cd BOMHort

# 2. Place your SBOM files in the sboms/ directory
#    Supported formats: SPDX JSON, CycloneDX JSON, in-toto attestation envelopes
#    (format is auto-detected — any .json file works)
#    Included examples: _example.spdx.json, _example-intoto.spdx.json,
#              _example.cdx.json, _example-violations.spdx.json, _example.openvex.json

# 3. Start everything
make dev

# Or without make:
docker compose up --build -d
```

This starts:
- **ClickHouse** on `localhost:9000` (TCP) / `localhost:8123` (HTTP)
- **API Gateway** on `localhost:8080`
- **Ingestion Watcher** (runs once, scans `sboms/` for new files)
- **Parsing Worker** (processes queued SBOM/VEX files)
- **Angular UI** on `localhost:8090`

Open **http://localhost:8090** in your browser.

## Option B: Local Kubernetes (Kind)

Deploy the full stack to a local [Kind](https://kind.sigs.k8s.io/) cluster:

```bash
# 1. Copy secrets template and fill in your values
cp examples/kind/secrets.env.example local/secrets.env
vi local/secrets.env

# 2. Deploy (builds images, loads into Kind, installs via Helm)
make kind-up

# UI: http://localhost:8090   API: http://localhost:8080/healthz
```

## Option C: Local Development (Hot Reload)

```bash
# 1. Start only ClickHouse
make ch-only

# 2. Run the migrations (first time only)
make ch-migrate

# 3. In separate terminals:
make api      # API Gateway
make ingest   # Ingestion Watcher (once)
make worker   # Parsing Worker
make ui-dev   # Angular dev server (http://localhost:4200)
```

## Configuration (`.env`)

Copy `.env.example` to `.env` and adjust:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `S3_BUCKETS` | *(empty)* | JSON array of S3 bucket configs (recommended) |
| `S3_BUCKET` | *(empty)* | Single S3 bucket name (alternative) |
| `SBOM_SOURCE_DIR` | `./sboms` | Path to local SBOM files |
| `SBOM_LIMIT` | `0` | Max SBOMs to enqueue (`0` = unlimited) |
| `SBOM_IGNORE_PREFIX` | `_` | Skip local files starting with this prefix |
| `WORKER_REPLICAS` | `1` | Number of parallel workers |
| `WORKER_BATCH_SIZE` | `50` | Jobs per polling cycle |
| `SKIP_OSV` | `false` | Skip vulnerability lookups for fast ingestion |
| `SKIP_GITHUB_RESOLVE` | `false` | Skip GitHub license resolution |
| `GITHUB_TOKEN` | *(empty)* | GitHub PAT (increases rate limit to 5000 req/h) |

{{% alert title="Recommended: Set GITHUB_TOKEN" color="warning" %}}
Without a GitHub token, license resolution is limited to **60 requests per hour** — most container-image SBOMs will have many packages stuck as `NOASSERTION`. Create a [Personal Access Token (classic)](https://github.com/settings/tokens) with **no scopes** and set it in your `.env` file. See [FAQ: Should I use a GitHub token?](/docs/faq/#should-i-use-a-github-token) for details.
{{% /alert %}}

