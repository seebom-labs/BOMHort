# Upload SBOM GitHub Action

A composite GitHub Action to upload an existing Software Bill of Materials (SBOM) or VEX document directly to a BOMHort instance using the push ingestion endpoint (`POST /api/v1/sboms/upload`).

## Usage

### Basic Upload

```yaml
steps:
  - uses: actions/checkout@v4

  - name: Upload SBOM to BOMHort
    uses: seebom-labs/BOMHort/.github/actions/upload-sbom@1b3e829fa97f21f2697bc6fc8d6dba8da77316af
    with:
      url: 'https://bomhort.example.com'
      token: ${{ secrets.BOMHORT_UPLOAD_TOKEN }}
      sbom: 'target/bom.spdx.json'
      cluster: 'prod-eu'
      namespace: 'payments'
      tags: 'tier-1,backend'
```

### CI Security Gating with SARIF Export

Wait for ingestion to complete, fail the build on high/critical findings, and publish SARIF results to GitHub Code Scanning:

```yaml
steps:
  - uses: actions/checkout@v4

  - name: Upload and gate on vulnerabilities
    id: bomhort
    uses: seebom-labs/BOMHort/.github/actions/upload-sbom@1b3e829fa97f21f2697bc6fc8d6dba8da77316af
    with:
      url: 'https://bomhort.example.com'
      token: ${{ secrets.BOMHORT_UPLOAD_TOKEN }}
      sbom: 'build/app.spdx.json'
      wait: 'true'
      fail-on: 'high'
      sarif: 'bomhort-results.sarif'

  - name: Upload SARIF report to GitHub
    uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: 'bomhort-results.sarif'
```

> **Pin the action version.** Use a full commit SHA or release tag instead of `@main`, which can change without notice. This example pins to the current action revision; update the pin deliberately when upgrading.

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `url` | BOMHort instance URL | Yes | - |
| `token` | Service token or API key, as selected by `auth-type` | Yes | - |
| `auth-type` | `bearer` sends `Authorization: Bearer` for a service token; `api-key` sends `X-API-Key` | No | `bearer` |
| `sbom` | Path or pattern for an SBOM or VEX JSON file (`.spdx.json`, `.cdx.json`, `.openvex.json`, `.vex.json`, `.json`) | Yes | - |
| `project` | Project name in BOMHort | No | `${{ github.event.repository.name }}` |
| `cluster` | Target cluster name | No | - |
| `namespace` | Target deployment namespace | No | - |
| `parent` | Parent product / group name | No | - |
| `tags` | Comma-separated grouping tags | No | - |
| `source-repo` | Source repository URL | No | `${{ github.server_url }}/${{ github.repository }}` |
| `source-ref` | Git commit SHA, branch, or tag | No | `${{ github.sha }}` |
| `wait` | Wait for the ingestion job to complete (automatically enabled if `sarif` or `fail-on` is specified) | No | `'false'` |
| `wait-timeout` | Maximum time in seconds to wait for ingestion to complete | No | `'300'` |
| `fail-on` | Fail if findings meet or exceed severity (`none`, `low`, `medium`, `high`, `critical`) | No | `'none'` |
| `sarif` | File path to download SARIF 2.1.0 report for `upload-sarif` | No | `''` |

The upload API extracts the artifact version from the SBOM itself; it is not a separate upload input.

The BOMHort API Gateway must have `AUTH_ENABLED=true`. Configure the credential as `SERVICE_TOKEN` when using the default `bearer` auth type, or as an entry in `API_KEYS` when using `api-key`.

## Outputs

| Output | Description |
|--------|-------------|
| `status` | Upload status (`pending` or `duplicate`) |
| `job-id` | Enqueued ingestion job ID (UUID) |
| `sha256-hash` | SHA-256 digest of the ingested document |
| `sbom-id` | SBOM UUID in BOMHort |
| `vulnerabilities` | JSON summary of vulnerability counts by severity (e.g. `{"critical":0,"high":1,"medium":2,"low":0}`) |
| `url` | Deep link to the SBOM detail in BOMHort |
