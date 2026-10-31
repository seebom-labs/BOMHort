# Upload SBOM GitHub Action

A composite GitHub Action to upload an existing Software Bill of Materials (SBOM) or VEX document directly to a BOMHort instance using the push ingestion endpoint (`POST /api/v1/sboms/upload`).

## Usage

```yaml
steps:
  - uses: actions/checkout@v4

  - name: Upload SBOM to BOMHort
    uses: seebom-labs/BOMHort/.github/actions/upload-sbom@main
    with:
      url: 'https://bomhort.example.com'
      token: ${{ secrets.BOMHORT_UPLOAD_TOKEN }}
      sbom: 'target/bom.spdx.json'
      cluster: 'prod-eu'
      namespace: 'payments'
      tags: 'tier-1,backend'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `url` | BOMHort instance URL | Yes | — |
| `token` | Service token or API key, as selected by `auth-type` | Yes | — |
| `auth-type` | `bearer` sends `Authorization: Bearer` for a service token; `api-key` sends `X-API-Key` | No | `bearer` |
| `sbom` | Path or pattern for an SBOM or VEX JSON file (`.spdx.json`, `.cdx.json`, `.openvex.json`, `.vex.json`, `.json`) | Yes | — |
| `project` | Project name in BOMHort | No | `${{ github.event.repository.name }}` |
| `cluster` | Target cluster name | No | — |
| `namespace` | Target deployment namespace | No | — |
| `parent` | Parent product / group name | No | — |
| `tags` | Comma-separated grouping tags | No | — |
| `source-repo` | Source repository URL | No | `${{ github.server_url }}/${{ github.repository }}` |
| `source-ref` | Git commit SHA, branch, or tag | No | `${{ github.sha }}` |

The upload API extracts the artifact version from the SBOM itself; it is not a separate upload input.

The BOMHort API Gateway must have `AUTH_ENABLED=true`. Configure the credential as `SERVICE_TOKEN` when using the default `bearer` auth type, or as an entry in `API_KEYS` when using `api-key`.

## Outputs

| Output | Description |
|--------|-------------|
| `status` | Upload status (`pending` or `duplicate`) |
| `job-id` | Enqueued ingestion job ID (UUID) |
| `sha256-hash` | SHA-256 digest of the ingested document |
