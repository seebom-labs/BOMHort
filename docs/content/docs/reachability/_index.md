---
title: "Reachability Evidence"
description: "How BOMHort records and verifies reachability evidence per vulnerability finding."
weight: 45
---

# Reachability Evidence

A vulnerability finding in a Software Bill of Materials (SBOM) indicates that a dependency version contains a known flaw. However, whether that flawed code is actually reachable or callable during execution depends on the application's binary or runtime call path.

Without reachability evidence, marking a finding as non-actionable is merely an assertion. With concrete evidence ("the vulnerable function is not reachable from this binary according to govulncheck 1.1.3 on commit abc1234"), security teams and compliance auditors can verify that the risk is mitigated.

BOMHort stores reachability evidence directly on the `vulnerabilities` table (introduced in migration `029_add_reachability.up.sql`), surfaces evidence badges and filters in the web console, and records the tool version and reference alongside each finding.

## Reachability Vocabulary

Every finding records its reachability status as one of three standard values:

| Value | Meaning | Evidence Source |
|---|---|---|
| `reachable` | The vulnerable function or symbol was called in the execution trace. | Call-graph analyzer (`govulncheck`) or explicit VEX statement |
| `not_reachable` | The vulnerable symbol is not called or reachable from the application code. | OpenVEX justification (`vulnerable_code_not_in_execute_path`) or report without trace |
| `unknown` | No reachability analyzer or evidence has been submitted for this finding. | Default state upon initial SBOM ingestion |

> **Important**: Reachability never alters vulnerability status by itself. A finding marked `not_reachable` retains its severity and findings record; it acts as verifiable input that an engineer or automated triage policy uses to formulate an official OpenVEX statement.

## Ingestion Paths

BOMHort supports two primary methods for ingesting reachability evidence:

### 1. OpenVEX Statements (Path A)

When ingesting an OpenVEX document, any statement that asserts the code is not in the execution path or includes a reachability prefix automatically populates reachability evidence on the affected SBOM findings:

- **Justification**: A statement with `status = "not_affected"` and `justification = "vulnerable_code_not_in_execute_path"` marks the matching vulnerability as `not_reachable`.
- **Impact Statement**: Statements whose `impact_statement` begins with recognised prefixes (such as `reachability: reachable`, `reachability: not_reachable`, `govulncheck: reachable`, or `govulncheck: unreachable`) set the corresponding status.
- **Evidence Attributes**:
  - `evidence_source`: Extracted from the statement's `tooling` field (or `OpenVEX` if omitted).
  - `evidence_ref`: Extracted from the OpenVEX document ID.
  - `evidence_at`: Timestamp from the statement.

When statements arrive before an SBOM has been ingested, BOMHort's post-ingest rescue pass re-evaluates and scopes the statement once the target SBOM exists, ensuring that evidence is reliably linked regardless of file delivery order.

### 2. Govulncheck JSON Ingestion (Path B)

For Go applications, BOMHort natively accepts raw `govulncheck -json` output via a dedicated REST endpoint:

```http
POST /api/v1/sboms/{id}/evidence?ref=https://github.com/org/repo/actions/runs/12345
Content-Type: application/json
```

The payload accepts standard newline-delimited JSON or a JSON array produced by running `govulncheck -json ./...`. Ingestion requires authentication (`AUTH_ENABLED=true`); requests return `403 Forbidden` if authentication is disabled. Payloads must contain valid scanner configuration (`scanner_name = "govulncheck"`) and at least one finding; empty configs or reports without findings return `400 Bad Request`.

#### How Govulncheck Evidence Is Processed

1. **Scanner Identity**: BOMHort decodes the `config` message to extract the scanner tool name and version (e.g. `govulncheck v1.1.3`).
2. **Aliases and Call Traces**: OSV IDs and their CVE/GHSA aliases are correlated per affected module and package. Findings with a non-empty `trace` slice indicate that vulnerable code was called (`reachable`).
3. **Per-Finding Attribution**: Evidence is scoped to distinct `(vuln_id, purl)` pairs:
   - Existing findings matching a report vulnerability and package module with an active call trace are updated to `reachable`.
   - Existing findings matching a report vulnerability and package module with no call trace are updated to `not_reachable`.
   - Unreported findings (such as non-Go components or packages not analyzed in the report) remain completely untouched, preserving their current reachability state (e.g. `unknown`).
4. **Audit Durability**: The update is executed as a synchronized ClickHouse mutation, preserving the original `discovered_at` finding timestamp while recording `evidence_source`, `evidence_ref`, and `evidence_at`.

#### Example Ingestion Request

```bash
govulncheck -json ./... | curl -X POST \
  -H "Content-Type: application/json" \
  --data-binary @- \
  "http://localhost:8080/api/v1/sboms/6f2b525a-fbde-5b43-aa92-ac06a3f7220d/evidence?ref=build-482"
```

Response (`200 OK`):
```json
{
  "sbom_id": "6f2b525a-fbde-5b43-aa92-ac06a3f7220d",
  "tool": "govulncheck v1.1.3",
  "ref": "build-482",
  "total_findings": 8,
  "reachable": 2,
  "not_reachable": 6,
  "timestamp": "2026-11-11T14:00:00Z"
}
```

## User Interface and Filtering

In the BOMHort web interface:

- **Evidence Badges**: Vulnerability lists and the SBOM Explorer render clear visual badges for each finding:
  - `REACHABLE` (critical/red highlight): The vulnerable symbol is directly invoked.
  - `NOT REACHABLE` (green highlight): Evidence confirms the code is unreachable.
  - Hovering over the badge displays a tooltip detailing the tool, version, and reference.
- **Register Filtering**: The global vulnerability view provides a **Reachability** dropdown filter, syncing with the `?reachability=` URL query parameter:
  - `/api/v1/vulnerabilities?reachability=reachable`
  - `/api/v1/vulnerabilities?reachability=not_reachable`
  - `/api/v1/vulnerabilities?reachability=unknown`
- **CSV Reports**: Exporting findings via `GET /api/v1/reports/vulnerabilities?format=csv` includes the four evidence columns (`reachability`, `evidence_source`, `evidence_ref`, and `evidence_at`) for offline review and audit reporting.

