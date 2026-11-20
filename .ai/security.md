# Security Hardening

## API Gateway (`cmd/api-gateway/main.go`)
- **Security headers** are set via `securityHeadersMiddleware`: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy`.
- **CORS** is configurable via `CORS_ALLOWED_ORIGINS` env var (default `*` for dev, restrict in production). `GET` and `OPTIONS` are allowed on every endpoint; `POST` is additionally advertised only for `/api/v1/sboms/upload` (checked by path in `corsMiddleware`, not applied globally).
- **Rate limiting** via `rateLimitMiddleware`: 100 requests per 10s per IP, with background cleanup to prevent memory leaks.
- **Authentication** via `authMiddleware` (opt-in, default off). Set `AUTH_ENABLED=true` plus either `SERVICE_TOKEN` (shared secret for upstream proxies, accepted as `Authorization: Bearer` or `X-Service-Token`) and/or `API_KEYS` (comma-separated list, accepted as `X-API-Key`). Uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks. Public paths (`/healthz`, `/livez`, `/readyz`) and `OPTIONS` preflight always bypass auth. `POST /api/v1/sboms/upload` (#135) additionally self-enforces `AUTH_ENABLED=true` inside `uploadHandler` itself — a write endpoint being open by default is a materially different risk than the read-only default, so it doesn't rely solely on the global opt-in.
- **Input validation**: All UUID path parameters (`sbomID`) are validated against `uuidPattern` regex. Vulnerability IDs (`vulnID`) are validated against `vulnIDPattern`. Query parameters that reach a query are whitelisted to known values; pagination parameters are parsed as integers and clamped.
- **Pagination bounds**: `clampPageSize()` enforces max 500 items per page to prevent abusive queries.
- **Log injection prevention**: `sanitizeLogParam()` strips newlines/control characters and truncates to 200 chars before logging user-supplied values.
- **No SQL injection risk**: All ClickHouse queries use parameterized queries (`?` placeholders), never string interpolation with user input.

## Nginx (`ui/nginx.conf`)
- Security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` (strict `default-src 'self'`), `Referrer-Policy`, `Permissions-Policy`.
- `server_tokens off` hides nginx version.

## Angular (Frontend)
- **Never bypass Angular sanitization** — use `DomSanitizer.sanitize(SecurityContext.HTML, ...)` which strips `<script>`, event handlers, and other dangerous HTML while preserving safe formatting (`<strong>`, `<a>`, `<em>`, `<code>`).
- Dashboard description and disclaimer use safe sanitization, not `bypassSecurityTrustHtml`.

## Supply Chain Security (OpenSSF Scorecard)
- **Signed Releases**: All container images are signed with [cosign](https://github.com/sigstore/cosign) (keyless/OIDC via Fulcio) and attested with SLSA provenance (`actions/attest-build-provenance`) in `.github/workflows/release.yml`.
- **Pinned Dependencies**: All GitHub Actions **and reusable workflows** (e.g. `cncf/prow-github-actions/.github/workflows/prow.yml`) are pinned by full commit SHA (not tags), with the tag as a `# vX.Y.Z` comment. When adding or updating a pinned action, **always verify the SHA against the GitHub API** (e.g., `gh api repos/{owner}/{action}/git/refs/tags/{version}`; for an annotated tag, dereference `git/tags/{sha}` to the commit) before committing — never invent or guess SHA hashes. External downloads (e.g., Hugo in `deploy-docs.yml`) include SHA256 checksum verification.
- **Token Permissions**: Every workflow declares top-level `permissions:` read-only (`contents: read` or `read-all`); write scopes go on the job that needs them. A single top-level `contents`/`actions` write drops Scorecard's Token-Permissions check to 0 — that is what happened with `prow.yml`. `deploy/helm/tests/test_workflow_security.py` enforces both rules in CI.
- **Vulnerabilities**: An advisory that cannot be fixed and provably does not affect BOMHort is ignored in `backend/osv-scanner.toml` (read by osv-scanner and Scorecard) with a reproducible reason and an `ignoreUntil` date — never without both.
- **Branch Protection**: Repository rulesets, not classic protection, are the source of truth (Scorecard can read rulesets without an admin token). *Release and Main* covers `main` + `release/**`: PR, required checks incl. `prow/lgtm`, up-to-date branch, one human approving review covering the latest push. *Release tags* makes `v*` tags immutable. Approvers use GitHub's Approve review, which Prow counts as `/approve` (CONTRIBUTING.md, "Merge gate").
- **Fuzzing**: Native Go fuzz tests exist for SPDX and VEX parsers (`internal/spdx/fuzz_test.go`, `internal/vex/fuzz_test.go`). The `.github/workflows/fuzz.yml` workflow runs them weekly and on PRs touching `backend/`.
- **SAST**: CodeQL runs on every push/PR for Go and TypeScript (`.github/workflows/codeql.yml`).
- **Scorecard**: The `.github/workflows/scorecard.yml` workflow runs the OpenSSF Scorecard weekly and publishes results as SARIF to GitHub Security tab.
- **Dependency Updates**: Dependabot covers `gomod`, `npm`, `github-actions`, and `docs` (`.github/dependabot.yml`).
