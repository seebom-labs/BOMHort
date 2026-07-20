# Security Policy

The BOMHort maintainers take security seriously. We appreciate your efforts to responsibly disclose your findings and will make every effort to acknowledge your contributions.

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, report them through one of these channels:

1. **GitHub Security Advisories** (preferred):  
   [https://github.com/seebom-labs/bomhort/security/advisories/new](https://github.com/seebom-labs/bomhort/security/advisories/new)

2. **Email:**  
   Contact the maintainers listed in [MAINTAINERS.md](MAINTAINERS.md) directly.

### What to Include

Please include as much of the following information as possible to help us triage your report quickly:

- Type of vulnerability (e.g. SQL injection, XSS, authentication bypass, container escape)
- Affected component(s) (API Gateway, Parsing Worker, UI, Helm Chart, ClickHouse schema)
- Full paths of affected source file(s)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact assessment (what an attacker could achieve)

## Response Timeline

| Action | Target |
|--------|--------|
| Acknowledgement of report | 3 business days |
| Initial assessment | 7 business days |
| Fix development | Depends on severity |
| Public disclosure | After fix is released |

We will work with you to understand and validate the report. Once confirmed, we will:

1. Develop a fix in a private branch
2. Assign a CVE identifier if appropriate
3. Release a patched version
4. Publish a security advisory on GitHub

## Severity Classification

We follow the [CVSS v3.1](https://www.first.org/cvss/calculator/3.1) scoring system:

| Severity | CVSS Score | Response |
|----------|-----------|----------|
| **Critical** | 9.0 – 10.0 | Immediate patch release |
| **High** | 7.0 – 8.9 | Patch release within 7 days |
| **Medium** | 4.0 – 6.9 | Fix in next scheduled release |
| **Low** | 0.1 – 3.9 | Fix when convenient |

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release (N) | ✅ Full support |
| N-1 | ✅ Security fixes only |
| N-2 | ✅ Security fixes only |
| Older versions | ❌ |

## Security-Related Configuration

When deploying BOMHort, pay attention to:

- **ClickHouse credentials**: Always change the default password. Use the `bomhort-secret` Kubernetes Secret.
- **API authentication (opt-in)**: The API Gateway ships with an authentication middleware that is **disabled by default**. Set `AUTH_ENABLED=true` plus `SERVICE_TOKEN` (Bearer / `X-Service-Token`) and/or `API_KEYS` (`X-API-Key`, comma-separated) to require credentials on every non-health endpoint. The bundled UI is automatically wired up — nginx injects the `SERVICE_TOKEN` on upstream `/api/` proxy calls so the secret never reaches the browser. Constant-time comparisons (`crypto/subtle`) prevent timing attacks. See [Deployment Guide § 6](./docs/content/docs/deployment/_index.md#6-api-authentication-optional).
- **UI is unauthenticated by default**: The Angular frontend has no built-in login. When `apiGateway.auth.enabled=true` the UI authenticates to the backend on the user's behalf, but the UI itself remains world-readable. For per-user authentication, place the UI behind an authentication proxy (e.g. OAuth2 Proxy, Pomerium, Cloudflare Access).
- **License exceptions are read-only**: By design, no API endpoint can modify license exceptions or policy — they are loaded from config files to prevent tampering via the public UI.
- **SBOM source directory**: Ensure only trusted SBOM/VEX files are placed in the ingestion directory. Malicious JSON payloads could attempt to exploit the parsers.
- **Container images**: All backend containers run as `nobody:nobody`. The UI runs as the `nginx` user. No container requires root privileges.
- **Network policies**: In production, restrict ClickHouse access to only the BOMHort pods.

## Disclosure Policy

- We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure).
- We will credit reporters in the security advisory unless they prefer to remain anonymous.
- We ask that you give us reasonable time to address the issue before public disclosure.
- We will not take legal action against researchers who follow this policy.

## Security Audits

BOMHort has not yet undergone a formal security audit. If you are interested in sponsoring or conducting one, please reach out to the maintainers.

---

Thank you for helping keep BOMHort and its users safe.

