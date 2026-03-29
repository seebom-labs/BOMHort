# Contributing to SeeBOM

Thank you for your interest in contributing to SeeBOM! We welcome contributions from everyone.

## Getting Started

1. **Fork** the repository and clone your fork
2. Set up the development environment (see [Getting Started](https://seebom.cncf.io/docs/getting-started/))
3. Create a feature branch from `main`
4. Make your changes
5. Submit a pull request

## Development Setup

```bash
# Full stack (recommended)
make dev

# Or local development with hot reload
make ch-only && make ch-migrate
make api      # Terminal 1
make ingest   # Terminal 2
make worker   # Terminal 3
make ui-dev   # Terminal 4
```

See the [Development Guide](https://seebom.cncf.io/docs/development/) for details.

## Coding Standards

### Go (Backend)

- Standard idiomatic Go with explicit error handling
- HTTP routing via Go 1.22+ stdlib (`net/http` method-pattern registration)
- Only 4 direct dependencies — keep it minimal
- Use `goccy/go-json` for JSON parsing
- All ClickHouse queries use parameterized queries (`?` placeholders)

### Angular (Frontend)

- Strict TypeScript mode, standalone components
- OnPush change detection for data-heavy components
- Virtual scrolling (`@angular/cdk`) for large lists
- Unit tests use **Vitest** (not Karma/Jasmine)
- Never use `bypassSecurityTrustHtml` — use `sanitizer.sanitize(SecurityContext.HTML, ...)`

### Tests

- All new features must have tests
- Run `cd backend && go test ./... -count=1 -race` before submitting
- See [Testing Guide](https://seebom.cncf.io/docs/development/testing/) for patterns and conventions

## Pull Request Process

1. Ensure all CI checks pass (Go build + test + vet, Angular build, Helm lint)
2. Fill out the [PR template](.github/PULL_REQUEST_TEMPLATE.md) completely
3. At least one maintainer approval is required for merge
4. Sign off your commits (Developer Certificate of Origin):
   ```bash
   git commit -s -m "feat: add new feature"
   ```

## What to Contribute

- **Bug fixes** — Check [open issues](https://github.com/seebom-labs/seebom/issues?q=is%3Aissue+is%3Aopen+label%3Abug)
- **Documentation** — Improvements to docs, README, or code comments
- **Tests** — Increase test coverage
- **Features** — Discuss in an issue first before implementing large changes

## Boundaries

- **Ask first** before adding new third-party dependencies, modifying the ClickHouse schema, or changing Kubernetes manifest structures
- **Never** commit secrets or API keys
- **Never** add write APIs for license exceptions (frontend is public)
- **Never** use a relational database for core SBOM data

## Reporting Issues

- **Bugs:** Use the [Bug Report](https://github.com/seebom-labs/seebom/issues/new?template=bug_report.yml) template
- **Features:** Use the [Feature Request](https://github.com/seebom-labs/seebom/issues/new?template=feature_request.yml) template
- **Security:** See [SECURITY.md](SECURITY.md) — **do not** use public issues

## Code of Conduct

All contributors must follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing to SeeBOM, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).

