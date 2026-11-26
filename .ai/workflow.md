# Boundaries

Read these rules for every task. Review-only requests follow
[the review procedure](review.md) instead of the feature/fix workflow: they
authorize safe disposable validation and a report, not code changes or publishing.
Preserve other contributors' files, services and data. Never run reset/re-scan/
demo commands against shared or production storage.

Commits require human DCO sign-off; AI co-author trailers are forbidden
([AI usage policy](../docs/content/docs/development/ai-policy.md)).

Before AI-assisted work, read the [guardrail and skill inventory](README.md)
and load its applicable rules/skills through the tool's repository entry point.
Ground changes in an actual requirement or reproducible problem. Unsolicited AI
codebase sweeps are not justification for cleanup PRs; broad refactors require
a maintainer request. For non-trivial work, open or reference an issue/discussion
and seek alignment before implementing substantial logic. Do not edit the roadmap
to justify an otherwise unaligned change.

The contributor must understand the implementation, explain design/tradeoffs and
verify generated claims, tests and descriptions. Check AI-provider output terms
and third-party provenance, compatible licensing and required attribution before
submission. Do not submit output whose origin or rights cannot be established.
Protect maintainer time: one focused, evidenced improvement beats many trivial
or speculative PRs. See the contributor AI policy for enforcement and disclosure.

- **Always do:** Write unit tests for new Go packages and Angular components. Ensure ClickHouse bulk inserts are batched. Update `docs/ARCHITECTURE_PLAN.md` when adding new services or features. **Before any minor/major release tag:** run `govulncheck ./...` (backend), `npm audit` (ui + docs), fix all vulnerabilities, and verify the build passes. Scan all three ecosystems (Go, Angular npm, Hugo docs npm). **Update `ROADMAP.md` when cutting a minor release, and only then** — mark completed items as done, adjust phase timelines, and ensure the dependency graph is current.
- **Workflow for every feature/fix:** (1) Write code, (2) Write tests for all new functionality, (3) Update API docs (`docs/content/docs/api-reference/_index.md`) for new/changed endpoints, (4) Update general docs (ARCHITECTURE_PLAN, deployment guide) — **but not `ROADMAP.md`**, see below, (5) Verify build + tests pass, (6) Push branch — **stop here**. Do NOT open a PR unless explicitly asked.
- **`ROADMAP.md` is a release-time file, not a per-PR file.** Feature PRs must not tick their own entry. Every PR that does touches the same v0.8.0 criteria line, the same milestone-map row and the same dependency graph, so two open PRs conflict on a checklist by construction — and the conflict is the dangerous kind: each side holds a tick the other lacks, so resolving it by picking a side silently un-ticks an issue that is already merged, in a file no reviewer reads line by line. Three PRs in a row (#423, #424, #431) hit exactly this. The roadmap is updated once when the release is cut, where the full set of merged items is known and a single author reconciles it; see `docs/RELEASE.md`.
- **Ask first:** Before adding new third-party dependencies (npm or Go modules), modifying the ClickHouse schema, changing Kubernetes manifest structures, or creating/merging pull requests.
- **Release branches (`release/vX.Y`):** branch features and fixes from `main` and target `main` — never a release branch. A fix that a released minor needs is backported *after* it merged to `main`, with `make cherry-pick PR=<n> BRANCH=X.Y` (a PR against the release branch). Never commit to a release branch directly, never backport features. Do not cut tags or create release branches unless explicitly asked.
- **Never do:** Never commit secrets or API keys. Never use a relational database (like PostgreSQL) for the core SBOM dependency trees. Never split the codebase into multiple repositories. Never add write APIs for license exceptions (frontend is public). Never use `bypassSecurityTrustHtml` in Angular — use `sanitizer.sanitize(SecurityContext.HTML, ...)` instead. Never invent or guess SHA hashes for pinned GitHub Actions — always verify against the GitHub API. Never push changes to upstream without explicit approval. Never bump the major version without a migration guide and 3-month advance notice via roadmap.

# Major Version Policy
- Major bumps happen every **2–3 years**, driven by accumulated breaking changes (schema, API, Helm values), not by calendar.
- Previous major receives security patches for 12 months after new major GA.
- A migration guide with automated tooling (schema scripts, Helm values converter) is mandatory before tagging.
- Projected: v1.0 October 2026, v2.0 earliest Q1/Q2 2028.
