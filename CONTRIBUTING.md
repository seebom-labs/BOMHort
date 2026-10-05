# Contributing to BOMHort

Thank you for your interest in contributing to BOMHort! We welcome contributions from everyone.

> 📖 **Full documentation:** [docs.bomhort.dev](https://docs.bomhort.dev/)  
> 🪜 **Contributor Ladder:** [docs.bomhort.dev/docs/development/contributor-ladder/](https://docs.bomhort.dev/docs/development/contributor-ladder/)  
> 🤖 **AI Usage Policy:** [docs.bomhort.dev/docs/development/ai-policy/](https://docs.bomhort.dev/docs/development/ai-policy/)  
> 🗺️ **Roadmap:** [docs.bomhort.dev/docs/roadmap/](https://docs.bomhort.dev/docs/roadmap/)

## Getting Started

1. **Fork** the repository and clone your fork
2. Set up the development environment (see [Getting Started](https://docs.bomhort.dev/docs/getting-started/))
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

See the [Development Guide](https://docs.bomhort.dev/docs/development/) for details.

## Coding Standards

### Go (Backend)

- Standard idiomatic Go with explicit error handling
- HTTP routing via Go 1.22+ stdlib (`net/http` method-pattern registration)
- Only 6 direct dependencies — keep it minimal; adding one is a maintainer decision
- Use `goccy/go-json` for JSON parsing
- All ClickHouse queries use parameterized queries (`?` placeholders)
- License heuristics are documented decisions: a new or changed rule needs a decision-log entry and table row on the [License Resolution](https://docs.bomhort.dev/docs/license-resolution/) page plus a golden-fixture package — `TestLicensePipelineGolden` and `TestDocsLicenseResolutionInSync` fail otherwise
- Never guess ambiguous license names (`BSD`, `Apache Software License`, `Public Domain`): they are kept as declared and categorized unapproved. A resolver never overrides a declared license, and every remaining `NOASSERTION` records a reason from `license.UnresolvedReasons`

### Angular (Frontend)

- Strict TypeScript mode, standalone components
- OnPush change detection for data-heavy components
- Virtual scrolling (`@angular/cdk`) for large lists
- Unit tests use **Vitest** (not Karma/Jasmine)
- Never use `bypassSecurityTrustHtml` — use `sanitizer.sanitize(SecurityContext.HTML, ...)`

### Tests

- All new features must have tests
- Run `cd backend && go test ./... -count=1 -race` before submitting
- Changed or added a ClickHouse query? Add it to `TestQueriesExecute` and run it against a live database: `make dev-up`, then `CLICKHOUSE_HOST=localhost go test ./internal/clickhouse/ -run TestQueriesExecute` (skipped without `CLICKHOUSE_HOST`)
- See [Testing Guide](https://docs.bomhort.dev/docs/development/testing/) for patterns and conventions

### Demo SBOMs

Sample SBOMs under `examples/` are **git-ignored on purpose** (`examples/**/*.spdx.json`,
`examples/**/*.cdx.json`): they carry deliberately outdated packages, and osv-scanner —
which drives the OpenSSF Scorecard — honours `.gitignore`, so this is what keeps the
demo data from being reported as BOMHort's own vulnerabilities (#394). Ignoring them
does not remove tracked files from git; it only affects new ones. So when you add a
fixture:

1. `git add -f examples/<dir>/<path>/<file>.spdx.json` — a plain `git add` silently skips it
2. Document it in that directory's `README.md` (`examples/fleet/README.md`, …)
3. Run `make check-demo-sboms` — it fails on a fixture that is on disk but untracked, on a
   README that names a file git does not have, and on a tracked fixture no README mentions.
   CI runs the same check.

## Pull Request Process

1. Ensure all CI checks pass (Go build + test + vet, Angular build, Helm lint)
2. Fill out the [PR template](.github/PULL_REQUEST_TEMPLATE.md) completely
3. `/lgtm` from an OWNERS reviewer and `/approve` from an OWNERS approver are required for merge (see [Labels and Chat-Ops](#labels-and-chat-ops))
4. Sign off your commits (Developer Certificate of Origin):
   ```bash
   git commit -s -m "feat: add new feature"
   ```

### Release branches and backports

Every minor version has a release branch `release/vX.Y`, cut from `main` at its first release candidate; all release tags of that minor come from it (see [docs/RELEASE.md](docs/RELEASE.md#release-branches)).

- **Always open your PR against `main`** — also for a fix a released version needs.
- If the fix should ship in a release, say so in the PR (e.g. "needs backport to 0.8"). After it merged, a maintainer — or you — backports it:
  ```bash
  make cherry-pick PR=<number> BRANCH=0.8   # picks the merged commit onto release/v0.8 (git cherry-pick -x),
                                            # pushes a branch to your fork, prints the PR link
  ```
  Title the backport PR `[release/v0.8] <original title>`. It runs the full CI and is reviewed and merged like any other PR. On a conflict the script stops and tells you how to finish.
- Only fixes are backported — bugs, security issues, CVE-driven dependency bumps, documentation corrections. Never features.

## Labels and Chat-Ops

Labeling, review routing and merging are automated with
[cncf/prow-github-actions](https://github.com/cncf/prow-github-actions), configured in
[`.github/prow.yaml`](.github/prow.yaml) and driven by
[`.github/workflows/prow.yml`](.github/workflows/prow.yml). Who may approve what is defined in the
`OWNERS` files (root and per component directory).

### What happens automatically

- Opening a PR applies component labels (`backend`, `frontend`, `helm`, `clickhouse`,
  `documentation`, `ci`, `examples`, `security`) from the `OWNERS` files covering the changed
  files and requests a review from one of their reviewers.
- New issues get `needs-triage` until a maintainer applies a `triage/*` label.
- A PR is merged (rebase) automatically once it carries `lgtm` and `approved`, has no
  `do-not-merge/*` or `hold` label, and all required checks pass. `lgtm` is bound to the
  reviewed commit; a new push removes it.

### Slash commands

Write a command at the start of a line in an issue or PR comment. Several commands may be placed
on separate lines. Commands inside code blocks or blockquotes are ignored. Every label command
has a `/remove-<command> <value>` form.

| Command | Who | Effect |
|---|---|---|
| `/lgtm`, `/lgtm cancel` | OWNERS reviewers/approvers (not the author) | Adds/removes `lgtm` |
| `/approve`, `/approve cancel` | OWNERS approvers | Marks the changed files as approved; `approved` is set once every file is covered. A GitHub approving review counts too — and is the preferred way, because it also satisfies the required review (see [Merge gate](#merge-gate-on-main-and-release-branches)) |
| `/hold`, `/hold cancel` (`/unhold`) | anyone | Adds/removes `do-not-merge/hold` |
| `/assign [@user]`, `/unassign`, `/cc [@user]`, `/uncc` | anyone | Assignees / review requests |
| `/priority <critical\|high\|medium\|low>` | org members | Exclusive `priority/*` label |
| `/triage <accepted\|needs-information\|duplicate\|not-planned>` | org members | Exclusive `triage/*` label; clears `needs-triage` |
| `/label <name>` | org members | Plain labels: `bug`, `enhancement`, `feature`, `fix`, `docs`, `chore`, `security`, `test`, `skip-changelog`, ... |
| `/good-first-issue`, `/help` | org members | `good first issue` / `help wanted` |
| `/close`, `/reopen`, `/retitle <title>`, `/milestone <name>`, `/lock` | org members | Issue / PR housekeeping |
| `/retest`, `/test <job>`, `/ok-to-test` | org members | Re-run CI |

Release-notes categories in [`.github/release.yml`](.github/release.yml) rely on the plain labels
(`enhancement`, `feature`, `bug`, `fix`, `docs`, `test`, `chore`, `dependencies`, `ci`,
`security`), so apply one of them with `/label` before a PR merges.

### Path-based labels (`OWNERS` instead of `labeler.yml`)

Component labels come from the `labels:` list in `OWNERS` files, not from glob rules:

- For every changed file the closest `OWNERS` file up the directory tree is used, and the
  `labels:` of **all** `OWNERS` files on the way to the repository root are applied. A change to
  `backend/internal/osv/client.go` therefore gets `security` (from `backend/internal/osv/OWNERS`)
  and `backend` (from `backend/OWNERS`).
- Matching is per directory. There are no `**/*.md`-style patterns; to label a subtree, add an
  `OWNERS` file with `labels:` to it (approvers/reviewers are inherited when omitted).
- Labels are only ever added, never removed. If a later push drops all changes to a component,
  its label stays until someone runs `/remove-label <name>`.
- Every label used in `OWNERS` must be listed under `labels.labels` in `.github/prow.yaml` so
  that label-sync creates it with color and description.

### Merge gate on `main` and release branches

Prow **is** the review gate; GitHub enforces the floor. The repository ruleset *Release and Main*
(since 2026-10-01; it applies to `main` and `release/**`) requires a pull request, the status
checks `Backend (Go)`, `Frontend (Angular)`, `Helm Lint` and **`prow/lgtm`** on an up-to-date
branch, and **one approving GitHub review** whose approval covers the latest push. Who may
approve what is still decided by the `OWNERS` files:

- `/lgtm` from an OWNERS reviewer writes the `prow/lgtm` commit status for the reviewed commit.
  Without it the PR cannot be merged at all — not by Tide, not by the merge button.
- **Approvers approve with GitHub's *Review changes → Approve*.** Prow counts that review exactly
  like `/approve` (it sets `approved` once every changed file is covered), and the same click
  satisfies the required review — one action, both gates. A `/approve` *comment* still sets
  `approved`, but GitHub then shows "Review required" and Tide waits until someone submits an
  approving review.
- Tide merges once the PR has `lgtm` + `approved` and GitHub reports it mergeable. A human
  pressing "Merge" is stopped by `prow/lgtm` and the required review, but not by a missing
  `approved` — do not press it without `approved`.
- The merge is a regular GitHub merge API call with the workflow's `GITHUB_TOKEN`. GitHub still
  rejects it until every required check is green and the branch is up to date; Prow retries on
  every PR/review/check event and hourly.
- Prow does not rebase or update branches. If `main` moved, update the branch (button in the PR
  or `git rebase`); this drops `lgtm` (bound to the commit) and — because the latest push must be
  approved by someone other than its pusher — the approval, both of which must be given again.
- The author's own review never counts, matching `require_self_approval` in `.github/prow.yaml`.
- The `Prow` *workflow* itself must not be a required status check (it runs on
  `pull_request_target` and would gate itself); `prow/lgtm` is a commit *status* the workflow
  writes, which is why it can be required.
- [`.github/CODEOWNERS`](.github/CODEOWNERS) still drives GitHub's automatic review requests and
  is kept in sync with the `approvers:` in `OWNERS`; it does not block merges.
- Release tags `v*` are protected by the ruleset *Release tags*: they can be created, never moved
  or deleted (repository admins can bypass, e.g. to remove a tag the release workflow rejected).

Why a required GitHub review on top of Prow? Without one, [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/seebom-labs/BOMHort)
rates branch protection 3/10, because "requires approvers" is the gate to every higher tier.
prow-github-actions deliberately submits no bot review on repositories with OWNERS files (a bot
review would satisfy the requirement by itself), so the review has to come from a human — and
since Prow counts a human approving review as `/approve`, it costs no extra step as long as
approvers use the GitHub review instead of the comment. This is the setup the
[prow-github-actions docs](https://github.com/cncf/prow-github-actions/blob/main/docs/automatic-merging.md)
recommend: "let a human's review, which the plugin also counts, satisfy the protection".

## What to Contribute

- **Bug fixes** — Check [open issues](https://github.com/seebom-labs/bomhort/issues?q=is%3Aissue+is%3Aopen+label%3Abug)
- **Documentation** — Improvements to docs, README, or code comments
- **Tests** — Increase test coverage
- **Features** — Discuss in an issue first before implementing large changes

## Boundaries

- **Ask first** before adding new third-party dependencies, modifying the ClickHouse schema, or changing Kubernetes manifest structures. A new migration takes the next free number in the Schema Change Register in `ROADMAP.md` — check upstream `main` and open PRs first, numbers collide easily
- **Never** commit secrets or API keys
- **Never** add write APIs for license exceptions (frontend is public)
- **Never** use a relational database for core SBOM data

## AI-Assisted Contributions

We welcome AI-assisted contributions (Copilot, ChatGPT, Claude, Cursor, etc.). Key rules:

- **You sign, not the AI** — every commit needs your DCO sign-off (`git commit -s`)
- **No `Co-authored-by: AI` trailers** — you are the sole author
- **Follow [AGENTS.md](AGENTS.md)** — feed it to your AI tool for project context
- **Review everything** — you're responsible for what you submit

See the full [AI Usage Policy](https://docs.bomhort.dev/docs/development/ai-policy/) for details.

## Contributor Ladder

We have a transparent contributor ladder: Community → Contributor → Reviewer → Maintainer. See the [Contributor Ladder](https://docs.bomhort.dev/docs/development/contributor-ladder/) for promotion criteria and expectations at each level.

## Reporting Issues

- **Bugs:** Use the [Bug Report](https://github.com/seebom-labs/bomhort/issues/new?template=bug_report.yml) template
- **Features:** Use the [Feature Request](https://github.com/seebom-labs/bomhort/issues/new?template=feature_request.yml) template
- **Security:** See [SECURITY.md](SECURITY.md) — **do not** use public issues

## Code of Conduct

All contributors must follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing to BOMHort, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).

