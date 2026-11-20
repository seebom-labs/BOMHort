---
title: "AI Usage Policy"
linkTitle: "AI Policy"
type: docs
weight: 4
description: >
  Guidelines for using AI tools (Copilot, ChatGPT, Claude, Cursor, etc.) when contributing to BOMHort.
---

## Policy

BOMHort **welcomes AI-assisted contributions**. We use AI tools extensively in our own development workflow (see [AGENTS.md](https://github.com/seebom-labs/BOMHort/blob/main/AGENTS.md)). However, we have clear rules to ensure accountability and code quality.

---

## Rules

### 1. You own it

If you use AI to generate code, **you are responsible** for that code. Review it, test it, and understand it before submitting. "The AI wrote it" is not an excuse for bugs, security issues, or convention violations.

You must be able to explain each change, why it is needed, its tradeoffs and the
validation performed, and address review feedback yourself. Do not delegate
accountability to an AI. Be prepared to help maintain or correct your contribution.

### 2. Sign your commits

Every commit must carry your DCO sign-off (`Signed-off-by: Your Name <your@email.com>`). This is **non-negotiable** — it certifies that *you* are the author and take responsibility, regardless of whether AI assisted you.

```bash
git commit -s -m "feat: add attestation verification"
```

### 3. No `Co-authored-by: AI` trailers

AI is a tool, not a co-author. We do **not** accept commits with `Co-authored-by` trailers attributing AI tools (e.g., `Co-authored-by: github-copilot[bot]`). The human who submits the PR is the sole author and takes full responsibility.

### 4. Follow the shared repository instructions

Every AI tool must start with [AGENTS.md](https://github.com/seebom-labs/BOMHort/blob/main/AGENTS.md)
and use the [guardrail and skill inventory](https://github.com/seebom-labs/BOMHort/blob/main/.ai/README.md)
before development or review. **These guidelines are mandatory**, not optional
prompt suggestions. Configure your coding/review tool to point at the repository
entry points and load the applicable local guardrails and skills. Verify discovery;
if your tool cannot load them automatically, provide them explicitly. A vendor
default prompt, personal plugin or external policy is not a substitute.

The root stays small; architecture, backend, database, frontend, operations,
security and review instructions live in `.ai/`. This includes:

- Architectural directives (monorepo, no custom operator, no polyrepo)
- Dependency restrictions (no new dependencies without asking)
- Security boundaries (parameterized queries, no `bypassSecurityTrustHtml`)
- Code style (idiomatic Go, OnPush Angular, MergeTree ClickHouse)
- The local Ponytail-informed coding approach: smallest complete solution,
  reuse existing patterns, fix root causes and preserve safeguards and tests

{{% alert title="Tip" color="success" %}}
Codex reads `AGENTS.md` and can invoke `$bomhort-review`. Claude's `CLAUDE.md`
imports the root instructions and `/bomhort-review` loads the review procedure.
Copilot has repository-wide and path-scoped adapters. For any other tool, supply
`AGENTS.md` explicitly and require it to read the referenced rules. Discovery
depends on the tool/version; adapters and skills are not enforcement mechanisms.
{{% /alert %}}

### 5. Don't submit blindly

AI-generated code must pass the same bar as hand-written code:

- All tests pass (`go test ./... -count=1 -race`, `npx ng test`)
- No new lint/vet warnings (`go vet ./...`)
- Security boundaries respected
- Matches existing patterns and conventions
- Documentation updated if user-facing behavior changes

### 6. Disclose when asked

Reviewers may ask if AI was used for a specific PR. Be honest. There is **no penalty** for using AI — but there *is* a penalty for submitting broken or unreviewed code.

### 7. Validate AI-assisted reviews against the running application

Follow the tool-neutral [review procedure](https://github.com/seebom-labs/BOMHort/blob/main/.ai/review.md),
not just the diff or a vendor's default review prompt. Read connected callers,
tests and contracts, and report concrete triggering conditions and impact.

For executable changes, start a **disposable local stack** built from the
reviewed code and run real end-to-end checks through the worker, ClickHouse,
API and UI as applicable. UI changes also require browser error/network checks,
light/dark and narrow-screen inspection, keyboard/accessibility checks, large-list
rendering analysis and the existing bundle-size gate. See [Testing](../testing/).

Record the base/head, commands, outcomes, fixtures and artifacts. A healthy
endpoint, mocked tests or skipped integration tests are not proof of the flow.
If Docker, browser access or required services are unavailable, label the review
**BLOCKED / incomplete** and name what remains untested. Hosted AI reviews without
execution capabilities may supply findings, but cannot replace local validation.
The documented exception applies only to strictly non-executable prose changes.

Review mode does not authorize fixes, commits, pushes, approval or merge commands.
Never run destructive demos/resets against shared data. Humans must verify AI
findings and validation evidence; existing CI and human approval remain required.

### 8. Start with intent and project alignment

BOMHort is not an AI experimentation sandbox. We do not accept contributions
produced by running an unrequested AI sweep over the codebase and submitting its
suggested "improvements" without a demonstrated problem or project context.
Requested audits and investigations are welcome; findings still need verification,
prioritization and alignment before they become changes.

- **No shotgun refactoring:** broad restructuring or cleanup suggested by AI
  requires an explicit maintainer request. Keep each PR focused; do not bundle
  unrelated edits or split speculative cleanup into a flood of tiny PRs.
- **Design first:** for non-trivial work, open or reference an issue/discussion
  before substantial implementation. Explain the problem, proposed approach,
  affected contracts and validation plan; seek alignment with the architecture
  and project direction. Do not modify the roadmap to legitimize a feature PR.
  Significant, unsolicited AI-generated changes that do not fit the project
  may be closed rather than redesigned by maintainers during review.
- **Quality over volume:** one understood, evidenced and maintainable contribution
  is worth more than many superficial fixes, whether written manually or with AI.
  Prove a bug or explain concrete user/maintenance value; an AI suggestion alone
  is not evidence that something needs changing.

### 9. Verify provenance, content and confidentiality

Submit only work you have the right to contribute under BOMHort's Apache-2.0
license. Check that the AI provider's output terms allow the intended use.
When output includes third-party material, verify its source and compatible
license and retain any required notices/attribution. Do not submit material
whose provenance or permission cannot be established.

Never send credentials, private SBOMs, non-public customer data or confidential
code to an external AI service without authorization. Use public or synthetic
fixtures for review evidence and redact sensitive logs/screenshots.

Remove unnecessary generated boilerplate. Verify that claimed APIs, features,
bugs, commands and test results exist and match the code. AI-assisted PR
descriptions and review replies must be accurate, specific and personally
understood: explain the actual change, its motivation and validation, not
generic praise or invented evidence.

### 10. Respect maintainer capacity

Maintainers may close submissions that violate this policy, lack project
alignment, contain unverified/generated noise, or cannot be explained by their
author. A closure does not oblige maintainers to debug every generated claim
or provide a line-by-line critique. Repeated disregard may lead to contribution
restrictions under the project's moderation practices.

AI use itself is not grounds for rejection. Human understanding, meaningful
scope, legal provenance, mandatory guardrails and reproducible evidence are
the acceptance criteria.

---

## Why This Policy?

| Principle | Reason |
|-----------|--------|
| **Accountability** | The DCO sign-off is a legal certification. A human must stand behind each contribution. |
| **Quality** | AI tools produce plausible-looking code that may have subtle bugs, security issues, or architectural violations. Human review is mandatory. |
| **Consistency** | AGENTS.md gives AI tools the context they need. Using it produces better code. |
| **Simplicity** | One author per commit. No ambiguity about who to contact for questions or fixes. |

---

## TL;DR

| ✅ Allowed | ❌ Not Allowed |
|-----------|---------------|
| Use AI to write code, tests, docs | Submit AI output without review |
| Use AI to explore approaches | Add `Co-authored-by: <AI tool>` |
| Use AI for scoped, project-aligned refactoring | Let AI commit without your sign-off |
| Load AGENTS.md and the guardrail/skill inventory | Ignore project conventions because "the AI did it" |
| Use any AI tool you prefer | Blame AI for bugs in your PR |
| Generate issue descriptions with AI | Submit issues without verifying accuracy |
| Propose a focused, evidenced change first | Send unsolicited AI cleanup/refactoring batches |
| Verify licenses and required attribution | Submit generated output of uncertain provenance |

---

## Recommended Workflow

Here's how we recommend using AI effectively with BOMHort:

```bash
# 1. Align non-trivial work in an issue/discussion first.
#    Configure your tool to read AGENTS.md and .ai/README.md,
#    then the applicable guardrails and local skills.

# 2. Let AI generate code

# 3. Review the output:
#    - Does it follow our conventions?
#    - Does it add unwanted dependencies?
#    - Does it handle errors properly?
#    - Are there security concerns?

# 4. Run the checks yourself
(cd backend && go test ./... -count=1 -race && go vet ./...)
(cd ui && npx ng test --watch=false)
# AI-assisted reviews also need the .ai/review.md local-stack/browser checks.

# 5. Commit with YOUR sign-off
git add .
git commit -s -m "feat(api): add attestation verification endpoint"

# 6. Push and open a PR
git push origin my-feature
```

---

## FAQ

### Can I use AI to write my entire PR?

Yes — as long as you review every line, understand what it does, test it, and sign off on it. The bar is the same whether you typed it or an AI did.

That does not exempt the PR from project alignment, mandatory guardrails or
the prohibition on unsolicited AI cleanup batches.

### Do I need to disclose AI usage in my PR description?

Not required, but appreciated. If a reviewer asks, be honest.

### What if the AI violates AGENTS.md conventions?

Fix it before submitting. You're responsible for the final output, not the AI.

### Can I use AI-generated commit messages?

Yes, but make sure they follow [Conventional Commits](https://www.conventionalcommits.org/) format and accurately describe the change. Don't let AI hallucinate what it changed.

### What about AI-generated issue descriptions?

Welcome! But verify that the technical details are accurate against the actual codebase. AI can (and does) hallucinate file paths, function names, and architectural details.

---

## Policy references

The intentional-contribution and accountability rules are informed by
[CloudNativePG's AI policy](https://github.com/cloudnative-pg/governance/blob/main/AI_POLICY.md).
The provenance checks follow the
[Linux Foundation's generative AI guidance](https://www.linuxfoundation.org/legal/generative-ai).
Our simplicity and review approach is informed by
[Ponytail](https://github.com/DietrichGebert/ponytail).
These are background references, not external instructions contributors must
install or load; BOMHort's checked-in policy is authoritative.

We retain BOMHort's disclosure rule (honest disclosure when asked) and do not
adopt CNPG's mandatory `Assisted-by` trailer. Human DCO sign-off remains required,
and AI `Co-authored-by` trailers remain prohibited.
