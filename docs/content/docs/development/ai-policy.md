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

### 2. Sign your commits

Every commit must carry your DCO sign-off (`Signed-off-by: Your Name <your@email.com>`). This is **non-negotiable** — it certifies that *you* are the author and take responsibility, regardless of whether AI assisted you.

```bash
git commit -s -m "feat: add attestation verification"
```

### 3. No `Co-authored-by: AI` trailers

AI is a tool, not a co-author. We do **not** accept commits with `Co-authored-by` trailers attributing AI tools (e.g., `Co-authored-by: github-copilot[bot]`). The human who submits the PR is the sole author and takes full responsibility.

### 4. Follow AGENTS.md

If you use AI coding agents, they must follow our project conventions documented in [AGENTS.md](https://github.com/seebom-labs/BOMHort/blob/main/AGENTS.md). This includes:

- Architectural directives (monorepo, no custom operator, no polyrepo)
- Dependency restrictions (only 4 Go deps, no new ones without asking)
- Security boundaries (parameterized queries, no `bypassSecurityTrustHtml`)
- Code style (idiomatic Go, OnPush Angular, MergeTree ClickHouse)

{{% alert title="Tip" color="success" %}}
Feed `AGENTS.md` to your AI tool as context. It was written specifically for this purpose — it gives AI agents all the constraints they need to produce code that fits our project.
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
| Use AI for refactoring | Let AI commit without your sign-off |
| Reference AGENTS.md in AI prompts | Ignore project conventions because "the AI did it" |
| Use any AI tool you prefer | Blame AI for bugs in your PR |
| Generate issue descriptions with AI | Submit issues without verifying accuracy |

---

## Recommended Workflow

Here's how we recommend using AI effectively with BOMHort:

```bash
# 1. Give your AI tool the project context
#    (paste AGENTS.md or use it as system prompt)

# 2. Let AI generate code

# 3. Review the output:
#    - Does it follow our conventions?
#    - Does it add unwanted dependencies?
#    - Does it handle errors properly?
#    - Are there security concerns?

# 4. Run the checks yourself
cd backend && go test ./... -count=1 -race
cd backend && go vet ./...
cd ui && npx ng test

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

### Do I need to disclose AI usage in my PR description?

Not required, but appreciated. If a reviewer asks, be honest.

### What if the AI violates AGENTS.md conventions?

Fix it before submitting. You're responsible for the final output, not the AI.

### Can I use AI-generated commit messages?

Yes, but make sure they follow [Conventional Commits](https://www.conventionalcommits.org/) format and accurately describe the change. Don't let AI hallucinate what it changed.

### What about AI-generated issue descriptions?

Welcome! But verify that the technical details are accurate against the actual codebase. AI can (and does) hallucinate file paths, function names, and architectural details.

