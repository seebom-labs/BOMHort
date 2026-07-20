---
title: "Contributor Ladder"
linkTitle: "Contributor Ladder"
type: docs
weight: 3
description: >
  How to grow from first-time contributor to maintainer — roles, expectations, and promotion criteria.
---

## Overview

BOMHort uses a transparent contributor ladder inspired by the [CNCF contributor ladder template](https://github.com/cncf/project-template/blob/main/CONTRIBUTOR_LADDER.md). Each rung provides clear expectations and privileges, so you always know what the next step looks like.

```text
┌─────────────────────────────────────────────┐
│  Maintainer   — merge, release, direction   │
├─────────────────────────────────────────────┤
│  Reviewer     — approve PRs in their area   │
├─────────────────────────────────────────────┤
│  Contributor  — regular code/docs/tests     │
├─────────────────────────────────────────────┤
│  Community    — issues, discussions, usage   │
└─────────────────────────────────────────────┘
```

---

## 🌱 Community Member

**Who:** Anyone who uses BOMHort, files issues, or participates in discussions.

**How to become one:** Just show up! No formal process.

**Expectations:**
- Follow the [Code of Conduct](https://github.com/seebom-labs/BOMHort/blob/main/CODE_OF_CONDUCT.md)
- File bugs and feature requests using the issue templates
- Help answer questions in discussions

**Privileges:**
- Open issues and participate in discussions
- Submit pull requests

---

## 🔧 Contributor

**Who:** Community members who have had at least one pull request merged.

**How to become one:** Get a PR merged. That's it.

**Expectations:**
- Sign off commits (Developer Certificate of Origin: `git commit -s`)
- Follow coding standards (see [Development Guide](/docs/development/))
- Write tests for new features
- Respond to review feedback in a timely manner

**Privileges:**
- Listed in release notes as a contributor
- Can be assigned to issues
- Eligible for `help wanted` and `good first issue` tasks

### Good First Contributions

| Area | Examples |
|------|----------|
| **Documentation** | Fix typos, improve examples, add FAQ entries |
| **Tests** | Add unit tests for uncovered code paths |
| **Bug fixes** | Issues labeled [`bug`](https://github.com/seebom-labs/BOMHort/labels/bug) |
| **Frontend** | Small UI improvements, accessibility fixes |
| **Backend** | Small query optimizations, error message improvements |

### Coding Standards Quick Reference

| Stack | Key Rules |
|-------|-----------|
| **Go** | Idiomatic, explicit error handling, `goccy/go-json`, parameterized queries, no new deps without asking |
| **Angular** | Strict TypeScript, standalone components, OnPush, Vitest, never `bypassSecurityTrustHtml` |
| **ClickHouse** | MergeTree family, batch inserts, low-cardinality ORDER BY prefix |
| **Helm** | Standard templates, ClickHouse Operator for DB, no custom CRDs |

---

## 👀 Reviewer

**Who:** Contributors who have demonstrated sustained, high-quality contributions in a specific area and are trusted to approve PRs.

**How to become one:**
1. Have **5+ merged PRs** in the area you want to review
2. Demonstrate understanding of the codebase architecture and conventions
3. Nominated by a maintainer, confirmed via lazy consensus (no objection in 7 days)

**Expectations:**
- Provide timely, constructive reviews (target: 48h for first response)
- Ensure code quality, test coverage, and documentation
- Help mentor new contributors
- Prioritize unblocking others over your own PRs

**Privileges:**
- Can approve PRs in their area (final merge still requires maintainer)
- Listed in [OWNERS](https://github.com/seebom-labs/BOMHort/blob/main/OWNERS) file
- Invited to architecture discussions

### Review Areas

| Area | Scope |
|------|-------|
| **Backend / Core** | `cmd/`, `internal/`, `pkg/` — Go binaries and shared packages |
| **Frontend** | `ui/` — Angular components, services, routing |
| **Infrastructure** | `deploy/`, `Makefile`, `docker-compose.yml`, `.github/` |
| **Database** | `db/migrations/`, ClickHouse schema changes |
| **Documentation** | `docs/`, `README.md`, `ARCHITECTURE_PLAN.md` |

---

## 🛡️ Maintainer

**Who:** The project's technical leadership with full write access and release authority.

**How to become one:**
1. Be an active Reviewer for **3+ months**
2. Demonstrate deep understanding of the full architecture (not just one area)
3. Show good judgment on API design, security, and backward compatibility
4. Nominated by an existing maintainer, approved by **supermajority (⅔)** of current maintainers

**Expectations:**
- Set technical direction and own the [Roadmap](/docs/roadmap/)
- Review and merge pull requests across all areas
- Cut releases (tag → CI → publish)
- Manage CI/CD pipeline and infrastructure
- Enforce Code of Conduct and resolve disputes
- Mentor reviewers and contributors
- Be responsive: triage new issues within 7 days

**Privileges:**
- Write access to the repository
- Merge pull requests
- Cut releases
- Manage GitHub project board and labels
- Represent the project externally

### Current Maintainers

| Name | GitHub | Area | Affiliation |
|------|--------|------|-------------|
| Mario Fahlandt | [@mfahlandt](https://github.com/mfahlandt) | Project Lead / Core | Kubermatic |
| Koray Oksay | [@koksay](https://github.com/koksay) | K8s Implementation | Kubermatic |

---

## 🏛️ Emeritus

Maintainers or reviewers who are no longer active may be moved to **emeritus** status. This is a recognition of past contributions, not a demotion. Emeritus members:

- Are listed in project history with gratitude
- No longer have active review or merge permissions
- Can return to active status by request + re-confirmation from current maintainers

---

## Promotion Process

```text
Community → Contributor:     First merged PR (automatic)
Contributor → Reviewer:      Nominated by maintainer, 7-day lazy consensus
Reviewer → Maintainer:       Nominated by maintainer, ⅔ supermajority vote
Active → Emeritus:           Self-request or 6 months of inactivity + maintainer consensus
```

### What We Look For

Beyond code quantity, promotion decisions consider:

- **Quality** — Are PRs well-tested, documented, and maintainable?
- **Consistency** — Are contributions sustained over time (not just a burst)?
- **Collaboration** — Do you help others, respond to reviews, and communicate well?
- **Judgment** — Do you make good trade-offs? Do you know when to ask vs. decide?
- **Alignment** — Do your contributions advance the project's mission and roadmap?

---

## 🤖 AI Usage Policy

We welcome AI-assisted contributions. See the dedicated [AI Usage Policy](/docs/development/ai-policy/) for full guidelines.

**Key points:**
- AI usage is welcome — you are responsible for the output
- DCO sign-off (`git commit -s`) is mandatory — you sign, not the AI
- No `Co-authored-by: AI` trailers — AI is a tool, not a co-author
- Follow [AGENTS.md](https://github.com/seebom-labs/BOMHort/blob/main/AGENTS.md) conventions

---

## Getting Started

Ready to climb the ladder? Here's how:

1. **Browse issues** labeled [`good first issue`](https://github.com/seebom-labs/BOMHort/labels/good%20first%20issue) or [`help wanted`](https://github.com/seebom-labs/BOMHort/labels/help%20wanted)
2. **Set up your dev environment** — see [Development Guide](/docs/development/)
3. **Read the architecture** — see [Architecture](/docs/architecture/)
4. **Submit a PR** — follow the [Contributing Guide](https://github.com/seebom-labs/BOMHort/blob/main/CONTRIBUTING.md)
5. **Check the Roadmap** — see [Roadmap](/docs/roadmap/) for what's planned next

{{% alert title="Questions?" color="info" %}}
Don't hesitate to open a [Discussion](https://github.com/seebom-labs/BOMHort/discussions) if you're unsure where to start or how to contribute. We're happy to help!
{{% /alert %}}

