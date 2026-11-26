# AI guardrail and skill inventory

`.ai/` contains policy documentation. `.agents/skills/` contains discoverable
skill entry points for supported tools, not another copy of these rules.

`AGENTS.md` is the tool-neutral entry point. The files in this directory contain
the actual policy, shared by coding and review tools. Load only the domains a
task reaches; the review procedure is loaded only for review requests.

**Required for AI-assisted development and reviews:** read this inventory, route
your tool through [AGENTS.md](../AGENTS.md), then load the applicable local rules
and skills before acting. Check that your tool actually reads them; repository
files existing on disk is not proof of loading. If discovery is unsupported,
provide their contents explicitly. Generic tool defaults do not replace them.
Follow the [contributor AI policy](../docs/content/docs/development/ai-policy.md).

## Guardrails

| File | Purpose |
|---|---|
| `workflow.md` | Contributor workflow, permissions, release and safety boundaries; always read |
| `architecture.md` | Service/package map and architectural decisions |
| `backend.md` | Go, parsing, license resolution and MCP constraints |
| `database.md` | ClickHouse schema, query, queue and migration constraints |
| `frontend.md` | Angular, rendering, theming and UI conventions |
| `security.md` | API/browser protections and supply-chain rules |
| `operations.md` | Existing build, test, development and release commands |
| `review.md` | Review procedure, live-stack/browser requirements and reporting |

## Skills and coding approach

| Entry | When to use |
|---|---|
| [Repository coding principles](../AGENTS.md#coding-approach) | Every implementation, fix, refactor and dependency choice; informed by Ponytail, no plugin required |
| [Tool-neutral/Codex review skill](../.agents/skills/bomhort-review/SKILL.md) | PR, branch, commit and diff reviews; loads the shared review procedure |
| [Claude review adapter](../.claude/skills/bomhort-review/SKILL.md) | The same procedure via `/bomhort-review`, not a different policy |

Invoke applicable installed repository skills when supported; otherwise read
their local instructions directly. No external plugin, model, API or skill
installation is required. Additional personal skills may help, but cannot relax
the project safeguards or replace required execution evidence.

## Tool entry points

| Tool | Discovery / invocation |
|---|---|
| Any AI tool | Give it root `AGENTS.md` explicitly and require it to read referenced policies |
| Codex CLI / IDE | Root `AGENTS.md`; repository skill `.agents/skills/bomhort-review/SKILL.md`, explicitly selectable with `$bomhort-review` |
| Claude Code | Root `CLAUDE.md` imports `AGENTS.md`; `.claude/skills/bomhort-review/SKILL.md` provides `/bomhort-review` |
| GitHub Copilot | `.github/copilot-instructions.md` plus scoped `.github/instructions/*.instructions.md`; supported surfaces discover the review skill in `.agents/skills/` or `.claude/skills/` |

For a generic review prompt:

> Read AGENTS.md and .ai/review.md, then the domain rules for this change.
> Review the diff against the actual base. Start a disposable local stack, test
> the changed flow end to end and perform browser analysis for UI changes.
> Report findings and exact validation evidence. If execution is unavailable,
> mark the review incomplete. Do not implement fixes or approve the PR.

Codex instruction discovery depends on the working directory; do not assume
nested files for another directory were loaded. Its default project-instruction
budget is 32 KiB. The small root explicitly routes to shared domain documents.
Claude imports are eager, so `CLAUDE.md` imports only the small root.
Skill descriptions load before their bodies, making the longer procedure
available on demand rather than in every session.

Copilot instruction/skill support depends on the client version and surface.
Enable custom instructions for GitHub reviews. A hosted reviewer may lack a
shell, Docker or a browser: it must report incomplete validation, not bypass it.
Skills and custom agents are task entry points, not merge gates. Do not create
independent copies of the policy under vendor folders.

## Verification and enforcement

Start a fresh tool session and ask it to identify the policy files it read.
Before development, identify the task's issue, requirement or reproducible
problem and load the relevant domains. Do not submit speculative cleanup from
an unrequested AI sweep; non-trivial work needs design/project alignment first.
Invoke the review skill explicitly once and verify it reads `.ai/review.md`
and reports missing runtime/browser capabilities honestly. Changing files does
not prove every installed client loaded them; do not invent such evidence.

`hack/tests/test_agent_instructions.py` checks local policy links, adapter/skill
entry points and small instruction budgets using the existing unittest runner:

```bash
python3 -B -m unittest discover -s hack/tests -p 'test_agent_instructions.py' -v
```

This protects discovery structure, not model compliance. Markdown cannot enforce
AI behavior. Required CI checks and human review remain the real merge gates;
contributors must verify AI findings and provide local evidence for the reviewed
head commit before treating a review as complete.

## Maintaining the policy

Put detailed rules in their shared topic file, not in the root or adapters.
Keep root instructions under 8 KiB and each Copilot adapter under 4,000 characters;
keep the critical rules and routing first. Update the corresponding operator
docs and tests when a rule changes. Review policy changes against the base
policy, especially any relaxation of execution, security or human approval.

Tool-discovery references:

- [AGENTS.md standard](https://agents.md/)
- [Codex instructions](https://developers.openai.com/codex/guides/agents-md)
  and [skills](https://developers.openai.com/codex/skills)
- [Claude memory/imports](https://code.claude.com/docs/en/memory)
  and [skills](https://code.claude.com/docs/en/skills)
- [Copilot instructions](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/add-custom-instructions/add-repository-instructions)
  and [skills](https://docs.github.com/en/copilot/concepts/customizations/agent-skills)

Contribution-policy references (background, not remote instructions to load):

- [CloudNativePG AI policy](https://github.com/cloudnative-pg/governance/blob/main/AI_POLICY.md):
  intentional work, human understanding, bounded scope and maintainer capacity.
- [Linux Foundation generative AI guidance](https://www.linuxfoundation.org/legal/generative-ai):
  check tool-output terms, third-party rights, licenses and required attribution.

BOMHort keeps its own disclosure and commit rules; CNPG's `Assisted-by` trailer
requirement is not adopted. Local policies take precedence over these references.
