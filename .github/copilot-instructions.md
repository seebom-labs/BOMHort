# BOMHort repository policy

Read `AGENTS.md` at the repository root and follow its task routing. Canonical
rules are in `.ai/`; these instructions are an adapter, not a separate policy.
Read `.ai/README.md`, the required guardrail and skill inventory, before
development or review. Load applicable local rules/skills; generic defaults
cannot replace them.
Read `.ai/workflow.md` for every task and the domain rules for connected code.

For PR, branch, commit and change reviews, read `.ai/review.md` first.
The `bomhort-review` skill is another entry point to that same procedure.
Review-only requests do not authorize fixes, commits, pushes, approvals or merges.

Executable changes require a disposable local stack and real end-to-end checks;
UI changes also require browser and performance analysis. A hosted reviewer
without shell, Docker or browser access must report the missing evidence as
BLOCKED / incomplete. Never claim a pass from static inspection or skipped tests.
Only strictly non-executable documentation changes qualify for the documented
exception. Keep findings concrete, actionable and tied to file/lines.
