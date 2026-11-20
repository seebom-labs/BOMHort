---
name: bomhort-review
description: Review a BOMHort PR, branch, commit or diff using repository rules, a disposable local stack, real end-to-end tests and browser analysis for UI changes. Report findings and validation gaps; do not implement fixes or approve PRs.
---

Read `AGENTS.md`, `.ai/workflow.md` and `.ai/review.md` from the repository
root before starting. Follow the shared review procedure and its domain routing.
Read `.ai/README.md` for the guardrail and skill inventory.
This skill is an entry point, not a copy of the policy.

Identify the reviewed base/head or worktree diff. Run the required local and
browser checks safely; retain commands, results and concrete findings.
If execution is unavailable, report BLOCKED / incomplete rather than "Ship".
Do not change tracked files, commit, push, approve or merge during a review.
