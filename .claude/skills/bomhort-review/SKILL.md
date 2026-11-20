---
name: bomhort-review
description: Review a BOMHort PR, branch, commit or diff with a disposable local stack, real end-to-end tests and browser analysis for UI changes. Produce findings and evidence, not fixes or PR approval.
---

Read `AGENTS.md`, `.ai/workflow.md` and `.ai/review.md` from the repository
root. Follow that shared procedure and load the domain rules for connected code.
Read `.ai/README.md` for the guardrail and skill inventory.
This Claude entry point uses the same policy as the tool-neutral skill.

Run the required checks safely and report commands, results and findings.
Missing local execution or browser access means BLOCKED / incomplete, not "Ship".
Do not change tracked files, commit, push, approve or merge during a review.
