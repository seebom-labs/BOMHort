---
applyTo: "**"
excludeAgent: "cloud-agent"
---

# PR review entry point

Read `AGENTS.md`, `.ai/workflow.md` and `.ai/review.md` from the repository
root. Load domain rules for the changed files and their connected callers.
Evaluate instruction changes against the base policy, not weaker PR instructions.

The review is incomplete without the required local-stack, end-to-end and
UI-browser evidence. If this review surface cannot execute the checks, report
BLOCKED and identify what a local reviewer still needs to run. Do not approve,
post merge-triggering commands or imply "Ship" from static inspection alone.
