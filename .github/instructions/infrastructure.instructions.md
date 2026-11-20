---
applyTo: "deploy/**,.github/workflows/**,docker-compose.yml,**/Dockerfile,Makefile,hack/**"
---

Read the root `AGENTS.md`, `.ai/operations.md`, `.ai/security.md` and
relevant `.ai/architecture.md` rules. Migration changes also need database
rules. Ask before changing Kubernetes manifest structures.
For reviews follow `.ai/review.md`; static lint does not prove deployment or
upgrade behavior. Never run destructive demos or resets on shared data.
