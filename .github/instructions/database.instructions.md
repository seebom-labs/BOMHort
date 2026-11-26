---
applyTo: "backend/internal/clickhouse/**,db/**,deploy/helm/bomhort/migrations/**"
---

Read the root `AGENTS.md`, `.ai/database.md` and `.ai/backend.md`.
Preserve ownership and VEX scope across every query/write path and keep both
migration directories byte-identical. Ask before schema changes.
For reviews follow `.ai/review.md`; execute affected queries against real
ClickHouse with migrations applied. Skipped integration tests are not passes.
