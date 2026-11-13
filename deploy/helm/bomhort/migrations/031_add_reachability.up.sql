-- 031_add_reachability.up.sql
-- Reachability evidence columns on vulnerabilities (#535).
-- Stores call-graph and symbol reachability evidence from govulncheck and OpenVEX.

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS reachability LowCardinality(String) DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS evidence_source String DEFAULT '',
    ADD COLUMN IF NOT EXISTS evidence_ref String DEFAULT '',
    ADD COLUMN IF NOT EXISTS evidence_at DateTime DEFAULT toDateTime(0);
