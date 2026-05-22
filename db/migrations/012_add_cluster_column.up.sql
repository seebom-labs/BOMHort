-- Migration 012: Add cluster column to core tables for multi-cluster support.
-- Non-destructive: existing data gets DEFAULT '' (unassigned/default cluster).
-- Note: Cannot alter ORDER BY on existing MergeTree tables, so cluster is a
-- regular column for now. A future breaking migration can optimize ORDER BY.

ALTER TABLE sboms ADD COLUMN IF NOT EXISTS cluster LowCardinality(String) DEFAULT '';
ALTER TABLE sbom_packages ADD COLUMN IF NOT EXISTS cluster LowCardinality(String) DEFAULT '';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cluster LowCardinality(String) DEFAULT '';
ALTER TABLE license_compliance ADD COLUMN IF NOT EXISTS cluster LowCardinality(String) DEFAULT '';
ALTER TABLE ingestion_queue ADD COLUMN IF NOT EXISTS cluster LowCardinality(String) DEFAULT '';
ALTER TABLE vex_statements ADD COLUMN IF NOT EXISTS cluster LowCardinality(String) DEFAULT '';

