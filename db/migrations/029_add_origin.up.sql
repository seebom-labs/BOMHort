-- Migration 029: Add origin dimension to record how an SBOM was produced (#455).
-- Fixed vocabulary: cluster-scan, ci, registry, vendor, manual, '' (unassigned).
-- Mirrors the ownership pattern of cluster (012), namespace, and project (015).

ALTER TABLE sboms ADD COLUMN IF NOT EXISTS origin LowCardinality(String) DEFAULT '';
ALTER TABLE sbom_packages ADD COLUMN IF NOT EXISTS origin LowCardinality(String) DEFAULT '';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS origin LowCardinality(String) DEFAULT '';
ALTER TABLE license_compliance ADD COLUMN IF NOT EXISTS origin LowCardinality(String) DEFAULT '';
ALTER TABLE ingestion_queue ADD COLUMN IF NOT EXISTS origin LowCardinality(String) DEFAULT '';
ALTER TABLE vex_statements ADD COLUMN IF NOT EXISTS origin LowCardinality(String) DEFAULT '';
ALTER TABLE document_store ADD COLUMN IF NOT EXISTS origin LowCardinality(String) DEFAULT '';
