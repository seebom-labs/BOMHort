-- Migration 030: Add uploaded_by column to record credential attribution (#456).
-- Records which named API key uploaded each SBOM document.
-- Carried on ingestion_queue so attribution survives the hop from gateway to worker.

ALTER TABLE sboms ADD COLUMN IF NOT EXISTS uploaded_by LowCardinality(String) DEFAULT '';
ALTER TABLE ingestion_queue ADD COLUMN IF NOT EXISTS uploaded_by LowCardinality(String) DEFAULT '';
