-- 029_add_sbom_quality_score.up.sql
-- Adds quality_score (0-100) and quality_flags to sboms table (#537).
-- Computes document completeness and compliance with NTIA minimum elements.

ALTER TABLE sboms
    ADD COLUMN IF NOT EXISTS quality_score UInt8 DEFAULT 0,
    ADD COLUMN IF NOT EXISTS quality_flags Array(LowCardinality(String)) DEFAULT [];

