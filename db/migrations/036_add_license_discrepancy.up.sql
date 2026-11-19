-- 033_add_license_discrepancy.up.sql
-- Concluded vs. declared license: records scan-derived expressions from
-- ClearlyDefined that disagree with the package's declared license (#530).
--
-- license_discrepancy is parallel to package_names (same index = same package).
-- Stored as a flag with the discovered expression (e.g. 'GPL-2.0'); empty string
-- when there is no discrepancy. Declared license always wins for compliance.
ALTER TABLE sbom_packages ADD COLUMN IF NOT EXISTS license_discrepancy Array(String) DEFAULT [];
