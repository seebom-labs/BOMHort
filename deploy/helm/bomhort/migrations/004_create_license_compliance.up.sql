-- 004_create_license_compliance.up.sql
-- License compliance status per SBOM.
-- ReplacingMergeTree keeps only the latest row per (sbom_id, license_id).
CREATE TABLE IF NOT EXISTS license_compliance (
    checked_at              DateTime          DEFAULT now(),
    sbom_id                 UUID,
    source_file             String,
    license_id              LowCardinality(String),
    category                LowCardinality(String),
    package_count           UInt32,
    non_compliant_packages  Array(String)
) ENGINE = ReplacingMergeTree(checked_at)
ORDER BY (sbom_id, license_id);

