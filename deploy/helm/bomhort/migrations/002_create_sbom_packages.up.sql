-- 002_create_sbom_packages.up.sql
-- Dependency trees stored as parallel arrays. One row per SBOM.
-- ClickHouse compresses columnar arrays extremely well.
CREATE TABLE IF NOT EXISTS sbom_packages (
    ingested_at         DateTime          DEFAULT now(),
    sbom_id             UUID,
    source_file         String,
    -- Packages as parallel arrays (columnar compression)
    package_spdx_ids    Array(String),
    package_names       Array(String),
    package_versions    Array(String),
    package_purls       Array(String),
    package_licenses    Array(LowCardinality(String)),
    -- Relationship graph as index references into the package arrays
    rel_source_indices  Array(UInt32),
    rel_target_indices  Array(UInt32),
    rel_types           Array(LowCardinality(String))
) ENGINE = ReplacingMergeTree(ingested_at)
ORDER BY (sbom_id);

