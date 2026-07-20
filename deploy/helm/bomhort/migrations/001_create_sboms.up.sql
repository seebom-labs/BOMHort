-- 001_create_sboms.up.sql
-- SBOM metadata table. One row per ingested SPDX document.
CREATE TABLE IF NOT EXISTS sboms (
    ingested_at         DateTime          DEFAULT now(),
    sbom_id             UUID,
    source_file         String,
    spdx_version        LowCardinality(String),
    document_name       String,
    document_namespace  String,
    sha256_hash         FixedString(64),
    creation_date       DateTime,
    creator_tools       Array(String)
) ENGINE = ReplacingMergeTree(ingested_at)
ORDER BY (sbom_id);

