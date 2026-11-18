CREATE TABLE IF NOT EXISTS tea_snapshots (
    sbom_id UUID,
    cluster LowCardinality(String) DEFAULT '',
    namespace LowCardinality(String) DEFAULT '',
    project LowCardinality(String) DEFAULT '',
    collection_version UInt64,
    vex_version UInt64,
    storage_ref String,
    sha256_hash FixedString(64)
) ENGINE = MergeTree()
ORDER BY (sbom_id, collection_version);
