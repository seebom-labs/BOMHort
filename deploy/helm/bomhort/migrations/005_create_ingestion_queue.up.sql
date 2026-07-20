-- 005_create_ingestion_queue.up.sql
-- ClickHouse-based job queue. ReplacingMergeTree ensures the latest
-- status wins after OPTIMIZE/FINAL queries.
-- Workers claim jobs by INSERTing updated rows with status='processing'.
CREATE TABLE IF NOT EXISTS ingestion_queue (
    created_at          DateTime          DEFAULT now(),
    job_id              UUID,
    source_file         String,
    sha256_hash         FixedString(64),
    status              LowCardinality(String) DEFAULT 'pending',
    job_type            LowCardinality(String) DEFAULT 'sbom',
    claimed_by          String            DEFAULT '',
    claimed_at          Nullable(DateTime),
    finished_at         Nullable(DateTime),
    error_message       String            DEFAULT ''
) ENGINE = ReplacingMergeTree(created_at)
ORDER BY (status, created_at, job_id);

