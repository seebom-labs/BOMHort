-- GitHub license cache: avoids redundant API calls across worker restarts.
CREATE TABLE IF NOT EXISTS github_license_cache (
    repo        LowCardinality(String),
    spdx_id     LowCardinality(String),
    fetched_at  DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(fetched_at)
ORDER BY (repo);

