-- GitHub repository metadata: tracks archived status, last activity, etc.
CREATE TABLE IF NOT EXISTS github_repo_metadata (
    repo            LowCardinality(String),
    archived        Bool DEFAULT false,
    fork            Bool DEFAULT false,
    pushed_at       DateTime DEFAULT now(),
    stargazers      UInt32 DEFAULT 0,
    fetched_at      DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(fetched_at)
ORDER BY (repo);

