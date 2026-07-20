-- CVE Refresh Log: tracks background CVE refresh runs.
CREATE TABLE IF NOT EXISTS cve_refresh_log (
    refresh_id       UUID DEFAULT generateUUIDv4(),
    started_at       DateTime DEFAULT now(),
    finished_at      DateTime DEFAULT now(),
    purls_checked    UInt64   DEFAULT 0,
    new_vulns_found  UInt64   DEFAULT 0,
    status           LowCardinality(String) DEFAULT 'running'
) ENGINE = MergeTree()
ORDER BY (started_at, refresh_id);

