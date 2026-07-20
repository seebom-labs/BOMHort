-- 003_create_vulnerabilities.up.sql
-- Vulnerabilities discovered via the OSV API.
-- ORDER BY starts with severity (4 values = lowest cardinality).
CREATE TABLE IF NOT EXISTS vulnerabilities (
    discovered_at       DateTime          DEFAULT now(),
    sbom_id             UUID,
    source_file         String,
    purl                String,
    vuln_id             String,
    severity            LowCardinality(String),
    summary             String,
    affected_versions   Array(String),
    fixed_version       String,
    osv_json            String
) ENGINE = ReplacingMergeTree(discovered_at)
ORDER BY (sbom_id, vuln_id, purl);

