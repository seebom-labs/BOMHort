-- 007_create_vex_statements.up.sql
-- VEX (Vulnerability Exploitability eXchange) statements.
-- Each statement links a product (PURL) to a vulnerability (CVE) with a status.
-- ReplacingMergeTree ensures the latest statement per vuln+product wins.
CREATE TABLE IF NOT EXISTS vex_statements (
    ingested_at         DateTime          DEFAULT now(),
    vex_id              UUID,
    document_id         String,
    source_file         String,
    product_purl        String,
    vuln_id             String,
    status              LowCardinality(String),          -- not_affected, affected, fixed, under_investigation
    justification       LowCardinality(String),          -- component_not_present, vulnerable_code_not_present, etc.
    impact_statement    String            DEFAULT '',
    action_statement    String            DEFAULT '',
    vex_timestamp       DateTime
) ENGINE = ReplacingMergeTree(ingested_at)
ORDER BY (vuln_id, product_purl, vex_id);

