-- 006_create_dashboard_mv.up.sql
-- Materialized view for pre-aggregated dashboard statistics.
-- SummingMergeTree auto-sums total_sboms and total_packages on merge.
CREATE MATERIALIZED VIEW IF NOT EXISTS dashboard_stats_mv
ENGINE = SummingMergeTree()
ORDER BY (stat_date)
AS SELECT
    toDate(ingested_at) AS stat_date,
    count()             AS total_sboms,
    sum(length(package_names)) AS total_packages
FROM sbom_packages
GROUP BY stat_date;

