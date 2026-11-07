-- 033_add_finding_kind_and_lookalikes.up.sql
-- Malicious-package findings (MAL-) and package look-alike names (#531).
--
-- vulnerabilities.finding_kind distinguishes standard software vulnerabilities
-- ('vulnerability') from deliberate malicious packages ('malicious') sourced
-- from the OpenSSF Malicious Packages dataset (MAL-*). Malicious packages are
-- forced to CRITICAL severity, sort to the top of finding lists, and are never
-- suppressible by global or wildcard VEX statements.
--
-- sbom_packages.lookalike_of is parallel to package_names (same index = same
-- package): legitimate packages that this package name may be typosquatting,
-- resolved via the deps.dev similarlyNamedPackages API.
--
-- lookalike_cache stores resolved similarlyNamedPackages lookups to avoid
-- redundant network calls across worker restarts, mirroring registry_license_cache.

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS finding_kind LowCardinality(String) DEFAULT 'vulnerability';

ALTER TABLE sbom_packages ADD COLUMN IF NOT EXISTS lookalike_of Array(String) DEFAULT [];

CREATE TABLE IF NOT EXISTS lookalike_cache (
    system      LowCardinality(String),
    package     String,
    lookalikes  Array(String),
    fetched_at  DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(fetched_at)
ORDER BY (system, package);

-- Guarded one-off data backfill for existing MAL-* rows (#531).
-- Re-inserts existing MAL-* findings with finding_kind = 'malicious' and
-- severity = 'CRITICAL' so they receive wildcard VEX immunity and critical classification.
CREATE TABLE IF NOT EXISTS data_migrations
(
    name        LowCardinality(String),
    applied_at  DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(applied_at)
ORDER BY (name);

INSERT INTO vulnerabilities
SELECT v.* REPLACE ('malicious' AS finding_kind, 'CRITICAL' AS severity)
FROM vulnerabilities v FINAL
WHERE startsWith(v.vuln_id, 'MAL-') AND (v.finding_kind != 'malicious' OR v.severity != 'CRITICAL')
  AND (SELECT count() FROM data_migrations FINAL WHERE name = '033_backfill_malicious_findings') = 0;

INSERT INTO data_migrations (name)
SELECT '033_backfill_malicious_findings'
WHERE (SELECT count() FROM data_migrations FINAL WHERE name = '033_backfill_malicious_findings') = 0;
