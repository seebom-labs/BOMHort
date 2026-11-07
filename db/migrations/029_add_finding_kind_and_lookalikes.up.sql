-- 029_add_finding_kind_and_lookalikes.up.sql
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
