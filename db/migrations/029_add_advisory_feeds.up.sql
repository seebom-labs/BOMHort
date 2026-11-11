-- Pluggable OSV-format advisory feeds (ADVISORY_SOURCES).
--
-- A distro or vendor feed knows about its own backports: pkg:apk/wolfi/
-- openssl@3.1.4-r2 may carry the fix for a CVE whose upstream range still
-- says 3.1.4 is vulnerable. A feed authoritative for a PURL prefix decides
-- the findings for that prefix; osv.dev's upstream match for the same flaw
-- is dropped.
--
-- vulnerabilities:
--   advisory_source     'osv' for a finding osv.dev alone reported (every
--                       row before this migration), else the configured
--                       feed name that decided it.
--   advisory_status     '' for an osv.dev finding, else the feed's status:
--                       affected, under_investigation, pending_upstream_fix,
--                       fix_not_planned or not_affected. A feed's "fixed"
--                       verdict produces no row. not_affected rows are
--                       additionally recorded as a VEX statement authored by
--                       the feed, so every existing suppression count applies.
--   component_location  JSON array of {purl, location, architecture} from the
--                       feed's ecosystem_specific.components[]: where in the
--                       image the vulnerable file sits. '' when not given.
--
-- advisory_records caches the feed records, keyed by (source, id). The
-- cve-refresher fetches only records whose index `modified` moved. It is a
-- global cache like registry_license_cache, not per-SBOM data, so it carries
-- no ownership columns. package_keys ("apk/wolfi/openssl") is what the
-- matcher searches by.
--
-- Cheap ADD COLUMN plus a new table; no ORDER BY change.
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS advisory_source LowCardinality(String) DEFAULT 'osv';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS advisory_status LowCardinality(String) DEFAULT '';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS component_location String DEFAULT '';

CREATE TABLE IF NOT EXISTS advisory_records (
    source        LowCardinality(String),
    id            String,
    modified      DateTime64(3),
    package_keys  Array(String),
    record_json   String,
    synced_at     DateTime64(3) DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(synced_at)
ORDER BY (source, id);
