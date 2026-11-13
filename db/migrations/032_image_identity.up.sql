ALTER TABLE sboms
    ADD COLUMN IF NOT EXISTS origin LowCardinality(String) DEFAULT '' AFTER supplier,
    ADD COLUMN IF NOT EXISTS image_ref String DEFAULT '' AFTER supplier,
    ADD COLUMN IF NOT EXISTS image_digest String DEFAULT '' AFTER image_ref,
    ADD INDEX IF NOT EXISTS idx_image_digest image_digest TYPE bloom_filter GRANULARITY 4;

ALTER TABLE sbom_packages
    ADD COLUMN IF NOT EXISTS image_digest String DEFAULT '' AFTER project;

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS image_digest String DEFAULT '' AFTER project;

ALTER TABLE ingestion_queue
    ADD COLUMN IF NOT EXISTS origin LowCardinality(String) DEFAULT '' AFTER parent,
    ADD COLUMN IF NOT EXISTS image_ref String DEFAULT '' AFTER parent,
    ADD COLUMN IF NOT EXISTS image_digest String DEFAULT '' AFTER image_ref;
