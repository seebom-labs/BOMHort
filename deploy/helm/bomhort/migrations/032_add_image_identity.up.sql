ALTER TABLE sboms ADD COLUMN IF NOT EXISTS image_ref String DEFAULT '';
ALTER TABLE sboms ADD COLUMN IF NOT EXISTS image_digest String DEFAULT '';
ALTER TABLE sboms ADD INDEX IF NOT EXISTS idx_sboms_image_ref image_ref TYPE tokenbf_v1(10240, 2, 0) GRANULARITY 1;

ALTER TABLE sbom_packages ADD COLUMN IF NOT EXISTS image_digest String DEFAULT '';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS image_digest String DEFAULT '';

ALTER TABLE ingestion_queue ADD COLUMN IF NOT EXISTS image_ref String DEFAULT '';
ALTER TABLE ingestion_queue ADD COLUMN IF NOT EXISTS image_digest String DEFAULT '';
