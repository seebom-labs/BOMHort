-- 020_add_vex_product_ref.up.sql
-- Persist the OpenVEX product @id on every statement.
--
-- Scoping a statement to its SBOM (#350) resolves the product @id at ingest
-- time. When the product's SBOM has not been ingested yet — VEX and SBOM
-- files land in arbitrary order — the resolution fails, the statement is
-- stored unscoped (sbom_id = ''), and because the ref itself was discarded
-- there was nothing left to retry: the statement stayed inert forever, and
-- the idempotency guard skipped the document on every later encounter.
--
-- With the ref persisted the parsing worker can rescue unscoped statements
-- after each successful SBOM ingest: re-resolve product_ref, and on a match
-- scope the statement (rewriting product_purl to '*' when the statement was
-- product-wide, i.e. product_purl still equals the raw ref).
--
-- Cheap ADD COLUMN, no ORDER BY change. Rows ingested before this migration
-- have '' and fall back to product_purl as the ref (identical value for the
-- shapes that can be rescued).
ALTER TABLE vex_statements ADD COLUMN IF NOT EXISTS product_ref String DEFAULT '';

