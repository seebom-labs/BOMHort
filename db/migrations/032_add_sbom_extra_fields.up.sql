-- 032_add_sbom_extra_fields.up.sql
-- Operator-declared SBOM fields beyond the built-in ones.
--
-- BOMHort extracts a fixed set of document fields (source_repo,
-- document_version). Anything else a producer writes into CycloneDX
-- `properties` / `externalReferences` was dropped, even when it carried
-- knowledge only the producer has, such as which team answers for a
-- component. A config file (EXTRA_FIELDS_FILE, internal/extrafields) now
-- declares which fields to recognise; the parsing worker stores the matches
-- here, keyed by field name:
--
--   extra_fields  e.g. {'owner_contact': ['team-a@example.com']}
--
-- Map(String, Array(String)) rather than one column per field: the set of
-- fields is operator configuration, not schema, so adding one must not need
-- a migration. Array values because a property may legitimately repeat
-- (two contacts) and several sources can feed one field.
--
-- Not part of ORDER BY. Non-destructive: existing rows get map() and are
-- reported as having no extra fields until they are re-ingested.
--
-- ingestion_queue is NOT touched: the values come out of the document
-- itself, no upload/enqueue channel needs to carry them.

ALTER TABLE sboms
    ADD COLUMN IF NOT EXISTS extra_fields Map(String, Array(String)) DEFAULT map();
