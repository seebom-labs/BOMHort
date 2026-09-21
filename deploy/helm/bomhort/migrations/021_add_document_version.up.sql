-- Migration 021: Add document_version column.
--
-- The product version was only visible mangled into document_name for
-- CycloneDX ("ledger v2.0.1") and not at all for SPDX, so the SBOM list
-- showed three indistinguishable "payment-api" rows. Stores the version of
-- the product the document DESCRIBES as its own attribute:
--
--   document_version  e.g. "1.4.2" — '' = unknown
--
-- Populated at parse time: SPDX root package versionInfo (the package the
-- document DESCRIBES), CycloneDX metadata.component.version. Plain String:
-- versions are near-unique per SBOM, a LowCardinality dictionary would not
-- pay off. Not part of ORDER BY (same reasoning as 015/016). Non-destructive:
-- existing rows get DEFAULT '' and fill in on their next re-ingestion.
--
-- ingestion_queue is NOT touched: the version comes out of the document
-- itself, no upload/enqueue channel needs to carry it.

ALTER TABLE sboms
    ADD COLUMN IF NOT EXISTS document_version String DEFAULT '';
