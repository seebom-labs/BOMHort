-- 008_add_license_exemption_columns.up.sql
-- Add columns for tracking exempted packages and exemption reasons.
ALTER TABLE license_compliance
    ADD COLUMN IF NOT EXISTS exempted_packages Array(String) DEFAULT [],
    ADD COLUMN IF NOT EXISTS exemption_reason  String        DEFAULT '';

