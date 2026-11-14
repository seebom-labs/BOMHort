-- Migration 032: Add workload identity columns (#458).
--
-- Allows runtime scanners walking Kubernetes pods to report the running
-- workload identity alongside the SBOM.
--
--   workload_kind  e.g. Deployment, StatefulSet, DaemonSet, Job, CronJob, Pod, Rollout
--   workload_name  e.g. payment-service
--   workload_uid   Kubernetes workload UID (UUID string)
--
-- Non-destructive: existing rows get DEFAULT '' (= unassigned).
--
-- ingestion_queue also gets the columns so upload parameters travel from the
-- gateway to the parsing worker.

ALTER TABLE sboms ADD COLUMN IF NOT EXISTS workload_kind LowCardinality(String) DEFAULT '';
ALTER TABLE sboms ADD COLUMN IF NOT EXISTS workload_name LowCardinality(String) DEFAULT '';
ALTER TABLE sboms ADD COLUMN IF NOT EXISTS workload_uid  String                 DEFAULT '';

ALTER TABLE ingestion_queue ADD COLUMN IF NOT EXISTS workload_kind LowCardinality(String) DEFAULT '';
ALTER TABLE ingestion_queue ADD COLUMN IF NOT EXISTS workload_name LowCardinality(String) DEFAULT '';
ALTER TABLE ingestion_queue ADD COLUMN IF NOT EXISTS workload_uid  String                 DEFAULT '';
