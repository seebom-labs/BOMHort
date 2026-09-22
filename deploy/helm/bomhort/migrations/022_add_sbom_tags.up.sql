-- 022_add_sbom_tags.up.sql
-- Free-form grouping labels on an SBOM, orthogonal to the ownership triple.
--
-- cluster/namespace/project describe *where a workload runs* — they are
-- Kubernetes semantics and are structurally empty for catalogue-style
-- instances (a foundation collecting SBOMs of its member projects never has
-- a cluster). Those instances still need to group projects: "these 300 SBOMs
-- are sandbox applications", "these are graduated". Overloading
-- `namespace` for that would mean two different meanings in one column
-- depending on how the instance is operated, which breaks the moment someone
-- runs both models side by side.
--
-- tags is therefore a separate, deployment-neutral dimension. It is an Array
-- because the groupings are genuinely many-to-many: one project is a sandbox
-- application *and* an observability tool *and* owned by a TAG. A scalar
-- column would only ever solve the first grouping.
--
-- A tagged SBOM keeps its own `project` — tags group projects, they do not
-- replace them. k2s with three SBOMs stays the project "k2s" and additionally
-- carries the tag "sandbox-applications".
--
-- ingestion_queue carries the column too so the value survives the hop from
-- the watcher/gateway to the parsing worker, like cluster/namespace/project.
--
-- Cheap ADD COLUMN, no ORDER BY change. Rows ingested before this migration
-- have [] and are reported as untagged.
ALTER TABLE sboms ADD COLUMN IF NOT EXISTS tags Array(String) DEFAULT [];
ALTER TABLE ingestion_queue ADD COLUMN IF NOT EXISTS tags Array(String) DEFAULT [];

