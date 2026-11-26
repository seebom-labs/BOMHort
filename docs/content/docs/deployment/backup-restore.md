---
title: "Backup and Disaster Recovery"
description: "End-to-end backup and disaster recovery procedures for BOMHort's ClickHouse database and original SBOM documents."
lead: "How to make a consistent, restorable snapshot of BOMHort's analytics database and original-document stores."
date: 2026-11-16T00:00:00Z
lastmod: 2026-11-20T00:00:00Z
draft: false
images: []
menu:
  docs:
    parent: "deployment"
weight: 85
toc: true
---

BOMHort keeps related state in ClickHouse and in the original-document store. A usable recovery point must include both, captured while BOMHort writers are stopped. This guide uses one saved snapshot ID for every artifact in that recovery point.

The commands below assume a POSIX shell (Linux, macOS, or WSL), the chart's default single ClickHouse shard and replica, `aws` CLI access to the backup bucket, and a storage backend compatible with the AWS CLI. For a multi-shard or multi-replica ClickHouse installation, use a cluster-wide `clickhouse-backup` plan that covers every shard; backing up one pod does not capture other shards.

## What is included

- A full backup of the `bomhort` database, including table definitions and data such as `sboms`, `sbom_packages`, `vulnerabilities`, `license_compliance`, `vex_statements`, `document_store`, `data_migrations`, and any other tables or views in that database.
- The exact S3 objects referenced by `document_store`, restored to their original bucket names and keys.
- If filesystem originals are enabled, an archive of the configured originals PVC, restored to the same PVC path.
- A record of the snapshot ID, backup object keys, ClickHouse image/chart version, and the Helm values or values-file revision used for the deployment. Store that record with the backups.

There is no `schema_migrations` table. Schema changes are the numbered SQL files shipped with the chart and are applied by its migration Job. `data_migrations` stores markers for one-time data backfills; it is included in the database backup.

## 1. Prepare one recovery point

Set the namespace and Helm release names, plus a unique snapshot ID. Keep these values in the same shell for the entire backup or restore operation:

```bash
NAMESPACE=bomhort
RELEASE=bomhort
DR_BACKUP_BUCKET=my-bomhort-dr
SNAPSHOT_ID="bomhort-$(date -u +%Y%m%dT%H%M%SZ)"
DB_BACKUP_NAME="$SNAPSHOT_ID"
DB_BACKUP_KEY="bomhort/clickhouse/${SNAPSHOT_ID}.tar.gz"
FS_BACKUP_KEY="bomhort/originals/${SNAPSHOT_ID}/filesystem.tar.gz"

CLICKHOUSE_POD=$(kubectl get pods -n "$NAMESPACE" \
  -l "clickhouse.altinity.com/chi=${RELEASE}-clickhouse" \
  -o jsonpath='{.items[0].metadata.name}')
test -n "$CLICKHOUSE_POD"
```

Enable versioning on the dedicated DR bucket and verify it is enabled. Use a dedicated bucket with restrictive write permissions; keep its retention policy independent of the source buckets.

```bash
aws s3api put-bucket-versioning --bucket "$DR_BACKUP_BUCKET" \
  --versioning-configuration Status=Enabled
aws s3api get-bucket-versioning --bucket "$DR_BACKUP_BUCKET"
```

The examples create a new key for each `SNAPSHOT_ID` and never use `aws s3 sync --delete`. Do not reuse an ID for another recovery point.

## 2. Stop every BOMHort writer

The API accepts upload and source-update requests. The parsing worker writes parsed records and original-document references. The ingestion watcher and CVE refresher are CronJobs; suspending a CronJob prevents new Jobs but does not stop Jobs already running.

Set the chart's maintenance flag, which scales the API and parsing worker to zero and suspends both CronJobs. This also records the paused state in Helm so a later `helm upgrade` does not accidentally restart writers during recovery.

```bash
helm upgrade "$RELEASE" deploy/helm/bomhort -n "$NAMESPACE" --reuse-values \
  --set maintenance.writersSuspended=true --no-hooks --wait

for cronjob in "${RELEASE}-ingestion-watcher" "${RELEASE}-cve-refresher"; do
  while [ -n "$(kubectl get cronjob "$cronjob" -n "$NAMESPACE" \
    -o jsonpath='{.status.active[0].name}')" ]; do
    echo "Waiting for active writer Job owned by ${cronjob} to finish..."
    sleep 5
  done
done

kubectl rollout status deployment/"${RELEASE}-api-gateway" -n "$NAMESPACE" --timeout=5m
kubectl rollout status deployment/"${RELEASE}-parsing-worker" -n "$NAMESPACE" --timeout=5m
```

Use the same chart version and migration configuration already installed; do not combine entering maintenance with an application or schema upgrade. `--no-hooks` prevents an enabled source-to-target data-migration hook from running as a side effect. If a schema migration Job is already running, wait for it to finish before taking the backup. The CronJob loop above waits for existing Jobs, including Jobs created before the release labels were added to the chart.

## 3. Back up the complete ClickHouse database

The chart's default `clickhouse/clickhouse-server:24.8.14.39` image does not include `clickhouse-backup`. Install the pinned official binary temporarily into the ClickHouse container. The tool must run beside the server and have access to the same `/var/lib/clickhouse` files; connecting to a remote server from a separate workstation only backs up schema.

Download the official Linux AMD64 release and verify its published checksum before copying it into the pod. Use the ARM64 release and checksum for an ARM64 cluster.

```bash
CLICKHOUSE_BACKUP_VERSION=2.8.3
curl -fL \
  "https://github.com/Altinity/clickhouse-backup/releases/download/v${CLICKHOUSE_BACKUP_VERSION}/clickhouse-backup-linux-amd64.tar.gz" \
  -o /tmp/clickhouse-backup-linux-amd64.tar.gz
echo '74b23fe1b5b808b947d44781627cf611dfa828a4ae4dad76babf0713d8df7d02  /tmp/clickhouse-backup-linux-amd64.tar.gz' \
  | sha256sum -c -
tar -xzf /tmp/clickhouse-backup-linux-amd64.tar.gz -C /tmp clickhouse-backup

kubectl exec -i -n "$NAMESPACE" "$CLICKHOUSE_POD" -c clickhouse -- \
  sh -c 'umask 077; cat > /tmp/clickhouse-backup' < /tmp/clickhouse-backup
kubectl exec -n "$NAMESPACE" "$CLICKHOUSE_POD" -c clickhouse -- \
  chmod 700 /tmp/clickhouse-backup
```

Create a protected config file on the operator workstation. The example matches the chart defaults; set `username` and `password` from your secret manager if ClickHouse authentication is enabled. Do not commit this file or place a password directly in a command line.

```bash
umask 077
cat > /tmp/clickhouse-backup.yml <<'YAML'
general:
  remote_storage: none
clickhouse:
  host: localhost
  port: 9000
  username: default
  password: ""
  data_path: /var/lib/clickhouse
YAML

kubectl exec -i -n "$NAMESPACE" "$CLICKHOUSE_POD" -c clickhouse -- \
  sh -c 'umask 077; cat > /tmp/clickhouse-backup.yml' < /tmp/clickhouse-backup.yml
```

Run one full database backup. The `DB_BACKUP_NAME` variable is reused for the local backup directory and the off-cluster archive key.

```bash
kubectl exec -n "$NAMESPACE" "$CLICKHOUSE_POD" -c clickhouse -- \
  /tmp/clickhouse-backup --config=/tmp/clickhouse-backup.yml \
  create --tables='bomhort.*' "$DB_BACKUP_NAME"

kubectl exec -n "$NAMESPACE" "$CLICKHOUSE_POD" -c clickhouse -- \
  /tmp/clickhouse-backup --config=/tmp/clickhouse-backup.yml list
```

Stream the resulting snapshot to its unique DR object key. This does not write the only copy to the pod's `/tmp` or ClickHouse PVC. The ClickHouse backup itself is retained locally until the upload succeeds.

```bash
kubectl exec -n "$NAMESPACE" "$CLICKHOUSE_POD" -c clickhouse -- \
  tar -czf - -C /var/lib/clickhouse/backup "$DB_BACKUP_NAME" \
  | aws s3 cp - "s3://${DR_BACKUP_BUCKET}/${DB_BACKUP_KEY}"

aws s3api head-object --bucket "$DR_BACKUP_BUCKET" --key "$DB_BACKUP_KEY" \
  --query '{Size:ContentLength,Version:VersionId}' --output table
```

Do not delete the local backup or resume writers until the upload has succeeded and the DR object is visible with a non-zero size.

## 4. Back up original SBOM bytes

The `document_store` table stores the exact `s3://bucket/key` or `fs://relative/path` for each original. `ORIGINAL_STORE_S3_PREFIX` only controls where new objects are written; changing it does not rewrite existing references. For S3-backed originals, record every referenced bucket and key at this recovery point. For the common case of a dedicated originals bucket, syncing its configured originals prefix is also sufficient.

Export the S3 references using an authenticated ClickHouse client. Save the output as a protected file named by this snapshot ID:

```sql
SELECT DISTINCT storage_ref
FROM bomhort.document_store FINAL
WHERE storage_backend = 's3' AND startsWith(storage_ref, 's3://')
FORMAT TSVRaw;
```

For the default chart credentials, capture that query output from the ClickHouse pod as follows. If the database uses a password, use your protected `clickhouse-client` config or secret manager rather than putting it in the command line.

```bash
S3_REFS_FILE="/secure-backups/${SNAPSHOT_ID}-s3-refs.tsv"
kubectl exec -n "$NAMESPACE" "$CLICKHOUSE_POD" -c clickhouse -- \
  clickhouse-client --query="SELECT DISTINCT storage_ref FROM bomhort.document_store FINAL WHERE storage_backend = 's3' AND startsWith(storage_ref, 's3://') FORMAT TSVRaw" \
  > "$S3_REFS_FILE"
```

Copy each referenced object to the DR bucket under the same snapshot ID, retaining its original bucket name and key in the DR path. This loop uses one `aws s3 cp` per object; use your provider's equivalent copy command for a non-AWS S3 endpoint.

```bash
while IFS= read -r ref; do
  uri=${ref#s3://}
  source_bucket=${uri%%/*}
  key=${uri#*/}
  test -n "$source_bucket" && test -n "$key"
  aws s3 cp "s3://${source_bucket}/${key}" \
    "s3://${DR_BACKUP_BUCKET}/${SNAPSHOT_ID}/s3/${source_bucket}/${key}"
done < "$S3_REFS_FILE"
```

On restore, copy those objects back to their **original bucket names and keys** before starting the API. If the original bucket name is not available in the recovery environment, stop and plan a tested `document_store.storage_ref` migration; changing the prefix or copying to a differently named bucket does not redirect references.

### Filesystem originals (PVC)

If `originalStore.fs.enabled` is true, use the PVC name from `originalStore.fs.pvcName` (default `bomhort-originals`). Create a temporary pod that mounts that claim and stream an archive directly to the versioned DR bucket. Do this after the API and parsing worker have stopped.

```bash
ORIGINALS_PVC=bomhort-originals
ARCHIVE_POD="${RELEASE}-originals-backup"

cat <<YAML | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${ARCHIVE_POD}
  namespace: ${NAMESPACE}
spec:
  restartPolicy: Never
  securityContext:
    runAsUser: 65534
    runAsGroup: 65534
    fsGroup: 65534
  containers:
    - name: archive
      image: busybox:1.36.1
      command: ["sh", "-c", "sleep 3600"]
      volumeMounts:
        - name: originals
          mountPath: /data/originals
          readOnly: true
  volumes:
    - name: originals
      persistentVolumeClaim:
        claimName: ${ORIGINALS_PVC}
YAML
kubectl wait -n "$NAMESPACE" --for=condition=Ready "pod/${ARCHIVE_POD}" --timeout=5m

kubectl exec -n "$NAMESPACE" "$ARCHIVE_POD" -- \
  tar -czf - -C /data/originals . \
  | aws s3 cp - "s3://${DR_BACKUP_BUCKET}/${FS_BACKUP_KEY}"
aws s3api head-object --bucket "$DR_BACKUP_BUCKET" --key "$FS_BACKUP_KEY" \
  --query '{Size:ContentLength,Version:VersionId}' --output table
kubectl delete pod -n "$NAMESPACE" "$ARCHIVE_POD" --wait=true
```

The archive is complete only after the upload succeeds and `head-object` reports a non-zero size. During recovery, mount the **same PVC** read-write in a temporary pod and stream the matching archive into `/data/originals` before starting application writers. Do not restore `fs://` references onto a new path unless `ORIGINAL_STORE_FS_PATH` points to that restored tree.

If a deployment has both S3 and filesystem history, back up and restore both stores and keep both configured so the gateway can resolve references from either backend.

After the ClickHouse archive and every enabled originals archive have uploaded and passed their size checks, resume writers for normal operation:

```bash
helm upgrade "$RELEASE" deploy/helm/bomhort -n "$NAMESPACE" --reuse-values \
  --set maintenance.writersSuspended=false --wait
```

## 5. Restore a recovery point

Restore into the intended namespace and ClickHouse installation. Keep all application writers stopped until database migrations, original-object restoration, and the download integrity check have passed. Use the exact `SNAPSHOT_ID` and `DB_BACKUP_NAME` recorded with the snapshot; do not calculate a new timestamp during restore. On an existing release, enter maintenance mode before restoring. On a new recovery deployment, install the chart with `maintenance.writersSuspended: true`.

```bash
helm upgrade "$RELEASE" deploy/helm/bomhort -n "$NAMESPACE" --reuse-values \
  --set maintenance.writersSuspended=true \
  --set dataMigration.enabled=false --wait
```

If the target ClickHouse pod was recreated, repeat the temporary `clickhouse-backup` binary and protected config installation from step 3 on the target pod before running the restore command.

First restore the original S3 objects to the same buckets and keys. Use the same reference file saved with the snapshot:

```bash
while IFS= read -r ref; do
  uri=${ref#s3://}
  source_bucket=${uri%%/*}
  key=${uri#*/}
  aws s3 cp "s3://${DR_BACKUP_BUCKET}/${SNAPSHOT_ID}/s3/${source_bucket}/${key}" \
    "s3://${source_bucket}/${key}"
done < "$S3_REFS_FILE"
```

If filesystem originals were enabled, restore the matching archive to the original PVC before restoring the database. The temporary pod below mounts that claim read-write; `ORIGINALS_PVC` must match the recorded Helm value.

```bash
ORIGINALS_PVC=bomhort-originals
RESTORE_POD="${RELEASE}-originals-restore"
cat <<YAML | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${RESTORE_POD}
  namespace: ${NAMESPACE}
spec:
  restartPolicy: Never
  securityContext:
    runAsUser: 65534
    runAsGroup: 65534
    fsGroup: 65534
  containers:
    - name: restore
      image: busybox:1.36.1
      command: ["sh", "-c", "sleep 3600"]
      volumeMounts:
        - name: originals
          mountPath: /data/originals
  volumes:
    - name: originals
      persistentVolumeClaim:
        claimName: ${ORIGINALS_PVC}
YAML
kubectl wait -n "$NAMESPACE" --for=condition=Ready "pod/${RESTORE_POD}" --timeout=5m
aws s3 cp "s3://${DR_BACKUP_BUCKET}/${FS_BACKUP_KEY}" - \
  | kubectl exec -i -n "$NAMESPACE" "$RESTORE_POD" -- \
      tar -xzf - -C /data/originals
kubectl delete pod -n "$NAMESPACE" "$RESTORE_POD" --wait=true
```

The maintenance flag keeps API and worker replicas at zero and both CronJobs suspended throughout the restore.

Fetch the ClickHouse archive from the exact saved object key and extract it into the same local backup path. Then restore the schema and data. `--rm` replaces any empty or partially initialized tables in the target database, so use it only after verifying the target cluster and keeping writers stopped.

```bash
aws s3 cp "s3://${DR_BACKUP_BUCKET}/${DB_BACKUP_KEY}" - \
  | kubectl exec -i -n "$NAMESPACE" "$CLICKHOUSE_POD" -c clickhouse -- \
      tar -xzf - -C /var/lib/clickhouse/backup

kubectl exec -n "$NAMESPACE" "$CLICKHOUSE_POD" -c clickhouse -- \
  /tmp/clickhouse-backup --config=/tmp/clickhouse-backup.yml \
  restore --schema --data --rm "$DB_BACKUP_NAME"
```

### Re-run the chart migrations

The chart names the schema Job `${RELEASE}-migrate-<content-hash>`. A completed Job with the current content hash will not rerun just because the database was restored to an older point. Delete the release's existing migration Job, upgrade the release with the current chart, and wait for the newly created Job to complete:

```bash
kubectl delete job -n "$NAMESPACE" \
  -l "app.kubernetes.io/instance=${RELEASE},app.kubernetes.io/component=migrate" \
  --ignore-not-found --cascade=foreground --wait=true

helm upgrade "$RELEASE" deploy/helm/bomhort -n "$NAMESPACE" --reuse-values \
  --set maintenance.writersSuspended=true --wait

MIGRATION_JOB=$(kubectl get jobs -n "$NAMESPACE" \
  -l "app.kubernetes.io/instance=${RELEASE},app.kubernetes.io/component=migrate" \
  --sort-by=.metadata.creationTimestamp \
  -o custom-columns=NAME:.metadata.name --no-headers | tail -n 1)
test -n "$MIGRATION_JOB"
kubectl wait -n "$NAMESPACE" --for=condition=complete \
  "job/${MIGRATION_JOB}" --timeout=20m
```

Keep `dataMigration.enabled=false` for this recovery release. That hook imports rows from a separate source database; it is not part of restoring this snapshot and must not write into the recovered database. The normal schema migration Job still runs as a chart resource during the upgrade. Re-enable a separately planned data migration only after recovery is complete and its source/target behavior has been reviewed. The restored `data_migrations` table preserves completed backfill markers; schema migration SQL writes any new markers required by the deployed chart.

## 6. Verify the restored original and database

Choose a real SBOM UUID from the restored database. First verify that ClickHouse has an original reference for that UUID and note its stored SHA-256:

```bash
SBOM_ID='00000000-0000-0000-0000-000000000000' # replace with a real UUID
kubectl exec -n "$NAMESPACE" "$CLICKHOUSE_POD" -c clickhouse -- \
  clickhouse-client --query="
    SELECT storage_backend, storage_ref, sha256_hash
    FROM bomhort.document_store FINAL
    WHERE sbom_id = toUUID('${SBOM_ID}')
    FORMAT TSV"
```

Temporarily scale up only the API Gateway, port-forward its service, and query the supported route. Protected deployments need a service token or API key. The `X-BOMHort-Original: true` header confirms the response came from `document_store`; the handler otherwise falls back to the source SBOM and can return HTTP 200 without proving the original store was restored.

```bash
kubectl scale deployment "${RELEASE}-api-gateway" -n "$NAMESPACE" --replicas=1
kubectl port-forward -n "$NAMESPACE" "svc/${RELEASE}-api-gateway" 18080:80 \
  >/tmp/bomhort-port-forward.log 2>&1 &
PORT_FORWARD_PID=$!
trap 'kill "$PORT_FORWARD_PID" 2>/dev/null || true' EXIT

API_URL=http://127.0.0.1:18080
curl -fsS -H "Authorization: Bearer ${BOMHORT_SERVICE_TOKEN}" \
  "$API_URL/readyz"

curl --fail --silent --show-error --compressed \
  -H "Authorization: Bearer ${BOMHORT_SERVICE_TOKEN}" \
  -D /tmp/bomhort-download.headers \
  "$API_URL/api/v1/sboms/${SBOM_ID}/download" \
  -o /tmp/bomhort-restored-original

grep -qi '^X-BOMHort-Original: true' /tmp/bomhort-download.headers
EXPECTED_SHA=$(awk 'BEGIN{IGNORECASE=1} /^X-BOMHort-SHA256:/ {gsub("\\r", "", $2); print $2}' \
  /tmp/bomhort-download.headers)
ACTUAL_SHA=$(sha256sum /tmp/bomhort-restored-original | awk '{print $1}')
test -n "$EXPECTED_SHA" && test "$ACTUAL_SHA" = "$EXPECTED_SHA"
```

Only after the integrity check passes, return the release to its configured replica counts and resume the CronJobs:

```bash
kill "$PORT_FORWARD_PID" 2>/dev/null || true
trap - EXIT
helm upgrade "$RELEASE" deploy/helm/bomhort -n "$NAMESPACE" --reuse-values \
  --set maintenance.writersSuspended=false --wait
```

## Recovery limitations

- A stored S3 reference contains its bucket name and key. The supported recovery path restores those objects to the same bucket identity. A different bucket name needs a separate, tested migration of every affected `document_store.storage_ref`; changing `ORIGINAL_STORE_S3_PREFIX` alone does not work.
- Filesystem references are relative to `ORIGINAL_STORE_FS_PATH`. Restore the PVC contents and mount path together.
- The ClickHouse database backup and document archives must share the same `SNAPSHOT_ID`. Keep the DR bucket versioned and retain each snapshot until a later recovery point has been restored in a drill.
- A recovery drill should use an isolated namespace and restore both storage layers, run the migration Job, and verify `X-BOMHort-Original` plus the returned SHA-256 before the snapshot is considered usable.
