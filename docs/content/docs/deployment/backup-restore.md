---
title: "Backup and Disaster Recovery"
description: "End-to-end backup and disaster recovery procedures for BOMHort's ClickHouse database and Tier-2 document store."
lead: "How to safely back up and restore BOMHort's parsed analytics data, migration state, and original SBOM documents."
date: 2026-11-16T00:00:00+00:00
lastmod: 2026-11-16T00:00:00+00:00
draft: false
images: []
menu:
  docs:
    parent: "deployment"
weight: 85
toc: true
---

BOMHort manages state across two storage layers:
1. **ClickHouse**: Houses analytical tables, parsed package graphs, relationships, vulnerability matches, license compliance records, and schema migration tracking (`schema_migrations`, `data_migrations`).
2. **Document Store (Tier-2 Originals)**: Houses original, unparsed SBOM and VEX files in either an S3 bucket or a persistent filesystem volume (PVC).

A complete disaster recovery plan requires consistent backups of **both** data stores to prevent broken references between ingested metadata and original documents.

---

## 1. Backing Up ClickHouse

BOMHort deploys ClickHouse via the Altinity ClickHouse Operator. Production deployments should use [`clickhouse-backup`](https://github.com/Altinity/clickhouse-backup) to create point-in-time snapshots and upload them to remote object storage.

### Manual Backup with `clickhouse-backup`

To trigger an ad-hoc full backup of the `bomhort` database:

```bash
# Exec into the ClickHouse pod
kubectl exec -it chi-bomhort-clickhouse-bomhort-cluster-0-0-0 -n bomhort -c clickhouse -- \
  clickhouse-backup create bomhort-backup-$(date +%Y%m%d%H%M%S)

# Upload the snapshot to remote S3 / Cloud Storage
kubectl exec -it chi-bomhort-clickhouse-bomhort-cluster-0-0-0 -n bomhort -c clickhouse -- \
  clickhouse-backup upload bomhort-backup-$(date +%Y%m%d%H%M%S)
```

### Native ClickHouse Freeze (Alternative)

If `clickhouse-backup` is not configured, freeze tables using SQL:

```sql
-- Creates hardlinks in /var/lib/clickhouse/shadow/<backup_name>/
ALTER TABLE bomhort.sboms FREEZE WITH NAME 'manual_backup_2026';
ALTER TABLE bomhort.sbom_packages FREEZE WITH NAME 'manual_backup_2026';
ALTER TABLE bomhort.ingestion_queue FREEZE WITH NAME 'manual_backup_2026';
ALTER TABLE bomhort.schema_migrations FREEZE WITH NAME 'manual_backup_2026';
ALTER TABLE bomhort.data_migrations FREEZE WITH NAME 'manual_backup_2026';
```

Back up the resulting shadow directory to off-cluster storage.

---

## 2. Backing Up the Document Store (Originals)

Depending on `originalStore.backend` configured in your Helm values:

### S3 / Cloud Storage
When using `originalStore.backend: "s3"`, configure S3 Bucket Versioning and replication rules on the originals bucket. Periodic cross-region replication or daily snapshot sync is recommended:

```bash
aws s3 sync s3://my-bomhort-originals/_bomhort/originals/ s3://my-bomhort-dr-backup/_bomhort/originals/ --delete
```

### Filesystem (PVC)
When using `originalStore.backend: "fs"` (PVC mounted on `/data/originals`), take a storage snapshot using CSI volume snapshots or create a tarball archive during non-peak ingestion hours:

```bash
kubectl exec -n bomhort deployment/bomhort-api-gateway -- \
  tar -czf /tmp/originals-backup.tar.gz -C /data/originals .
```

---

## 3. End-to-End Recovery Runbook

When recovering from data loss or restoring into a staging/disaster recovery cluster:

### Step 1: Pause Ingestion Writers
Before restoring data, stop or scale down ingestion workers and the ingestion watcher so concurrent jobs do not conflict with restored tables:

```bash
kubectl scale deployment -n bomhort bomhort-parsing-worker --replicas=0
kubectl scale cronjob -n bomhort bomhort-ingestion-watcher --suspend=true
```

### Step 2: Restore ClickHouse Tables
Download and restore the backup using `clickhouse-backup`:

```bash
# Download backup from remote store
kubectl exec -it chi-bomhort-clickhouse-bomhort-cluster-0-0-0 -n bomhort -c clickhouse -- \
  clickhouse-backup download <backup_name>

# Restore schema and data
kubectl exec -it chi-bomhort-clickhouse-bomhort-cluster-0-0-0 -n bomhort -c clickhouse -- \
  clickhouse-backup restore --schema --data <backup_name>
```

### Step 3: Restore Original Documents
Sync or unpack the original documents into the designated S3 bucket or PVC. Ensure permissions and path prefixes match `ORIGINAL_STORE_S3_PREFIX` (default: `_bomhort/originals/`).

### Step 4: Validate Migration State
After ClickHouse data is restored from an older snapshot, re-run migration jobs to apply any migrations that were deployed after the backup snapshot was taken:

```bash
kubectl delete job -n bomhort bomhort-migrate --ignore-not-found
helm upgrade bomhort deploy/helm/bomhort --reuse-values -n bomhort
```

### Step 5: Resume Processing & Health Check
1. Resume the parsing worker and watcher:
   ```bash
   kubectl scale deployment -n bomhort bomhort-parsing-worker --replicas=2
   kubectl scale cronjob -n bomhort bomhort-ingestion-watcher --suspend=false
   ```
2. Verify system health via the API gateway:
   ```bash
   curl -fsS http://bomhort-api-gateway.bomhort.svc/readyz
   curl -fsS http://bomhort-api-gateway.bomhort.svc/api/v1/stats/dashboard
   ```
3. Test downloading an original SBOM from the restored repository:
   ```bash
   curl -fsS http://bomhort-api-gateway.bomhort.svc/api/v1/sboms/<sample_sbom_id>/download/original -o /dev/null
   ```
