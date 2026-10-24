package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// queueColumns is the full ingestion_queue column list, shared by every write
// path below. The queue is append-only (status transitions are new rows, not
// updates), so all five writers must agree on the column set exactly —
// keeping it in one place is what stops a newly added dimension from being
// silently dropped on claim/complete/fail and resurfacing as empty data.
const queueColumns = "created_at, job_id, source_file, sha256_hash, status, job_type, claimed_by, claimed_at, finished_at, error_message, cluster, namespace, project, source_repo, source_ref, target_sbom_id, tags, parent, retry_after"

// EnqueueJobs inserts a batch of new ingestion jobs with status 'pending'.
func (c *Client) EnqueueJobs(ctx context.Context, jobs []models.IngestionJob) error {
	if len(jobs) == 0 {
		return nil
	}

	batch, err := c.Conn.PrepareBatch(ctx, "INSERT INTO ingestion_queue ("+queueColumns+")")
	if err != nil {
		return fmt.Errorf("failed to prepare queue batch: %w", err)
	}

	for _, job := range jobs {
		jobType := job.JobType
		if jobType == "" {
			jobType = models.JobTypeSBOM
		}
		if err := batch.Append(
			job.CreatedAt,
			job.JobID,
			job.SourceFile,
			job.SHA256Hash,
			models.JobStatusPending,
			jobType,
			"",
			(*time.Time)(nil),
			(*time.Time)(nil),
			"",
			job.Cluster,
			job.Namespace,
			job.Project,
			job.SourceRepo,
			job.SourceRef,
			job.TargetSBOMID,
			job.Tags,
			job.Parent,
			job.RetryAfter,
		); err != nil {
			return fmt.Errorf("failed to append queue job: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("failed to send queue batch: %w", err)
	}

	return nil
}

// latestJobs reduces the append-only queue to one row per job carrying the
// latest value of every column. Every reader that asks "what state is this
// job in" must go through it: the table is ORDER BY (status, created_at,
// job_id), so FINAL never collapses a job's older status rows and a plain
// WHERE status = … matches history, not state.
// where optionally prefilters the rows before aggregation.
func latestJobs(where string) string {
	return `
		    SELECT
		        job_id,
		        argMax(source_file, created_at)  AS source_file,
		        argMax(sha256_hash, created_at)  AS sha256_hash,
		        min(created_at)                  AS min_created,
		        argMax(job_type, created_at)      AS job_type,
		        argMax(status, created_at)        AS latest_status,
		        argMax(claimed_at, created_at)    AS claimed_at,
		        argMax(cluster, created_at)       AS cluster,
		        argMax(namespace, created_at)     AS namespace,
		        argMax(project, created_at)       AS project,
		        argMax(source_repo, created_at)   AS source_repo,
		        argMax(source_ref, created_at)    AS source_ref,
		        argMax(target_sbom_id, created_at) AS target_sbom_id,
		        argMax(tags, created_at)          AS tags,
		        argMax(parent, created_at)        AS parent,
		        argMax(retry_after, created_at)   AS retry_after
		    FROM ingestion_queue ` + where + `
		    GROUP BY job_id`
}

// selectJobs returns the jobs whose latest state matches where, oldest first.
func (c *Client) selectJobs(ctx context.Context, where string, limit int) ([]models.IngestionJob, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT job_id, source_file, sha256_hash, min_created, job_type, cluster, namespace, project, source_repo, source_ref, target_sbom_id, tags, parent
		FROM (`+latestJobs("")+`) sub
		WHERE `+where+`
		ORDER BY min_created ASC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query jobs: %w", err)
	}
	defer rows.Close()

	var jobs []models.IngestionJob
	for rows.Next() {
		var job models.IngestionJob
		if err := rows.Scan(&job.JobID, &job.SourceFile, &job.SHA256Hash, &job.CreatedAt, &job.JobType, &job.Cluster, &job.Namespace, &job.Project, &job.SourceRepo, &job.SourceRef, &job.TargetSBOMID, &job.Tags, &job.Parent); err != nil {
			return nil, fmt.Errorf("failed to scan job row: %w", err)
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

// ClaimJobs selects up to `limit` pending jobs and marks them as processing.
// Uses argMax aggregation to reliably determine the latest status per job,
// regardless of merge timing. This avoids phantom re-claims entirely.
func (c *Client) ClaimJobs(ctx context.Context, workerID string, limit int) ([]models.IngestionJob, error) {
	jobs, err := c.selectJobs(ctx, "latest_status = 'pending' AND retry_after <= now()", limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending jobs: %w", err)
	}
	now := time.Now()
	for i := range jobs {
		jobs[i].Status = models.JobStatusProcessing
		jobs[i].ClaimedBy = workerID
		jobs[i].ClaimedAt = &now
	}

	if len(jobs) == 0 {
		return nil, nil
	}

	// Mark claimed jobs as processing.
	batch, err := c.Conn.PrepareBatch(ctx, "INSERT INTO ingestion_queue ("+queueColumns+")")
	if err != nil {
		return nil, fmt.Errorf("failed to prepare claim batch: %w", err)
	}

	for _, job := range jobs {
		if err := batch.Append(
			now,
			job.JobID,
			job.SourceFile,
			job.SHA256Hash,
			models.JobStatusProcessing,
			job.JobType,
			workerID,
			job.ClaimedAt,
			(*time.Time)(nil),
			"",
			job.Cluster,
			job.Namespace,
			job.Project,
			job.SourceRepo,
			job.SourceRef,
			job.TargetSBOMID,
			job.Tags,
			job.Parent,
			time.Time{},
		); err != nil {
			return nil, fmt.Errorf("failed to append claim: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		return nil, fmt.Errorf("failed to send claim batch: %w", err)
	}

	return jobs, nil
}

// CompleteJob marks a job as done.
func (c *Client) CompleteJob(ctx context.Context, job models.IngestionJob) error {
	now := time.Now()
	return c.Conn.Exec(ctx,
		`INSERT INTO ingestion_queue (`+queueColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		now, job.JobID, job.SourceFile, job.SHA256Hash, models.JobStatusDone, job.JobType, job.ClaimedBy, job.ClaimedAt, &now, "", job.Cluster, job.Namespace, job.Project, job.SourceRepo, job.SourceRef, job.TargetSBOMID, job.Tags, job.Parent, time.Time{})
}

// FailJob marks a job as failed with an error message.
func (c *Client) FailJob(ctx context.Context, job models.IngestionJob, errMsg string) error {
	now := time.Now()
	return c.Conn.Exec(ctx,
		`INSERT INTO ingestion_queue (`+queueColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		now, job.JobID, job.SourceFile, job.SHA256Hash, models.JobStatusFailed, job.JobType, job.ClaimedBy, job.ClaimedAt, &now, errMsg, job.Cluster, job.Namespace, job.Project, job.SourceRepo, job.SourceRef, job.TargetSBOMID, job.Tags, job.Parent, time.Time{})
}

// DeferJob puts a claimed job back to 'pending' so that ClaimJobs picks it up
// again once retryAfter has passed. Nothing about the job's result is
// recorded: a deferred job ran into a condition that will clear by itself
// (an upstream rate limit) and must run again from the start rather than
// finish with whatever a worse source would say. reason is kept in
// error_message for operators watching the queue.
func (c *Client) DeferJob(ctx context.Context, job models.IngestionJob, retryAfter time.Time, reason string) error {
	return c.Conn.Exec(ctx,
		`INSERT INTO ingestion_queue (`+queueColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now(), job.JobID, job.SourceFile, job.SHA256Hash, models.JobStatusPending, job.JobType, "", (*time.Time)(nil), (*time.Time)(nil), reason, job.Cluster, job.Namespace, job.Project, job.SourceRepo, job.SourceRef, job.TargetSBOMID, job.Tags, job.Parent, retryAfter)
}

// RequeueStaleJobs puts jobs back to 'pending' that have been 'processing'
// for longer than olderThan. A worker that was OOM-killed or lost its node
// never writes a final status, and without this its claims would stay
// 'processing' forever. Returns how many jobs were requeued.
func (c *Client) RequeueStaleJobs(ctx context.Context, olderThan time.Duration) (int, error) {
	stale, err := c.selectJobs(ctx, fmt.Sprintf("latest_status = 'processing' AND claimed_at < now() - INTERVAL %d SECOND", int(olderThan.Seconds())), 10000)
	if err != nil {
		return 0, fmt.Errorf("failed to query stale jobs: %w", err)
	}
	for _, job := range stale {
		if err := c.DeferJob(ctx, job, time.Now(), fmt.Sprintf("requeued: processing for more than %s", olderThan)); err != nil {
			return 0, err
		}
	}
	return len(stale), nil
}

// KnownHashes returns every content hash the queue has a non-failed job for,
// judged on each job's latest status. The watcher checks a whole scan against
// this set in memory instead of asking once per file (#487); a failed job's
// hash is absent, so the next scan enqueues the file again (#482).
func (c *Client) KnownHashes(ctx context.Context) (map[string]struct{}, error) {
	// toString strips the NUL padding of FixedString(64): S3 ETags are 32
	// chars and would otherwise never match a Go string.
	rows, err := c.Conn.Query(ctx, "SELECT DISTINCT toString(sha256_hash) FROM ("+latestJobs("")+") WHERE latest_status != 'failed'")
	if err != nil {
		return nil, fmt.Errorf("failed to load known hashes: %w", err)
	}
	defer rows.Close()
	known := make(map[string]struct{})
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("failed to scan hash: %w", err)
		}
		known[h] = struct{}{}
	}
	return known, rows.Err()
}
