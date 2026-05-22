package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/seebom-labs/seebom/backend/pkg/models"
)

// EnqueueJobs inserts a batch of new ingestion jobs with status 'pending'.
func (c *Client) EnqueueJobs(ctx context.Context, jobs []models.IngestionJob) error {
	if len(jobs) == 0 {
		return nil
	}

	batch, err := c.Conn.PrepareBatch(ctx,
		"INSERT INTO ingestion_queue (created_at, job_id, source_file, sha256_hash, status, job_type, claimed_by, claimed_at, finished_at, error_message, cluster)")
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
		); err != nil {
			return fmt.Errorf("failed to append queue job: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("failed to send queue batch: %w", err)
	}

	return nil
}

// ClaimJobs selects up to `limit` pending jobs and marks them as processing.
// Uses argMax aggregation to reliably determine the latest status per job,
// regardless of merge timing. This avoids phantom re-claims entirely.
func (c *Client) ClaimJobs(ctx context.Context, workerID string, limit int) ([]models.IngestionJob, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT job_id, source_file, sha256_hash, min_created, job_type, cluster
		FROM (
		    SELECT
		        job_id,
		        argMax(source_file, created_at)  AS source_file,
		        argMax(sha256_hash, created_at)  AS sha256_hash,
		        min(created_at)                  AS min_created,
		        argMax(job_type, created_at)      AS job_type,
		        argMax(status, created_at)        AS latest_status,
		        argMax(cluster, created_at)       AS cluster
		    FROM ingestion_queue
		    GROUP BY job_id
		) sub
		WHERE latest_status = 'pending'
		ORDER BY min_created ASC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending jobs: %w", err)
	}
	defer rows.Close()

	var jobs []models.IngestionJob
	for rows.Next() {
		var job models.IngestionJob
		if err := rows.Scan(&job.JobID, &job.SourceFile, &job.SHA256Hash, &job.CreatedAt, &job.JobType, &job.Cluster); err != nil {
			return nil, fmt.Errorf("failed to scan job row: %w", err)
		}
		job.Status = models.JobStatusProcessing
		job.ClaimedBy = workerID
		now := time.Now()
		job.ClaimedAt = &now
		jobs = append(jobs, job)
	}

	if len(jobs) == 0 {
		return nil, nil
	}

	// Mark claimed jobs as processing.
	batch, err := c.Conn.PrepareBatch(ctx,
		"INSERT INTO ingestion_queue (created_at, job_id, source_file, sha256_hash, status, job_type, claimed_by, claimed_at, finished_at, error_message, cluster)")
	if err != nil {
		return nil, fmt.Errorf("failed to prepare claim batch: %w", err)
	}

	for _, job := range jobs {
		if err := batch.Append(
			time.Now(),
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
		`INSERT INTO ingestion_queue (created_at, job_id, source_file, sha256_hash, status, job_type, claimed_by, claimed_at, finished_at, error_message, cluster)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		now, job.JobID, job.SourceFile, job.SHA256Hash, models.JobStatusDone, job.JobType, job.ClaimedBy, job.ClaimedAt, &now, "", job.Cluster)
}

// FailJob marks a job as failed with an error message.
func (c *Client) FailJob(ctx context.Context, job models.IngestionJob, errMsg string) error {
	now := time.Now()
	return c.Conn.Exec(ctx,
		`INSERT INTO ingestion_queue (created_at, job_id, source_file, sha256_hash, status, job_type, claimed_by, claimed_at, finished_at, error_message, cluster)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		now, job.JobID, job.SourceFile, job.SHA256Hash, models.JobStatusFailed, job.JobType, job.ClaimedBy, job.ClaimedAt, &now, errMsg, job.Cluster)
}
