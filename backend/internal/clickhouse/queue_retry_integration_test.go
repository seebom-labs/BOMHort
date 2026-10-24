package clickhouse

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// TestFailedJobHashIsForgotten proves the retry contract (#482/#487): a job's
// hash counts as known while it is pending/processing/done and stops counting
// once its latest status is 'failed', for both the per-hash check and the
// bulk set the watcher uses. The queue is append-only with status in ORDER
// BY, so a naive `WHERE status != 'failed'` would still see the older rows;
// only a real ClickHouse can show the argMax form gets this right.
//
// Writes to ingestion_queue; run only against a disposable database.
// Skipped unless CLICKHOUSE_HOST is set.
func TestFailedJobHashIsForgotten(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	job := models.IngestionJob{
		JobID:      uuid.New(),
		SourceFile: "integration-test/retry-" + uuid.NewString() + ".spdx.json",
		SHA256Hash: uuid.NewString(),
		Status:     models.JobStatusPending,
		JobType:    "sbom",
		// Keep it out of other tests' ClaimJobs.
		RetryAfter: time.Now().Add(24 * time.Hour),
	}
	if err := c.EnqueueJobs(ctx, []models.IngestionJob{job}); err != nil {
		t.Fatalf("EnqueueJobs: %v", err)
	}

	known := func() bool {
		exists, err := c.HashExists(ctx, job.SHA256Hash)
		if err != nil {
			t.Fatalf("HashExists: %v", err)
		}
		set, err := c.KnownHashes(ctx)
		if err != nil {
			t.Fatalf("KnownHashes: %v", err)
		}
		_, inSet := set[job.SHA256Hash]
		if exists != inSet {
			t.Fatalf("HashExists=%v but KnownHashes contains=%v — the two readers disagree", exists, inSet)
		}
		return exists
	}

	if !known() {
		t.Fatal("pending job: hash should be known")
	}
	if err := c.FailJob(ctx, job, "boom"); err != nil {
		t.Fatalf("FailJob: %v", err)
	}
	if known() {
		t.Fatal("failed job: hash must be forgotten so the watcher re-enqueues the file")
	}
}

// TestRequeueStaleJobs proves a job stuck in 'processing' past the timeout is
// handed back to the queue and claimable again, while a fresh claim is not.
func TestRequeueStaleJobs(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mk := func(claimedAgo time.Duration) models.IngestionJob {
		claimed := time.Now().Add(-claimedAgo)
		j := models.IngestionJob{
			JobID:      uuid.New(),
			SourceFile: "integration-test/stale-" + uuid.NewString() + ".spdx.json",
			SHA256Hash: uuid.NewString(),
			Status:     models.JobStatusProcessing,
			JobType:    "sbom",
			ClaimedBy:  "dead-worker",
			ClaimedAt:  &claimed,
		}
		// EnqueueJobs always writes 'pending'; a dead worker's claim row is
		// what ClaimJobs would have written, so write it the same way.
		if err := c.Conn.Exec(ctx, `INSERT INTO ingestion_queue (`+queueColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			claimed, j.JobID, j.SourceFile, j.SHA256Hash, j.Status, j.JobType, j.ClaimedBy, j.ClaimedAt, (*time.Time)(nil), "",
			"", "", "", "", "", "", []string{}, "", time.Time{}); err != nil {
			t.Fatalf("insert claim: %v", err)
		}
		return j
	}
	stale, fresh := mk(3*time.Hour), mk(time.Minute)

	n, err := c.RequeueStaleJobs(ctx, time.Hour)
	if err != nil {
		t.Fatalf("RequeueStaleJobs: %v", err)
	}
	if n < 1 {
		t.Fatalf("requeued %d jobs, want at least the stale one", n)
	}

	jobs, err := c.ClaimJobs(ctx, "stale-test", 10000)
	if err != nil {
		t.Fatalf("ClaimJobs: %v", err)
	}
	gotStale, gotFresh := false, false
	for _, j := range jobs {
		gotStale = gotStale || j.JobID == stale.JobID
		gotFresh = gotFresh || j.JobID == fresh.JobID
	}
	if !gotStale {
		t.Error("stale job was not claimable after the sweep")
	}
	if gotFresh {
		t.Error("fresh processing job was requeued; it is still being worked on")
	}
}
