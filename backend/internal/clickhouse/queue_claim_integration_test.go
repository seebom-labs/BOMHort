package clickhouse

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/claimlock"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// TestConcurrentClaimJobs returns each pending job to only one caller.
// Skipped unless CLICKHOUSE_HOST is set.
func TestConcurrentClaimJobs(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	job := models.IngestionJob{
		CreatedAt:  time.Now(),
		JobID:      uuid.New(),
		SourceFile: "integration-test/concurrent-claim-" + uuid.NewString() + ".spdx.json",
		SHA256Hash: uuid.NewString(),
		JobType:    "sbom",
	}
	if err := c.EnqueueJobs(ctx, []models.IngestionJob{job}); err != nil {
		t.Fatalf("EnqueueJobs: %v", err)
	}

	locker := claimlock.Local()
	start := make(chan struct{})
	type result struct {
		jobs []models.IngestionJob
		err  error
	}
	results := make(chan result, 2)
	for _, worker := range []string{"claim-a", "claim-b"} {
		go func(worker string) {
			<-start
			jobs, err := c.ClaimJobs(ctx, worker, 10000, locker)
			results <- result{jobs: jobs, err: err}
		}(worker)
	}
	close(start)

	claims := 0
	for range 2 {
		got := <-results
		if got.err != nil {
			t.Fatalf("ClaimJobs: %v", got.err)
		}
		for _, claimed := range got.jobs {
			if claimed.JobID == job.JobID {
				claims++
			}
		}
	}
	if claims != 1 {
		t.Fatalf("concurrent ClaimJobs returned target job %d times, want once", claims)
	}
}

// TestOwnClaimedJobIDsIgnoresSupersededClaim proves a worker does not process a
// job when another worker's newer claim row is the latest queue state.
// Skipped unless CLICKHOUSE_HOST is set.
func TestOwnClaimedJobIDsIgnoresSupersededClaim(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	jobID := uuid.New()
	now := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	insert := func(createdAt time.Time, worker string) {
		t.Helper()
		if err := c.Conn.Exec(ctx, `INSERT INTO ingestion_queue (`+queueColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			createdAt, jobID, "integration-test/claim.spdx.json", uuid.NewString(),
			"processing", "sbom", worker, &createdAt, (*time.Time)(nil), "",
			"", "", "", "", "", "", []string{}, "", "", "", "", time.Time{}); err != nil {
			t.Fatalf("insert claim for %s: %v", worker, err)
		}
	}
	insert(now, "worker-a")
	insert(now.Add(time.Millisecond), "worker-b")

	jobIDs := []uuid.UUID{jobID}
	for _, tc := range []struct {
		worker string
		want   bool
	}{{"worker-a", false}, {"worker-b", true}} {
		owned, err := c.ownClaimedJobIDs(ctx, jobIDs, tc.worker)
		if err != nil {
			t.Fatalf("ownClaimedJobIDs(%q): %v", tc.worker, err)
		}
		_, got := owned[jobID]
		if got != tc.want {
			t.Errorf("worker %q owns job = %v, want %v", tc.worker, got, tc.want)
		}
	}
}

// TestTransitionsOutrankPreviousRow proves claim and completion stay ordered
// when the enqueuing host's clock is ahead and transitions land in the same
// millisecond. Skipped unless CLICKHOUSE_HOST is set.
func TestTransitionsOutrankPreviousRow(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	job := models.IngestionJob{
		CreatedAt:  time.Now().Add(5 * time.Second),
		JobID:      uuid.New(),
		SourceFile: "integration-test/skew-" + uuid.NewString() + ".spdx.json",
		SHA256Hash: uuid.NewString(),
		JobType:    "sbom",
	}
	if err := c.EnqueueJobs(ctx, []models.IngestionJob{job}); err != nil {
		t.Fatalf("EnqueueJobs: %v", err)
	}
	claimed, err := c.ClaimJobs(ctx, "skew-worker", 10000, claimlock.Local())
	if err != nil {
		t.Fatalf("ClaimJobs: %v", err)
	}
	var mine *models.IngestionJob
	for i := range claimed {
		if claimed[i].JobID == job.JobID {
			mine = &claimed[i]
		}
	}
	if mine == nil {
		t.Fatal("claim of a future-dated pending row did not become the latest state")
	}
	if err := c.CompleteJob(ctx, *mine); err != nil {
		t.Fatalf("CompleteJob: %v", err)
	}
	var status string
	if err := c.Conn.QueryRow(ctx,
		"SELECT argMax(status, created_at) FROM ingestion_queue WHERE job_id = ?", job.JobID).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != models.JobStatusDone {
		t.Fatalf("latest status = %q, want %q", status, models.JobStatusDone)
	}
}

// TestClaimJobsReleasesOwnAbandonedClaims proves a worker's leftover
// 'processing' rows (discarded lock result, crash) are requeued on its next
// claim instead of waiting for RequeueStaleJobs. Skipped unless CLICKHOUSE_HOST is set.
func TestClaimJobsReleasesOwnAbandonedClaims(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	worker := "abandon-" + uuid.NewString()
	job := models.IngestionJob{
		CreatedAt:  time.Now(),
		JobID:      uuid.New(),
		SourceFile: "integration-test/abandoned-" + uuid.NewString() + ".spdx.json",
		SHA256Hash: uuid.NewString(),
		JobType:    "sbom",
	}
	if err := c.EnqueueJobs(ctx, []models.IngestionJob{job}); err != nil {
		t.Fatalf("EnqueueJobs: %v", err)
	}
	if _, err := c.claimJobs(ctx, worker, 10000); err != nil {
		t.Fatalf("claimJobs: %v", err)
	}

	// The worker's next claim (holding nothing) gets its own abandoned job back.
	claimed, err := c.ClaimJobs(ctx, worker, 10000, claimlock.Local())
	if err != nil {
		t.Fatalf("ClaimJobs: %v", err)
	}
	for _, got := range claimed {
		if got.JobID == job.JobID {
			return
		}
	}
	t.Fatal("abandoned processing job was not released and reclaimed")
}
