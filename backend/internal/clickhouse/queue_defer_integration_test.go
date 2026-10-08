package clickhouse

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// TestDeferJobRespectsRetryAfter proves the deferral contract against a real
// ClickHouse: a job parked by DeferJob is invisible to ClaimJobs until its
// retry_after has passed, and becomes claimable again afterwards. The claim
// filter is `argMax(retry_after, created_at) <= now()`, which the unit tests
// cannot plan; this test is what guards it.
//
// It writes to ingestion_queue and claims whatever is pending, so run it only
// against a disposable database. Skipped unless CLICKHOUSE_HOST is set.
func TestDeferJobRespectsRetryAfter(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	job := models.IngestionJob{
		JobID:      uuid.New(),
		SourceFile: "integration-test/defer-" + uuid.NewString() + ".spdx.json",
		SHA256Hash: uuid.NewString(),
		Status:     models.JobStatusPending,
		JobType:    "sbom",
	}
	if err := c.EnqueueJobs(ctx, []models.IngestionJob{job}); err != nil {
		t.Fatalf("EnqueueJobs: %v", err)
	}

	claimed := func() bool {
		jobs, err := c.ClaimJobs(ctx, "defer-test", 1000)
		if err != nil {
			t.Fatalf("ClaimJobs: %v", err)
		}
		for _, j := range jobs {
			if j.JobID == job.JobID {
				return true
			}
		}
		return false
	}

	if !claimed() {
		t.Fatal("freshly enqueued job (retry_after = epoch) was not claimable")
	}

	// created_at is a DateTime with second resolution, so two queue rows written
	// within the same second tie in argMax. Production never writes two deferral
	// rows that close together (the retry is an hour away); the test has to wait.
	tick := func() { time.Sleep(1100 * time.Millisecond) }

	tick()
	if err := c.DeferJob(ctx, job, time.Now().Add(time.Hour), "github rate limit"); err != nil {
		t.Fatalf("DeferJob: %v", err)
	}
	if claimed() {
		t.Fatal("deferred job with retry_after one hour ahead was claimed")
	}

	tick()
	if err := c.DeferJob(ctx, job, time.Now().Add(-time.Minute), "github rate limit"); err != nil {
		t.Fatalf("DeferJob (past): %v", err)
	}
	if !claimed() {
		t.Fatal("deferred job whose retry_after has passed was not claimable")
	}

	tick()
	if err := c.CompleteJob(ctx, job); err != nil {
		t.Fatalf("CompleteJob: %v", err)
	}
}
