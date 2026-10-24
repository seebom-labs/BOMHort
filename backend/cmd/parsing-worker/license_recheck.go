package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/rulesource"
	s3client "github.com/seebom-labs/bomhort/backend/internal/s3"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// A granted or revoked license exception has to reach the SBOMs that were
// ingested before it, not only the next ones. The exception decision is
// stored per (SBOM, license) in license_compliance, so instead of re-parsing
// every SBOM, a license_recheck job re-splits the stored package lists with
// the current rules (license.Reevaluate) and rewrites only the rows whose
// outcome changed.
//
// Every worker replica watches the exceptions, so every replica notices a
// change. The queue makes it one recheck: the job id is derived from the
// previous recheck and the new digest, so replicas that see the same change
// enqueue the same job, and the claim collapses it.

// recheckNamespace scopes the deterministic license_recheck job ids.
var recheckNamespace = uuid.MustParse("6f1c1c4e-8a4b-4c55-9d43-1b6c3e0f7a21")

// recheckBatchSize bounds one license_compliance insert of the recheck.
const recheckBatchSize = 10000

// configMapPropagation is how long the kubelet may take to project a
// ConfigMap edit into a pod (sync period plus cache TTL). Replicas see a
// mounted file change up to this far apart.
const configMapPropagation = 90 * time.Second

type recheckStore interface {
	LatestLicenseRecheck(ctx context.Context) (*clickhouse.LicenseRecheckState, error)
	EnqueueJobs(ctx context.Context, jobs []models.IngestionJob) error
	EachLicenseCompliance(ctx context.Context, fn func(clickhouse.StoredLicenseCompliance) error) error
	InsertLicenseCompliance(ctx context.Context, items []models.LicenseCompliance) error
}

// recheckDelay is how long a recheck waits before it may be claimed. Every
// replica has to be on the new rules by then, or an SBOM ingested in between
// by a replica still on the old rules would keep the old outcome: the recheck
// would already have run. Replicas poll every interval, and a ConfigMap
// reaches them up to configMapPropagation apart.
func recheckDelay(interval time.Duration, remote bool) time.Duration {
	d := 2 * interval
	if !remote {
		d += configMapPropagation
	}
	return d
}

// recheckStaleAfter is how long a recheck may stay 'processing' before it is
// presumed dead (its worker was killed mid-run) and queued again. Running a
// recheck twice is harmless: it is idempotent.
const recheckStaleAfter = time.Hour

// staleClaimAfter is how long any claimed job may stay 'processing' before a
// worker sweep hands it back to the queue (see RequeueStaleJobs). Large
// SBOMs with full OSV hydration finish in minutes; an hour is a dead worker.
const staleClaimAfter = time.Hour

// ensureLicenseRecheck enqueues a recheck unless the latest one already
// covers digest. A recheck for the same digest that failed, or whose worker
// died while processing it, is queued again. Workers call it on every poll,
// not only when they see a change, so neither a failed enqueue nor a failed
// recheck is lost while the pods keep running.
func ensureLicenseRecheck(ctx context.Context, store recheckStore, digest string, delay time.Duration, now time.Time) error {
	latest, err := store.LatestLicenseRecheck(ctx)
	if err != nil {
		return err
	}
	prev := ""
	if latest != nil {
		if latest.Digest == digest && !recheckNeedsRetry(latest, now) {
			return nil
		}
		prev = latest.JobID.String()
	}
	job := models.IngestionJob{
		CreatedAt:  now,
		JobID:      uuid.NewSHA1(recheckNamespace, []byte(prev+"|"+digest)),
		SourceFile: "license-exceptions@" + shortDigest(digest),
		SHA256Hash: digest,
		JobType:    models.JobTypeLicenseRecheck,
		RetryAfter: now.Add(delay),
	}
	if err := store.EnqueueJobs(ctx, []models.IngestionJob{job}); err != nil {
		return fmt.Errorf("enqueue license recheck: %w", err)
	}
	log.Printf("License exceptions changed (%s): recheck of stored results queued, runs after %s",
		shortDigest(digest), job.RetryAfter.Format(time.RFC3339))
	return nil
}

func recheckNeedsRetry(st *clickhouse.LicenseRecheckState, now time.Time) bool {
	switch st.Status {
	case models.JobStatusFailed:
		return true
	case models.JobStatusProcessing:
		return now.Sub(st.UpdatedAt) > recheckStaleAfter
	}
	return false
}

// runLicenseRecheckJob runs a claimed recheck, but only against the rules it
// was queued for. A worker that has not picked up those rules yet (a slow
// ConfigMap sync, a failing remote fetch) would otherwise re-apply its old
// rules, find nothing to change and mark the job done — and the change
// would never reach the stored results. Such a worker defers the job; a job
// that a newer one has superseded completes without work, the newer one
// covers it.
func runLicenseRecheckJob(ctx context.Context, store recheckStore, job models.IngestionJob, rules rulesource.Snapshot[*license.ExceptionIndex], retry time.Duration) error {
	if rules.Digest != job.SHA256Hash {
		latest, err := store.LatestLicenseRecheck(ctx)
		if err != nil {
			return err
		}
		if latest != nil && latest.JobID != job.JobID {
			log.Printf("License recheck %s superseded by %s, skipping", shortDigest(job.SHA256Hash), shortDigest(latest.Digest))
			return nil
		}
		return &deferError{
			until: time.Now().Add(retry),
			cause: fmt.Errorf("license recheck for %s, but this worker has %s loaded", shortDigest(job.SHA256Hash), shortDigest(rules.Digest)),
		}
	}
	if err := processLicenseRecheckJob(ctx, store, rules.Value); err != nil {
		if ctx.Err() != nil {
			// Interrupted by shutdown: run it again rather than fail it.
			return &deferError{until: time.Now(), cause: err}
		}
		return err
	}
	return nil
}

// recheckPollInterval is how often a worker re-asserts that the stored
// results match its rules. With reloading disabled it still runs, so a
// failed recheck is retried.
func recheckPollInterval(refresh time.Duration) time.Duration {
	if refresh <= 0 {
		return time.Minute
	}
	return refresh
}

func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// processLicenseRecheckJob re-applies exceptions to every stored compliance
// row and rewrites the changed ones. license_compliance is a
// ReplacingMergeTree on (sbom_id, license_id), so the new row replaces the
// old one.
func processLicenseRecheckJob(ctx context.Context, store recheckStore, exceptions *license.ExceptionIndex) error {
	now := time.Now()
	var checked int
	var changed []models.LicenseCompliance
	err := store.EachLicenseCompliance(ctx, func(row clickhouse.StoredLicenseCompliance) error {
		checked++
		stored := license.Result{
			LicenseID:            row.LicenseID,
			Category:             license.Category(row.Category),
			PackageCount:         row.PackageCount,
			NonCompliantPackages: row.NonCompliantPackages,
			ExemptedPackages:     row.ExemptedPackages,
			ExemptionReason:      row.ExemptionReason,
		}
		next := license.Reevaluate(stored, exceptions, row.DocumentName)
		if license.SameOutcome(stored, next) {
			return nil
		}
		m := row.LicenseCompliance
		m.CheckedAt = now
		m.NonCompliantPackages = nonNil(next.NonCompliantPackages)
		m.ExemptedPackages = nonNil(next.ExemptedPackages)
		m.ExemptionReason = next.ExemptionReason
		changed = append(changed, m)
		return nil
	})
	if err != nil {
		return err
	}
	for start := 0; start < len(changed); start += recheckBatchSize {
		end := min(start+recheckBatchSize, len(changed))
		if err := store.InsertLicenseCompliance(ctx, changed[start:end]); err != nil {
			return err
		}
	}
	log.Printf("License recheck: %d stored results checked, %d updated", checked, len(changed))
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// objectGetter avoids handing rulesource a typed nil: a nil *s3client.Client
// in an interface is not a nil interface.
func objectGetter(c *s3client.Client) rulesource.ObjectGetter {
	if c == nil {
		return nil
	}
	return c
}

func logExceptions(s rulesource.Snapshot[*license.ExceptionIndex]) {
	if !s.Present || s.Value == nil {
		log.Printf("No license exceptions loaded (%s)", s.Source)
		return
	}
	log.Printf("Loaded license exceptions from %s (%d blanket, %d specific, %s)",
		s.Source, len(s.Value.Raw.BlanketExceptions), len(s.Value.Raw.Exceptions), shortDigest(s.Digest))
}
