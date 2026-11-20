package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/rulesource"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

type fakeRecheckStore struct {
	latest   *clickhouse.LicenseRecheckState
	enqueued []models.IngestionJob
	rows     []clickhouse.StoredLicenseCompliance
	inserts  [][]models.LicenseCompliance
	eachErr  error
}

func (f *fakeRecheckStore) LatestLicenseRecheck(context.Context) (*clickhouse.LicenseRecheckState, error) {
	return f.latest, nil
}

func (f *fakeRecheckStore) EnqueueJobs(_ context.Context, jobs []models.IngestionJob) error {
	f.enqueued = append(f.enqueued, jobs...)
	return nil
}

func (f *fakeRecheckStore) EachLicenseCompliance(_ context.Context, fn func(clickhouse.StoredLicenseCompliance) error) error {
	if f.eachErr != nil {
		return f.eachErr
	}
	for _, r := range f.rows {
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeRecheckStore) InsertLicenseCompliance(_ context.Context, items []models.LicenseCompliance) error {
	f.inserts = append(f.inserts, append([]models.LicenseCompliance(nil), items...))
	return nil
}

func TestEnsureLicenseRecheck(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	prevID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	t.Run("first run enqueues a delayed job", func(t *testing.T) {
		store := &fakeRecheckStore{}
		if err := ensureLicenseRecheck(ctx, store, "abc123abc123abc123", time.Minute, now); err != nil {
			t.Fatal(err)
		}
		if len(store.enqueued) != 1 {
			t.Fatalf("enqueued %d jobs", len(store.enqueued))
		}
		job := store.enqueued[0]
		if job.JobType != models.JobTypeLicenseRecheck || job.SHA256Hash != licenseRecheckDigest("abc123abc123abc123") ||
			!job.RetryAfter.Equal(now.Add(time.Minute)) || job.SourceFile != "license-rules@"+shortDigest(licenseRecheckDigest("abc123abc123abc123")) {
			t.Fatalf("job = %+v", job)
		}
	})

	for _, status := range []string{models.JobStatusPending, models.JobStatusProcessing, models.JobStatusDone} {
		t.Run("same digest "+status+" is covered", func(t *testing.T) {
			store := &fakeRecheckStore{latest: &clickhouse.LicenseRecheckState{JobID: prevID, Digest: licenseRecheckDigest("d1"), Status: status, UpdatedAt: now}}
			if err := ensureLicenseRecheck(ctx, store, "d1", time.Minute, now); err != nil {
				t.Fatal(err)
			}
			if len(store.enqueued) != 0 {
				t.Fatal("no new recheck for rules that are already applied or queued")
			}
		})
	}

	t.Run("a failed recheck is retried", func(t *testing.T) {
		store := &fakeRecheckStore{latest: &clickhouse.LicenseRecheckState{JobID: prevID, Digest: licenseRecheckDigest("d1"), Status: models.JobStatusFailed}}
		if err := ensureLicenseRecheck(ctx, store, "d1", time.Minute, now); err != nil {
			t.Fatal(err)
		}
		if len(store.enqueued) != 1 || store.enqueued[0].JobID == prevID {
			t.Fatalf("enqueued = %+v", store.enqueued)
		}
	})

	t.Run("replicas seeing the same change enqueue the same job", func(t *testing.T) {
		a := &fakeRecheckStore{latest: &clickhouse.LicenseRecheckState{JobID: prevID, Digest: licenseRecheckDigest("d1"), Status: models.JobStatusDone}}
		b := &fakeRecheckStore{latest: a.latest}
		_ = ensureLicenseRecheck(ctx, a, "d2", time.Minute, now)
		_ = ensureLicenseRecheck(ctx, b, "d2", time.Minute, now.Add(time.Second))
		if a.enqueued[0].JobID != b.enqueued[0].JobID {
			t.Fatal("job ids differ, the queue would run the recheck twice")
		}
	})

	t.Run("reverting to earlier rules is a new recheck", func(t *testing.T) {
		// d1 → d2 → d1: the last transition must not reuse the first job id.
		first := uuid.NewSHA1(recheckNamespace, []byte("|"+licenseRecheckDigest("d1")))
		store := &fakeRecheckStore{latest: &clickhouse.LicenseRecheckState{JobID: uuid.New(), Digest: licenseRecheckDigest("d2"), Status: models.JobStatusDone}}
		_ = ensureLicenseRecheck(ctx, store, "d1", time.Minute, now)
		if len(store.enqueued) != 1 || store.enqueued[0].JobID == first {
			t.Fatalf("enqueued = %+v", store.enqueued)
		}
	})
}

func TestEnsureLicenseRecheckTracksPolicyChanges(t *testing.T) {
	originalMode := license.GetExpressionMode()
	defer license.SetExpressionMode(originalMode)
	ctx := context.Background()
	now := time.Now().UTC()
	license.SetExpressionMode(license.ExpressionModeStrict)
	before := licenseRecheckDigest("same-exceptions")

	store := &fakeRecheckStore{latest: &clickhouse.LicenseRecheckState{
		JobID: uuid.New(), Digest: before, Status: models.JobStatusDone, UpdatedAt: now,
	}}
	license.SetExpressionMode(license.ExpressionModePermissiveWins)
	after := licenseRecheckDigest("same-exceptions")
	if after == before {
		t.Fatal("changing expression mode did not change the recheck digest")
	}
	if err := ensureLicenseRecheck(ctx, store, "same-exceptions", time.Minute, now); err != nil {
		t.Fatal(err)
	}
	if len(store.enqueued) != 1 || store.enqueued[0].SHA256Hash != after {
		t.Fatalf("policy change did not queue the new rules: %+v", store.enqueued)
	}
}

func TestRecheckDelay(t *testing.T) {
	if got := recheckDelay(time.Minute, true); got != 2*time.Minute {
		t.Fatalf("remote: %s", got)
	}
	if got := recheckDelay(time.Minute, false); got != 2*time.Minute+configMapPropagation {
		t.Fatalf("file: %s", got)
	}
}

func TestProcessLicenseRecheckJob(t *testing.T) {
	sbomA, sbomB := uuid.New(), uuid.New()
	row := func(id uuid.UUID, doc, lic, cat string, nc, ex []string) clickhouse.StoredLicenseCompliance {
		return clickhouse.StoredLicenseCompliance{
			LicenseCompliance: models.LicenseCompliance{
				SBOMID: id, SourceFile: doc + ".json", LicenseID: lic, Category: cat,
				PackageCount: uint32(len(nc) + len(ex)), NonCompliantPackages: nc, ExemptedPackages: ex,
				Cluster: "prod", Namespace: "team", Project: doc,
			},
			DocumentName: doc,
		}
	}
	store := &fakeRecheckStore{rows: []clickhouse.StoredLicenseCompliance{
		row(sbomA, "alpha", "GPL-3.0-only", "copyleft", []string{"lib-x", "lib-y"}, []string{}),
		row(sbomB, "beta", "GPL-3.0-only", "copyleft", []string{"lib-x"}, []string{}),
		row(sbomA, "alpha", "MIT", "permissive", []string{}, []string{}),
		row(sbomB, "beta", "LGPL-2.1-only", "copyleft", []string{}, []string{"old-exempt"}),
	}}
	idx := license.BuildIndex(&license.ExceptionsFile{BlanketExceptions: []license.BlanketException{}, Exceptions: []license.Exception{
		// Granted for alpha only: beta's lib-x must stay a violation.
		{ID: "grant", Package: "lib-x", License: "GPL-3.0-only", Project: "alpha", Status: "approved"},
	}})

	if err := processLicenseRecheckJob(context.Background(), store, idx); err != nil {
		t.Fatal(err)
	}
	if len(store.inserts) != 1 {
		t.Fatalf("inserts = %d", len(store.inserts))
	}
	got := map[string]models.LicenseCompliance{}
	for _, m := range store.inserts[0] {
		got[m.SBOMID.String()+"/"+m.LicenseID] = m
	}
	if len(got) != 2 {
		t.Fatalf("only changed rows are rewritten, got %d: %+v", len(got), got)
	}

	granted := got[sbomA.String()+"/GPL-3.0-only"]
	if len(granted.NonCompliantPackages) != 1 || granted.NonCompliantPackages[0] != "lib-y" ||
		len(granted.ExemptedPackages) != 1 || granted.ExemptedPackages[0] != "lib-x" {
		t.Fatalf("granted row = %+v", granted)
	}
	if granted.Cluster != "prod" || granted.Namespace != "team" || granted.Project != "alpha" || granted.SourceFile != "alpha.json" || granted.CheckedAt.IsZero() {
		t.Fatalf("ownership and source must be carried over: %+v", granted)
	}

	revoked := got[sbomB.String()+"/LGPL-2.1-only"]
	if len(revoked.NonCompliantPackages) != 1 || revoked.NonCompliantPackages[0] != "old-exempt" || revoked.ExemptedPackages == nil {
		t.Fatalf("an exception that disappeared turns back into a violation: %+v", revoked)
	}
}

func TestProcessLicenseRecheckPersistsCategoryAndRecoversPackages(t *testing.T) {
	originalMode := license.GetExpressionMode()
	defer license.SetExpressionMode(originalMode)

	license.SetExpressionMode(license.ExpressionModeStrict)
	stored := clickhouse.StoredLicenseCompliance{
		LicenseCompliance: models.LicenseCompliance{
			SBOMID: uuid.New(), LicenseID: "MIT AND GPL-3.0-only", Category: string(license.CategoryCopyleft),
			PackageCount: 1, NonCompliantPackages: []string{"pkg-dual"}, ExemptedPackages: []string{},
		},
		PackageNames: []string{"pkg-dual"},
	}
	idx := license.BuildIndex(&license.ExceptionsFile{BlanketExceptions: []license.BlanketException{}, Exceptions: []license.Exception{}})

	license.SetExpressionMode(license.ExpressionModePermissiveWins)
	store := &fakeRecheckStore{rows: []clickhouse.StoredLicenseCompliance{stored}}
	if err := processLicenseRecheckJob(context.Background(), store, idx); err != nil {
		t.Fatal(err)
	}
	if len(store.inserts) != 1 || len(store.inserts[0]) != 1 {
		t.Fatalf("permissive recheck inserts = %+v", store.inserts)
	}
	permissive := store.inserts[0][0]
	if permissive.Category != string(license.CategoryPermissive) || len(permissive.NonCompliantPackages) != 0 {
		t.Fatalf("permissive recheck did not persist the changed category: %+v", permissive)
	}

	// The source package row is joined again on the next recheck, so the
	// license identity survives even though permissive compliance stores no
	// violation package list.
	stored.LicenseCompliance = permissive
	stored.PackageNames = []string{"pkg-dual"}
	license.SetExpressionMode(license.ExpressionModeStrict)
	roundTripStore := &fakeRecheckStore{rows: []clickhouse.StoredLicenseCompliance{stored}}
	if err := processLicenseRecheckJob(context.Background(), roundTripStore, idx); err != nil {
		t.Fatal(err)
	}
	if len(roundTripStore.inserts) != 1 || len(roundTripStore.inserts[0]) != 1 {
		t.Fatalf("strict recheck inserts = %+v", roundTripStore.inserts)
	}
	strict := roundTripStore.inserts[0][0]
	if strict.Category != string(license.CategoryCopyleft) ||
		len(strict.NonCompliantPackages) != 1 || strict.NonCompliantPackages[0] != "pkg-dual" {
		t.Fatalf("strict recheck lost the previous package identity: %+v", strict)
	}
}

func TestProcessLicenseRecheckFailsClosedWithoutPermissivePackageNames(t *testing.T) {
	originalMode := license.GetExpressionMode()
	defer license.SetExpressionMode(originalMode)
	license.SetExpressionMode(license.ExpressionModeStrict)
	row := clickhouse.StoredLicenseCompliance{LicenseCompliance: models.LicenseCompliance{
		SBOMID: uuid.New(), LicenseID: "MIT AND GPL-3.0-only", Category: string(license.CategoryPermissive),
		PackageCount: 1, NonCompliantPackages: []string{}, ExemptedPackages: []string{},
	}}
	store := &fakeRecheckStore{rows: []clickhouse.StoredLicenseCompliance{row}}
	if err := processLicenseRecheckJob(context.Background(), store, nil); err == nil {
		t.Fatal("expected missing source package identities to fail the recheck")
	}
	if len(store.inserts) != 0 {
		t.Fatalf("must not persist a policy reclassification with missing package identities: %+v", store.inserts)
	}
}

func TestPermissivePackageNamesPreserveIngestExclusions(t *testing.T) {
	row := clickhouse.StoredLicenseCompliance{
		LicenseCompliance: models.LicenseCompliance{Category: string(license.CategoryPermissive)},
		RootPURL:          "pkg:generic/product@1",
		PackageNames:      []string{"product", "workspace", "dependency", "first-party-unresolved"},
		PackagePURLs: []string{
			"pkg:generic/product@1",
			"pkg:npm/@workspace/app@0.0.0-use.local",
			"pkg:npm/library@1.0.0",
			"pkg:generic/private-module",
		},
		PackageLicenseSources: []string{"declared", "declared", "declared", license.ReasonFirstParty},
	}
	got := permissivePackageNames(row)
	if len(got) != 1 || got[0] != "dependency" {
		t.Fatalf("recheck names = %v, want only the checked dependency", got)
	}
}

func TestProcessLicenseRecheckJobBatches(t *testing.T) {
	store := &fakeRecheckStore{}
	for i := 0; i < recheckBatchSize+1; i++ {
		store.rows = append(store.rows, clickhouse.StoredLicenseCompliance{
			LicenseCompliance: models.LicenseCompliance{SBOMID: uuid.New(), LicenseID: "GPL-3.0-only", Category: "copyleft", NonCompliantPackages: []string{"p"}},
		})
	}
	idx := license.BuildIndex(&license.ExceptionsFile{BlanketExceptions: []license.BlanketException{
		{ID: "b", License: "GPL-3.0-only", Status: "approved"},
	}, Exceptions: []license.Exception{}})
	if err := processLicenseRecheckJob(context.Background(), store, idx); err != nil {
		t.Fatal(err)
	}
	if len(store.inserts) != 2 || len(store.inserts[0]) != recheckBatchSize || len(store.inserts[1]) != 1 {
		t.Fatalf("batches = %d", len(store.inserts))
	}
}

func TestObjectGetterAvoidsTypedNil(t *testing.T) {
	if objectGetter(nil) != nil {
		t.Fatal("a nil client must become a nil interface")
	}
}

func TestEnsureLicenseRecheckRetriesStaleProcessing(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		age  time.Duration
		want int
	}{{10 * time.Minute, 0}, {2 * time.Hour, 1}} {
		store := &fakeRecheckStore{latest: &clickhouse.LicenseRecheckState{
			JobID: uuid.New(), Digest: licenseRecheckDigest("d1"), Status: models.JobStatusProcessing, UpdatedAt: now.Add(-tt.age),
		}}
		if err := ensureLicenseRecheck(ctx, store, "d1", time.Minute, now); err != nil {
			t.Fatal(err)
		}
		if len(store.enqueued) != tt.want {
			t.Errorf("processing for %s: enqueued %d, want %d", tt.age, len(store.enqueued), tt.want)
		}
	}
}

// A worker that has not loaded the rules a recheck was queued for must not
// run it: it would re-apply its old rules, change nothing and mark the job
// done, and the change would never reach the stored results.
func TestRunLicenseRecheckJobOnlyWithItsRules(t *testing.T) {
	ctx := context.Background()
	job := models.IngestionJob{JobID: uuid.New(), SHA256Hash: licenseRecheckDigest("new"), JobType: models.JobTypeLicenseRecheck}
	grant := license.BuildIndex(&license.ExceptionsFile{BlanketExceptions: []license.BlanketException{}, Exceptions: []license.Exception{
		{ID: "grant", Package: "lib-x", License: "GPL-3.0-only", Status: "approved"},
	}})
	rows := func() []clickhouse.StoredLicenseCompliance {
		return []clickhouse.StoredLicenseCompliance{{LicenseCompliance: models.LicenseCompliance{
			SBOMID: uuid.New(), LicenseID: "GPL-3.0-only", Category: "copyleft", PackageCount: 1,
			NonCompliantPackages: []string{"lib-x"}, ExemptedPackages: []string{},
		}, DocumentName: "p"}}
	}

	t.Run("behind: deferred, nothing written", func(t *testing.T) {
		store := &fakeRecheckStore{rows: rows(), latest: &clickhouse.LicenseRecheckState{JobID: job.JobID, Digest: licenseRecheckDigest("new")}}
		err := runLicenseRecheckJob(ctx, store, job, rulesource.Snapshot[*license.ExceptionIndex]{Digest: "old"}, time.Minute)
		var d *deferError
		if !errors.As(err, &d) {
			t.Fatalf("err = %v, want a deferral", err)
		}
		if len(store.inserts) != 0 {
			t.Fatal("rows rewritten with the old rules")
		}
	})

	t.Run("superseded: completes without work", func(t *testing.T) {
		store := &fakeRecheckStore{rows: rows(), latest: &clickhouse.LicenseRecheckState{JobID: uuid.New(), Digest: licenseRecheckDigest("newer")}}
		if err := runLicenseRecheckJob(ctx, store, job, rulesource.Snapshot[*license.ExceptionIndex]{Digest: "newer"}, time.Minute); err != nil {
			t.Fatal(err)
		}
		if len(store.inserts) != 0 {
			t.Fatal("superseded recheck did work")
		}
	})

	t.Run("matching rules: applied", func(t *testing.T) {
		store := &fakeRecheckStore{rows: rows()}
		if err := runLicenseRecheckJob(ctx, store, job, rulesource.Snapshot[*license.ExceptionIndex]{Digest: "new", Value: grant}, time.Minute); err != nil {
			t.Fatal(err)
		}
		if len(store.inserts) != 1 || len(store.inserts[0][0].ExemptedPackages) != 1 {
			t.Fatalf("inserts = %+v", store.inserts)
		}
	})

	t.Run("interrupted by shutdown: deferred, not failed", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		store := &fakeRecheckStore{rows: rows(), eachErr: context.Canceled}
		err := runLicenseRecheckJob(cctx, store, job, rulesource.Snapshot[*license.ExceptionIndex]{Digest: "new", Value: grant}, time.Minute)
		var d *deferError
		if !errors.As(err, &d) {
			t.Fatalf("err = %v, want a deferral", err)
		}
	})
}

func TestRecheckPollInterval(t *testing.T) {
	// Reloading disabled still re-asserts once a minute so a failed recheck is retried.
	if got := recheckPollInterval(0); got != time.Minute {
		t.Fatalf("disabled: %s", got)
	}
	if got := recheckPollInterval(5 * time.Minute); got != 5*time.Minute {
		t.Fatalf("enabled: %s", got)
	}
}
