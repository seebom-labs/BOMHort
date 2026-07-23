package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// fakeUploadStore mirrors fakePinger (health_test.go) so uploadHandler can be
// exercised without a live ClickHouse connection.
type fakeUploadStore struct {
	hashExists    bool
	hashExistsErr error
	enqueueErr    error
	enqueuedJobs  []models.IngestionJob
}

func (f *fakeUploadStore) HashExists(ctx context.Context, hash string) (bool, error) {
	return f.hashExists, f.hashExistsErr
}

func (f *fakeUploadStore) EnqueueJobs(ctx context.Context, jobs []models.IngestionJob) error {
	if f.enqueueErr != nil {
		return f.enqueueErr
	}
	f.enqueuedJobs = append(f.enqueuedJobs, jobs...)
	return nil
}

// fakeS3Store implements uploadObjectStore for testing the S3 push-upload
// routing path (#135) without a live S3-compatible endpoint.
type fakeS3Store struct {
	putErr      error
	removeErr   error
	puts        []fakePut
	removedKeys []string
}

type fakePut struct {
	bucket string
	key    string
	size   int64
	body   []byte
}

func (f *fakeS3Store) PutObject(ctx context.Context, bucket, key string, body io.Reader, size int64) error {
	if f.putErr != nil {
		return f.putErr
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	f.puts = append(f.puts, fakePut{bucket: bucket, key: key, size: size, body: data})
	return nil
}

func (f *fakeS3Store) RemoveObject(ctx context.Context, bucket, key string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	f.removedKeys = append(f.removedKeys, bucket+"/"+key)
	return nil
}

// testUploadConfig defaults AuthEnabled to true since uploadHandler refuses
// to serve at all when it's false (see TestUploadHandler_AuthDisabled_Returns403).
// Tests that specifically need the disabled case override it explicitly.
func testUploadConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		SBOMDir:         t.TempDir(),
		MaxUploadSizeMB: 1,
		ClusterName:     "default-cluster",
		AuthEnabled:     true,
	}
}

// localUploadHandler builds an uploadHandler configured for the local-
// filesystem fallback path (no S3 skipScan bucket configured) — the mode
// most tests in this file exercise.
func localUploadHandler(cfg *config.Config, store uploadStore) http.HandlerFunc {
	return uploadHandler(cfg, store, nil, config.S3BucketConfig{}, false, true)
}

// assertNoFilesInPushedDir fails the test if SBOM_DIR/pushed contains any
// file — used to prove temp files are cleaned up on every non-persisting path
// (duplicate hash, enqueue failure, invalid content, S3 routing).
func assertNoFilesInPushedDir(t *testing.T, cfg *config.Config) {
	t.Helper()
	pushedDir := filepath.Join(cfg.SBOMDir, "pushed")
	entries, err := os.ReadDir(pushedDir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("failed to read pushed dir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("expected no files left in pushed dir, found: %v", names)
	}
}

func TestUploadHandler_HappyPath(t *testing.T) {
	cfg := testUploadConfig(t)
	store := &fakeUploadStore{}
	h := localUploadHandler(cfg, store)

	body := []byte(`{"spdxVersion": "SPDX-2.3"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader(body))
	req.Header.Set("X-Filename", "project.spdx.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "pending" {
		t.Errorf("expected status=pending, got %q", resp["status"])
	}
	if resp["job_type"] != "sbom" {
		t.Errorf("expected job_type=sbom, got %q", resp["job_type"])
	}
	if resp["job_id"] == "" {
		t.Error("expected non-empty job_id")
	}

	if len(store.enqueuedJobs) != 1 {
		t.Fatalf("expected 1 enqueued job, got %d", len(store.enqueuedJobs))
	}
	job := store.enqueuedJobs[0]
	if job.JobType != "sbom" {
		t.Errorf("enqueued job type = %q, want sbom", job.JobType)
	}
	if job.Status != models.JobStatusPending {
		t.Errorf("enqueued job status = %q, want pending", job.Status)
	}
	if job.Cluster != "default-cluster" {
		t.Errorf("enqueued job cluster = %q, want default-cluster", job.Cluster)
	}
	if !strings.HasPrefix(job.SourceFile, "pushed"+string(filepath.Separator)) {
		t.Errorf("enqueued job source file = %q, want prefix pushed/", job.SourceFile)
	}

	// The file must actually be written under SBOM_DIR/pushed/.
	absPath := filepath.Join(cfg.SBOMDir, job.SourceFile)
	written, err := os.ReadFile(absPath)
	if err != nil {
		t.Fatalf("expected uploaded file on disk at %s: %v", absPath, err)
	}
	if !bytes.Equal(written, body) {
		t.Errorf("written file contents = %q, want %q", written, body)
	}
}

func TestUploadHandler_AuthDisabled_Returns403(t *testing.T) {
	cfg := testUploadConfig(t)
	cfg.AuthEnabled = false
	store := &fakeUploadStore{}
	h := localUploadHandler(cfg, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{"spdxVersion": "SPDX-2.3"}`)))
	req.Header.Set("X-Filename", "project.spdx.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when AUTH_ENABLED=false, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(store.enqueuedJobs) != 0 {
		t.Errorf("upload must not proceed to enqueue when auth is disabled")
	}
	assertNoFilesInPushedDir(t, cfg)
}

func TestUploadHandler_NoStorageConfigured_Returns503(t *testing.T) {
	cfg := testUploadConfig(t)
	store := &fakeUploadStore{}
	// useS3Push=false, localWritable=false: neither storage backend usable.
	h := uploadHandler(cfg, store, nil, config.S3BucketConfig{}, false, false)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
	req.Header.Set("X-Filename", "project.spdx.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no upload storage is configured, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(store.enqueuedJobs) != 0 {
		t.Errorf("must not enqueue a job when no storage is available")
	}
}

func TestUploadHandler_MissingFilenameHeader(t *testing.T) {
	cfg := testUploadConfig(t)
	h := localUploadHandler(cfg, &fakeUploadStore{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing X-Filename, got %d", rec.Code)
	}
}

func TestUploadHandler_UnsupportedExtension(t *testing.T) {
	cfg := testUploadConfig(t)
	h := localUploadHandler(cfg, &fakeUploadStore{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`hello`)))
	req.Header.Set("X-Filename", "notes.txt")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unsupported extension, got %d", rec.Code)
	}
}

func TestUploadHandler_DuplicateContentHash(t *testing.T) {
	cfg := testUploadConfig(t)
	store := &fakeUploadStore{hashExists: true}
	h := localUploadHandler(cfg, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{"bomFormat":"CycloneDX"}`)))
	req.Header.Set("X-Filename", "app.cdx.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for duplicate content, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "duplicate" {
		t.Errorf("expected status=duplicate, got %q", resp["status"])
	}
	if len(store.enqueuedJobs) != 0 {
		t.Errorf("duplicate content must not enqueue a job, got %d", len(store.enqueuedJobs))
	}

	// The staged temp file must be cleaned up — a duplicate must not leave
	// anything behind in SBOM_DIR/pushed/.
	assertNoFilesInPushedDir(t, cfg)
}

func TestUploadHandler_OversizedBody(t *testing.T) {
	cfg := testUploadConfig(t) // MaxUploadSizeMB: 1
	h := localUploadHandler(cfg, &fakeUploadStore{})

	oversized := bytes.Repeat([]byte("a"), (1<<20)+1) // 1 byte over the 1MB limit
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader(oversized))
	req.Header.Set("X-Filename", "huge.spdx.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 for oversized body, got %d", rec.Code)
	}
	assertNoFilesInPushedDir(t, cfg)
}

func TestUploadHandler_ClusterQueryParamOverride(t *testing.T) {
	cfg := testUploadConfig(t) // ClusterName: "default-cluster"
	store := &fakeUploadStore{}
	h := localUploadHandler(cfg, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload?cluster=staging-us-east", bytes.NewReader([]byte(`{"@context":"openvex"}`)))
	req.Header.Set("X-Filename", "advisory.openvex.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["cluster"] != "staging-us-east" {
		t.Errorf("expected cluster=staging-us-east in response, got %q", resp["cluster"])
	}
	if resp["job_type"] != "vex" {
		t.Errorf("expected job_type=vex, got %q", resp["job_type"])
	}

	if len(store.enqueuedJobs) != 1 {
		t.Fatalf("expected 1 enqueued job, got %d", len(store.enqueuedJobs))
	}
	if got := store.enqueuedJobs[0].Cluster; got != "staging-us-east" {
		t.Errorf("enqueued job cluster = %q, want query param override staging-us-east", got)
	}
}

func TestUploadHandler_HashCheckErrorReturns500(t *testing.T) {
	cfg := testUploadConfig(t)
	store := &fakeUploadStore{hashExistsErr: errors.New("clickhouse unavailable")}
	h := localUploadHandler(cfg, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("X-Filename", "app.spdx.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when hash check fails, got %d", rec.Code)
	}
}

func TestUploadHandler_InvalidVEXContent_Returns400(t *testing.T) {
	cfg := testUploadConfig(t)
	store := &fakeUploadStore{}
	h := localUploadHandler(cfg, store)

	// Valid JSON, but not a VEX document: no @context and no statements.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("X-Filename", "broken.openvex.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid VEX content, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(store.enqueuedJobs) != 0 {
		t.Errorf("invalid VEX content must not enqueue a job")
	}
	assertNoFilesInPushedDir(t, cfg)
}

func TestUploadHandler_InvalidSBOMContent_Returns400(t *testing.T) {
	cfg := testUploadConfig(t)
	store := &fakeUploadStore{}
	h := localUploadHandler(cfg, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`this is not json at all`)))
	req.Header.Set("X-Filename", "broken.spdx.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid SBOM content, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(store.enqueuedJobs) != 0 {
		t.Errorf("invalid SBOM content must not enqueue a job")
	}
	assertNoFilesInPushedDir(t, cfg)
}

func TestUploadHandler_EnqueueFailure_CleansUpFile(t *testing.T) {
	cfg := testUploadConfig(t)
	store := &fakeUploadStore{enqueueErr: errors.New("clickhouse insert failed")}
	h := localUploadHandler(cfg, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
	req.Header.Set("X-Filename", "project.spdx.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when enqueue fails, got %d: %s", rec.Code, rec.Body.String())
	}

	// The file was renamed into place before EnqueueJobs was called; the
	// handler's best-effort cleanup must remove it on failure.
	assertNoFilesInPushedDir(t, cfg)
}

func TestUploadHandler_PathTraversalFilename_IsNeutralized(t *testing.T) {
	tests := []struct {
		name     string
		filename string
	}{
		{"relative traversal", "../../../etc/passwd.spdx.json"},
		{"absolute path", "/etc/passwd.spdx.json"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testUploadConfig(t)
			store := &fakeUploadStore{}
			h := localUploadHandler(cfg, store)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
			req.Header.Set("X-Filename", tc.filename)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusAccepted {
				t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
			}
			if len(store.enqueuedJobs) != 1 {
				t.Fatalf("expected 1 enqueued job, got %d", len(store.enqueuedJobs))
			}

			// filepath.Base (applied to X-Filename before it ever reaches disk)
			// must have stripped every directory component.
			job := store.enqueuedJobs[0]
			if strings.Contains(job.SourceFile, "..") {
				t.Errorf("source file retains traversal component: %q", job.SourceFile)
			}
			if !strings.HasPrefix(job.SourceFile, "pushed"+string(filepath.Separator)) {
				t.Errorf("source file escaped pushed/ prefix: %q", job.SourceFile)
			}

			absPath := filepath.Join(cfg.SBOMDir, job.SourceFile)
			if !strings.HasPrefix(absPath, filepath.Clean(cfg.SBOMDir)+string(filepath.Separator)) {
				t.Errorf("resolved path escaped SBOM_DIR: %q", absPath)
			}
			if _, err := os.Stat(absPath); err != nil {
				t.Errorf("expected file written at %s: %v", absPath, err)
			}
		})
	}
}

// --- S3 push-routing tests (#135 follow-up) -------------------------------

func TestUploadHandler_S3Push_HappyPath(t *testing.T) {
	cfg := testUploadConfig(t)
	store := &fakeUploadStore{}
	s3Store := &fakeS3Store{}
	pushBucket := config.S3BucketConfig{Name: "push-bucket", Prefix: "myprefix"}
	h := uploadHandler(cfg, store, s3Store, pushBucket, true, false)

	body := []byte(`{"spdxVersion": "SPDX-2.3"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader(body))
	req.Header.Set("X-Filename", "project.spdx.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}

	if len(s3Store.puts) != 1 {
		t.Fatalf("expected 1 S3 PutObject call, got %d", len(s3Store.puts))
	}
	put := s3Store.puts[0]
	if put.bucket != "push-bucket" {
		t.Errorf("PutObject bucket = %q, want push-bucket", put.bucket)
	}
	if !strings.HasPrefix(put.key, "myprefix/pushed/") {
		t.Errorf("PutObject key = %q, want prefix myprefix/pushed/", put.key)
	}
	if !strings.HasSuffix(put.key, "-project.spdx.json") {
		t.Errorf("PutObject key = %q, want suffix -project.spdx.json", put.key)
	}
	if put.size != int64(len(body)) {
		t.Errorf("PutObject size = %d, want %d", put.size, len(body))
	}
	if !bytes.Equal(put.body, body) {
		t.Errorf("PutObject body = %q, want %q", put.body, body)
	}

	if len(store.enqueuedJobs) != 1 {
		t.Fatalf("expected 1 enqueued job, got %d", len(store.enqueuedJobs))
	}
	job := store.enqueuedJobs[0]
	wantSource := "s3://push-bucket/" + put.key
	if job.SourceFile != wantSource {
		t.Errorf("enqueued job source file = %q, want %q", job.SourceFile, wantSource)
	}

	// Routing to S3 must not leave anything on the local filesystem.
	assertNoFilesInPushedDir(t, cfg)
}

func TestUploadHandler_S3Push_PutObjectFailure(t *testing.T) {
	cfg := testUploadConfig(t)
	store := &fakeUploadStore{}
	s3Store := &fakeS3Store{putErr: errors.New("s3 unavailable")}
	pushBucket := config.S3BucketConfig{Name: "push-bucket"}
	h := uploadHandler(cfg, store, s3Store, pushBucket, true, false)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
	req.Header.Set("X-Filename", "project.spdx.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when S3 put fails, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(store.enqueuedJobs) != 0 {
		t.Errorf("must not enqueue a job when S3 put fails")
	}
}

func TestUploadHandler_S3Push_EnqueueFailure_RemovesObject(t *testing.T) {
	cfg := testUploadConfig(t)
	store := &fakeUploadStore{enqueueErr: errors.New("clickhouse insert failed")}
	s3Store := &fakeS3Store{}
	pushBucket := config.S3BucketConfig{Name: "push-bucket"}
	h := uploadHandler(cfg, store, s3Store, pushBucket, true, false)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
	req.Header.Set("X-Filename", "project.spdx.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when enqueue fails, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(s3Store.puts) != 1 {
		t.Fatalf("expected the object to have been put once, got %d", len(s3Store.puts))
	}
	wantKey := s3Store.puts[0].key
	if len(s3Store.removedKeys) != 1 {
		t.Fatalf("expected 1 RemoveObject cleanup call, got %d", len(s3Store.removedKeys))
	}
	if got := s3Store.removedKeys[0]; got != "push-bucket/"+wantKey {
		t.Errorf("RemoveObject target = %q, want push-bucket/%s", got, wantKey)
	}
}
