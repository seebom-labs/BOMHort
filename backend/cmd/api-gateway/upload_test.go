package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seebom-labs/seebom/backend/internal/config"
	"github.com/seebom-labs/seebom/backend/pkg/models"
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

func testUploadConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		SBOMDir:         t.TempDir(),
		MaxUploadSizeMB: 1,
		ClusterName:     "default-cluster",
	}
}

func TestUploadHandler_HappyPath(t *testing.T) {
	cfg := testUploadConfig(t)
	store := &fakeUploadStore{}
	h := uploadHandler(cfg, store)

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

func TestUploadHandler_MissingFilenameHeader(t *testing.T) {
	cfg := testUploadConfig(t)
	h := uploadHandler(cfg, &fakeUploadStore{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing X-Filename, got %d", rec.Code)
	}
}

func TestUploadHandler_UnsupportedExtension(t *testing.T) {
	cfg := testUploadConfig(t)
	h := uploadHandler(cfg, &fakeUploadStore{})

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
	h := uploadHandler(cfg, store)

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
}

func TestUploadHandler_OversizedBody(t *testing.T) {
	cfg := testUploadConfig(t) // MaxUploadSizeMB: 1
	h := uploadHandler(cfg, &fakeUploadStore{})

	oversized := bytes.Repeat([]byte("a"), (1<<20)+1) // 1 byte over the 1MB limit
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader(oversized))
	req.Header.Set("X-Filename", "huge.spdx.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 for oversized body, got %d", rec.Code)
	}
}

func TestUploadHandler_ClusterQueryParamOverride(t *testing.T) {
	cfg := testUploadConfig(t) // ClusterName: "default-cluster"
	store := &fakeUploadStore{}
	h := uploadHandler(cfg, store)

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
	h := uploadHandler(cfg, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("X-Filename", "app.spdx.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when hash check fails, got %d", rec.Code)
	}
}
