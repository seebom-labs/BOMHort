package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// #332: X-Source-Repo/X-Source-Ref upload headers travel into the enqueued
// job, get normalised on the way, and malformed values are rejected — not
// silently dropped.

func doSourceUpload(t *testing.T, store *fakeUploadStore, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	cfg := testUploadConfig(t)
	h := localUploadHandler(cfg, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload",
		bytes.NewReader([]byte(`{"spdxVersion": "SPDX-2.3"}`)))
	req.Header.Set("X-Filename", "project.spdx.json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUploadSourceHeadersEnqueued(t *testing.T) {
	store := &fakeUploadStore{}
	rec := doSourceUpload(t, store, map[string]string{
		"X-Source-Repo": "https://github.com/example-org/example-app",
		"X-Source-Ref":  "v1.2.3",
	})

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(store.enqueuedJobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(store.enqueuedJobs))
	}
	job := store.enqueuedJobs[0]
	if job.SourceRepo != "https://github.com/example-org/example-app" || job.SourceRef != "v1.2.3" {
		t.Errorf("job carries (%q, %q)", job.SourceRepo, job.SourceRef)
	}
}

// The stored form must be canonical regardless of entry path: a .git suffix
// and inline @ref in the header get normalised exactly like extraction does.
func TestUploadSourceHeaderNormalized(t *testing.T) {
	store := &fakeUploadStore{}
	rec := doSourceUpload(t, store, map[string]string{
		"X-Source-Repo": "https://github.com/x/y.git@v2.0",
	})

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	job := store.enqueuedJobs[0]
	if job.SourceRepo != "https://github.com/x/y" {
		t.Errorf("repo = %q, want normalised", job.SourceRepo)
	}
	if job.SourceRef != "v2.0" {
		t.Errorf("ref = %q, want inline ref extracted", job.SourceRef)
	}
}

// An explicit X-Source-Ref outranks a ref embedded in the repo URL.
func TestUploadSourceExplicitRefWins(t *testing.T) {
	store := &fakeUploadStore{}
	rec := doSourceUpload(t, store, map[string]string{
		"X-Source-Repo": "https://github.com/x/y.git@embedded",
		"X-Source-Ref":  "explicit",
	})

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
	if got := store.enqueuedJobs[0].SourceRef; got != "explicit" {
		t.Errorf("ref = %q, want explicit header value", got)
	}
}

func TestUploadSourceHeadersAbsent(t *testing.T) {
	store := &fakeUploadStore{}
	rec := doSourceUpload(t, store, nil)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
	job := store.enqueuedJobs[0]
	if job.SourceRepo != "" || job.SourceRef != "" {
		t.Errorf("expected empty source fields, got (%q, %q)", job.SourceRepo, job.SourceRef)
	}
}

// Malformed values are a 400, and nothing is stored or enqueued: rejecting
// loudly beats persisting a value that breaks git clone fleet-wide.
func TestUploadSourceHeaderRejected(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
	}{
		{"scheme-less repo", map[string]string{"X-Source-Repo": "github.com/x/y"}},
		{"ssh repo", map[string]string{"X-Source-Repo": "ssh://git@github.com/x/y"}},
		{"credentials", map[string]string{"X-Source-Repo": "https://tok:sec@github.com/x/y"}},
		{"ref with space", map[string]string{"X-Source-Ref": "not a ref"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeUploadStore{}
			cfg := testUploadConfig(t)
			rec := doSourceUpload(t, store, tt.headers)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			if len(store.enqueuedJobs) != 0 {
				t.Error("nothing may be enqueued on invalid headers")
			}
			assertNoFilesInPushedDir(t, cfg)
		})
	}
}
