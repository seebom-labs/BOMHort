package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// #350: ?sbom_id= on VEX uploads travels into the enqueued job as the explicit
// statement→SBOM mapping; it is rejected on SBOM uploads and for malformed
// values instead of being silently dropped — a bad mapping would scope
// statements to a nonexistent SBOM and hide them from every view.

const testVEXBody = `{
	"@context": "https://openvex.dev/ns/v0.2.0",
	"@id": "https://example-org.dev/vex/test",
	"author": "Tester",
	"statements": [
		{
			"vulnerability": {"name": "CVE-2026-0001"},
			"products": [{"@id": "pkg:golang/example.com/app@v1.0.0"}],
			"status": "not_affected"
		}
	]
}`

func doVEXUpload(t *testing.T, store *fakeUploadStore, query, filename, body string) *httptest.ResponseRecorder {
	t.Helper()
	cfg := testUploadConfig(t)
	h := localUploadHandler(cfg, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload"+query,
		bytes.NewReader([]byte(body)))
	req.Header.Set("X-Filename", filename)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUploadVEXSBOMIDEnqueued(t *testing.T) {
	store := &fakeUploadStore{}
	rec := doVEXUpload(t, store,
		"?sbom_id=11111111-1111-1111-1111-111111111111",
		"test.openvex.json", testVEXBody)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(store.enqueuedJobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(store.enqueuedJobs))
	}
	if got := store.enqueuedJobs[0].TargetSBOMID; got != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("target_sbom_id = %q, want explicit mapping", got)
	}
}

func TestUploadVEXSBOMIDAbsent(t *testing.T) {
	store := &fakeUploadStore{}
	rec := doVEXUpload(t, store, "", "test.openvex.json", testVEXBody)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := store.enqueuedJobs[0].TargetSBOMID; got != "" {
		t.Errorf("target_sbom_id = %q, want empty (worker auto-resolves)", got)
	}
}

func TestUploadSBOMIDRejected(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		filename string
		body     string
	}{
		// ?sbom_id= on an SBOM upload is a caller error: the mapping is
		// meaningless there and silently ignoring it would hide the typo.
		{"sbom upload", "?sbom_id=11111111-1111-1111-1111-111111111111",
			"project.spdx.json", `{"spdxVersion": "SPDX-2.3"}`},
		{"malformed uuid", "?sbom_id=not-a-uuid",
			"test.openvex.json", testVEXBody},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeUploadStore{}
			rec := doVEXUpload(t, store, tt.query, tt.filename, tt.body)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
			if len(store.enqueuedJobs) != 0 {
				t.Error("nothing may be enqueued on an invalid sbom_id mapping")
			}
		})
	}
}
