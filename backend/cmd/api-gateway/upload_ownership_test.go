package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/config"
)

// ownershipUploadConfig is testUploadConfig plus instance-wide namespace and
// project defaults, so the tests below can tell "inherited the default" apart
// from "read the query param".
func ownershipUploadConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := testUploadConfig(t)
	cfg.Namespace = "default-namespace"
	cfg.Project = "default-project"
	return cfg
}

func postSBOM(t *testing.T, h http.HandlerFunc, target string) map[string]string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
	req.Header.Set("X-Filename", "app.spdx.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	return resp
}

func TestUploadHandler_NamespaceProjectQueryParams(t *testing.T) {
	cfg := ownershipUploadConfig(t)
	store := &fakeUploadStore{}
	h := localUploadHandler(cfg, store)

	resp := postSBOM(t, h, "/api/v1/sboms/upload?namespace=payments&project=payment-service")

	if resp["namespace"] != "payments" {
		t.Errorf("response namespace = %q, want payments", resp["namespace"])
	}
	if resp["project"] != "payment-service" {
		t.Errorf("response project = %q, want payment-service", resp["project"])
	}
	// cluster was not supplied, so it must still fall back to the default.
	if resp["cluster"] != "default-cluster" {
		t.Errorf("response cluster = %q, want the configured default", resp["cluster"])
	}

	if len(store.enqueuedJobs) != 1 {
		t.Fatalf("expected 1 enqueued job, got %d", len(store.enqueuedJobs))
	}
	job := store.enqueuedJobs[0]
	if job.Namespace != "payments" {
		t.Errorf("job namespace = %q, want payments", job.Namespace)
	}
	if job.Project != "payment-service" {
		t.Errorf("job project = %q, want payment-service", job.Project)
	}
	if job.Cluster != "default-cluster" {
		t.Errorf("job cluster = %q, want default-cluster", job.Cluster)
	}
}

func TestUploadHandler_OwnershipDefaultsWhenParamsAbsent(t *testing.T) {
	cfg := ownershipUploadConfig(t)
	store := &fakeUploadStore{}
	h := localUploadHandler(cfg, store)

	resp := postSBOM(t, h, "/api/v1/sboms/upload")

	if resp["namespace"] != "default-namespace" {
		t.Errorf("response namespace = %q, want the configured default", resp["namespace"])
	}
	if resp["project"] != "default-project" {
		t.Errorf("response project = %q, want the configured default", resp["project"])
	}

	job := store.enqueuedJobs[0]
	if job.Namespace != "default-namespace" || job.Project != "default-project" {
		t.Errorf("job ownership = (%q, %q), want the configured defaults", job.Namespace, job.Project)
	}
}

// A blank param is treated as absent, not as "clear the default". Otherwise
// `?namespace=` and omitting it entirely — two spellings of the same intent —
// would write different data.
func TestUploadHandler_BlankOwnershipParamKeepsDefault(t *testing.T) {
	cfg := ownershipUploadConfig(t)
	store := &fakeUploadStore{}
	h := localUploadHandler(cfg, store)

	resp := postSBOM(t, h, "/api/v1/sboms/upload?namespace=&project=%20%20")

	if resp["namespace"] != "default-namespace" {
		t.Errorf("blank namespace param: got %q, want the configured default", resp["namespace"])
	}
	if resp["project"] != "default-project" {
		t.Errorf("whitespace-only project param: got %q, want the configured default", resp["project"])
	}
}

func TestUploadHandler_AllThreeDimensionsOverridden(t *testing.T) {
	cfg := ownershipUploadConfig(t)
	store := &fakeUploadStore{}
	h := localUploadHandler(cfg, store)

	resp := postSBOM(t, h, "/api/v1/sboms/upload?cluster=prod-eu&namespace=payments&project=payment-service")

	want := map[string]string{
		"cluster":   "prod-eu",
		"namespace": "payments",
		"project":   "payment-service",
	}
	for k, v := range want {
		if resp[k] != v {
			t.Errorf("response %s = %q, want %q", k, resp[k], v)
		}
	}

	job := store.enqueuedJobs[0]
	if job.Cluster != "prod-eu" || job.Namespace != "payments" || job.Project != "payment-service" {
		t.Errorf("job ownership = (%q, %q, %q), want (prod-eu, payments, payment-service)",
			job.Cluster, job.Namespace, job.Project)
	}
}

func TestQueryOverride(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		param    string
		fallback string
		want     string
	}{
		{"absent", "/x", "namespace", "fallback", "fallback"},
		{"present", "/x?namespace=team-a", "namespace", "fallback", "team-a"},
		{"blank", "/x?namespace=", "namespace", "fallback", "fallback"},
		{"whitespace only", "/x?namespace=%20", "namespace", "fallback", "fallback"},
		{"trimmed", "/x?namespace=%20team-a%20", "namespace", "fallback", "team-a"},
		{"empty fallback", "/x", "namespace", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			if got := queryOverride(req, tt.param, tt.fallback); got != tt.want {
				t.Errorf("queryOverride() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUploadHandler_OriginQueryParam(t *testing.T) {
	cfg := ownershipUploadConfig(t)
	cfg.Origin = "manual"
	store := &fakeUploadStore{}
	h := localUploadHandler(cfg, store)

	// Valid origin overrides default
	resp := postSBOM(t, h, "/api/v1/sboms/upload?origin=ci")
	if resp["origin"] != "ci" {
		t.Errorf("response origin = %q, want ci", resp["origin"])
	}
	if len(store.enqueuedJobs) != 1 || store.enqueuedJobs[0].Origin != "ci" {
		t.Errorf("job origin = %q, want ci", store.enqueuedJobs[0].Origin)
	}

	// Absent origin uses default
	store.enqueuedJobs = nil
	respDefault := postSBOM(t, h, "/api/v1/sboms/upload")
	if respDefault["origin"] != "manual" {
		t.Errorf("response origin = %q, want manual (default)", respDefault["origin"])
	}
	if len(store.enqueuedJobs) != 1 || store.enqueuedJobs[0].Origin != "manual" {
		t.Errorf("job origin = %q, want manual", store.enqueuedJobs[0].Origin)
	}

	// Invalid origin returns 400
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload?origin=unsupported", bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
	req.Header.Set("X-Filename", "app.spdx.json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid origin, got %d", rec.Code)
	}
}
