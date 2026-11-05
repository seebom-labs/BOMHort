package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/apikey"
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

func TestUploadHandler_ScopedAPIKey_SingleOriginDefaultAndAttribution(t *testing.T) {
	cfg := ownershipUploadConfig(t)
	store := &fakeUploadStore{}
	h := localUploadHandler(cfg, store)

	key := &apikey.Key{
		Name:   "ci-builder",
		Secret: "secret-token-123",
		Scope: apikey.Scope{
			Origins: []string{"ci"},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
	req.Header.Set("X-Filename", "app.spdx.json")
	ctx := apikey.WithKey(req.Context(), key)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["uploaded_by"] != "ci-builder" {
		t.Errorf("expected uploaded_by 'ci-builder', got %q", resp["uploaded_by"])
	}

	if len(store.enqueuedJobs) != 1 {
		t.Fatalf("expected 1 enqueued job, got %d", len(store.enqueuedJobs))
	}
	job := store.enqueuedJobs[0]
	if job.UploadedBy != "ci-builder" {
		t.Errorf("job uploaded_by = %q, want 'ci-builder'", job.UploadedBy)
	}
}

func TestUploadHandler_ScopedAPIKey_ScopeViolationRejection(t *testing.T) {
	cfg := ownershipUploadConfig(t)
	cfg.ClusterName = ""
	store := &fakeUploadStore{}
	h := localUploadHandler(cfg, store)

	key := &apikey.Key{
		Name:   "restricted-runner",
		Secret: "super-secret-xyz",
		Scope: apikey.Scope{
			Origins:    []string{"ci"},
			Clusters:   []string{"prod-eu"},
			Namespaces: []string{"payments"},
			Projects:   []string{"my-org/pay"},
		},
	}

	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{
			name:    "forbidden origin",
			url:     "/api/v1/sboms/upload?origin=manual",
			wantErr: `credential "restricted-runner" is not permitted for origin "manual"`,
		},
		{
			name:    "forbidden cluster",
			url:     "/api/v1/sboms/upload?cluster=prod-us",
			wantErr: `credential "restricted-runner" is not permitted for cluster "prod-us"`,
		},
		{
			name:    "forbidden namespace",
			url:     "/api/v1/sboms/upload?namespace=auth",
			wantErr: `credential "restricted-runner" is not permitted for namespace "auth"`,
		},
		{
			name:    "forbidden project",
			url:     "/api/v1/sboms/upload?project=other/project",
			wantErr: `credential "restricted-runner" is not permitted for project "other/project"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.url, bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
			req.Header.Set("X-Filename", "app.spdx.json")
			req = req.WithContext(apikey.WithKey(req.Context(), key))

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403 Forbidden, got %d: %s", rec.Code, rec.Body.String())
			}

			// Verify error message contains credential name and never leaks secrets
			var errResp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("failed to decode error response: %v", err)
			}
			if errResp["error"] != tc.wantErr {
				t.Errorf("error = %q, want %q", errResp["error"], tc.wantErr)
			}
			if strings.Contains(rec.Body.String(), "super-secret-xyz") {
				t.Errorf("error leaked credential secret: %s", rec.Body.String())
			}
		})
	}
}

func TestUploadHandler_ScopedAPIKey_MultiOriginRequiresExplicitParam(t *testing.T) {
	cfg := ownershipUploadConfig(t)
	store := &fakeUploadStore{}
	h := localUploadHandler(cfg, store)

	key := &apikey.Key{
		Name:   "multi-origin-key",
		Secret: "secret-token",
		Scope: apikey.Scope{
			Origins: []string{"ci", "manual"},
		},
	}

	// Upload without origin: cannot default (multiple origins), so rejected with 403
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
	req.Header.Set("X-Filename", "app.spdx.json")
	req = req.WithContext(apikey.WithKey(req.Context(), key))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when origin left off without single default, got %d: %s", rec.Code, rec.Body.String())
	}
	var errResp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	expectedMsg := `credential "multi-origin-key" requires origin to be one of [ci, manual]`
	if errResp["error"] != expectedMsg {
		t.Errorf("got error %q, want %q", errResp["error"], expectedMsg)
	}

	// Upload with allowed origin from the list: accepted
	reqOk := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload?origin=manual", bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
	reqOk.Header.Set("X-Filename", "app.spdx.json")
	reqOk = reqOk.WithContext(apikey.WithKey(reqOk.Context(), key))

	recOk := httptest.NewRecorder()
	h.ServeHTTP(recOk, reqOk)

	if recOk.Code != http.StatusAccepted {
		t.Fatalf("expected 202 when origin in allowed list, got %d: %s", recOk.Code, recOk.Body.String())
	}
}
