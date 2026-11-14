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

func TestUploadHandler_WorkloadIdentity(t *testing.T) {
	cfg := ownershipUploadConfig(t)
	// Clear default project so we test workload_name defaulting
	cfg.Project = ""

	t.Run("query parameters and project defaulting", func(t *testing.T) {
		store := &fakeUploadStore{}
		h := localUploadHandler(cfg, store)

		resp := postSBOM(t, h, "/api/v1/sboms/upload?workload_kind=deployment&workload_name=payment-service&workload_uid=11111111-1111-1111-1111-111111111111")

		if resp["workload_kind"] != "Deployment" {
			t.Errorf("response workload_kind = %q, want Deployment", resp["workload_kind"])
		}
		if resp["workload_name"] != "payment-service" {
			t.Errorf("response workload_name = %q, want payment-service", resp["workload_name"])
		}
		if resp["workload_uid"] != "11111111-1111-1111-1111-111111111111" {
			t.Errorf("response workload_uid = %q, want 11111111-1111-1111-1111-111111111111", resp["workload_uid"])
		}
		if resp["project"] != "payment-service" {
			t.Errorf("response project = %q, want payment-service (defaulted from workload_name)", resp["project"])
		}

		if len(store.enqueuedJobs) != 1 {
			t.Fatalf("enqueued %d jobs, want 1", len(store.enqueuedJobs))
		}
		job := store.enqueuedJobs[0]
		if job.WorkloadKind != "Deployment" || job.WorkloadName != "payment-service" || job.WorkloadUID != "11111111-1111-1111-1111-111111111111" {
			t.Errorf("job workload fields = (%q, %q, %q), want (Deployment, payment-service, 11111111-1111-1111-1111-111111111111)",
				job.WorkloadKind, job.WorkloadName, job.WorkloadUID)
		}
		if job.Project != "payment-service" {
			t.Errorf("job.Project = %q, want payment-service", job.Project)
		}
	})

	t.Run("headers", func(t *testing.T) {
		store := &fakeUploadStore{}
		h := localUploadHandler(cfg, store)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
		req.Header.Set("X-Filename", "app.spdx.json")
		req.Header.Set("X-Workload-Kind", "StatefulSet")
		req.Header.Set("X-Workload-Name", "redis-cluster")
		req.Header.Set("X-Workload-UID", "22222222-2222-2222-2222-222222222222")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusAccepted {
			t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
		}
		job := store.enqueuedJobs[0]
		if job.WorkloadKind != "StatefulSet" || job.WorkloadName != "redis-cluster" || job.WorkloadUID != "22222222-2222-2222-2222-222222222222" {
			t.Errorf("job workload fields = (%q, %q, %q), want (StatefulSet, redis-cluster, 22222222-2222-2222-2222-222222222222)",
				job.WorkloadKind, job.WorkloadName, job.WorkloadUID)
		}
		if job.Project != "redis-cluster" {
			t.Errorf("job.Project = %q, want redis-cluster (defaulted from Workload-Name)", job.Project)
		}
	})

	t.Run("invalid workload kind rejected with 400", func(t *testing.T) {
		store := &fakeUploadStore{}
		h := localUploadHandler(cfg, store)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload?workload_kind=not-a-kind", bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
		req.Header.Set("X-Filename", "app.spdx.json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("invalid workload uid rejected with 400", func(t *testing.T) {
		store := &fakeUploadStore{}
		h := localUploadHandler(cfg, store)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload?workload_uid=oops", bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
		req.Header.Set("X-Filename", "app.spdx.json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}
