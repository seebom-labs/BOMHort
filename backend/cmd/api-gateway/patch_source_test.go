package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/internal/apikey"
	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
)

// fakeSourceStore implements sourceUpdater + sourceReader in memory.
type fakeSourceStore struct {
	repo, ref   string
	origin      string
	cluster     string
	namespace   string
	project     string
	exists      bool
	gotRepo     string
	gotRef      string
	updateCalls int
}

func (f *fakeSourceStore) UpdateSBOMSource(_ context.Context, _, repo, ref string) error {
	if !f.exists {
		return clickhouse.ErrSBOMNotFound
	}
	f.updateCalls++
	f.gotRepo, f.gotRef = repo, ref
	return nil
}

func (f *fakeSourceStore) QuerySBOMSource(_ context.Context, _ string) (string, string, string, string, string, string, error) {
	if !f.exists {
		return "", "", "", "", "", "", clickhouse.ErrSBOMNotFound
	}
	return f.repo, f.ref, f.origin, f.cluster, f.namespace, f.project, nil
}

const patchTestID = "d5b0d9c8-1111-2222-3333-444455556666"

func doPatch(t *testing.T, store *fakeSourceStore, authEnabled bool, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	cfg := &config.Config{AuthEnabled: authEnabled}
	handler := patchSBOMSourceHandler(cfg, store, store)

	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /api/v1/sboms/{id}", handler)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/sboms/"+id, strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestPatchSourceRequiresAuthEnabled(t *testing.T) {
	store := &fakeSourceStore{exists: true}
	rec := doPatch(t, store, false, patchTestID, `{"source_repo":"https://github.com/x/y"}`)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 when AUTH_ENABLED=false", rec.Code)
	}
	if store.updateCalls != 0 {
		t.Error("update must not run without auth")
	}
}

func TestPatchSourceSetsBothFields(t *testing.T) {
	store := &fakeSourceStore{exists: true}
	rec := doPatch(t, store, true, patchTestID,
		`{"source_repo":"https://github.com/example-org/example-app","source_ref":"v1.2.3"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if store.gotRepo != "https://github.com/example-org/example-app" || store.gotRef != "v1.2.3" {
		t.Errorf("stored (%q, %q)", store.gotRepo, store.gotRef)
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	if resp["source_repo"] != "https://github.com/example-org/example-app" || resp["source_ref"] != "v1.2.3" {
		t.Errorf("response = %v", resp)
	}
}

// Partial PATCH: the absent field keeps its current value.
func TestPatchSourcePartialKeepsOtherField(t *testing.T) {
	store := &fakeSourceStore{exists: true, repo: "https://github.com/old/repo", ref: "keep-me"}
	rec := doPatch(t, store, true, patchTestID, `{"source_repo":"https://github.com/new/repo"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if store.gotRepo != "https://github.com/new/repo" || store.gotRef != "keep-me" {
		t.Errorf("stored (%q, %q), want ref preserved", store.gotRepo, store.gotRef)
	}
}

// Explicit "" clears a field — how a wrong pin is removed.
func TestPatchSourceEmptyStringClears(t *testing.T) {
	store := &fakeSourceStore{exists: true, repo: "https://github.com/wrong/repo", ref: "wrong"}
	rec := doPatch(t, store, true, patchTestID, `{"source_repo":"","source_ref":""}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if store.gotRepo != "" || store.gotRef != "" {
		t.Errorf("stored (%q, %q), want cleared", store.gotRepo, store.gotRef)
	}
}

// The stored form must match extraction output: PATCH normalises too.
func TestPatchSourceNormalizes(t *testing.T) {
	store := &fakeSourceStore{exists: true}
	rec := doPatch(t, store, true, patchTestID,
		`{"source_repo":"https://github.com/x/y.git@v2.0"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if store.gotRepo != "https://github.com/x/y" {
		t.Errorf("repo = %q, want normalised form", store.gotRepo)
	}
	if store.gotRef != "v2.0" {
		t.Errorf("ref = %q, want inline ref extracted", store.gotRef)
	}
}

func TestPatchSourceValidation(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty body object", `{}`},
		{"not json", `no json`},
		{"scheme-less repo", `{"source_repo":"github.com/x/y"}`},
		{"ssh repo", `{"source_repo":"ssh://git@github.com/x/y"}`},
		{"credentials in repo", `{"source_repo":"https://user:pw@github.com/x/y"}`},
		{"ref with whitespace", `{"source_ref":"has space"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeSourceStore{exists: true}
			rec := doPatch(t, store, true, patchTestID, tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			if store.updateCalls != 0 {
				t.Error("update must not run on invalid input")
			}
		})
	}
}

func TestPatchSourceInvalidID(t *testing.T) {
	store := &fakeSourceStore{exists: true}
	rec := doPatch(t, store, true, "not-a-uuid", `{"source_repo":"https://github.com/x/y"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestPatchSourceNotFound(t *testing.T) {
	store := &fakeSourceStore{exists: false}
	rec := doPatch(t, store, true, patchTestID, `{"source_repo":"https://github.com/x/y"}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestPatchSource_ScopedAPIKeyAuthorization(t *testing.T) {
	key := &apikey.Key{
		Name:   "team-a-key",
		Secret: "sec-a",
		Scope: apikey.Scope{
			Projects: []string{"team-a"},
		},
	}

	t.Run("scoped key forbidden on foreign project", func(t *testing.T) {
		store := &fakeSourceStore{
			exists:  true,
			project: "team-b",
		}
		cfg := &config.Config{AuthEnabled: true}
		handler := patchSBOMSourceHandler(cfg, store, store)

		req := httptest.NewRequest(http.MethodPatch, "/api/v1/sboms/"+patchTestID, strings.NewReader(`{"source_repo":"https://github.com/new/repo"}`))
		req = req.WithContext(apikey.WithKey(req.Context(), key))
		req.SetPathValue("id", patchTestID)

		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for scoped key modifying foreign project, got %d: %s", rec.Code, rec.Body.String())
		}
		if store.updateCalls != 0 {
			t.Errorf("store updateCalls = %d, want 0", store.updateCalls)
		}
	})

	t.Run("scoped key allowed on own project", func(t *testing.T) {
		store := &fakeSourceStore{
			exists:  true,
			project: "team-a",
		}
		cfg := &config.Config{AuthEnabled: true}
		handler := patchSBOMSourceHandler(cfg, store, store)

		req := httptest.NewRequest(http.MethodPatch, "/api/v1/sboms/"+patchTestID, strings.NewReader(`{"source_repo":"https://github.com/new/repo"}`))
		req = req.WithContext(apikey.WithKey(req.Context(), key))
		req.SetPathValue("id", patchTestID)

		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for scoped key modifying own project, got %d: %s", rec.Code, rec.Body.String())
		}
		if store.updateCalls != 1 {
			t.Errorf("store updateCalls = %d, want 1", store.updateCalls)
		}
	})
}
