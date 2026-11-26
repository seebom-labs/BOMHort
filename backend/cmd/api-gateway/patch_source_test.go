package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
)

// fakeSourceStore implements sourceUpdater + sourceReader in memory.
// Only non-nil pointer fields are updated, mimicking ClickHouse partial column mutations.
type fakeSourceStore struct {
	repo, ref   string
	tags        []string
	exists      bool
	gotRepo     *string
	gotRef      *string
	gotTags     *[]string
	updateCalls int
}

func (f *fakeSourceStore) UpdateSBOMSource(_ context.Context, _ string, repo, ref *string, tags *[]string) error {
	if !f.exists {
		return clickhouse.ErrSBOMNotFound
	}
	f.updateCalls++
	f.gotRepo, f.gotRef, f.gotTags = repo, ref, tags
	if repo != nil {
		f.repo = *repo
	}
	if ref != nil {
		f.ref = *ref
	}
	if tags != nil {
		f.tags = *tags
	}
	return nil
}

func (f *fakeSourceStore) QuerySBOMSource(_ context.Context, _ string) (string, string, []string, error) {
	if !f.exists {
		return "", "", nil, clickhouse.ErrSBOMNotFound
	}
	return f.repo, f.ref, f.tags, nil
}

const patchTestID = "d5b0d9c8-1111-2222-3333-444455556666"

func doPatch(t *testing.T, store *fakeSourceStore, authEnabled bool, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	return doPatchWithConfig(t, store, &config.Config{AuthEnabled: authEnabled}, id, body)
}

func doPatchWithConfig(t *testing.T, store *fakeSourceStore, cfg *config.Config, id, body string) *httptest.ResponseRecorder {
	t.Helper()
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
	if store.gotRepo == nil || *store.gotRepo != "https://github.com/example-org/example-app" ||
		store.gotRef == nil || *store.gotRef != "v1.2.3" {
		t.Errorf("stored (%v, %v)", store.gotRepo, store.gotRef)
	}
	if store.gotTags != nil {
		t.Errorf("gotTags = %v, want nil (not updated)", store.gotTags)
	}

	var resp patchSourceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	if resp.SourceRepo != "https://github.com/example-org/example-app" || resp.SourceRef != "v1.2.3" {
		t.Errorf("response = %+v", resp)
	}
}

func TestPatchSourceSetsTags(t *testing.T) {
	store := &fakeSourceStore{exists: true}
	rec := doPatch(t, store, true, patchTestID,
		`{"tags":["owner-b","production"]}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if store.gotRepo != nil || store.gotRef != nil {
		t.Errorf("stored repo/ref (%v, %v), want nil (untouched)", store.gotRepo, store.gotRef)
	}
	wantTags := []string{"owner-b", "production"}
	if store.gotTags == nil || strings.Join(*store.gotTags, ",") != strings.Join(wantTags, ",") {
		t.Errorf("stored tags = %v, want %v", store.gotTags, wantTags)
	}

	var resp patchSourceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	if strings.Join(resp.Tags, ",") != strings.Join(wantTags, ",") {
		t.Errorf("response tags = %v, want %v", resp.Tags, wantTags)
	}
}

func TestPatchSourceMergesInstanceWideTags(t *testing.T) {
	store := &fakeSourceStore{exists: true}
	cfg := &config.Config{
		AuthEnabled: true,
		Tags:        []string{"instance-tag"},
	}
	rec := doPatchWithConfig(t, store, cfg, patchTestID, `{"tags":["custom-tag"]}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	wantTags := []string{"custom-tag", "instance-tag"}
	if store.gotTags == nil || strings.Join(*store.gotTags, ",") != strings.Join(wantTags, ",") {
		t.Errorf("stored tags = %v, want %v", store.gotTags, wantTags)
	}
}

func TestPatchSourceEmptyTagsClearsCustomTags(t *testing.T) {
	store := &fakeSourceStore{exists: true, tags: []string{"old-custom"}}
	cfg := &config.Config{
		AuthEnabled: true,
		Tags:        []string{"instance-tag"},
	}
	rec := doPatchWithConfig(t, store, cfg, patchTestID, `{"tags":[]}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	wantTags := []string{"instance-tag"}
	if store.gotTags == nil || strings.Join(*store.gotTags, ",") != strings.Join(wantTags, ",") {
		t.Errorf("stored tags = %v, want %v (custom cleared, instance-wide preserved)", store.gotTags, wantTags)
	}
}

func TestPatchSourceEmptyTagsClearsAllWhenNoInstanceTags(t *testing.T) {
	store := &fakeSourceStore{exists: true, tags: []string{"old-custom"}}
	rec := doPatch(t, store, true, patchTestID, `{"tags":[]}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if store.gotTags == nil || len(*store.gotTags) != 0 {
		t.Errorf("stored tags = %v, want empty slice", store.gotTags)
	}

	var resp patchSourceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	if len(resp.Tags) != 0 {
		t.Errorf("response tags = %v, want empty array", resp.Tags)
	}
}

func TestPatchSourcePreservesTagsWhenOmitted(t *testing.T) {
	store := &fakeSourceStore{exists: true, repo: "https://github.com/old/repo", tags: []string{"keep-tag"}}
	rec := doPatch(t, store, true, patchTestID, `{"source_repo":"https://github.com/new/repo"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if store.gotRepo == nil || *store.gotRepo != "https://github.com/new/repo" {
		t.Errorf("gotRepo = %v, want new repo", store.gotRepo)
	}
	// Tags was not sent, so it must not be written to store (gotTags == nil).
	if store.gotTags != nil {
		t.Errorf("gotTags = %v, want nil (untouched column)", store.gotTags)
	}
	// The store's existing tags remain preserved.
	if strings.Join(store.tags, ",") != "keep-tag" {
		t.Errorf("store.tags = %v, want keep-tag preserved", store.tags)
	}
}

func TestPatchSourcePreservesSourceWhenOnlyTagsSent(t *testing.T) {
	store := &fakeSourceStore{exists: true, repo: "https://github.com/keep/repo", ref: "v1.0.0"}
	rec := doPatch(t, store, true, patchTestID, `{"tags":["new-tag"]}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if store.gotRepo != nil || store.gotRef != nil {
		t.Errorf("stored (%v, %v), want source columns untouched (nil)", store.gotRepo, store.gotRef)
	}
	if store.gotTags == nil || strings.Join(*store.gotTags, ",") != "new-tag" {
		t.Errorf("gotTags = %v, want new-tag", store.gotTags)
	}
	if store.repo != "https://github.com/keep/repo" || store.ref != "v1.0.0" {
		t.Errorf("store repo/ref = (%q, %q), want unchanged", store.repo, store.ref)
	}

	var resp patchSourceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	if resp.SourceRepo != "https://github.com/keep/repo" || resp.SourceRef != "v1.0.0" {
		t.Errorf("response source = (%q, %q), want preserved", resp.SourceRepo, resp.SourceRef)
	}
}

func TestPatchSourceNormalizesTags(t *testing.T) {
	store := &fakeSourceStore{exists: true}
	rec := doPatch(t, store, true, patchTestID, `{"tags":["  Production  ", "frontend", "PRODUCTION", ""]}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	wantTags := []string{"frontend", "production"}
	if store.gotTags == nil || strings.Join(*store.gotTags, ",") != strings.Join(wantTags, ",") {
		t.Errorf("gotTags = %v, want normalized %v", store.gotTags, wantTags)
	}
}

func TestPatchSourceRejectsCommaInTag(t *testing.T) {
	store := &fakeSourceStore{exists: true}
	rec := doPatch(t, store, true, patchTestID, `{"tags":["team,a"]}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for comma in tag", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "tags cannot contain commas") {
		t.Errorf("expected 'tags cannot contain commas' in body, got: %s", rec.Body.String())
	}
	if store.updateCalls != 0 {
		t.Error("update must not run when tag contains comma")
	}
}

func TestPatchSourceResponseRetainsEmptyFields(t *testing.T) {
	// Without omitempty, source_repo and source_ref must be present as empty strings.
	store := &fakeSourceStore{exists: true}
	rec := doPatch(t, store, true, patchTestID, `{"tags":["alpha"]}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	if v, ok := raw["source_repo"]; !ok || v != "" {
		t.Errorf("source_repo missing or not empty string: %v (raw: %v)", v, raw)
	}
	if v, ok := raw["source_ref"]; !ok || v != "" {
		t.Errorf("source_ref missing or not empty string: %v (raw: %v)", v, raw)
	}
	if _, ok := raw["tags"]; !ok {
		t.Errorf("tags missing from response: %v", raw)
	}
}

// Partial PATCH: the absent field keeps its current value.
func TestPatchSourcePartialKeepsOtherField(t *testing.T) {
	store := &fakeSourceStore{exists: true, repo: "https://github.com/old/repo", ref: "keep-me"}
	rec := doPatch(t, store, true, patchTestID, `{"source_repo":"https://github.com/new/repo"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if store.gotRepo == nil || *store.gotRepo != "https://github.com/new/repo" || store.gotRef != nil {
		t.Errorf("stored (%v, %v), want ref untouched", store.gotRepo, store.gotRef)
	}
	if store.ref != "keep-me" {
		t.Errorf("store.ref = %q, want keep-me", store.ref)
	}
}

// Explicit "" clears a field — how a wrong pin is removed.
func TestPatchSourceEmptyStringClears(t *testing.T) {
	store := &fakeSourceStore{exists: true, repo: "https://github.com/wrong/repo", ref: "wrong"}
	rec := doPatch(t, store, true, patchTestID, `{"source_repo":"","source_ref":""}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if store.gotRepo == nil || *store.gotRepo != "" || store.gotRef == nil || *store.gotRef != "" {
		t.Errorf("stored (%v, %v), want cleared", store.gotRepo, store.gotRef)
	}

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	if v, ok := raw["source_repo"]; !ok || v != "" {
		t.Errorf("source_repo not present or not empty string: %v", v)
	}
	if v, ok := raw["source_ref"]; !ok || v != "" {
		t.Errorf("source_ref not present or not empty string: %v", v)
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
	if store.gotRepo == nil || *store.gotRepo != "https://github.com/x/y" {
		t.Errorf("repo = %v, want normalised form", store.gotRepo)
	}
	if store.gotRef == nil || *store.gotRef != "v2.0" {
		t.Errorf("ref = %v, want inline ref extracted", store.gotRef)
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
		{"tag with comma", `{"tags":["team,a"]}`},
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
