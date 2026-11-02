package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
)

func TestArchivedPackagesHandler(t *testing.T) {
	const id = "6f2b525a-fbde-5b43-aa92-ac06a3f7220d"
	for _, tt := range []struct {
		name, url, wantScope string
		queryErr             error
		status               int
	}{
		{"unscoped", "/api/v1/packages/archived", "", nil, http.StatusOK},
		{"scoped", "/api/v1/packages/archived?sbom_id=" + id, id, nil, http.StatusOK},
		{"invalid sbom_id", "/api/v1/packages/archived?sbom_id=x'--", "", nil, http.StatusBadRequest},
		{"query error", "/api/v1/packages/archived", "", errors.New("boom"), http.StatusInternalServerError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var gotScope string
			called := false
			h := archivedPackagesHandler(func(_ context.Context, sbomID string) ([]clickhouse.ArchivedPackageInfo, error) {
				called, gotScope = true, sbomID
				return []clickhouse.ArchivedPackageInfo{}, tt.queryErr
			})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.url, nil))
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tt.status, rec.Body)
			}
			if tt.status == http.StatusBadRequest && called {
				t.Fatal("invalid sbom_id reached the query")
			}
			if gotScope != tt.wantScope {
				t.Fatalf("scope = %q, want %q", gotScope, tt.wantScope)
			}
			if tt.status == http.StatusOK && rec.Body.String() != "[]\n" {
				t.Fatalf("body = %q, want []", rec.Body)
			}
		})
	}
}
