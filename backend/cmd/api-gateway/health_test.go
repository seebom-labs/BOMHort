package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMiddleware_PublicPaths_LivezReadyz(t *testing.T) {
	h := authMiddleware(true, "secret-token", nil, okHandler())

	for _, path := range []string{"/healthz", "/livez", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 for public path %s with auth enabled, got %d", path, rec.Code)
		}
	}
}

func TestSanitizeClusterName(t *testing.T) {
	// Cluster names are sanitized via sanitizeLogParam for logging.
	// Ensure names with newlines are stripped.
	result := sanitizeLogParam("my-cluster\ninjected")
	if result != "my-clusterinjected" {
		t.Errorf("expected newline stripped, got %q", result)
	}
}
