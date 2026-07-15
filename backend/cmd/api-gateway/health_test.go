package main

import (
	"context"
	"errors"
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

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }
func TestLivezHandler_AlwaysOK(t *testing.T) {
	rec := httptest.NewRecorder()
	livezHandler()(rec, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("livez: expected 200, got %d", rec.Code)
	}
}
func TestReadyzHandler_Healthy(t *testing.T) {
	rec := httptest.NewRecorder()
	readyzHandler(fakePinger{err: nil})(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("readyz healthy: expected 200, got %d", rec.Code)
	}
}
func TestReadyzHandler_DBDown(t *testing.T) {
	rec := httptest.NewRecorder()
	readyzHandler(fakePinger{err: errors.New("connection refused")})(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz db down: expected 503, got %d", rec.Code)
	}
}
