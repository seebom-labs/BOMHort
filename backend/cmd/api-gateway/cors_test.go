package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCorsMiddleware_AllowMethods_ScopedToUploadRoute(t *testing.T) {
	h := corsMiddleware("*", okHandler())

	tests := []struct {
		path        string
		wantMethods string
	}{
		{"/api/v1/sboms", "GET, HEAD, OPTIONS"},
		{"/api/v1/stats/dashboard", "GET, HEAD, OPTIONS"},
		{"/api/v1/sboms/c8734994-df7a-4ec6-8964-b8166c303115/evidence", "GET, POST, OPTIONS"},
		{uploadPath, "GET, POST, OPTIONS"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, tc.path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if got := rec.Header().Get("Access-Control-Allow-Methods"); got != tc.wantMethods {
				t.Errorf("Access-Control-Allow-Methods for %s = %q, want %q", tc.path, got, tc.wantMethods)
			}
		})
	}
}

func TestCorsMiddlewareAllowsAndExposesRequestIDCrossOrigin(t *testing.T) {
	h := loggingAndRequestIDMiddleware(corsMiddleware("https://ui.example", okHandler()))

	preflight := httptest.NewRequest(http.MethodOptions, "/api/v1/stats/dashboard", nil)
	preflight.Header.Set("Origin", "https://ui.example")
	preflight.Header.Set("Access-Control-Request-Method", "GET")
	preflight.Header.Set("Access-Control-Request-Headers", "X-Request-ID")
	preflightRec := httptest.NewRecorder()
	h.ServeHTTP(preflightRec, preflight)
	if got := preflightRec.Header().Get("Access-Control-Allow-Origin"); got != "https://ui.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if got := strings.ToLower(preflightRec.Header().Get("Access-Control-Allow-Headers")); !strings.Contains(got, "x-request-id") {
		t.Fatalf("preflight allow headers omit X-Request-ID: %q", got)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/stats/dashboard", nil)
	request.Header.Set("Origin", "https://ui.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request)
	if got := strings.ToLower(rec.Header().Get("Access-Control-Expose-Headers")); !strings.Contains(got, "x-request-id") {
		t.Fatalf("response expose headers omit X-Request-ID: %q", got)
	}
	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatal("response did not include X-Request-ID")
	}
}
