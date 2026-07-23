package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCorsMiddleware_AllowMethods_ScopedToUploadRoute(t *testing.T) {
	h := corsMiddleware("*", okHandler())

	tests := []struct {
		path        string
		wantMethods string
	}{
		{"/api/v1/sboms", "GET, OPTIONS"},
		{"/api/v1/stats/dashboard", "GET, OPTIONS"},
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
