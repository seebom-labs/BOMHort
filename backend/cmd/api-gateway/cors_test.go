package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/config"
)

func TestCorsMiddleware_AllowMethods_ScopedToUploadRoute(t *testing.T) {
	h := corsMiddleware(&config.Config{CORSAllowedOrigins: "*"}, okHandler())

	tests := []struct {
		path        string
		wantMethods string
	}{
		{"/api/v1/sboms", "GET, HEAD, OPTIONS"},
		{"/api/v1/stats/dashboard", "GET, HEAD, OPTIONS"},
		{"/api/v1/sboms/c8734994-df7a-4ec6-8964-b8166c303115/evidence", "GET, POST, OPTIONS"},
		{uploadPath, "GET, POST, OPTIONS"},
		{"/api/v1/sboms/c8734994-df7a-4ec6-8964-b8166c303115", "GET, HEAD, PATCH, OPTIONS"},
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

func TestCorsMiddleware_ConfigurableMethods(t *testing.T) {
	cfg := &config.Config{
		CORSAllowedOrigins: "*",
		CORSAllowedMethods: "GET, POST, PATCH, DELETE, OPTIONS",
	}
	h := corsMiddleware(cfg, okHandler())

	for _, path := range []string{"/api/v1/sboms", uploadPath, "/api/v1/sboms/c8734994-df7a-4ec6-8964-b8166c303115"} {
		req := httptest.NewRequest(http.MethodOptions, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if got := rec.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST, PATCH, DELETE, OPTIONS" {
			t.Errorf("Access-Control-Allow-Methods for %s = %q, want overridden methods", path, got)
		}
	}
}

func TestCorsMiddleware_ConfigurableHeaders(t *testing.T) {
	// Default headers
	hDefault := corsMiddleware(&config.Config{CORSAllowedOrigins: "*"}, okHandler())
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/sboms", nil)
	rec := httptest.NewRecorder()
	hDefault.ServeHTTP(rec, req)
	wantDefaultHeaders := "Content-Type, Authorization, X-Service-Token, X-API-Key, X-Filename, X-Evidence-Ref"
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got != wantDefaultHeaders {
		t.Errorf("default headers = %q, want %q", got, wantDefaultHeaders)
	}

	// Custom headers
	cfgCustom := &config.Config{
		CORSAllowedOrigins: "*",
		CORSAllowedHeaders: "Authorization, Content-Type, X-Custom-Header",
	}
	hCustom := corsMiddleware(cfgCustom, okHandler())
	recCustom := httptest.NewRecorder()
	hCustom.ServeHTTP(recCustom, req)
	if got := recCustom.Header().Get("Access-Control-Allow-Headers"); got != "Authorization, Content-Type, X-Custom-Header" {
		t.Errorf("custom headers = %q, want %q", got, "Authorization, Content-Type, X-Custom-Header")
	}
}

func TestCorsMiddleware_Credentials_AllowedWithSpecificOrigin(t *testing.T) {
	cfg := &config.Config{
		CORSAllowedOrigins:   "https://dashboard.example.com, https://admin.internal",
		CORSAllowCredentials: true,
	}
	h := corsMiddleware(cfg, okHandler())

	// Matched origin gets credentials header and Vary: Origin
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req.Header.Set("Origin", "https://dashboard.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://dashboard.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want https://dashboard.example.com", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want true", got)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want Origin", got)
	}

	// Unmatched origin does not get origin or credentials header
	reqUnmatched := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	reqUnmatched.Header.Set("Origin", "https://unauthorized.evil.com")
	recUnmatched := httptest.NewRecorder()
	h.ServeHTTP(recUnmatched, reqUnmatched)

	if got := recUnmatched.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q for unauthorized origin, want empty", got)
	}
	if got := recUnmatched.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("Access-Control-Allow-Credentials = %q for unauthorized origin, want empty", got)
	}
}

func TestCorsMiddleware_Credentials_DisallowedWithWildcardOrigin(t *testing.T) {
	// W3C CORS specification forbids credentials when origin is wildcard "*"
	cfg := &config.Config{
		CORSAllowedOrigins:   "*",
		CORSAllowCredentials: true,
	}
	h := corsMiddleware(cfg, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req.Header.Set("Origin", "https://dashboard.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("Access-Control-Allow-Credentials = %q with wildcard origin, want empty", got)
	}
}

func TestCorsMiddleware_ConfigurableMaxAge(t *testing.T) {
	// Default max-age is 86400
	hDefault := corsMiddleware(&config.Config{CORSAllowedOrigins: "*"}, okHandler())
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/sboms", nil)
	rec := httptest.NewRecorder()
	hDefault.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Max-Age"); got != "86400" {
		t.Errorf("default max-age = %q, want 86400", got)
	}

	// Custom max-age
	hCustom := corsMiddleware(&config.Config{CORSAllowedOrigins: "*", CORSMaxAge: 3600}, okHandler())
	recCustom := httptest.NewRecorder()
	hCustom.ServeHTTP(recCustom, req)
	if got := recCustom.Header().Get("Access-Control-Max-Age"); got != "3600" {
		t.Errorf("custom max-age = %q, want 3600", got)
	}
}

func TestCorsMiddleware_PreflightOptions(t *testing.T) {
	cfg := &config.Config{
		CORSAllowedOrigins:   "https://app.example.com",
		CORSAllowedMethods:   "GET, POST, OPTIONS",
		CORSAllowedHeaders:   "Content-Type, Authorization",
		CORSAllowCredentials: true,
		CORSMaxAge:           7200,
	}
	calledNext := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledNext = true
	})

	h := corsMiddleware(cfg, nextHandler)
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/sboms", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204 No Content for OPTIONS preflight", rec.Code)
	}
	if calledNext {
		t.Error("preflight OPTIONS must not call next handler")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST, OPTIONS" {
		t.Errorf("Access-Control-Allow-Methods = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got != "Content-Type, Authorization" {
		t.Errorf("Access-Control-Allow-Headers = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Max-Age"); got != "7200" {
		t.Errorf("Access-Control-Max-Age = %q", got)
	}
}
