package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
}

func TestAuthMiddleware_Disabled_AllowsAllRequests(t *testing.T) {
	h := authMiddleware(false, "", nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/dashboard", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 when auth disabled, got %d", rec.Code)
	}
}

func TestAuthMiddleware_Enabled_RejectsMissingCredential(t *testing.T) {
	h := authMiddleware(true, "secret", nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing credential, got %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Error("expected WWW-Authenticate header on 401")
	}
}

func TestAuthMiddleware_Enabled_RejectsInvalidToken(t *testing.T) {
	h := authMiddleware(true, "correct-secret", nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req.Header.Set("Authorization", "Bearer wrong-secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", rec.Code)
	}
}

func TestAuthMiddleware_Enabled_AcceptsValidBearerToken(t *testing.T) {
	h := authMiddleware(true, "my-service-token", nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req.Header.Set("Authorization", "Bearer my-service-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with valid Bearer token, got %d", rec.Code)
	}
}

func TestAuthMiddleware_Enabled_AcceptsValidServiceTokenHeader(t *testing.T) {
	h := authMiddleware(true, "my-service-token", nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req.Header.Set("X-Service-Token", "my-service-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with valid X-Service-Token, got %d", rec.Code)
	}
}

func TestAuthMiddleware_Enabled_AcceptsValidAPIKey(t *testing.T) {
	h := authMiddleware(true, "", []string{"key1", "key2", "key3"}, okHandler())

	for _, k := range []string{"key1", "key2", "key3"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
		req.Header.Set("X-API-Key", k)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 with valid API key %q, got %d", k, rec.Code)
		}
	}
}

func TestAuthMiddleware_Enabled_RejectsInvalidAPIKey(t *testing.T) {
	h := authMiddleware(true, "", []string{"key1", "key2"}, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid API key, got %d", rec.Code)
	}
}

func TestAuthMiddleware_Enabled_BothModesCanCoexist(t *testing.T) {
	h := authMiddleware(true, "service-secret", []string{"api-key-1"}, okHandler())

	// Service token via Bearer.
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req1.Header.Set("Authorization", "Bearer service-secret")
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Errorf("Bearer service-token: expected 200, got %d", rec1.Code)
	}

	// API key via X-API-Key.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req2.Header.Set("X-API-Key", "api-key-1")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("X-API-Key: expected 200, got %d", rec2.Code)
	}
}

func TestAuthMiddleware_PublicPathsBypassAuth(t *testing.T) {
	h := authMiddleware(true, "secret", nil, okHandler())

	for _, path := range []string{"/healthz", "/livez", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		// No auth header.
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("public path %q: expected 200 without auth, got %d", path, rec.Code)
		}
	}
}

func TestAuthMiddleware_OptionsPreflightBypassesAuth(t *testing.T) {
	h := authMiddleware(true, "secret", nil, okHandler())

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/sboms", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("OPTIONS preflight: expected 200 without auth, got %d", rec.Code)
	}
}

func TestAuthMiddleware_EmptyBearerRejected(t *testing.T) {
	h := authMiddleware(true, "secret", nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	// Bearer with empty token.
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for empty bearer token, got %d", rec.Code)
	}
}

func TestAuthMiddleware_EnabledWithNoConfiguredCredentials_RejectsAll(t *testing.T) {
	// AUTH_ENABLED=true but no service token and no API keys configured.
	// This is a misconfiguration — all authenticated requests must fail.
	h := authMiddleware(true, "", nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when no credentials configured, got %d", rec.Code)
	}
}
