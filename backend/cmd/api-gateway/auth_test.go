package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/apikey"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
}

func TestAuthMiddleware_Disabled_AllowsAllRequests(t *testing.T) {
	h := authMiddleware(false, false, "", nil, nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/dashboard", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 when auth disabled, got %d", rec.Code)
	}
}

func TestAuthMiddleware_Enabled_RejectsMissingCredential(t *testing.T) {
	h := authMiddleware(true, false, "secret", nil, nil, okHandler())

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
	h := authMiddleware(true, false, "correct-secret", nil, nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req.Header.Set("Authorization", "Bearer wrong-secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", rec.Code)
	}
}

func TestAuthMiddleware_Enabled_AcceptsValidBearerToken(t *testing.T) {
	h := authMiddleware(true, false, "my-service-token", nil, nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req.Header.Set("Authorization", "Bearer my-service-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with valid Bearer token, got %d", rec.Code)
	}
}

func TestAuthMiddleware_Enabled_AcceptsValidServiceTokenHeader(t *testing.T) {
	h := authMiddleware(true, false, "my-service-token", nil, nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req.Header.Set("X-Service-Token", "my-service-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with valid X-Service-Token, got %d", rec.Code)
	}
}

func TestAuthMiddleware_Enabled_AcceptsValidAPIKey(t *testing.T) {
	h := authMiddleware(true, false, "", []string{"key1", "key2", "key3"}, nil, okHandler())

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
	h := authMiddleware(true, false, "", []string{"key1", "key2"}, nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid API key, got %d", rec.Code)
	}
}

func TestAuthMiddleware_Enabled_BothModesCanCoexist(t *testing.T) {
	h := authMiddleware(true, false, "service-secret", []string{"api-key-1"}, nil, okHandler())

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
	h := authMiddleware(true, false, "secret", nil, nil, okHandler())

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
	h := authMiddleware(true, false, "secret", nil, nil, okHandler())

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/sboms", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("OPTIONS preflight: expected 200 without auth, got %d", rec.Code)
	}
}

func TestAuthMiddleware_EmptyBearerRejected(t *testing.T) {
	h := authMiddleware(true, false, "secret", nil, nil, okHandler())

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
	h := authMiddleware(true, false, "", nil, nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when no credentials configured, got %d", rec.Code)
	}
}

func TestAuthMiddleware_BadgesPublic_AllowsBadgePathsWithoutAuth(t *testing.T) {
	h := authMiddleware(true, true, "secret", nil, nil, okHandler())

	badgePaths := []string{
		"/api/v1/badges/projects/my-project/vulnerabilities.svg",
		"/api/v1/badges/projects/my-project/licenses.svg",
		"/api/v1/badges/projects/org%2Frepo/vulnerabilities.svg",
		"/api/v1/badges/projects/org%2Frepo/licenses.svg",
		"/api/v1/badges/projects/org/repo/vulnerabilities.svg",
		"/api/v1/badges/projects/org/repo/licenses.svg",
	}

	for _, p := range badgePaths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 for badge path %s when BADGES_PUBLIC=true, got %d", p, rec.Code)
		}

		// Non-GET requests (e.g. POST) must still be rejected
		postReq := httptest.NewRequest(http.MethodPost, p, nil)
		postRec := httptest.NewRecorder()
		h.ServeHTTP(postRec, postReq)
		if postRec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for non-GET badge request on %s, got %d", p, postRec.Code)
		}
	}

	// Paths that are not exact badge endpoints must not bypass auth
	invalidPaths := []string{
		"/api/v1/badges/",
		"/api/v1/badges/projects/",
		"/api/v1/badges/projects/my-project",
		"/api/v1/badges/projects/my-project/other.svg",
		"/api/v1/badges/projects//vulnerabilities.svg",
		"/api/v1/badges/projects//licenses.svg",
	}
	for _, p := range invalidPaths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for invalid badge path %s when BADGES_PUBLIC=true, got %d", p, rec.Code)
		}
	}
}

func TestAuthMiddleware_BadgesPrivate_RejectsBadgePathsWithoutAuth(t *testing.T) {
	h := authMiddleware(true, false, "secret", nil, nil, okHandler())

	badgePaths := []string{
		"/api/v1/badges/projects/my-project/vulnerabilities.svg",
		"/api/v1/badges/projects/my-project/licenses.svg",
		"/api/v1/badges/projects/org%2Frepo/vulnerabilities.svg",
		"/api/v1/badges/projects/org%2Frepo/licenses.svg",
		"/api/v1/badges/projects/org/repo/vulnerabilities.svg",
		"/api/v1/badges/projects/org/repo/licenses.svg",
	}

	for _, p := range badgePaths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for badge path %s when BADGES_PUBLIC=false, got %d", p, rec.Code)
		}
	}
}

func TestAuthMiddleware_NamedAPIKeys(t *testing.T) {
	namedKeys := []apikey.Key{
		{
			Name:   "ci-key",
			Secret: "ci-secret-123",
			Scope: apikey.Scope{
				Origins: []string{"ci"},
			},
		},
		{
			Name:   "scanner-key",
			Secret: "scanner-secret-456",
		},
	}

	var capturedKey *apikey.Key
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedKey = apikey.FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	h := authMiddleware(true, false, "", nil, namedKeys, handler)

	// Valid named key via X-API-Key
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req.Header.Set("X-API-Key", "ci-secret-123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid named API key, got %d", rec.Code)
	}
	if capturedKey == nil || capturedKey.Name != "ci-key" {
		t.Errorf("expected captured key with name 'ci-key', got %+v", capturedKey)
	}

	// Valid second named key
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req.Header.Set("X-API-Key", "scanner-secret-456")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with second named key, got %d", rec.Code)
	}
	if capturedKey == nil || capturedKey.Name != "scanner-key" {
		t.Errorf("expected captured key with name 'scanner-key', got %+v", capturedKey)
	}

	// Invalid key
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	req.Header.Set("X-API-Key", "wrong-secret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong key secret, got %d", rec.Code)
	}
}

func TestAuthMiddleware_AllThreeModesCanCoexist(t *testing.T) {
	namedKeys := []apikey.Key{
		{Name: "named-1", Secret: "named-secret"},
	}
	flatKeys := []string{"flat-secret"}
	serviceToken := "service-secret"

	h := authMiddleware(true, false, serviceToken, flatKeys, namedKeys, okHandler())

	for _, tc := range []struct {
		name   string
		header string
		val    string
	}{
		{"bearer service token", "Authorization", "Bearer service-secret"},
		{"x-service-token", "X-Service-Token", "service-secret"},
		{"flat api key", "X-API-Key", "flat-secret"},
		{"named api key", "X-API-Key", "named-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
			req.Header.Set(tc.header, tc.val)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("%s: expected 200, got %d", tc.name, rec.Code)
			}
		})
	}
}
