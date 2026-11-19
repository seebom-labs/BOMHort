package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func guardedHandler(t *testing.T, token string, origins []string) (http.Handler, *bool) {
	t.Helper()
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	return httpGuard(next, token, origins), &reached
}

func do(t *testing.T, h http.Handler, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestGuardRejectsMissingAndWrongToken(t *testing.T) {
	h, reached := guardedHandler(t, "s3cret", []string{"https://agent.example"})

	cases := map[string]map[string]string{
		"no credentials":   {},
		"wrong bearer":     {"Authorization": "Bearer nope"},
		"wrong api key":    {"X-API-Key": "nope"},
		"empty bearer":     {"Authorization": "Bearer "},
		"prefix of token":  {"Authorization": "Bearer s3cre"},
		"token plus extra": {"X-API-Key": "s3cretx"},
	}
	for name, headers := range cases {
		t.Run(name, func(t *testing.T) {
			*reached = false
			rec := do(t, h, headers)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
			if *reached {
				t.Error("the MCP handler was reached without a valid token")
			}
			if got := rec.Header().Get("WWW-Authenticate"); got == "" {
				t.Error("401 without a WWW-Authenticate header")
			}
		})
	}
}

func TestGuardAcceptsBothCredentialSpellings(t *testing.T) {
	for name, headers := range map[string]map[string]string{
		"bearer":  {"Authorization": "Bearer s3cret"},
		"api key": {"X-API-Key": "s3cret"},
	} {
		t.Run(name, func(t *testing.T) {
			h, reached := guardedHandler(t, "s3cret", []string{"https://agent.example"})
			rec := do(t, h, headers)
			if rec.Code != http.StatusOK || !*reached {
				t.Errorf("status = %d, reached = %v, want 200/true", rec.Code, *reached)
			}
		})
	}
}

// CVE-2026-33252 in one test: a page the victim happens to have open must not
// be able to drive this server, even though the browser sends the user's
// credentials for it.
func TestGuardRejectsUnknownOriginBeforeCheckingTheToken(t *testing.T) {
	h, reached := guardedHandler(t, "s3cret", []string{"https://agent.example"})

	rec := do(t, h, map[string]string{
		"Origin":        "https://evil.example",
		"Authorization": "Bearer s3cret",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if *reached {
		t.Error("a cross-origin request reached the MCP handler")
	}
}

func TestGuardAcceptsAllowedOriginIgnoringCaseAndTrailingSlash(t *testing.T) {
	h, _ := guardedHandler(t, "s3cret", []string{"https://Agent.Example/"})

	for _, origin := range []string{"https://agent.example", "https://agent.example/", "https://AGENT.example"} {
		rec := do(t, h, map[string]string{"Origin": origin, "Authorization": "Bearer s3cret"})
		if rec.Code != http.StatusOK {
			t.Errorf("origin %q: status = %d, want 200", origin, rec.Code)
		}
	}
}

// A CLI MCP client sends no Origin at all. Treating "absent" as "unknown"
// would make the HTTP transport unusable for exactly the clients it is for.
func TestGuardAllowsRequestWithoutOrigin(t *testing.T) {
	h, reached := guardedHandler(t, "s3cret", []string{"https://agent.example"})

	rec := do(t, h, map[string]string{"Authorization": "Bearer s3cret"})
	if rec.Code != http.StatusOK || !*reached {
		t.Errorf("status = %d, reached = %v, want 200/true", rec.Code, *reached)
	}
}

// An empty token would otherwise mean "everything matches the empty string".
func TestGuardWithoutTokenRejectsEverything(t *testing.T) {
	h, reached := guardedHandler(t, "", []string{"https://agent.example"})

	rec := do(t, h, map[string]string{"Authorization": "Bearer "})
	if rec.Code != http.StatusUnauthorized || *reached {
		t.Errorf("status = %d, reached = %v, want 401/false", rec.Code, *reached)
	}
}

func TestSanitizeHeaderStripsControlCharacters(t *testing.T) {
	got := sanitizeHeader("https://evil\r\nWARN: forged log line")
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("sanitizeHeader kept newlines: %q", got)
	}
	if gotC1 := sanitizeHeader("https://evil\u009b31m.example"); gotC1 != "https://evil31m.example" {
		t.Errorf("sanitizeHeader kept C1 control sequence: %q", gotC1)
	}
	truncated := sanitizeHeader(strings.Repeat("a", 500))
	if len(truncated) > 205 || !strings.HasSuffix(truncated, "...") {
		t.Errorf("sanitizeHeader did not truncate properly: %q", truncated)
	}
}
