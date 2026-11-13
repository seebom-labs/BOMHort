package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSanitizeProjectName pins the contract that a project name is an
// identity, not a search term (#398): characters a project can legitimately
// carry survive, control characters do not.
func TestSanitizeProjectName(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"kubernetes", "kubernetes"},
		{"  kubernetes  ", "kubernetes"},
		// The org/project fallback shape must round-trip; sanitizeSearchTerm
		// would have been wrong here in spirit (it strips nothing for "/"
		// today, but it strips "&", "'" and ";" which a name may carry).
		{"cncf/kubernetes", "cncf/kubernetes"},
		{"tom&jerry", "tom&jerry"},
		{"o'reilly", "o'reilly"},
		// Control characters and NUL are garbage, not identity.
		{"kube\x00rnetes", "kubernetes"},
		{"kube\x1bnetes", "kubenetes"},
		{"kube\x7fnetes", "kubenetes"},
		{"", ""},
		{"   ", ""},
	}
	for _, tt := range tests {
		if got := sanitizeProjectName(tt.in); got != tt.want {
			t.Errorf("sanitizeProjectName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}

	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	if got := sanitizeProjectName(string(long)); len(got) != 256 {
		t.Errorf("length cap: got %d, want 256", len(got))
	}
}

// TestProjectRoutes_PathValueDecoding guards the routing assumptions the
// project endpoints rely on: a percent-encoded slash stays inside {name}
// (so org%2Fproject reaches the detail handler as "org/project"), the
// sub-resource routes still match behind such a name, and the pre-existing
// literal /projects/license-compliance keeps winning over {name}.
//
// It uses a bare mux with stub handlers rather than the real ones: the
// question is what net/http does with the pattern, not what ClickHouse
// returns.
func TestProjectRoutes_PathValueDecoding(t *testing.T) {
	mux := http.NewServeMux()
	echo := func(prefix string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(prefix + ":" + r.PathValue("name")))
		}
	}
	mux.HandleFunc("GET /api/v1/projects/license-compliance", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("literal"))
	})
	mux.HandleFunc("GET /api/v1/projects/{name}", echo("detail"))
	mux.HandleFunc("GET /api/v1/projects/{name}/sboms", echo("sboms"))
	mux.HandleFunc("GET /api/v1/projects/{name}/vulnerabilities", echo("vulns"))
	mux.HandleFunc("GET /api/v1/projects/{name}/packages", echo("packages"))
	mux.HandleFunc("GET /api/v1/projects/{name}/vex", echo("vex"))

	tests := []struct {
		path, want string
	}{
		{"/api/v1/projects/kubernetes", "detail:kubernetes"},
		{"/api/v1/projects/kubernetes/sboms", "sboms:kubernetes"},
		{"/api/v1/projects/kubernetes/vulnerabilities", "vulns:kubernetes"},
		{"/api/v1/projects/kubernetes/packages", "packages:kubernetes"},
		{"/api/v1/projects/kubernetes/vex", "vex:kubernetes"},
		{"/api/v1/projects/cncf%2Fkubernetes", "detail:cncf/kubernetes"},
		{"/api/v1/projects/cncf%2Fkubernetes/sboms", "sboms:cncf/kubernetes"},
		{"/api/v1/projects/cncf%2Fkubernetes/vex", "vex:cncf/kubernetes"},
		{"/api/v1/projects/license-compliance", "literal"},
		{"/api/v1/projects/a%20b", "detail:a b"},
	}
	for _, tt := range tests {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d", tt.path, rec.Code)
			continue
		}
		if got := rec.Body.String(); got != tt.want {
			t.Errorf("%s: routed to %q, want %q", tt.path, got, tt.want)
		}
	}

	// An unencoded slash is a different path and must NOT reach detail with
	// "cncf/kubernetes" — it is either the sboms route or nothing. This is
	// why the UI must encode the name.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/projects/cncf/kubernetes", nil))
	if rec.Body.String() == "detail:cncf/kubernetes" {
		t.Errorf("unencoded slash reached the detail handler; encoding would be pointless")
	}
}

// The VEX export (#533) puts the project name into a quoted
// Content-Disposition filename; nothing that could end the quote or the
// header may survive.
func TestSafeFileName(t *testing.T) {
	for in, want := range map[string]string{
		"payments-api":        "payments-api",
		"cncf/kubernetes":     "cncf-kubernetes",
		"v1.2_rc":             "v1.2_rc",
		"a\"b\r\nSet-Cookie:": "a-b--Set-Cookie-",
		"ünïcode":             "-n-code",
	} {
		if got := safeFileName(in); got != want {
			t.Errorf("safeFileName(%q) = %q, want %q", in, got, want)
		}
	}
}
