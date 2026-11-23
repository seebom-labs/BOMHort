package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthMiddleware_PublicPaths_LivezReadyz(t *testing.T) {
	h := authMiddleware(true, false, "secret-token", nil, okHandler())

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

func TestSanitizeLogParam(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain string unchanged",
			input:    "cluster-prod-1",
			expected: "cluster-prod-1",
		},
		{
			name:     "strips newlines and carriage returns",
			input:    "line1\r\nline2\nline3\r",
			expected: "line1line2line3",
		},
		{
			name:     "strips ANSI escapes, NUL, and control characters",
			input:    "\x1b[31;1mCRITICAL\x1b[0m\x00\a\b\f\x7flog",
			expected: "[31;1mCRITICAL[0mlog",
		},
		{
			name:     "strips tab characters",
			input:    "col1\tcol2",
			expected: "col1col2",
		},
		{
			name:     "strips C1 control characters (U+0080 to U+009F)",
			input:    "a\u009b31mb",
			expected: "a31mb",
		},
		{
			name:     "strips C1 next-line character (U+0085)",
			input:    "line1\u0085line2",
			expected: "line1line2",
		},
		{
			name:     "preserves exact 200 characters without ellipsis",
			input:    strings.Repeat("a", 200),
			expected: strings.Repeat("a", 200),
		},
		{
			name:     "truncates strings exceeding 200 runes with ellipsis",
			input:    strings.Repeat("a", 205),
			expected: strings.Repeat("a", 200) + "...",
		},
		{
			name:     "unicode multi-byte safe truncation",
			input:    strings.Repeat("日", 210),
			expected: strings.Repeat("日", 200) + "...",
		},
		{
			name:     "ignores control characters when counting rune bounds",
			input:    strings.Repeat("\n", 50) + strings.Repeat("x", 200),
			expected: strings.Repeat("x", 200),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeLogParam(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeLogParam(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
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
