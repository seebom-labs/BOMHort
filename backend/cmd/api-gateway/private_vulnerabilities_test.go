package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/privatevuln"
	"github.com/seebom-labs/bomhort/backend/internal/rulesource"
)

func TestPrivateVulnerabilitiesHandler_Empty(t *testing.T) {
	watcher, err := privatevuln.Watch(rulesource.Options{
		Paths: []string{filepath.Join(t.TempDir(), "nonexistent.json")},
	})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if _, err := watcher.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/private-vulnerabilities", nil)
	rec := httptest.NewRecorder()
	privateVulnerabilitiesHandler(watcher).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var entries []privatevuln.Entry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestPrivateVulnerabilitiesHandler_Populated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private-vulnerabilities.json")
	doc := `[
		{
			"id": "BOMHORT-2024-001",
			"summary": "Internal security finding",
			"details": "Details of private finding",
			"references": [
				{"type": "ADVISORY", "url": "https://security.example.com/BOMHORT-2024-001"}
			],
			"affected": [
				{
					"package": {
						"name": "internal-tool",
						"ecosystem": "npm",
						"purl": "pkg:npm/internal-tool"
					},
					"versions": ["1.0.0"]
				}
			]
		},
		{
			"id": "BOMHORT-2024-WITHDRAWN",
			"summary": "Withdrawn internal finding",
			"withdrawn": "2026-01-01T00:00:00Z",
			"affected": []
		}
	]`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	watcher, err := privatevuln.Watch(rulesource.Options{
		Paths: []string{path},
	})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if _, err := watcher.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/private-vulnerabilities", nil)
	rec := httptest.NewRecorder()
	privateVulnerabilitiesHandler(watcher).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var entries []privatevuln.Entry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "BOMHORT-2024-001" {
		t.Fatalf("entries = %+v", entries)
	}
	if entries[0].Details != "Details of private finding" {
		t.Errorf("details = %q", entries[0].Details)
	}
	if len(entries[0].References) != 1 || entries[0].References[0].URL != "https://security.example.com/BOMHORT-2024-001" {
		t.Errorf("references = %+v", entries[0].References)
	}
}

func TestParseSource(t *testing.T) {
	tests := []struct {
		raw   string
		want  string
		valid bool
	}{
		{"", "", true},
		{"private", "private", true},
		{"PRIVATE", "private", true},
		{"osv", "osv", true},
		{"wolfi", "wolfi", true},
		{"cgr.dev", "cgr.dev", true},
		{"invalid source with spaces", "", false},
		{"invalid/slash", "", false},
	}

	for _, tc := range tests {
		got, ok := parseSource(tc.raw)
		if ok != tc.valid {
			t.Errorf("parseSource(%q) ok = %v, want %v", tc.raw, ok, tc.valid)
		}
		if got != tc.want {
			t.Errorf("parseSource(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}
