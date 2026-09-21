package vex

import (
	"strings"
	"testing"
)

// TestParse_Provenance verifies that document-level author/role/tooling and
// statement-level status_notes are captured on every extracted statement (#334).
func TestParse_Provenance(t *testing.T) {
	doc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://example-org.dev/vex/example-app-2026-09-17",
		"author": "Security Team",
		"role": "automated vulnerability triage",
		"tooling": "VEXViper/0.1.0",
		"timestamp": "2026-09-17T08:00:00Z",
		"version": 1,
		"statements": [
			{
				"vulnerability": {"name": "CVE-2026-0001"},
				"products": [{"@id": "pkg:golang/example.com/app@v1.2.3"}],
				"status": "not_affected",
				"justification": "vulnerable_code_not_present",
				"status_notes": "confidence=0.94; call graph shows the vulnerable symbol is never reachable"
			},
			{
				"vulnerability": {"name": "CVE-2026-0002"},
				"products": [{"@id": "pkg:golang/example.com/app@v1.2.3"}],
				"status": "under_investigation"
			}
		]
	}`

	result, err := Parse(strings.NewReader(doc), "example.openvex.json")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(result.Statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(result.Statements))
	}

	for i, stmt := range result.Statements {
		if stmt.Author != "Security Team" {
			t.Errorf("statement %d: author = %q, want %q", i, stmt.Author, "Security Team")
		}
		if stmt.Role != "automated vulnerability triage" {
			t.Errorf("statement %d: role = %q, want %q", i, stmt.Role, "automated vulnerability triage")
		}
		if stmt.Tooling != "VEXViper/0.1.0" {
			t.Errorf("statement %d: tooling = %q, want %q", i, stmt.Tooling, "VEXViper/0.1.0")
		}
	}

	// status_notes is per statement: set on the first, empty on the second.
	if want := "confidence=0.94; call graph shows the vulnerable symbol is never reachable"; result.Statements[0].StatusNotes != want {
		t.Errorf("statement 0: status_notes = %q, want %q", result.Statements[0].StatusNotes, want)
	}
	if result.Statements[1].StatusNotes != "" {
		t.Errorf("statement 1: status_notes = %q, want empty", result.Statements[1].StatusNotes)
	}
}

// TestParse_ProvenanceAbsent verifies that documents without provenance fields
// (all pre-#334 documents) still parse and leave the fields empty.
func TestParse_ProvenanceAbsent(t *testing.T) {
	doc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://example-org.dev/vex/minimal",
		"statements": [
			{
				"vulnerability": {"name": "CVE-2026-0003"},
				"products": [{"@id": "pkg:npm/left-pad@1.3.0"}],
				"status": "fixed"
			}
		]
	}`

	result, err := Parse(strings.NewReader(doc), "minimal.openvex.json")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(result.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(result.Statements))
	}
	s := result.Statements[0]
	if s.Author != "" || s.Role != "" || s.Tooling != "" || s.StatusNotes != "" {
		t.Errorf("expected empty provenance, got author=%q role=%q tooling=%q status_notes=%q",
			s.Author, s.Role, s.Tooling, s.StatusNotes)
	}
}
