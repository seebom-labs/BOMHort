package evidence

import (
	"strings"
	"testing"
)

func TestParseGovulncheckJSONLines(t *testing.T) {
	input := `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.1.3"}}
{"progress":{"message":"Scanning your code..."}}
{"osv":{"id":"GO-2022-0965","aliases":["CVE-2022-32149","GHSA-69ch-w2m2-3vjp"]}}
{"finding":{"osv":"GO-2022-0965","fixed_version":"v0.1.0","trace":[{"module":"example.com/mod","package":"example.com/mod","function":"main"}]}}
{"osv":{"id":"GO-2023-1495","aliases":["CVE-2023-24538"]}}
{"finding":{"osv":"GO-2023-1495","fixed_version":"v1.20.3","trace":[]}}
`

	report, err := ParseGovulncheck(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Tool != "govulncheck v1.1.3" {
		t.Errorf("Tool = %q, want 'govulncheck v1.1.3'", report.Tool)
	}
	if report.TotalFindings != 2 {
		t.Errorf("TotalFindings = %d, want 2", report.TotalFindings)
	}
	if report.CalledCount != 1 {
		t.Errorf("CalledCount = %d, want 1", report.CalledCount)
	}

	for _, id := range []string{"GO-2022-0965", "CVE-2022-32149", "GHSA-69ch-w2m2-3vjp"} {
		if !report.ReachableIDs[id] {
			t.Errorf("expected %s to be marked reachable", id)
		}
	}

	for _, id := range []string{"GO-2023-1495", "CVE-2023-24538"} {
		if report.ReachableIDs[id] {
			t.Errorf("expected %s NOT to be marked reachable", id)
		}
	}

	// Verify structured findings extraction (#535).
	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 structured findings, got %d", len(report.Findings))
	}
	for _, f := range report.Findings {
		switch f.OSV {
		case "GO-2022-0965":
			if !f.Reachable {
				t.Errorf("expected GO-2022-0965 to be reachable")
			}
			if f.Module != "example.com/mod" {
				t.Errorf("expected module 'example.com/mod', got %q", f.Module)
			}
		case "GO-2023-1495":
			if f.Reachable {
				t.Errorf("expected GO-2023-1495 to be not reachable")
			}
		default:
			t.Errorf("unexpected finding OSV: %s", f.OSV)
		}
	}
}

func TestParseGovulncheckJSONArray(t *testing.T) {
	input := `[
		{"config":{"scanner_name":"govulncheck","scanner_version":"1.2.0"}},
		{"osv":{"id":"GO-2024-0001","aliases":["CVE-2024-0001"]}},
		{"finding":{"osv":"GO-2024-0001","trace":[{"module":"example.com/mod","package":"example.com/mod","function":"run"}]}}
	]`

	report, err := ParseGovulncheck(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Tool != "govulncheck 1.2.0" {
		t.Errorf("Tool = %q, want 'govulncheck 1.2.0'", report.Tool)
	}
	if !report.ReachableIDs["GO-2024-0001"] || !report.ReachableIDs["CVE-2024-0001"] {
		t.Errorf("expected GO-2024-0001 and CVE-2024-0001 to be reachable")
	}
}

func TestParseGovulncheckErrors(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		_, err := ParseGovulncheck(strings.NewReader(""))
		if err == nil {
			t.Fatal("expected error for empty input")
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		_, err := ParseGovulncheck(strings.NewReader("{invalid json"))
		if err == nil {
			t.Fatal("expected error for malformed json")
		}
	})

	t.Run("unrecognized format", func(t *testing.T) {
		_, err := ParseGovulncheck(strings.NewReader(`{"unrelated_key": "val"}`))
		if err == nil {
			t.Fatal("expected error for unrecognized format")
		}
	})

	t.Run("empty config rejected", func(t *testing.T) {
		// Empty config lacks scanner identity and findings (#535).
		_, err := ParseGovulncheck(strings.NewReader(`{"config":{}}`))
		if err == nil {
			t.Fatal("expected error for empty config")
		}
		if !strings.Contains(err.Error(), "expected scanner_name 'govulncheck'") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("unrecognized scanner name rejected", func(t *testing.T) {
		_, err := ParseGovulncheck(strings.NewReader(`{"config":{"scanner_name":"trivy"}}`))
		if err == nil {
			t.Fatal("expected error for non-govulncheck scanner")
		}
		if !strings.Contains(err.Error(), "expected scanner_name 'govulncheck'") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("report with no findings rejected", func(t *testing.T) {
		// Valid scanner name but zero findings must be rejected (#535).
		input := `{"config":{"scanner_name":"govulncheck","scanner_version":"v1.1.3"}}
{"progress":{"message":"Scanning completed with no findings."}}`
		_, err := ParseGovulncheck(strings.NewReader(input))
		if err == nil {
			t.Fatal("expected error for report with no findings")
		}
		if !strings.Contains(err.Error(), "report contains no scan findings") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}
