package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/evidence"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

func TestParseReachability(t *testing.T) {
	tests := []struct {
		input   string
		wantVal string
		wantOK  bool
	}{
		{"", "", true},
		{"   ", "", true},
		{"reachable", "reachable", true},
		{"not_reachable", "not_reachable", true},
		{"unknown", "unknown", true},
		{"invalid", "", false},
		{"yes", "", false},
		{"true", "", false},
	}

	for _, tc := range tests {
		got, ok := parseReachability(tc.input)
		if ok != tc.wantOK {
			t.Errorf("parseReachability(%q) ok = %v, want %v", tc.input, ok, tc.wantOK)
		}
		if got != tc.wantVal {
			t.Errorf("parseReachability(%q) val = %q, want %q", tc.input, got, tc.wantVal)
		}
	}
}

func testEvidenceMux(authEnabled bool) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/sboms/{id}/evidence", func(w http.ResponseWriter, r *http.Request) {
		if !authEnabled {
			writeError(w, http.StatusForbidden, "Evidence ingest requires AUTH_ENABLED=true")
			return
		}
		sbomID := r.PathValue("id")
		if !isValidUUID(sbomID) {
			writeError(w, http.StatusBadRequest, "Invalid SBOM ID")
			return
		}
		ref := r.URL.Query().Get("ref")
		if ref == "" {
			ref = r.Header.Get("X-Evidence-Ref")
		}
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		report, err := evidence.ParseGovulncheck(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, &dto.ReachabilitySummary{
			SBOMID:        sbomID,
			Tool:          report.Tool,
			Ref:           ref,
			TotalFindings: report.TotalFindings,
			Reachable:     report.CalledCount,
			NotReachable:  report.TotalFindings - report.CalledCount,
			Timestamp:     "2026-11-11T12:00:00Z",
		})
	})
	return mux
}

func TestEvidenceHandler_AuthDisabledRejected(t *testing.T) {
	// Mutating endpoint must reject writes when AUTH_ENABLED=false (#535).
	mux := testEvidenceMux(false)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/c8734994-df7a-4ec6-8964-b8166c303115/evidence", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when AUTH_ENABLED=false, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEvidenceHandler_InvalidUUID(t *testing.T) {
	mux := testEvidenceMux(true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/not-a-uuid/evidence", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEvidenceHandler_MalformedPayload(t *testing.T) {
	mux := testEvidenceMux(true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/c8734994-df7a-4ec6-8964-b8166c303115/evidence", bytes.NewReader([]byte("{invalid")))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEvidenceHandler_EmptyConfigRejected(t *testing.T) {
	// Empty config lacks recognized identity and findings (#535).
	mux := testEvidenceMux(true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/c8734994-df7a-4ec6-8964-b8166c303115/evidence", bytes.NewReader([]byte(`{"config":{}}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty config, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEvidenceHandler_ValidPayload(t *testing.T) {
	mux := testEvidenceMux(true)

	govulnPayload := `{"config":{"scanner_name":"govulncheck","scanner_version":"v1.1.3"}}
{"osv":{"id":"GO-2022-0965","aliases":["CVE-2022-32149"]}}
{"finding":{"osv":"GO-2022-0965","trace":[{"module":"example.com/mod","package":"example.com/mod","function":"main"}]}}
{"osv":{"id":"GO-2023-1495","aliases":["CVE-2023-24538"]}}
{"finding":{"osv":"GO-2023-1495","trace":[]}}
`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/c8734994-df7a-4ec6-8964-b8166c303115/evidence?ref=job-99", bytes.NewReader([]byte(govulnPayload)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp dto.ReachabilitySummary
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Tool != "govulncheck v1.1.3" {
		t.Errorf("Tool = %q, want 'govulncheck v1.1.3'", resp.Tool)
	}
	if resp.Ref != "job-99" {
		t.Errorf("Ref = %q, want 'job-99'", resp.Ref)
	}
	if resp.Reachable != 1 || resp.NotReachable != 1 || resp.TotalFindings != 2 {
		t.Errorf("unexpected counts: %+v", resp)
	}
}
