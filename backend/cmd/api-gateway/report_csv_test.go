package main

import (
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

type fakeVulnRows struct {
	items  []dto.VulnerabilityListItem
	i      int
	err    error
	closed bool
}

func (f *fakeVulnRows) Next() bool {
	if f.i >= len(f.items) {
		return false
	}
	f.i++
	return true
}
func (f *fakeVulnRows) Item() dto.VulnerabilityListItem { return f.items[f.i-1] }
func (f *fakeVulnRows) Err() error                      { return f.err }
func (f *fakeVulnRows) Close() error                    { f.closed = true; return nil }

var fixedNow = func() time.Time { return time.Date(2026, 10, 14, 23, 30, 0, 0, time.FixedZone("CEST", 2*3600)) }

func runReport(t *testing.T, url string, rows *fakeVulnRows, streamErr error) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var gotScope string
	h := vulnerabilityReportHandler(noParents, func(_ context.Context, scope string, _ clickhouse.VulnFilter) (vulnerabilityRows, error) {
		gotScope = scope
		if streamErr != nil {
			return nil, streamErr
		}
		return rows, nil
	}, fixedNow)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, url, nil))
	return rec, gotScope
}

func depth(d uint16) *uint16 { return &d }

func TestVulnerabilityReportCSV(t *testing.T) {
	rows := &fakeVulnRows{items: []dto.VulnerabilityListItem{
		{
			VulnID: "GO-2024-3333", CVEID: "CVE-2024-45338",
			Aliases:  []string{"CVE-2024-45338", "GHSA-w32m-9786-jp63"},
			Severity: "HIGH", PURL: "pkg:golang/golang.org/x/net@v0.21.0",
			Summary: "Non-linear parsing, \"quoted\", with a comma", FixedVersion: "v0.33.0",
			SourceFile: "etcd.spdx.json", DiscoveredAt: "2026-05-15T00:00:00Z",
			DependencyScope: "direct", DependencyDepth: depth(1), VEXStatus: "not_affected",
			Reachability: "not_reachable", EvidenceSource: "govulncheck v1.1.3",
			EvidenceRef: "job-42", EvidenceAt: "2026-05-15T01:00:00Z",
			ExploitAvailable: true, ExploitSources: []string{"nuclei", "exploitdb"},
		},
		{VulnID: "GHSA-aaaa-bbbb-cccc", Severity: "LOW", PURL: "pkg:npm/x@1", DependencyScope: "unknown"},
	}}
	rec, scope := runReport(t, "/api/v1/reports/vulnerabilities?format=csv&scope=direct", rows, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if scope != "direct" {
		t.Errorf("scope passed to the query = %q, want direct", scope)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/csv; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	// The date is the UTC date, not the server's local one.
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="bomhort-vulnerabilities-2026-10-14.csv"` {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if !rows.closed {
		t.Error("cursor not closed")
	}

	records, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("response is not valid CSV: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("want header + 2 rows, got %d: %v", len(records), records)
	}
	if strings.Join(records[0], ",") != strings.Join(vulnerabilityCSVHeader, ",") || records[0][0] != "cve_id" {
		t.Errorf("header = %v", records[0])
	}
	want := []string{"CVE-2024-45338", "GO-2024-3333", "CVE-2024-45338;GHSA-w32m-9786-jp63", "HIGH",
		"pkg:golang/golang.org/x/net@v0.21.0", "Non-linear parsing, \"quoted\", with a comma", "v0.33.0",
		"etcd.spdx.json", "2026-05-15T00:00:00Z", "direct", "1", "not_affected",
		"not_reachable", "govulncheck v1.1.3", "job-42", "2026-05-15T01:00:00Z", "true", "nuclei;exploitdb"}
	if strings.Join(records[1], "|") != strings.Join(want, "|") {
		t.Errorf("row 1 =\n%v\nwant\n%v", records[1], want)
	}
	// No CVE, no aliases, unknown depth: empty cells, not "0" or "null".
	if records[2][0] != "" || records[2][2] != "" || records[2][10] != "" || records[2][16] != "false" || records[2][17] != "" {
		t.Errorf("row 2 = %v", records[2])
	}
}

func TestVulnerabilityReportIgnoresLegacyVexFilter(t *testing.T) {
	// The JSON listing ignores vex_filter; the export must return the same rows.
	rows := &fakeVulnRows{items: []dto.VulnerabilityListItem{{VulnID: "CVE-2024-0001", VEXStatus: "not_affected"}}}
	rec, _ := runReport(t, "/api/v1/reports/vulnerabilities?format=csv&vex_filter=effective", rows, nil)
	if rec.Code != http.StatusOK || strings.Count(rec.Body.String(), "\n") != 2 {
		t.Errorf("status %d body %q", rec.Code, rec.Body.String())
	}
}

func TestVulnerabilityReportRejectsBadParams(t *testing.T) {
	for _, url := range []string{
		"/api/v1/reports/vulnerabilities",
		"/api/v1/reports/vulnerabilities?format=pdf",
		"/api/v1/reports/vulnerabilities?format=CSV",
		"/api/v1/reports/vulnerabilities?format=csv&scope=indirect",
		"/api/v1/reports/vulnerabilities?format=csv&exploit=yes",
	} {
		called := false
		h := vulnerabilityReportHandler(noParents, func(context.Context, string, clickhouse.VulnFilter) (vulnerabilityRows, error) {
			called = true
			return &fakeVulnRows{}, nil
		}, fixedNow)
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, url, nil))
		if rec.Code != http.StatusBadRequest || called {
			t.Errorf("%s: status %d, query run %v; want 400 without a query", url, rec.Code, called)
		}
	}
}

func TestVulnerabilityReportQueryFailureIsA500NotAnEmptyCSV(t *testing.T) {
	rec, _ := runReport(t, "/api/v1/reports/vulnerabilities?format=csv", nil, errors.New("boom"))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d", rec.Code)
	}
	if rec.Header().Get("Content-Disposition") != "" {
		t.Error("a failed export must not be offered as a file download")
	}
}

func TestVulnerabilityReportStreams(t *testing.T) {
	items := make([]dto.VulnerabilityListItem, csvFlushEvery*2+1)
	for i := range items {
		items[i] = dto.VulnerabilityListItem{VulnID: "CVE-2024-1000", Severity: "LOW"}
	}
	rows := &fakeVulnRows{items: items}
	rec, _ := runReport(t, "/api/v1/reports/vulnerabilities?format=csv", rows, nil)
	if !rec.Flushed {
		t.Error("rows were not flushed to the client while streaming")
	}
	if got := strings.Count(rec.Body.String(), "\n"); got != len(items)+1 {
		t.Errorf("lines = %d, want %d", got, len(items)+1)
	}
}

func TestCSVSafe(t *testing.T) {
	cases := map[string]string{
		"=HYPERLINK(\"x\")": "'=HYPERLINK(\"x\")",
		"+1":                "'+1",
		"-cmd":              "'-cmd",
		"@SUM(A1)":          "'@SUM(A1)",
		"\tx":               "'\tx",
		"CVE-2024-1":        "CVE-2024-1",
		"":                  "",
		"a=b":               "a=b",
	}
	for in, want := range cases {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVulnerabilityReportPassesExploitFilter(t *testing.T) {
	var got clickhouse.VulnFilter
	h := vulnerabilityReportHandler(noParents, func(_ context.Context, _ string, f clickhouse.VulnFilter) (vulnerabilityRows, error) {
		got = f
		return &fakeVulnRows{}, nil
	}, fixedNow)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/v1/reports/vulnerabilities?format=csv&exploit=available", nil))
	if rec.Code != http.StatusOK || !got.ExploitAvailable {
		t.Fatalf("status %d, filter %+v; want the exploit filter passed to the query", rec.Code, got)
	}
}
