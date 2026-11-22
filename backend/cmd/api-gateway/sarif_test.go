package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

func TestSARIFLevel(t *testing.T) {
	cases := []struct {
		severity string
		want     string
	}{
		{"CRITICAL", "error"},
		{"critical", "error"},
		{"HIGH", "error"},
		{"high", "error"},
		{"MEDIUM", "warning"},
		{"medium", "warning"},
		{"LOW", "note"},
		{"low", "note"},
		{"UNKNOWN", "none"},
		{"", "none"},
	}

	for _, tc := range cases {
		got := sarifLevel(tc.severity)
		if got != tc.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", tc.severity, got, tc.want)
		}
	}
}

func TestSARIFSecuritySeverity(t *testing.T) {
	cases := []struct {
		severity string
		want     string
	}{
		{"CRITICAL", "9.5"},
		{"critical", "9.5"},
		{"HIGH", "7.5"},
		{"high", "7.5"},
		{"MEDIUM", "5.0"},
		{"medium", "5.0"},
		{"LOW", "2.0"},
		{"low", "2.0"},
		{"UNKNOWN", ""},
		{"", ""},
	}

	for _, tc := range cases {
		got := sarifSecuritySeverity(tc.severity)
		if got != tc.want {
			t.Errorf("sarifSecuritySeverity(%q) = %q, want %q", tc.severity, got, tc.want)
		}
	}
}

func TestParsePURLPkg(t *testing.T) {
	cases := []struct {
		purl        string
		wantName    string
		wantVersion string
	}{
		{"pkg:golang/golang.org/x/net@v0.21.0", "golang.org/x/net", "v0.21.0"},
		{"pkg:npm/%40angular/core@17.0.0", "%40angular/core", "17.0.0"},
		{"pkg:npm/lodash@4.17.15", "lodash", "4.17.15"},
		{"pkg:deb/debian/curl@7.88.1?arch=amd64", "debian/curl", "7.88.1"},
		{"pkg:generic/myapp", "myapp", ""},
		{"custom-pkg@1.2.3", "custom-pkg", "1.2.3"},
		{"plain-name", "plain-name", ""},
		{"", "", ""},
	}

	for _, tc := range cases {
		name, ver := parsePURLPkg(tc.purl)
		if name != tc.wantName || ver != tc.wantVersion {
			t.Errorf("parsePURLPkg(%q) = (%q, %q), want (%q, %q)", tc.purl, name, ver, tc.wantName, tc.wantVersion)
		}
	}
}

func TestFormatPackage(t *testing.T) {
	cases := []struct {
		purl string
		want string
	}{
		{"pkg:golang/golang.org/x/net@v0.21.0", "golang.org/x/net@v0.21.0"},
		{"pkg:generic/myapp", "myapp"},
		{"", "unknown package"},
	}

	for _, tc := range cases {
		got := formatPackage(tc.purl)
		if got != tc.want {
			t.Errorf("formatPackage(%q) = %q, want %q", tc.purl, got, tc.want)
		}
	}
}

func TestBuildSARIF_Full(t *testing.T) {
	d := uint16(2)
	items := []dto.VulnerabilityListItem{
		{
			VulnID:           "CVE-2024-45338",
			Aliases:          []string{"CVE-2024-45338", "GHSA-w32m-9786-jp63"},
			Severity:         "HIGH",
			PURL:             "pkg:golang/golang.org/x/net@v0.21.0",
			Summary:          "HTTP/2 rapid reset",
			FixedVersion:     "v0.33.0",
			SourceFile:       "etcd.spdx.json",
			DependencyScope:  "direct",
			DependencyDepth:  &d,
			VEXStatus:        "not_affected",
			VEXJustification: "vulnerable_code_not_in_execute_path",
		},
		{
			VulnID:          "CVE-2024-45338",
			Severity:        "HIGH",
			PURL:            "pkg:golang/golang.org/x/net@v0.20.0",
			SourceFile:      "",
			DependencyScope: "transitive",
			VEXStatus:       "affected",
		},
		{
			VulnID:       "GHSA-1111-2222-3333",
			Severity:     "CRITICAL",
			PURL:         "pkg:npm/lodash@4.17.15",
			Summary:      "Prototype pollution",
			FixedVersion: "",
			SourceFile:   "package-lock.json",
			VEXStatus:    "fixed",
		},
	}

	logData := buildSARIF(items)

	if logData.Schema != sarifSchemaURI {
		t.Errorf("Schema = %q, want %q", logData.Schema, sarifSchemaURI)
	}
	if logData.Version != sarifSchemaVersion {
		t.Errorf("Version = %q, want %q", logData.Version, sarifSchemaVersion)
	}
	if len(logData.Runs) != 1 {
		t.Fatalf("len(Runs) = %d, want 1", len(logData.Runs))
	}

	run := logData.Runs[0]
	if run.Tool.Driver.Name != "BOMHort" {
		t.Errorf("Driver.Name = %q, want BOMHort", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.InformationURI != sarifInfoURI {
		t.Errorf("Driver.InformationURI = %q", run.Tool.Driver.InformationURI)
	}

	// 2 distinct rules, sorted deterministically by ID: CVE-2024-45338, GHSA-1111-2222-3333.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("len(Rules) = %d, want 2", len(run.Tool.Driver.Rules))
	}
	rule0 := run.Tool.Driver.Rules[0]
	if rule0.ID != "CVE-2024-45338" {
		t.Errorf("Rule 0 ID = %q, want CVE-2024-45338", rule0.ID)
	}
	if rule0.ShortDescription == nil || rule0.ShortDescription.Text != "HTTP/2 rapid reset" {
		t.Errorf("Rule 0 ShortDescription = %+v", rule0.ShortDescription)
	}
	if rule0.HelpURI != "https://osv.dev/vulnerability/CVE-2024-45338" {
		t.Errorf("Rule 0 HelpURI = %q", rule0.HelpURI)
	}
	if rule0.Properties["security-severity"] != "7.5" {
		t.Errorf("Rule 0 security-severity = %v, want 7.5", rule0.Properties["security-severity"])
	}

	rule1 := run.Tool.Driver.Rules[1]
	if rule1.ID != "GHSA-1111-2222-3333" {
		t.Errorf("Rule 1 ID = %q, want GHSA-1111-2222-3333", rule1.ID)
	}
	if rule1.Properties["security-severity"] != "9.5" {
		t.Errorf("Rule 1 security-severity = %v, want 9.5", rule1.Properties["security-severity"])
	}

	// Results verification.
	if len(run.Results) != 3 {
		t.Fatalf("len(Results) = %d, want 3", len(run.Results))
	}

	res0 := run.Results[0]
	if res0.RuleID != "CVE-2024-45338" {
		t.Errorf("Res 0 RuleID = %q", res0.RuleID)
	}
	if res0.Level != "error" {
		t.Errorf("Res 0 Level = %q, want error", res0.Level)
	}
	wantMsg0 := "golang.org/x/net@v0.21.0 is affected by CVE-2024-45338 (fixed in: v0.33.0)"
	if res0.Message.Text != wantMsg0 {
		t.Errorf("Res 0 Message = %q, want %q", res0.Message.Text, wantMsg0)
	}
	if len(res0.Locations) != 1 || res0.Locations[0].PhysicalLocation.ArtifactLocation.URI != "etcd.spdx.json" {
		t.Errorf("Res 0 Locations = %+v", res0.Locations)
	}
	if res0.Properties["dependency_scope"] != "direct" {
		t.Errorf("Res 0 dependency_scope = %v", res0.Properties["dependency_scope"])
	}
	if res0.Properties["dependency_depth"] != uint16(2) {
		t.Errorf("Res 0 dependency_depth = %v", res0.Properties["dependency_depth"])
	}
	if len(res0.Suppressions) != 1 {
		t.Fatalf("len(res0.Suppressions) = %d, want 1", len(res0.Suppressions))
	}
	if res0.Suppressions[0].Kind != "external" || res0.Suppressions[0].Justification != "not_affected: vulnerable_code_not_in_execute_path" {
		t.Errorf("Res 0 Suppressions = %+v", res0.Suppressions)
	}

	// Res 1: empty source file falls back to PURL, affected status produces no suppression.
	res1 := run.Results[1]
	if len(res1.Locations) != 1 || res1.Locations[0].PhysicalLocation.ArtifactLocation.URI != "pkg:golang/golang.org/x/net@v0.20.0" {
		t.Errorf("Res 1 Locations = %+v", res1.Locations)
	}
	if len(res1.Suppressions) != 0 {
		t.Errorf("Res 1 should have no suppressions, got %+v", res1.Suppressions)
	}

	// Res 2: no fix available message, fixed VEX status produces suppression.
	res2 := run.Results[2]
	wantMsg2 := "lodash@4.17.15 is affected by GHSA-1111-2222-3333 (no fix available)"
	if res2.Message.Text != wantMsg2 {
		t.Errorf("Res 2 Message = %q, want %q", res2.Message.Text, wantMsg2)
	}
	if len(res2.Suppressions) != 1 || res2.Suppressions[0].Justification != "fixed" {
		t.Errorf("Res 2 Suppressions = %+v", res2.Suppressions)
	}
}

func TestBuildSARIF_Empty(t *testing.T) {
	logData := buildSARIF(nil)
	data, err := json.Marshal(logData)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	runs := parsed["runs"].([]interface{})
	if len(runs) != 1 {
		t.Fatalf("len(runs) = %d, want 1", len(runs))
	}
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	if results == nil || len(results) != 0 {
		t.Errorf("results = %v, want empty array []", results)
	}

	driver := run["tool"].(map[string]interface{})["driver"].(map[string]interface{})
	rules := driver["rules"].([]interface{})
	if rules == nil || len(rules) != 0 {
		t.Errorf("rules = %v, want empty array []", rules)
	}
}

func TestVulnerabilityReportSARIF(t *testing.T) {
	rows := &fakeVulnRows{items: []dto.VulnerabilityListItem{
		{
			VulnID:          "CVE-2024-45338",
			Severity:        "HIGH",
			PURL:            "pkg:golang/golang.org/x/net@v0.21.0",
			Summary:         "HTTP/2 rapid reset",
			FixedVersion:    "v0.33.0",
			SourceFile:      "etcd.spdx.json",
			DependencyScope: "direct",
			VEXStatus:       "not_affected",
		},
	}}

	rec, scope := runReport(t, "/api/v1/reports/vulnerabilities?format=sarif&scope=direct", rows, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if scope != "direct" {
		t.Errorf("scope = %q, want direct", scope)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/sarif+json" {
		t.Errorf("Content-Type = %q, want application/sarif+json", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="bomhort-vulnerabilities-2026-10-14.sarif"` {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}

	var sarif SARIFLog
	if err := json.Unmarshal(rec.Body.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid SARIF response: %v", err)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
		t.Fatalf("unexpected runs/results: %+v", sarif)
	}
	if sarif.Runs[0].Results[0].RuleID != "CVE-2024-45338" {
		t.Errorf("RuleID = %q", sarif.Runs[0].Results[0].RuleID)
	}
}

func TestVulnerabilityReportSARIF_StreamError(t *testing.T) {
	rec, _ := runReport(t, "/api/v1/reports/vulnerabilities?format=sarif", nil, errors.New("boom"))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if rec.Header().Get("Content-Disposition") != "" {
		t.Error("failed SARIF export must not have Content-Disposition header")
	}
}

func TestSBOMVulnerabilitiesSARIFHandler(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/sboms/{id}/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		sbomID := r.PathValue("id")
		if !isValidUUID(sbomID) {
			writeError(w, http.StatusBadRequest, "Invalid SBOM ID")
			return
		}
		format := r.URL.Query().Get("format")
		if format != "" && format != "sarif" {
			writeError(w, http.StatusBadRequest, "Invalid format (expected sarif)")
			return
		}
		vulns := []dto.VulnerabilityListItem{
			{
				VulnID:       "CVE-2024-1111",
				Severity:     "HIGH",
				PURL:         "pkg:npm/foo@1.0.0",
				FixedVersion: "1.0.1",
			},
		}
		if format == "sarif" {
			writeSARIF(w, http.StatusOK, vulns)
			return
		}
		writeJSON(w, http.StatusOK, vulns)
	})

	// Happy path: format=sarif
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms/00000000-0000-0000-0000-000000000001/vulnerabilities?format=sarif", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/sarif+json" {
		t.Errorf("Content-Type = %q, want application/sarif+json", ct)
	}
	var sarif SARIFLog
	if err := json.Unmarshal(rec.Body.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid SARIF json: %v", err)
	}
	if len(sarif.Runs[0].Results) != 1 || sarif.Runs[0].Results[0].RuleID != "CVE-2024-1111" {
		t.Errorf("unexpected results: %+v", sarif.Runs[0].Results)
	}

	// JSON fallback without format param
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms/00000000-0000-0000-0000-000000000001/vulnerabilities", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	// Invalid format returns 400
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms/00000000-0000-0000-0000-000000000001/vulnerabilities?format=csv", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestProjectVulnerabilitiesSARIFHandler(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/projects/{name}/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		name := sanitizeProjectName(r.PathValue("name"))
		if name == "" {
			writeError(w, http.StatusBadRequest, "Invalid project name")
			return
		}
		format := r.URL.Query().Get("format")
		if format != "" && format != "sarif" {
			writeError(w, http.StatusBadRequest, "Invalid format (expected sarif)")
			return
		}
		items := []dto.VulnerabilityListItem{
			{
				VulnID:       "CVE-2024-2222",
				Severity:     "CRITICAL",
				PURL:         "pkg:golang/bar@v2.0.0",
				FixedVersion: "v2.0.1",
			},
		}
		if format == "sarif" {
			writeSARIF(w, http.StatusOK, items)
			return
		}
		writeJSON(w, http.StatusOK, items)
	})

	// Happy path: format=sarif
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/my-project/vulnerabilities?format=sarif", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/sarif+json" {
		t.Errorf("Content-Type = %q, want application/sarif+json", ct)
	}
	var sarif SARIFLog
	if err := json.Unmarshal(rec.Body.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid SARIF json: %v", err)
	}
	if len(sarif.Runs[0].Results) != 1 || sarif.Runs[0].Results[0].RuleID != "CVE-2024-2222" {
		t.Errorf("unexpected results: %+v", sarif.Runs[0].Results)
	}

	// Invalid format returns 400
	req = httptest.NewRequest(http.MethodGet, "/api/v1/projects/my-project/vulnerabilities?format=pdf", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
