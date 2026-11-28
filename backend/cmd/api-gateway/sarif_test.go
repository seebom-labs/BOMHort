package main

import (
	"encoding/json"
	"errors"
	"fmt"
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

func TestCleanArtifactLocation(t *testing.T) {
	cases := []struct {
		input   string
		want    string
		wantOK  bool
	}{
		{
			input:  "pushed/550e8400-e29b-41d4-a716-446655440000-package-lock.json",
			want:   "package-lock.json",
			wantOK: true,
		},
		{
			input:  "pushed\\550e8400-e29b-41d4-a716-446655440000-package-lock.json",
			want:   "package-lock.json",
			wantOK: true,
		},
		{
			input:  "s3://my-bucket/pushed/550e8400-e29b-41d4-a716-446655440000-package-lock.json",
			want:   "package-lock.json",
			wantOK: true,
		},
		{
			input:  "s3://my-bucket/myprefix/pushed/550e8400-e29b-41d4-a716-446655440000-nested/dir/go.mod",
			want:   "nested/dir/go.mod",
			wantOK: true,
		},
		{
			input:  "src/package.json",
			want:   "src/package.json",
			wantOK: true,
		},
		{
			input:  "etcd.spdx.json",
			want:   "etcd.spdx.json",
			wantOK: true,
		},
		{
			input:  "s3://my-bucket/scan-folder/etcd.spdx.json",
			want:   "",
			wantOK: false,
		},
		{
			input:  "",
			want:   "",
			wantOK: false,
		},
		{
			input:  "pkg:npm/foo@1.0.0",
			want:   "",
			wantOK: false,
		},
		{
			input:  "../traversal/file.json",
			want:   "",
			wantOK: false,
		},
	}

	for _, tc := range cases {
		got, ok := cleanArtifactLocation(tc.input)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("cleanArtifactLocation(%q) = (%q, %v), want (%q, %v)", tc.input, got, ok, tc.want, tc.wantOK)
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
	cvssScore := 8.8
	items := []dto.VulnerabilityListItem{
		{
			VulnID:           "CVE-2024-45338",
			Aliases:          []string{"CVE-2024-45338", "GHSA-w32m-9786-jp63"},
			Severity:         "HIGH",
			CVSSScore:        &cvssScore,
			PURL:             "pkg:golang/golang.org/x/net@v0.21.0",
			Summary:          "HTTP/2 rapid reset",
			FixedVersion:     "v0.33.0",
			SourceFile:       "pushed/550e8400-e29b-41d4-a716-446655440000-etcd.spdx.json",
			DependencyScope:  "direct",
			DependencyDepth:  &d,
			VEXStatus:        "not_affected",
			VEXJustification: "vulnerable_code_not_in_execute_path",
		},
		{
			VulnID:          "CVE-2024-45338",
			Severity:        "HIGH",
			PURL:            "pkg:golang/golang.org/x/net@v0.20.0",
			SourceFile:      "s3://bucket/unpushed/sbom.json",
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

	// 2 distinct rules sorted deterministically by ID: CVE-2024-45338, GHSA-1111-2222-3333.
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
	if rule0.Properties["security-severity"] != "8.8" {
		t.Errorf("Rule 0 security-severity = %v, want 8.8", rule0.Properties["security-severity"])
	}

	rule1 := run.Tool.Driver.Rules[1]
	if rule1.ID != "GHSA-1111-2222-3333" {
		t.Errorf("Rule 1 ID = %q, want GHSA-1111-2222-3333", rule1.ID)
	}
	// No CVSS score provided for GHSA-1111-2222-3333, must not have invented security-severity.
	if rule1.Properties != nil && rule1.Properties["security-severity"] != nil {
		t.Errorf("Rule 1 security-severity must be omitted when absent, got %v", rule1.Properties["security-severity"])
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
	// Pushed UUID prefix stripped -> etcd.spdx.json
	if len(res0.Locations) != 1 || res0.Locations[0].PhysicalLocation.ArtifactLocation.URI != "etcd.spdx.json" {
		t.Errorf("Res 0 Locations = %+v, want etcd.spdx.json", res0.Locations)
	}
	if res0.CorrelationGUID == "" {
		t.Error("Res 0 must have non-empty CorrelationGUID")
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

	// Res 1: non-pushed S3 URI has no repo location, must omit Locations and preserve source_file in properties.
	res1 := run.Results[1]
	if len(res1.Locations) != 0 {
		t.Errorf("Res 1 Locations must be empty for S3 non-pushed URI, got %+v", res1.Locations)
	}
	if res1.Properties["source_file"] != "s3://bucket/unpushed/sbom.json" {
		t.Errorf("Res 1 source_file property = %v", res1.Properties["source_file"])
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
	if len(res2.Locations) != 1 || res2.Locations[0].PhysicalLocation.ArtifactLocation.URI != "package-lock.json" {
		t.Errorf("Res 2 Locations = %+v, want package-lock.json", res2.Locations)
	}
	if len(res2.Suppressions) != 1 || res2.Suppressions[0].Justification != "fixed" {
		t.Errorf("Res 2 Suppressions = %+v", res2.Suppressions)
	}
}

func TestBuildSARIF_CVSSAndAggregation(t *testing.T) {
	scoreLow := 2.5
	scoreHigh := 9.8

	rowLow := dto.VulnerabilityListItem{
		VulnID:    "CVE-2024-9999",
		Severity:  "LOW",
		CVSSScore: &scoreLow,
		PURL:      "pkg:npm/foo@1.0.0",
	}
	rowCrit := dto.VulnerabilityListItem{
		VulnID:    "CVE-2024-9999",
		Severity:  "CRITICAL",
		CVSSScore: &scoreHigh,
		PURL:      "pkg:npm/bar@1.0.0",
	}

	// Order 1: LOW first, then CRITICAL
	log1 := buildSARIF([]dto.VulnerabilityListItem{rowLow, rowCrit})
	rule1 := log1.Runs[0].Tool.Driver.Rules[0]
	if rule1.Properties["security-severity"] != "9.8" {
		t.Errorf("log1 rule security-severity = %v, want 9.8", rule1.Properties["security-severity"])
	}

	// Order 2: CRITICAL first, then LOW (must be deterministic regardless of slice order)
	log2 := buildSARIF([]dto.VulnerabilityListItem{rowCrit, rowLow})
	rule2 := log2.Runs[0].Tool.Driver.Rules[0]
	if rule2.Properties["security-severity"] != "9.8" {
		t.Errorf("log2 rule security-severity = %v, want 9.8", rule2.Properties["security-severity"])
	}

	// Finding without any CVSS score: rule must omit security-severity property entirely.
	rowNoScore := dto.VulnerabilityListItem{
		VulnID:   "CVE-2024-0001",
		Severity: "HIGH",
		PURL:     "pkg:npm/baz@1.0.0",
	}
	logNoScore := buildSARIF([]dto.VulnerabilityListItem{rowNoScore})
	ruleNoScore := logNoScore.Runs[0].Tool.Driver.Rules[0]
	if ruleNoScore.Properties != nil && ruleNoScore.Properties["security-severity"] != nil {
		t.Errorf("security-severity should be omitted when absent, got %v", ruleNoScore.Properties["security-severity"])
	}
}

func TestBuildSARIF_TwoVersionSuppressionRegression(t *testing.T) {
	// Finding with 2 affected SBOMs in project, but only 1 covered by VEX -> MUST NOT be suppressed.
	partiallyCovered := dto.VulnerabilityListItem{
		VulnID:           "CVE-2024-8888",
		Severity:         "HIGH",
		PURL:             "pkg:npm/lib@1.0.0",
		VEXStatus:        "not_affected",
		VEXJustification: "vulnerable_code_not_in_execute_path",
		AffectedSBOMs:    2,
		VEXAffectedSBOMs: 1,
	}
	logPartial := buildSARIF([]dto.VulnerabilityListItem{partiallyCovered})
	if len(logPartial.Runs[0].Results[0].Suppressions) != 0 {
		t.Errorf("partially assessed project finding must not be suppressed, got suppressions: %+v", logPartial.Runs[0].Results[0].Suppressions)
	}

	// Finding with 2 affected SBOMs and both covered by VEX -> MUST be suppressed.
	fullyCovered := dto.VulnerabilityListItem{
		VulnID:           "CVE-2024-8888",
		Severity:         "HIGH",
		PURL:             "pkg:npm/lib@1.0.0",
		VEXStatus:        "not_affected",
		VEXJustification: "vulnerable_code_not_in_execute_path",
		AffectedSBOMs:    2,
		VEXAffectedSBOMs: 2,
	}
	logFull := buildSARIF([]dto.VulnerabilityListItem{fullyCovered})
	if len(logFull.Runs[0].Results[0].Suppressions) != 1 {
		t.Fatalf("fully assessed project finding must be suppressed, got: %+v", logFull.Runs[0].Results[0].Suppressions)
	}
	if logFull.Runs[0].Results[0].Suppressions[0].Justification != "not_affected: vulnerable_code_not_in_execute_path" {
		t.Errorf("unexpected justification: %q", logFull.Runs[0].Results[0].Suppressions[0].Justification)
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

func TestSBOMVulnerabilitiesSARIFHandler(t *testing.T) {
	knownID := "00000000-0000-0000-0000-000000000001"
	cleanID := "00000000-0000-0000-0000-000000000002"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/sboms/{id}/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		sbomID := r.PathValue("id")
		if !isValidUUID(sbomID) {
			writeError(w, http.StatusBadRequest, "Invalid SBOM ID")
			return
		}
		if sbomID != knownID && sbomID != cleanID {
			writeError(w, http.StatusNotFound, "SBOM not found")
			return
		}
		format := r.URL.Query().Get("format")
		if format != "" && format != "sarif" {
			writeError(w, http.StatusBadRequest, "Invalid format (expected sarif)")
			return
		}
		var vulns []dto.VulnerabilityListItem
		if sbomID == knownID {
			vulns = []dto.VulnerabilityListItem{
				{
					VulnID:       "CVE-2024-1111",
					Severity:     "HIGH",
					PURL:         "pkg:npm/foo@1.0.0",
					FixedVersion: "1.0.1",
				},
			}
		}
		if format == "sarif" {
			writeSARIF(w, http.StatusOK, vulns)
			return
		}
		writeJSON(w, http.StatusOK, vulns)
	})

	// Missing SBOM returns 404
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms/00000000-0000-0000-0000-000000000099/vulnerabilities?format=sarif", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing SBOM status = %d, want 404", rec.Code)
	}

	// Genuinely clean SBOM returns 200 with empty SARIF results
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms/"+cleanID+"/vulnerabilities?format=sarif", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("clean SBOM status = %d, want 200", rec.Code)
	}
	var cleanLog SARIFLog
	if err := json.Unmarshal(rec.Body.Bytes(), &cleanLog); err != nil {
		t.Fatalf("invalid SARIF json: %v", err)
	}
	if len(cleanLog.Runs[0].Results) != 0 {
		t.Errorf("clean SBOM should have 0 results, got %d", len(cleanLog.Runs[0].Results))
	}

	// Known SBOM with findings
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms/"+knownID+"/vulnerabilities?format=sarif", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
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
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms/"+knownID+"/vulnerabilities", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	// Invalid format returns 400
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms/"+knownID+"/vulnerabilities?format=csv", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestProjectVulnerabilitiesSARIFHandler(t *testing.T) {
	knownProject := "my-project"
	cleanProject := "clean-project"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/projects/{name}/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		name := sanitizeProjectName(r.PathValue("name"))
		if name == "" {
			writeError(w, http.StatusBadRequest, "Invalid project name")
			return
		}
		if name != knownProject && name != cleanProject {
			writeError(w, http.StatusNotFound, "Project not found")
			return
		}
		format := r.URL.Query().Get("format")
		if format != "" && format != "sarif" {
			writeError(w, http.StatusBadRequest, "Invalid format (expected sarif)")
			return
		}
		var items []dto.VulnerabilityListItem
		if name == knownProject {
			items = []dto.VulnerabilityListItem{
				{
					VulnID:       "CVE-2024-2222",
					Severity:     "CRITICAL",
					PURL:         "pkg:golang/bar@v2.0.0",
					FixedVersion: "v2.0.1",
				},
			}
		}
		if format == "sarif" {
			writeSARIF(w, http.StatusOK, items)
			return
		}
		writeJSON(w, http.StatusOK, items)
	})

	// Missing project returns 404
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/non-existent/vulnerabilities?format=sarif", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing project status = %d, want 404", rec.Code)
	}

	// Genuinely clean project returns 200 with empty SARIF results
	req = httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+cleanProject+"/vulnerabilities?format=sarif", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("clean project status = %d, want 200", rec.Code)
	}
	var cleanLog SARIFLog
	if err := json.Unmarshal(rec.Body.Bytes(), &cleanLog); err != nil {
		t.Fatalf("invalid SARIF json: %v", err)
	}
	if len(cleanLog.Runs[0].Results) != 0 {
		t.Errorf("clean project should have 0 results, got %d", len(cleanLog.Runs[0].Results))
	}

	// Known project with findings
	req = httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+knownProject+"/vulnerabilities?format=sarif", nil)
	rec = httptest.NewRecorder()
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
	req = httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+knownProject+"/vulnerabilities?format=pdf", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
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

func TestVulnerabilityReportSARIF_ResultLimitsAndPartitioning(t *testing.T) {
	// Generate 25,005 items to exceed GitHub's 25,000 result limit.
	totalItems := 25005
	items := make([]dto.VulnerabilityListItem, totalItems)
	for i := 0; i < totalItems; i++ {
		items[i] = dto.VulnerabilityListItem{
			VulnID:   fmt.Sprintf("CVE-2024-%05d", i),
			Severity: "HIGH",
			PURL:     fmt.Sprintf("pkg:npm/pkg-%d@1.0.0", i),
		}
	}

	// 1. Unpartitioned request above limit must return 400 rather than silently dropping findings.
	rowsUnbounded := &fakeVulnRows{items: items}
	recUnbounded, _ := runReport(t, "/api/v1/reports/vulnerabilities?format=sarif", rowsUnbounded, nil)
	if recUnbounded.Code != http.StatusBadRequest {
		t.Fatalf("unbounded large export status = %d, want 400", recUnbounded.Code)
	}

	// 2. Partitioned request with ?limit=25000&offset=0 succeeds, returns 25,000 items and Link next.
	rowsPart1 := &fakeVulnRows{items: items}
	recPart1, _ := runReport(t, "/api/v1/reports/vulnerabilities?format=sarif&limit=25000&offset=0", rowsPart1, nil)
	if recPart1.Code != http.StatusOK {
		t.Fatalf("partition 1 status = %d, body = %s", recPart1.Code, recPart1.Body.String())
	}
	if recPart1.Header().Get("X-Has-More") != "true" {
		t.Errorf("partition 1 X-Has-More = %q, want true", recPart1.Header().Get("X-Has-More"))
	}
	if link := recPart1.Header().Get("Link"); link == "" {
		t.Error("partition 1 must include Link header for next page")
	}
	var sarifPart1 SARIFLog
	if err := json.Unmarshal(recPart1.Body.Bytes(), &sarifPart1); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if len(sarifPart1.Runs[0].Results) != 25000 {
		t.Errorf("len(Results) = %d, want 25000", len(sarifPart1.Runs[0].Results))
	}

	// 3. Partition 2 with offset=25000 returns the remaining 5 items with X-Has-More: false.
	rowsPart2 := &fakeVulnRows{items: items}
	recPart2, _ := runReport(t, "/api/v1/reports/vulnerabilities?format=sarif&limit=25000&offset=25000", rowsPart2, nil)
	if recPart2.Code != http.StatusOK {
		t.Fatalf("partition 2 status = %d", recPart2.Code)
	}
	if recPart2.Header().Get("X-Has-More") != "false" {
		t.Errorf("partition 2 X-Has-More = %q, want false", recPart2.Header().Get("X-Has-More"))
	}
	var sarifPart2 SARIFLog
	if err := json.Unmarshal(recPart2.Body.Bytes(), &sarifPart2); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if len(sarifPart2.Runs[0].Results) != 5 {
		t.Errorf("len(Results) = %d, want 5", len(sarifPart2.Runs[0].Results))
	}

	// 4. Exceeding 25,000 limit parameter returns 400.
	rowsLimitOver := &fakeVulnRows{items: items[:10]}
	recOver, _ := runReport(t, "/api/v1/reports/vulnerabilities?format=sarif&limit=30000", rowsLimitOver, nil)
	if recOver.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for limit > 25000", recOver.Code)
	}

	// 5. Invalid offset returns 400.
	recInvalidOffset, _ := runReport(t, "/api/v1/reports/vulnerabilities?format=sarif&offset=invalid", rowsLimitOver, nil)
	if recInvalidOffset.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for invalid offset", recInvalidOffset.Code)
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
