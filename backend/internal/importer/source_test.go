package importer

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// appCDX has nested components, a BOM-Link ref, a ref without a purl, a
// purl used directly as ref, and a finding without analysis.
const appCDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "metadata": {"component": {"bom-ref": "app", "name": "payments-api", "version": "1.4.0"}},
  "components": [
    {"bom-ref": "c-log4j", "name": "log4j-core", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
     "components": [{"bom-ref": "c-api", "name": "log4j-api", "purl": "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1"}]},
    {"bom-ref": "c-nopurl", "name": "vendored"}
  ],
  "vulnerabilities": [
    {"id": "CVE-2021-44228", "references": [{"id": "GHSA-jfh8-c2jp-5v3q"}],
     "analysis": {"state": "not_affected", "justification": "code_not_reachable", "detail": "JNDI lookups disabled.",
                  "firstIssued": "2022-01-01T00:00:00Z", "lastUpdated": "2022-02-01T10:00:00Z"},
     "affects": [{"ref": "c-log4j"}, {"ref": "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#c-api"}]},
    {"id": "CVE-2023-0001", "analysis": {"state": "resolved"}, "affects": [{"ref": "c-nopurl"}]},
    {"id": "GHSA-xxxx-yyyy-zzzz", "analysis": {"state": "in_triage"}, "affects": [{"ref": "pkg:npm/left-pad@1.3.0"}]},
    {"id": "CVE-2024-9999", "affects": [{"ref": "c-log4j"}]}
  ]
}`

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDirSource_ListProjects(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "team-a/payments.cdx.json", appCDX)
	writeFile(t, dir, "unnamed.json", `{"bomFormat":"CycloneDX","specVersion":"1.4"}`)
	writeFile(t, dir, "doc.spdx.json", `{"spdxVersion":"SPDX-2.3"}`)
	writeFile(t, dir, "old.openvex.json", `{"@context":"https://openvex.dev/ns/v0.2.0"}`)
	writeFile(t, dir, "config.json", `{"hello":"world"}`)
	writeFile(t, dir, "broken.json", `{`)
	writeFile(t, dir, "README.md", "not json")

	src, err := NewDirSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := src.ListProjects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Project{
		{ID: "team-a/payments.cdx.json", Name: "payments-api", FileName: "payments.cdx.json"},
		{ID: "unnamed.json", Name: "unnamed", FileName: "unnamed.json"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListProjects() = %+v, want %+v", got, want)
	}
	if len(src.Skipped) != 4 {
		t.Errorf("Skipped = %v, want the SPDX, OpenVEX, non-CycloneDX and broken files", src.Skipped)
	}

	data, err := src.GetSBOM(context.Background(), got[0])
	if err != nil || string(data) != appCDX {
		t.Errorf("GetSBOM must return the file unchanged (err %v)", err)
	}
}

func TestDirSource_ListAnalyses(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "payments.cdx.json", appCDX)
	src, err := NewDirSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, notes, err := src.ListAnalyses(context.Background(), Project{ID: "payments.cdx.json"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Analysis{
		{
			VulnID:  "CVE-2021-44228",
			Aliases: []string{"GHSA-jfh8-c2jp-5v3q"},
			PURLs: []string{
				"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
				"pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1", // nested, via BOM-Link
			},
			State: "not_affected", Justification: "code_not_reachable", Detail: "JNDI lookups disabled.",
			Updated: time.Date(2022, 2, 1, 10, 0, 0, 0, time.UTC),
		},
		{VulnID: "GHSA-xxxx-yyyy-zzzz", PURLs: []string{"pkg:npm/left-pad@1.3.0"}, State: "in_triage"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListAnalyses() =\n%+v\nwant\n%+v", got, want)
	}
	// CVE-2023-0001 only affects a component without a purl: nothing could
	// match it, so it is reported instead of imported. CVE-2024-9999 has no
	// analysis and is not a decision at all.
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "CVE-2023-0001") || strings.Contains(joined, "CVE-2024-9999") {
		t.Errorf("notes = %v", notes)
	}
}

func TestNewDirSource_RejectsFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.json", "{}")
	if _, err := NewDirSource(filepath.Join(dir, "a.json")); err == nil {
		t.Error("a file was accepted as the source directory")
	}
	if _, err := NewDirSource(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing directory was accepted")
	}
}
