package sbom

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/license"
)

func namingFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/temporary-document.spdx.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDocumentNameFallbackAcrossBackends(t *testing.T) {
	data := namingFixture(t)
	const source = "s3://bucket/example-org/widget/v1.2.3/widget_spdx.json"
	for _, tt := range []struct{ name, from, to, want string }{
		{"temporary", "", "", "example-org/widget v1.2.3"},
		{"empty", `"name": "tmp.ABC123xyz"`, `"name": ""`, "example-org/widget v1.2.3"},
		{"valid", `"name": "tmp.ABC123xyz"`, `"name": "Published title"`, "Published title"},
		{"root name temporary", `"name": "example-org/widget"`, `"name": "tmp.XYZ987abc"`, "example-org/widget/v1.2.3/widget"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := data
			if tt.from != "" {
				input = []byte(strings.Replace(string(data), tt.from, tt.to, 1))
			}
			before := append([]byte(nil), input...)
			for _, backend := range []struct {
				name  string
				parse func([]byte, string, string) (*ParseResult, error)
			}{{"builtin", parseSPDX}, {"protobom", parseWithProtobom}} {
				t.Run(backend.name, func(t *testing.T) {
					result, err := backend.parse(input, source, "fixture-hash")
					if err != nil {
						t.Fatal(err)
					}
					if result.SBOM.DocumentName != tt.want {
						t.Fatalf("name=%q, want %q", result.SBOM.DocumentName, tt.want)
					}
					if result.SBOM.SourceFile != source || result.SBOM.SHA256Hash != "fixture-hash" {
						t.Fatal("source identity changed")
					}
					if !bytes.Equal(input, before) {
						t.Fatal("source bytes changed")
					}
					// Compare with the same backend parsing the same packages under a
					// valid document name; only the displayed document name may differ.
					var doc map[string]any
					if err := json.Unmarshal(input, &doc); err != nil {
						t.Fatal(err)
					}
					doc["name"] = "Reference document"
					control, err := json.Marshal(doc)
					if err != nil {
						t.Fatal(err)
					}
					baseline, err := backend.parse(control, source, "fixture-hash")
					if err != nil {
						t.Fatal(err)
					}
					if result.SBOM.SBOMID != baseline.SBOM.SBOMID || result.SBOM.DocumentNamespace != baseline.SBOM.DocumentNamespace {
						t.Fatal("SBOM identity/namespace changed")
					}
					actualPackages, expectedPackages := result.Packages, baseline.Packages
					actualPackages.IngestedAt = expectedPackages.IngestedAt
					if !reflect.DeepEqual(actualPackages, expectedPackages) {
						t.Fatal("package identities, licenses, or relationships changed")
					}
				})
			}
		})
	}
}

func TestDocumentNameFallbackSPDXEnvelope(t *testing.T) {
	envelope := `{"predicateType":"https://spdx.dev/Document","predicate":` + string(namingFixture(t)) + `}`
	result, err := parseSPDX([]byte(envelope), "attestation.json", "fixture-hash")
	if err != nil {
		t.Fatal(err)
	}
	if result.SBOM.DocumentName != "example-org/widget v1.2.3" {
		t.Fatalf("unexpected name %q", result.SBOM.DocumentName)
	}
}

func TestDocumentNameFallbackCycloneDX(t *testing.T) {
	for _, tt := range []struct{ component, serial, want string }{
		{`{"type":"application","name":"widget","version":"1.0"}`, "", "widget 1.0"},
		{`{"type":"application","name":"tmp.ABC123xyz","version":"1.0"}`, "", "widget"},
		{`{"type":"application","name":"","version":"1.0"}`, "", "widget"},
		{`null`, "", "widget"},
		{`null`, "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"},
	} {
		input := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","serialNumber":"` + tt.serial + `","version":1,"metadata":{"component":` + tt.component + `},"components":[{"type":"library","name":"not-the-root","version":"5"}]}`)
		for _, parse := range []func([]byte, string, string) (*ParseResult, error){parseCycloneDX, parseWithProtobom} {
			result, err := parse(input, "widget.cdx.json", "fixture-hash")
			if err != nil {
				t.Fatal(err)
			}
			if result.SBOM.DocumentName != tt.want {
				t.Errorf("component=%s: name=%q want=%q", tt.component, result.SBOM.DocumentName, tt.want)
			}
		}
	}
}

func TestNormalizedDocumentNameUsesExactLicenseProjectScope(t *testing.T) {
	for _, parse := range []func([]byte, string, string) (*ParseResult, error){parseSPDX, parseWithProtobom} {
		result, err := parse(namingFixture(t), "widget.spdx.json", "fixture-hash")
		if err != nil {
			t.Fatal(err)
		}
		for _, project := range []string{"example-org/widget v1.2.3", "example-org/widget v2.0.0", "tmp.ABC123xyz"} {
			idx := license.BuildIndex(&license.ExceptionsFile{Exceptions: []license.Exception{{
				ID: "scoped", Package: "unrelated-dependency", License: "MPL-2.0", Status: "approved", Project: project,
			}}})
			results := license.CheckWithExceptions(result.Packages.PackageNames, result.Packages.PackageLicenses, idx, result.SBOM.DocumentName)
			found := false
			for _, check := range results {
				if check.LicenseID != "MPL-2.0" {
					continue
				}
				found = true
				if (len(check.ExemptedPackages) == 1) != (project == result.SBOM.DocumentName) {
					t.Fatalf("project %q applied incorrectly: %+v", project, check)
				}
			}
			if !found {
				t.Fatal("missing copyleft result")
			}
		}
	}
}
