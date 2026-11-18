package sbom

import (
	"strings"
	"testing"

	json "github.com/goccy/go-json"
)

func TestParse_DetectsSPDX(t *testing.T) {
	spdxJSON := `{
		"spdxVersion": "SPDX-2.3",
		"name": "test-doc",
		"documentNamespace": "https://example.com/test",
		"creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
		"packages": [
			{"SPDXID": "SPDXRef-Package-foo", "name": "foo", "versionInfo": "1.0", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:golang/foo@1.0"}], "licenseDeclared": "MIT"}
		],
		"relationships": []
	}`

	result, err := Parse(strings.NewReader(spdxJSON), "test.spdx.json", "hash123", false)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if result.SBOM.SPDXVersion != "SPDX-2.3" {
		t.Errorf("expected SPDX-2.3, got %q", result.SBOM.SPDXVersion)
	}
	if len(result.Packages.PackageNames) != 1 {
		t.Errorf("expected 1 package, got %d", len(result.Packages.PackageNames))
	}
}

func TestParse_DetectsCycloneDX(t *testing.T) {
	cdxJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {"timestamp": "2024-01-01T00:00:00Z"},
		"components": [
			{"type": "library", "bom-ref": "ref1", "name": "bar", "version": "2.0", "purl": "pkg:npm/bar@2.0", "licenses": [{"license": {"id": "Apache-2.0"}}]}
		]
	}`

	result, err := Parse(strings.NewReader(cdxJSON), "test.cdx.json", "hash456", false)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if result.SBOM.SPDXVersion != "CycloneDX-1.5" {
		t.Errorf("expected CycloneDX-1.5, got %q", result.SBOM.SPDXVersion)
	}
	if result.Packages.PackageNames[0] != "bar" {
		t.Errorf("expected 'bar', got %q", result.Packages.PackageNames[0])
	}
	if result.Packages.PackageLicenses[0] != "Apache-2.0" {
		t.Errorf("expected Apache-2.0, got %q", result.Packages.PackageLicenses[0])
	}
}

func TestParse_DetectsInTotoEnvelope(t *testing.T) {
	// in-toto envelope wrapping an SPDX document.
	inTotoJSON := `{
		"predicateType": "https://spdx.dev/Document",
		"predicate": {
			"spdxVersion": "SPDX-2.3",
			"name": "wrapped-doc",
			"documentNamespace": "https://example.com/wrapped",
			"creationInfo": {"created": "2024-06-01T00:00:00Z", "creators": ["Tool: buildkit"]},
			"packages": [
				{"SPDXID": "SPDXRef-Package-wrapped", "name": "wrapped-pkg", "versionInfo": "3.0", "externalRefs": [], "licenseDeclared": "BSD-3-Clause"}
			],
			"relationships": []
		}
	}`

	result, err := Parse(strings.NewReader(inTotoJSON), "intoto.spdx.json", "hash789", false)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if result.SBOM.SPDXVersion != "SPDX-2.3" {
		t.Errorf("expected SPDX-2.3 from in-toto, got %q", result.SBOM.SPDXVersion)
	}
	if result.Packages.PackageNames[0] != "wrapped-pkg" {
		t.Errorf("expected 'wrapped-pkg', got %q", result.Packages.PackageNames[0])
	}
}

func TestParse_ProtobomBackend(t *testing.T) {
	// Enable protobom backend for this test.
	SetUseProtobom(true)
	defer SetUseProtobom(false)

	cdxJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {"timestamp": "2024-01-01T00:00:00Z"},
		"components": [
			{"type": "library", "bom-ref": "ref1", "name": "proto-pkg", "version": "3.0", "purl": "pkg:npm/proto-pkg@3.0", "licenses": [{"license": {"id": "MIT"}}]}
		]
	}`

	result, err := Parse(strings.NewReader(cdxJSON), "protobom.cdx.json", "hash-proto", false)
	if err != nil {
		t.Fatalf("Parse with protobom failed: %v", err)
	}

	if len(result.Packages.PackageNames) == 0 {
		t.Fatal("expected at least 1 package from protobom")
	}

	found := false
	for _, name := range result.Packages.PackageNames {
		if name == "proto-pkg" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'proto-pkg' in packages, got: %v", result.Packages.PackageNames)
	}
}
func TestParse_DetectsSPDX3(t *testing.T) {
	// SPDX 3 must be routed to protobom even when the protobom backend is not
	// enabled globally – the built-in SPDX parser cannot read JSON-LD.
	if UseProtobom() {
		t.Fatal("precondition: protobom backend must be disabled")
	}
	spdx3 := `{
"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
"@graph": [
{"type": "CreationInfo", "@id": "_:ci", "specVersion": "3.0.1",
 "created": "2026-01-01T00:00:00Z",
 "createdBy": ["https://spdx.org/rdf/3.0.1/terms/Core/SpdxOrganization"]},
{"type": "SpdxDocument", "spdxId": "https://example.com/doc", "name": "spdx3-doc",
 "creationInfo": "_:ci", "profileConformance": ["core", "software"],
 "rootElement": ["https://example.com/doc#pkg"]},
{"type": "software_Package", "spdxId": "https://example.com/doc#pkg",
 "creationInfo": "_:ci", "name": "spdx3-pkg", "software_packageVersion": "1.0.0",
 "software_packageUrl": "pkg:npm/spdx3-pkg@1.0.0"}
]
}`
	result, err := Parse(strings.NewReader(spdx3), "doc.spdx3.json", "hash-spdx3", false)
	if err != nil {
		t.Fatalf("Parse SPDX 3 failed: %v", err)
	}
	if result.SBOM.SPDXVersion != "SPDX-3.0.1" {
		t.Errorf("SPDXVersion = %q, want SPDX-3.0.1", result.SBOM.SPDXVersion)
	}
	if len(result.Packages.PackageNames) != 1 || result.Packages.PackageNames[0] != "spdx3-pkg" {
		t.Errorf("packages = %v, want [spdx3-pkg]", result.Packages.PackageNames)
	}
	if result.Packages.PackagePURLs[0] != "pkg:npm/spdx3-pkg@1.0.0" {
		t.Errorf("purl = %q", result.Packages.PackagePURLs[0])
	}
}
func TestIsSPDX3Context(t *testing.T) {
	tests := map[string]bool{
		`"https://spdx.org/rdf/3.0.1/spdx-context.jsonld"`:                  true,
		`["https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "https://x/y"]`: true,
		`"https://spdx.org/rdf/3.0.0/spdx-context.jsonld"`:                  true,
		`"https://cyclonedx.org/schema/bom-1.6.schema.json"`:                false,
		`{"@vocab": "https://spdx.org/rdf/3.0.1/terms/"}`:                   false,
		`null`: false,
		``:     false,
	}
	for in, want := range tests {
		if got := isSPDX3Context(json.RawMessage(in)); got != want {
			t.Errorf("isSPDX3Context(%s) = %v, want %v", in, got, want)
		}
	}
}
