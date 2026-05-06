package sbom

import (
	"strings"
	"testing"
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

	result, err := Parse(strings.NewReader(spdxJSON), "test.spdx.json", "hash123")
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

	result, err := Parse(strings.NewReader(cdxJSON), "test.cdx.json", "hash456")
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

	result, err := Parse(strings.NewReader(inTotoJSON), "intoto.spdx.json", "hash789")
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

	result, err := Parse(strings.NewReader(cdxJSON), "protobom.cdx.json", "hash-proto")
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
