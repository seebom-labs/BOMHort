package cyclonedx

import (
	"testing"
)

func TestParse_MinimalCycloneDX(t *testing.T) {
	cdxJSON := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		"version": 1,
		"metadata": {
			"timestamp": "2024-01-15T10:30:00Z",
			"tools": [{"vendor": "anchore", "name": "syft", "version": "0.100.0"}],
			"component": {"type": "application", "name": "my-app", "version": "1.0.0"}
		},
		"components": [
			{
				"type": "library",
				"bom-ref": "pkg:golang/github.com/foo/bar@v1.2.3",
				"name": "github.com/foo/bar",
				"version": "v1.2.3",
				"purl": "pkg:golang/github.com/foo/bar@v1.2.3",
				"licenses": [{"license": {"id": "MIT"}}]
			},
			{
				"type": "library",
				"bom-ref": "pkg:golang/github.com/baz/qux@v0.1.0",
				"name": "github.com/baz/qux",
				"version": "v0.1.0",
				"purl": "pkg:golang/github.com/baz/qux@v0.1.0",
				"licenses": [{"expression": "Apache-2.0 OR MIT"}]
			}
		],
		"dependencies": [
			{
				"ref": "pkg:golang/github.com/foo/bar@v1.2.3",
				"dependsOn": ["pkg:golang/github.com/baz/qux@v0.1.0"]
			}
		]
	}`)

	result, err := Parse(cdxJSON, "test.cdx.json", "abc123hash")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Check SBOM metadata.
	if result.SBOM.SPDXVersion != "CycloneDX-1.5" {
		t.Errorf("expected SPDXVersion='CycloneDX-1.5', got %q", result.SBOM.SPDXVersion)
	}
	if result.SBOM.DocumentName != "my-app 1.0.0" {
		t.Errorf("expected DocumentName='my-app 1.0.0', got %q", result.SBOM.DocumentName)
	}
	if result.SBOM.DocumentNamespace != "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" {
		t.Errorf("expected serial number as namespace, got %q", result.SBOM.DocumentNamespace)
	}
	if len(result.SBOM.CreatorTools) != 1 || result.SBOM.CreatorTools[0] != "Tool: anchore syft 0.100.0" {
		t.Errorf("unexpected tools: %v", result.SBOM.CreatorTools)
	}

	// Check packages.
	if len(result.Packages.PackageNames) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(result.Packages.PackageNames))
	}
	if result.Packages.PackageNames[0] != "github.com/foo/bar" {
		t.Errorf("unexpected package name: %q", result.Packages.PackageNames[0])
	}
	if result.Packages.PackagePURLs[0] != "pkg:golang/github.com/foo/bar@v1.2.3" {
		t.Errorf("unexpected PURL: %q", result.Packages.PackagePURLs[0])
	}
	if result.Packages.PackageLicenses[0] != "MIT" {
		t.Errorf("expected license 'MIT', got %q", result.Packages.PackageLicenses[0])
	}
	if result.Packages.PackageLicenses[1] != "Apache-2.0 OR MIT" {
		t.Errorf("expected license expression, got %q", result.Packages.PackageLicenses[1])
	}

	// Check relationships.
	if len(result.Packages.RelSourceIndices) != 1 {
		t.Fatalf("expected 1 relationship, got %d", len(result.Packages.RelSourceIndices))
	}
	if result.Packages.RelSourceIndices[0] != 0 || result.Packages.RelTargetIndices[0] != 1 {
		t.Errorf("unexpected relationship indices: src=%d, tgt=%d",
			result.Packages.RelSourceIndices[0], result.Packages.RelTargetIndices[0])
	}
	if result.Packages.RelTypes[0] != "DEPENDS_ON" {
		t.Errorf("expected DEPENDS_ON, got %q", result.Packages.RelTypes[0])
	}
}

func TestParse_NoLicenses(t *testing.T) {
	cdxJSON := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"metadata": {"timestamp": "2024-01-01T00:00:00Z"},
		"components": [
			{"type": "library", "bom-ref": "ref1", "name": "nolic-pkg", "version": "1.0"}
		]
	}`)

	result, err := Parse(cdxJSON, "nolic.cdx.json", "def456hash")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if result.Packages.PackageLicenses[0] != "NOASSERTION" {
		t.Errorf("expected NOASSERTION for missing license, got %q", result.Packages.PackageLicenses[0])
	}
}

func TestParse_NotCycloneDX(t *testing.T) {
	_, err := Parse([]byte(`{"bomFormat": "other"}`), "test.json", "hash")
	if err == nil {
		t.Error("expected error for non-CycloneDX document")
	}
}

