package protobomparser

import (
	"reflect"
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
)

func TestParse_CycloneDX(t *testing.T) {
	cdxJSON := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"serialNumber": "urn:uuid:test-123",
		"version": 1,
		"metadata": {
			"timestamp": "2024-03-01T12:00:00Z",
			"tools": [{"vendor": "anchore", "name": "syft", "version": "1.0.0"}],
			"component": {"type": "application", "name": "test-app", "version": "2.0"}
		},
		"components": [
			{
				"type": "library",
				"bom-ref": "pkg:golang/github.com/example/lib@v1.0.0",
				"name": "github.com/example/lib",
				"version": "v1.0.0",
				"purl": "pkg:golang/github.com/example/lib@v1.0.0",
				"licenses": [{"license": {"id": "MIT"}}]
			}
		],
		"dependencies": []
	}`)

	result, err := Parse(cdxJSON, "test.cdx.json", "protobom-test-hash")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(result.Packages.PackageNames) == 0 {
		t.Fatal("expected at least 1 package")
	}

	// Protobom should extract the component name.
	found := false
	for _, name := range result.Packages.PackageNames {
		if name == "github.com/example/lib" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find 'github.com/example/lib' in packages, got: %v", result.Packages.PackageNames)
	}

	// Check that PURL was extracted.
	purlFound := false
	for _, p := range result.Packages.PackagePURLs {
		if p == "pkg:golang/github.com/example/lib@v1.0.0" {
			purlFound = true
			break
		}
	}
	if !purlFound {
		t.Errorf("expected PURL 'pkg:golang/github.com/example/lib@v1.0.0', got: %v", result.Packages.PackagePURLs)
	}
}

func TestParse_SPDX(t *testing.T) {
	spdxJSON := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test-spdx-doc",
		"documentNamespace": "https://example.com/test",
		"creationInfo": {
			"created": "2024-01-01T00:00:00Z",
			"creators": ["Tool: test-tool"],
			"licenseListVersion": "3.19"
		},
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-foo",
				"name": "foo",
				"versionInfo": "1.0.0",
				"downloadLocation": "NOASSERTION",
				"licenseConcluded": "Apache-2.0",
				"licenseDeclared": "Apache-2.0",
				"externalRefs": [
					{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/foo@1.0.0"}
				]
			}
		],
		"relationships": []
	}`)

	result, err := Parse(spdxJSON, "test.spdx.json", "spdx-proto-hash")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(result.Packages.PackageNames) == 0 {
		t.Fatal("expected at least 1 package")
	}

	found := false
	for _, name := range result.Packages.PackageNames {
		if name == "foo" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find 'foo' in packages, got: %v", result.Packages.PackageNames)
	}
}

func TestExtractNodeLicense_CompoundParenthesized(t *testing.T) {
	tests := []struct {
		name string
		node *sbom.Node
		want string
	}{
		{
			name: "single license unchanged",
			node: &sbom.Node{Licenses: []string{"MIT"}},
			want: "MIT",
		},
		{
			name: "single compound expression unchanged",
			node: &sbom.Node{Licenses: []string{"MIT OR Apache-2.0"}},
			want: "MIT OR Apache-2.0",
		},
		{
			name: "multiple licenses with compound expression",
			node: &sbom.Node{Licenses: []string{"MIT OR Apache-2.0", "GPL-3.0-only"}},
			want: "(MIT OR Apache-2.0) AND GPL-3.0-only",
		},
		{
			name: "multiple licenses with nested parens compound",
			node: &sbom.Node{Licenses: []string{"(MIT) OR (Apache-2.0)", "GPL-3.0-only"}},
			want: "((MIT) OR (Apache-2.0)) AND GPL-3.0-only",
		},
		{
			name: "fall back to concluded license",
			node: &sbom.Node{LicenseConcluded: "Apache-2.0"},
			want: "Apache-2.0",
		},
		{
			name: "noassertion on empty",
			node: &sbom.Node{},
			want: "NOASSERTION",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNodeLicense(tt.node)
			if got != tt.want {
				t.Errorf("extractNodeLicense() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParse_CycloneDXToolsObject(t *testing.T) {
	cdxJSON := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": "urn:uuid:test-cdx16-tools",
		"version": 1,
		"metadata": {
			"timestamp": "2026-11-24T21:00:00Z",
			"tools": {
				"components": [
					{"type": "application", "author": "anchore", "name": "syft", "version": "1.55.0"}
				],
				"services": [
					{"provider": {"name": "acme"}, "name": "bom-relay", "version": "1.0.0"}
				]
			},
			"component": {"type": "application", "name": "test-app", "version": "2.0"}
		},
		"components": [
			{
				"type": "library",
				"bom-ref": "pkg:golang/github.com/example/lib@v1.0.0",
				"name": "github.com/example/lib",
				"version": "v1.0.0",
				"purl": "pkg:golang/github.com/example/lib@v1.0.0",
				"licenses": [{"license": {"id": "MIT"}}]
			}
		],
		"dependencies": []
	}`)

	result, err := Parse(cdxJSON, "syft.cdx.json", "protobom-cdx16-hash")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	wantTools := []string{
		"Tool: anchore syft 1.55.0",
		"Tool: acme bom-relay 1.0.0",
	}
	if !reflect.DeepEqual(result.SBOM.CreatorTools, wantTools) {
		t.Errorf("CreatorTools = %v, want %v", result.SBOM.CreatorTools, wantTools)
	}
}
