package sbom

import (
	"reflect"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/depgraph"
)

func TestParse_SPDXDepthsFromDescribedRoot(t *testing.T) {
	spdxJSON := `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "app",
		"documentNamespace": "https://example.com/app",
		"creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
		"packages": [
			{"SPDXID": "SPDXRef-lib-b", "name": "lib-b", "versionInfo": "1.0", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:golang/lib-b@1.0"}]},
			{"SPDXID": "SPDXRef-app", "name": "app", "versionInfo": "2.0", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:golang/app@2.0"}]},
			{"SPDXID": "SPDXRef-lib-a", "name": "lib-a", "versionInfo": "1.0", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:golang/lib-a@1.0"}]},
			{"SPDXID": "SPDXRef-lib-c", "name": "lib-c", "versionInfo": "1.0", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:golang/lib-c@1.0"}]}
		],
		"relationships": [
			{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-app"},
			{"spdxElementId": "SPDXRef-app", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-lib-a"},
			{"spdxElementId": "SPDXRef-lib-b", "relationshipType": "DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-lib-a"}
		]
	}`

	result, err := Parse(strings.NewReader(spdxJSON), "app.spdx.json", "h", false)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	p := result.Packages
	if len(p.PackageDepths) != len(p.PackageNames) {
		t.Fatalf("depths not parallel: %d vs %d", len(p.PackageDepths), len(p.PackageNames))
	}
	byName := map[string]uint16{}
	for i, n := range p.PackageNames {
		byName[n] = p.PackageDepths[i]
	}
	want := map[string]uint16{"app": 0, "lib-a": 1, "lib-b": 2, "lib-c": depgraph.Unknown}
	if !reflect.DeepEqual(byName, want) {
		t.Fatalf("depths by name = %v, want %v", byName, want)
	}
}

func TestParse_CycloneDXDepthsFromMetadataComponent(t *testing.T) {
	cdxJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {
			"timestamp": "2024-01-01T00:00:00Z",
			"component": {"type": "application", "bom-ref": "root", "name": "my-app", "version": "1.0.0"}
		},
		"components": [
			{"type": "library", "bom-ref": "a", "name": "a", "version": "1", "purl": "pkg:npm/a@1"},
			{"type": "library", "bom-ref": "b", "name": "b", "version": "1", "purl": "pkg:npm/b@1"},
			{"type": "library", "bom-ref": "c", "name": "c", "version": "1", "purl": "pkg:npm/c@1"}
		],
		"dependencies": [
			{"ref": "root", "dependsOn": ["a"]},
			{"ref": "a", "dependsOn": ["b"]}
		]
	}`

	result, err := Parse(strings.NewReader(cdxJSON), "app.cdx.json", "h", false)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	want := []uint16{1, 2, depgraph.Unknown}
	if !reflect.DeepEqual(result.Packages.PackageDepths, want) {
		t.Fatalf("depths = %v, want %v", result.Packages.PackageDepths, want)
	}
	// The root is not part of the component array and must not create a
	// phantom relationship.
	for _, src := range result.Packages.RelSourceIndices {
		if int(src) >= len(result.Packages.PackageNames) {
			t.Fatalf("relationship source %d out of range", src)
		}
	}
}

func TestParse_NoGraphLeavesDepthsUnknown(t *testing.T) {
	cdxJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {"timestamp": "2024-01-01T00:00:00Z"},
		"components": [
			{"type": "library", "bom-ref": "a", "name": "a", "version": "1", "purl": "pkg:npm/a@1"},
			{"type": "library", "bom-ref": "b", "name": "b", "version": "1", "purl": "pkg:npm/b@1"}
		]
	}`
	result, err := Parse(strings.NewReader(cdxJSON), "flat.cdx.json", "h", false)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	for i, d := range result.Packages.PackageDepths {
		if d != depgraph.Unknown {
			t.Fatalf("package %d: depth %d, want Unknown (no graph)", i, d)
		}
	}
}
