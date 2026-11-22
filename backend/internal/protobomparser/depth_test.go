package protobomparser

import (
	"reflect"
	"testing"
)

// protobom exposes the document's root elements (SPDX DESCRIBES targets);
// they must reach RootIndices so depth computation starts from the product
// rather than guessing a root from in-degree.
func TestParse_SPDXDescribesBecomesRootIndices(t *testing.T) {
	spdxJSON := []byte(`{
		"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
		"name": "root-test", "documentNamespace": "https://example.com/root-test",
		"creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
		"packages": [
			{"SPDXID": "SPDXRef-lib", "name": "lib", "versionInfo": "1", "downloadLocation": "NOASSERTION"},
			{"SPDXID": "SPDXRef-app", "name": "app", "versionInfo": "1", "downloadLocation": "NOASSERTION"}
		],
		"relationships": [
			{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-app"},
			{"spdxElementId": "SPDXRef-app", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-lib"}
		]
	}`)

	res, err := Parse(spdxJSON, "t.spdx.json", "h", "")
	if err != nil {
		t.Fatal(err)
	}
	var appIdx uint32
	found := false
	for i, name := range res.Packages.PackageNames {
		if name == "app" {
			appIdx, found = uint32(i), true
		}
	}
	if !found {
		t.Fatalf("package app not parsed: %v", res.Packages.PackageNames)
	}
	if got, want := res.Packages.RootIndices, []uint32{appIdx}; !reflect.DeepEqual(got, want) {
		t.Errorf("RootIndices = %v, want %v", got, want)
	}
}
