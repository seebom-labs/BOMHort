package sbom

import (
	"bytes"
	"testing"
)

// FuzzParse tests end-to-end format detection, dispatching, depth calculation,
// and quality evaluation, ensuring arbitrary input never panics.
func FuzzParse(f *testing.F) {
	// Seed 1: SPDX 2.3 JSON
	f.Add([]byte(`{
		"spdxVersion": "SPDX-2.3",
		"name": "spdx-app",
		"documentNamespace": "https://example.com/spdx/1",
		"creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
		"packages": [{"name": "pkg1", "SPDXID": "SPDXRef-Package-1"}],
		"relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-1"}]
	}`))

	// Seed 2: CycloneDX JSON
	f.Add([]byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"components": [{"name": "pkg2", "version": "1.0.0", "purl": "pkg:npm/pkg2@1.0.0"}]
	}`))

	// Seed 3: SPDX 3 JSON-LD
	f.Add([]byte(`{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		"@graph": []
	}`))

	// Seed 4: in-toto envelope
	f.Add([]byte(`{
		"payloadType": "application/vnd.in-toto+json",
		"payload": "",
		"predicateType": "https://spdx.dev/Document",
		"predicate": {"spdxVersion": "SPDX-2.3", "name": "envelope-test"}
	}`))

	// Seed 5: Malformed JSON and arbitrary strings
	f.Add([]byte(``))
	f.Add([]byte(`{`))
	f.Add([]byte(`{"nested": {"array": [1, 2, null, true]}}`))
	f.Add([]byte(`{"@context": ["https://spdx.org/rdf/3.0.0"]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic
		_, _ = Parse(bytes.NewReader(data), "fuzz.sbom.json", "fakehash")
	})
}
