package cyclonedx

import (
	"testing"
)

// FuzzParse ensures the CycloneDX parser never panics on arbitrary or malformed input.
func FuzzParse(f *testing.F) {
	// Seed corpus: valid minimal CycloneDX document
	f.Add([]byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		"version": 1,
		"metadata": {
			"timestamp": "2024-01-01T00:00:00Z",
			"component": {
				"name": "fuzz-root",
				"version": "1.0.0",
				"type": "application"
			}
		},
		"components": [
			{
				"name": "dep-a",
				"version": "2.0.0",
				"purl": "pkg:npm/dep-a@2.0.0"
			}
		],
		"dependencies": [
			{
				"ref": "fuzz-root",
				"dependsOn": ["pkg:npm/dep-a@2.0.0"]
			}
		]
	}`))

	// Malformed, edge case, and empty seeds
	f.Add([]byte(``))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"bomFormat": "CycloneDX"}`))
	f.Add([]byte(`{"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"tools": {"components": [{"type": "application", "author": "anchore", "name": "syft", "version": "1.55.0"}], "services": [{"provider": {"name": "acme"}, "name": "signer"}]}}}`))
	f.Add([]byte(`{"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"tools": {}}}`))
	f.Add([]byte(`{"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"tools": null}}`))
	f.Add([]byte(`{"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"tools": {"components": [null, {}]}}}`))
	f.Add([]byte(`{"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"tools": 123}}`))
	f.Add([]byte(`{"bomFormat": "CycloneDX", "components": "not-an-array"}`))
	f.Add([]byte(`{"bomFormat": "CycloneDX", "components": [null, {}]}`))
	f.Add([]byte(`{"bomFormat": "CycloneDX", "dependencies": [{"ref": "a", "dependsOn": [123]}]}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"components": [{"licenses": [{"license": {"id": "MIT"}}]}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic — returning an error is acceptable
		_, _ = Parse(data, "fuzz.cdx.json", "fakehash")
	})
}
