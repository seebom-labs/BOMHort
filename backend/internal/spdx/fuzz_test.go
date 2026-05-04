package spdx

import (
	"bytes"
	"testing"
)

// FuzzParse ensures the SPDX parser never panics on arbitrary input.
func FuzzParse(f *testing.F) {
	// Seed corpus with minimal valid SPDX document
	f.Add([]byte(`{
		"spdxVersion": "SPDX-2.3",
		"name": "fuzz-test",
		"documentNamespace": "https://example.com/fuzz",
		"creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: fuzz"]},
		"packages": [],
		"relationships": []
	}`))

	// In-toto envelope wrapper
	f.Add([]byte(`{
		"payloadType": "application/vnd.in-toto+json",
		"payload": "",
		"signatures": [],
		"predicate": {
			"spdxVersion": "SPDX-2.3",
			"name": "envelope-test",
			"documentNamespace": "https://example.com/envelope",
			"creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: fuzz"]},
			"packages": [],
			"relationships": []
		}
	}`))

	// Empty input
	f.Add([]byte(``))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic — errors are acceptable
		_, _ = Parse(bytes.NewReader(data), "fuzz.spdx.json", "fakehash")
	})
}

