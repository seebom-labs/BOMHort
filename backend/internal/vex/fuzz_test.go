package vex

import (
	"bytes"
	"testing"
)

// FuzzParse ensures the VEX parser never panics on arbitrary input.
func FuzzParse(f *testing.F) {
	// Seed corpus with minimal valid OpenVEX document
	f.Add([]byte(`{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://example.com/vex/fuzz",
		"author": "fuzz",
		"timestamp": "2024-01-01T00:00:00Z",
		"version": 1,
		"statements": []
	}`))

	// Empty / invalid inputs
	f.Add([]byte(``))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic — errors are acceptable
		_, _ = Parse(bytes.NewReader(data), "fuzz.openvex.json")
	})
}

