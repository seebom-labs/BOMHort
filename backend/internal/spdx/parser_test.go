package spdx

import (
	"strings"
	"testing"
)

const testSPDXJSON = `{
	"spdxVersion": "SPDX-2.3",
	"name": "test-document",
	"documentNamespace": "https://example.com/test",
	"creationInfo": {
		"created": "2025-01-15T10:00:00Z",
		"creators": ["Tool: test-tool-1.0"]
	},
	"packages": [
		{
			"SPDXID": "SPDXRef-Package-A",
			"name": "package-a",
			"versionInfo": "1.0.0",
			"licenseConcluded": "MIT",
			"licenseDeclared": "MIT",
			"externalRefs": [
				{
					"referenceCategory": "PACKAGE-MANAGER",
					"referenceType": "purl",
					"referenceLocator": "pkg:npm/package-a@1.0.0"
				}
			]
		},
		{
			"SPDXID": "SPDXRef-Package-B",
			"name": "package-b",
			"versionInfo": "2.0.0",
			"licenseConcluded": "Apache-2.0",
			"licenseDeclared": "NOASSERTION",
			"externalRefs": []
		}
	],
	"relationships": [
		{
			"spdxElementId": "SPDXRef-Package-A",
			"relationshipType": "DEPENDS_ON",
			"relatedSpdxElement": "SPDXRef-Package-B"
		}
	]
}`

func TestParse(t *testing.T) {
	result, err := Parse(strings.NewReader(testSPDXJSON), "test.spdx.json", "abc123")
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	// Verify SBOM metadata.
	if result.SBOM.SPDXVersion != "SPDX-2.3" {
		t.Errorf("expected SPDX-2.3, got %s", result.SBOM.SPDXVersion)
	}
	if result.SBOM.DocumentName != "test-document" {
		t.Errorf("expected test-document, got %s", result.SBOM.DocumentName)
	}
	if result.SBOM.SHA256Hash != "abc123" {
		t.Errorf("expected abc123, got %s", result.SBOM.SHA256Hash)
	}

	// Verify packages.
	if len(result.Packages.PackageNames) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(result.Packages.PackageNames))
	}
	if result.Packages.PackageNames[0] != "package-a" {
		t.Errorf("expected package-a, got %s", result.Packages.PackageNames[0])
	}
	if result.Packages.PackagePURLs[0] != "pkg:npm/package-a@1.0.0" {
		t.Errorf("expected purl, got %s", result.Packages.PackagePURLs[0])
	}

	// Verify license fallback (NOASSERTION → concluded).
	if result.Packages.PackageLicenses[1] != "Apache-2.0" {
		t.Errorf("expected Apache-2.0 (fallback), got %s", result.Packages.PackageLicenses[1])
	}

	// Verify relationships.
	if len(result.Packages.RelSourceIndices) != 1 {
		t.Fatalf("expected 1 relationship, got %d", len(result.Packages.RelSourceIndices))
	}
	if result.Packages.RelSourceIndices[0] != 0 || result.Packages.RelTargetIndices[0] != 1 {
		t.Errorf("expected relationship 0→1, got %d→%d",
			result.Packages.RelSourceIndices[0], result.Packages.RelTargetIndices[0])
	}
	if result.Packages.RelTypes[0] != "DEPENDS_ON" {
		t.Errorf("expected DEPENDS_ON, got %s", result.Packages.RelTypes[0])
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := Parse(strings.NewReader(`{invalid`), "bad.json", "hash")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParse_EmptyPackages(t *testing.T) {
	doc := `{
		"spdxVersion": "SPDX-2.3",
		"name": "empty-sbom",
		"documentNamespace": "https://example.com/empty",
		"creationInfo": {"created": "2025-01-01T00:00:00Z", "creators": ["Tool: test"]},
		"packages": [],
		"relationships": []
	}`

	result, err := Parse(strings.NewReader(doc), "empty.spdx.json", "hash1")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if result.SBOM.DocumentName != "empty-sbom" {
		t.Errorf("expected empty-sbom, got %s", result.SBOM.DocumentName)
	}
	if len(result.Packages.PackageNames) != 0 {
		t.Errorf("expected 0 packages, got %d", len(result.Packages.PackageNames))
	}
}

func TestParse_DeterministicSBOMID(t *testing.T) {
	// Same SHA256 hash should produce the same SBOM ID.
	r1, _ := Parse(strings.NewReader(testSPDXJSON), "a.json", "same-hash")
	r2, _ := Parse(strings.NewReader(testSPDXJSON), "b.json", "same-hash")

	if r1.SBOM.SBOMID != r2.SBOM.SBOMID {
		t.Errorf("expected same SBOM ID for same hash, got %s vs %s",
			r1.SBOM.SBOMID, r2.SBOM.SBOMID)
	}

	// Different hash → different ID.
	r3, _ := Parse(strings.NewReader(testSPDXJSON), "c.json", "different-hash")
	if r1.SBOM.SBOMID == r3.SBOM.SBOMID {
		t.Error("expected different SBOM ID for different hash")
	}
}

func TestParse_LicenseFallback(t *testing.T) {
	// When licenseDeclared is NOASSERTION, should fallback to licenseConcluded.
	doc := `{
		"spdxVersion": "SPDX-2.3",
		"name": "license-test",
		"documentNamespace": "https://example.com/lic-test",
		"creationInfo": {"created": "2025-01-01T00:00:00Z", "creators": ["Tool: test"]},
		"packages": [
			{"SPDXID": "SPDXRef-A", "name": "pkg", "versionInfo": "1.0",
			 "licenseConcluded": "MIT", "licenseDeclared": "NOASSERTION", "externalRefs": []},
			{"SPDXID": "SPDXRef-B", "name": "pkg2", "versionInfo": "1.0",
			 "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "externalRefs": []}
		],
		"relationships": []
	}`

	result, err := Parse(strings.NewReader(doc), "lic.json", "h")
	if err != nil {
		t.Fatal(err)
	}
	if result.Packages.PackageLicenses[0] != "MIT" {
		t.Errorf("expected MIT fallback, got %s", result.Packages.PackageLicenses[0])
	}
	if result.Packages.PackageLicenses[1] != "NOASSERTION" {
		t.Errorf("expected NOASSERTION when both are NOASSERTION, got %s", result.Packages.PackageLicenses[1])
	}
}

func TestCleanPackageName(t *testing.T) {
	tests := []struct {
		name     string
		pkgName  string
		purl     string
		spdxID   string
		expected string
	}{
		{
			name:     "normal package name unchanged",
			pkgName:  "github.com/foo/bar",
			purl:     "pkg:golang/github.com/foo/bar@v1.0.0",
			spdxID:   "SPDXRef-Package-bar",
			expected: "github.com/foo/bar",
		},
		{
			name:     "go temp name replaced by PURL",
			pkgName:  "tmp.ej9m9OiO2V",
			purl:     "pkg:golang/github.com/cncf/xds/go@v0.0.0-20240905190251-b4127c9b8d78",
			spdxID:   "SPDXRef-Package-go",
			expected: "github.com/cncf/xds/go",
		},
		{
			name:     "go temp name replaced by npm PURL",
			pkgName:  "tmp.AbCdEfGhIj",
			purl:     "pkg:npm/lodash@4.17.21",
			spdxID:   "SPDXRef-Package-lodash",
			expected: "lodash",
		},
		{
			name:     "go temp name falls back to SPDX ID",
			pkgName:  "tmp.XyZ123AbCd",
			purl:     "",
			spdxID:   "SPDXRef-Package-my-module",
			expected: "my-module",
		},
		{
			name:     "go temp name with only SPDXRef prefix",
			pkgName:  "tmp.AAAAAA",
			purl:     "",
			spdxID:   "SPDXRef-RootPackage",
			expected: "RootPackage",
		},
		{
			name:     "go temp name no PURL no useful SPDX ID",
			pkgName:  "tmp.AAAAAA",
			purl:     "",
			spdxID:   "",
			expected: "tmp.AAAAAA",
		},
		{
			name:     "short tmp not matched (too short)",
			pkgName:  "tmp.abc",
			purl:     "pkg:npm/test@1.0",
			spdxID:   "",
			expected: "tmp.abc",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cleanPackageName(tc.pkgName, tc.purl, tc.spdxID)
			if got != tc.expected {
				t.Errorf("cleanPackageName(%q, %q, %q) = %q, want %q",
					tc.pkgName, tc.purl, tc.spdxID, got, tc.expected)
			}
		})
	}
}

func TestParse_GoTempModuleName(t *testing.T) {
	doc := `{
		"spdxVersion": "SPDX-2.3",
		"name": "go-project",
		"documentNamespace": "https://example.com/go-project",
		"creationInfo": {"created": "2025-06-01T00:00:00Z", "creators": ["Tool: bom-1.0"]},
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-go",
				"name": "tmp.ej9m9OiO2V",
				"versionInfo": "",
				"licenseConcluded": "Apache-2.0",
				"licenseDeclared": "Apache-2.0",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:golang/github.com/cncf/xds/go@v0.0.0-20240905"
					}
				]
			},
			{
				"SPDXID": "SPDXRef-Package-real",
				"name": "github.com/real/package",
				"versionInfo": "1.2.3",
				"licenseConcluded": "MIT",
				"licenseDeclared": "MIT",
				"externalRefs": []
			}
		],
		"relationships": []
	}`

	result, err := Parse(strings.NewReader(doc), "go.spdx.json", "hash-go")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if result.Packages.PackageNames[0] == "tmp.ej9m9OiO2V" {
		t.Errorf("expected Go temp name to be cleaned, got %s", result.Packages.PackageNames[0])
	}
	if result.Packages.PackageNames[0] != "github.com/cncf/xds/go" {
		t.Errorf("expected github.com/cncf/xds/go, got %s", result.Packages.PackageNames[0])
	}
	// Normal package should be unchanged.
	if result.Packages.PackageNames[1] != "github.com/real/package" {
		t.Errorf("expected github.com/real/package, got %s", result.Packages.PackageNames[1])
	}
}

func TestParse_InTotoAttestation(t *testing.T) {
	doc := `{
		"_type": "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://spdx.dev/Document",
		"subject": [
			{
				"name": "pkg:docker/example/app@latest",
				"digest": {"sha256": "abc123"}
			}
		],
		"predicate": {
			"spdxVersion": "SPDX-2.3",
			"name": "wrapped-sbom",
			"documentNamespace": "https://example.com/wrapped",
			"creationInfo": {"created": "2025-06-01T00:00:00Z", "creators": ["Tool: buildkit-v0.28.0"]},
			"packages": [
				{
					"SPDXID": "SPDXRef-Package-foo",
					"name": "foo",
					"versionInfo": "1.0.0",
					"licenseConcluded": "MIT",
					"licenseDeclared": "MIT",
					"externalRefs": [
						{
							"referenceCategory": "PACKAGE-MANAGER",
							"referenceType": "purl",
							"referenceLocator": "pkg:golang/github.com/foo/bar@v1.0.0"
						}
					]
				},
				{
					"SPDXID": "SPDXRef-Package-baz",
					"name": "baz",
					"versionInfo": "2.0.0",
					"licenseConcluded": "Apache-2.0",
					"licenseDeclared": "Apache-2.0",
					"externalRefs": []
				}
			],
			"relationships": [
				{
					"spdxElementId": "SPDXRef-Package-foo",
					"relationshipType": "DEPENDS_ON",
					"relatedSpdxElement": "SPDXRef-Package-baz"
				}
			]
		}
	}`

	result, err := Parse(strings.NewReader(doc), "wrapped.spdx.json", "hash-wrapped")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if result.SBOM.SPDXVersion != "SPDX-2.3" {
		t.Errorf("expected SPDX-2.3, got %s", result.SBOM.SPDXVersion)
	}
	if result.SBOM.DocumentName != "wrapped-sbom" {
		t.Errorf("expected wrapped-sbom, got %s", result.SBOM.DocumentName)
	}
	if len(result.Packages.PackageNames) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(result.Packages.PackageNames))
	}
	if result.Packages.PackageNames[0] != "foo" {
		t.Errorf("expected foo, got %s", result.Packages.PackageNames[0])
	}
	if result.Packages.PackagePURLs[0] != "pkg:golang/github.com/foo/bar@v1.0.0" {
		t.Errorf("expected purl, got %s", result.Packages.PackagePURLs[0])
	}
	if len(result.Packages.RelSourceIndices) != 1 {
		t.Fatalf("expected 1 relationship, got %d", len(result.Packages.RelSourceIndices))
	}
}

func TestParse_DocumentVersion(t *testing.T) {
	t.Run("root package versionInfo wins", func(t *testing.T) {
		doc := `{
			"spdxVersion": "SPDX-2.3",
			"SPDXID": "SPDXRef-DOCUMENT",
			"name": "payment-api",
			"documentNamespace": "https://example.com/payment-api",
			"creationInfo": {"created": "2025-01-15T10:00:00Z", "creators": ["Tool: t"]},
			"packages": [
				{"SPDXID": "SPDXRef-Root", "name": "payment-api", "versionInfo": "1.4.2"},
				{"SPDXID": "SPDXRef-Dep", "name": "lodash", "versionInfo": "4.17.15"}
			],
			"relationships": [
				{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Root"},
				{"spdxElementId": "SPDXRef-Root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Dep"}
			]
		}`
		result, err := Parse(strings.NewReader(doc), "payment-api.spdx.json", "h1")
		if err != nil {
			t.Fatalf("Parse() returned error: %v", err)
		}
		if result.SBOM.DocumentVersion != "1.4.2" {
			t.Errorf("expected document version 1.4.2, got %q", result.SBOM.DocumentVersion)
		}
	})

	t.Run("no DESCRIBES root means no version, never a dependency's", func(t *testing.T) {
		// testSPDXJSON has no DESCRIBES relationship at all.
		result, err := Parse(strings.NewReader(testSPDXJSON), "test.spdx.json", "h2")
		if err != nil {
			t.Fatalf("Parse() returned error: %v", err)
		}
		if result.SBOM.DocumentVersion != "" {
			t.Errorf("expected empty document version, got %q", result.SBOM.DocumentVersion)
		}
	})

	t.Run("NOASSERTION is treated as unset", func(t *testing.T) {
		doc := `{
			"spdxVersion": "SPDX-2.3",
			"SPDXID": "SPDXRef-DOCUMENT",
			"name": "tool",
			"documentNamespace": "https://example.com/tool",
			"creationInfo": {"created": "2025-01-15T10:00:00Z", "creators": ["Tool: t"]},
			"packages": [{"SPDXID": "SPDXRef-Root", "name": "tool", "versionInfo": "NOASSERTION"}],
			"relationships": [
				{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Root"}
			]
		}`
		result, err := Parse(strings.NewReader(doc), "tool.spdx.json", "h3")
		if err != nil {
			t.Fatalf("Parse() returned error: %v", err)
		}
		if result.SBOM.DocumentVersion != "" {
			t.Errorf("expected empty document version, got %q", result.SBOM.DocumentVersion)
		}
	})
}
