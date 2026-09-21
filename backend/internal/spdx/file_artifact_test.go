package spdx

import (
	"strings"
	"testing"
)

// waybill-style document: a described root, real dependencies, and file-tier
// entries that must be dropped. Mirrors agones_1_57_0_spdx.json.
const testWaybillSPDXJSON = `{
	"SPDXID": "SPDXRef-DOCUMENT",
	"spdxVersion": "SPDX-2.3",
	"name": "agones-dev/agones",
	"documentDescribes": ["SPDXRef-DocumentRoot-ABC"],
	"creationInfo": {"created": "2026-08-25T13:20:14Z", "creators": ["Tool: waybill-0.2.0"]},
	"packages": [
		{
			"SPDXID": "SPDXRef-DocumentRoot-ABC",
			"name": "agones-dev/agones",
			"versionInfo": "v1.57.0",
			"licenseDeclared": "NOASSERTION",
			"licenseConcluded": "NOASSERTION",
			"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:generic/agones-dev%2Fagones@v1.57.0"}]
		},
		{
			"SPDXID": "SPDXRef-Package-FILE1",
			"name": "build-sdk-test.sh",
			"versionInfo": "NOASSERTION",
			"licenseDeclared": "NOASSERTION",
			"licenseConcluded": "NOASSERTION",
			"annotations": [
				{"annotator": "Tool: waybill-0.2.0", "annotationType": "OTHER",
				 "comment": "{\"schema\":\"waybill-annotation/v1\",\"field\":\"waybill:component-tier\",\"value\":\"file\"}"}
			]
		},
		{
			"SPDXID": "SPDXRef-Package-STDLIB",
			"name": "stdlib",
			"versionInfo": "v1.25.0",
			"licenseDeclared": "NOASSERTION",
			"licenseConcluded": "NOASSERTION",
			"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/stdlib@v1.25.0"}],
			"annotations": [
				{"annotator": "Tool: waybill-0.2.0", "annotationType": "OTHER",
				 "comment": "{\"schema\":\"waybill-annotation/v1\",\"field\":\"waybill:component-tier\",\"value\":\"package\"}"}
			]
		},
		{
			"SPDXID": "SPDXRef-Package-FILE2",
			"name": "Cargo.toml",
			"versionInfo": "NOASSERTION",
			"licenseDeclared": "NOASSERTION",
			"licenseConcluded": "NOASSERTION"
		},
		{
			"SPDXID": "SPDXRef-Package-DEP",
			"name": "github.com/foo/bar",
			"versionInfo": "v2.0.0",
			"licenseDeclared": "Apache-2.0",
			"licenseConcluded": "Apache-2.0",
			"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/github.com/foo/bar@v2.0.0"}]
		}
	],
	"relationships": [
		{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-DocumentRoot-ABC"},
		{"spdxElementId": "SPDXRef-DocumentRoot-ABC", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Package-STDLIB"},
		{"spdxElementId": "SPDXRef-DocumentRoot-ABC", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Package-DEP"}
	]
}`

func TestParse_DropsFileArtifacts(t *testing.T) {
	result, err := Parse(strings.NewReader(testWaybillSPDXJSON), "agones.spdx.json", "hash")
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	want := []string{"agones-dev/agones", "stdlib", "github.com/foo/bar"}
	got := result.Packages.PackageNames
	if len(got) != len(want) {
		t.Fatalf("expected %d packages %v, got %d: %v", len(want), want, len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("package[%d]: expected %q, got %q", i, want[i], got[i])
		}
	}

	// Relationship indices must be remapped to the filtered arrays:
	// root(0) -> stdlib(1), root(0) -> dep(2). The DESCRIBES edge from the
	// document itself is not a package-to-package relationship and is dropped.
	if len(result.Packages.RelSourceIndices) != 2 {
		t.Fatalf("expected 2 relationships, got %d", len(result.Packages.RelSourceIndices))
	}
	for i, src := range result.Packages.RelSourceIndices {
		if src != 0 {
			t.Errorf("rel[%d] source: expected root index 0, got %d", i, src)
		}
	}
	if tg := result.Packages.RelTargetIndices; tg[0] != 1 || tg[1] != 2 {
		t.Errorf("expected targets [1 2], got %v", tg)
	}

	if len(result.Packages.RootIndices) != 1 || result.Packages.RootIndices[0] != 0 {
		t.Errorf("expected RootIndices [0], got %v", result.Packages.RootIndices)
	}
}

func TestParse_RootIndices_FromRelationshipOnly(t *testing.T) {
	// No documentDescribes – root must still be detected via DESCRIBES relationship.
	doc := `{
		"spdxVersion": "SPDX-2.3",
		"name": "doc",
		"creationInfo": {"created": "2025-01-01T00:00:00Z"},
		"packages": [
			{"SPDXID": "SPDXRef-Package-B", "name": "b", "versionInfo": "1.0"},
			{"SPDXID": "SPDXRef-Package-A", "name": "a", "versionInfo": "1.0"}
		],
		"relationships": [
			{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-A"},
			{"spdxElementId": "SPDXRef-Package-A", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Package-B"}
		]
	}`
	result, err := Parse(strings.NewReader(doc), "x.spdx.json", "h")
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}
	if len(result.Packages.RootIndices) != 1 || result.Packages.RootIndices[0] != 1 {
		t.Errorf("expected RootIndices [1], got %v", result.Packages.RootIndices)
	}
	if len(result.Packages.PackageNames) != 2 {
		t.Errorf("no packages should be dropped, got %v", result.Packages.PackageNames)
	}
}

func TestIsFileArtifact(t *testing.T) {
	tests := []struct {
		name       string
		pkg        SPDXPackage
		purl       string
		referenced bool
		want       bool
	}{
		{
			name: "waybill file tier annotation",
			pkg: SPDXPackage{Name: "ttar", VersionInfo: "NOASSERTION", Annotations: []SPDXAnnotation{{
				Comment: `{"schema":"waybill-annotation/v1","field":"waybill:component-tier","value":"file"}`,
			}}},
			want: true,
		},
		{
			name: "waybill package tier annotation",
			pkg: SPDXPackage{Name: "stdlib", VersionInfo: "v1.25.0", Annotations: []SPDXAnnotation{{
				Comment: `{"schema":"waybill-annotation/v1","field":"waybill:component-tier","value":"package"}`,
			}}},
			purl: "pkg:golang/stdlib@v1.25.0",
			want: false,
		},
		{
			name: "heuristic: script without purl/version/relationship",
			pkg:  SPDXPackage{Name: "gen.sh", VersionInfo: "NOASSERTION"},
			want: true,
		},
		{
			name: "heuristic: manifest with empty version",
			pkg:  SPDXPackage{Name: "package.json"},
			want: true,
		},
		{
			name: "heuristic: file-like name but has purl",
			pkg:  SPDXPackage{Name: "package.json", VersionInfo: "NOASSERTION"},
			purl: "pkg:npm/package.json@1.0.0",
			want: false,
		},
		{
			name:       "heuristic: file-like name but referenced in graph",
			pkg:        SPDXPackage{Name: "setup.sh", VersionInfo: "NOASSERTION"},
			referenced: true,
			want:       false,
		},
		{
			name: "heuristic: file-like name but versioned",
			pkg:  SPDXPackage{Name: "foo.sh", VersionInfo: "1.2.3"},
			want: false,
		},
		{
			name: "plain package name without purl is kept",
			pkg:  SPDXPackage{Name: "Moq", VersionInfo: "NOASSERTION"},
			want: false,
		},
		{
			name: "go module path is kept",
			pkg:  SPDXPackage{Name: "github.com/foo/bar", VersionInfo: ""},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isFileArtifact(tt.pkg, tt.purl, tt.referenced); got != tt.want {
				t.Errorf("isFileArtifact() = %v, want %v", got, tt.want)
			}
		})
	}
}
