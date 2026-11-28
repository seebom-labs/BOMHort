package cyclonedx

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/license"
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
	if result.SBOM.DocumentVersion != "1.0.0" {
		t.Errorf("expected DocumentVersion='1.0.0', got %q", result.SBOM.DocumentVersion)
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

func TestExtractLicense_CompoundParenthesized(t *testing.T) {
	tests := []struct {
		name string
		lics []CDXLicense
		want string
	}{
		{
			name: "empty list",
			lics: nil,
			want: "NOASSERTION",
		},
		{
			name: "single ID",
			lics: []CDXLicense{
				{License: &CDXLicenseID{ID: "MIT"}},
			},
			want: "MIT",
		},
		{
			name: "single expression",
			lics: []CDXLicense{
				{Expression: "MIT OR Apache-2.0"},
			},
			want: "MIT OR Apache-2.0",
		},
		{
			name: "two simple IDs joined with AND",
			lics: []CDXLicense{
				{License: &CDXLicenseID{ID: "MIT"}},
				{License: &CDXLicenseID{ID: "Apache-2.0"}},
			},
			want: "MIT AND Apache-2.0",
		},
		{
			name: "compound expression joined with ID parenthesizes compound",
			lics: []CDXLicense{
				{Expression: "MIT OR Apache-2.0"},
				{License: &CDXLicenseID{ID: "GPL-3.0-only"}},
			},
			want: "(MIT OR Apache-2.0) AND GPL-3.0-only",
		},
		{
			name: "ID joined with compound expression",
			lics: []CDXLicense{
				{License: &CDXLicenseID{ID: "BSD-3-Clause"}},
				{Expression: "MIT OR Apache-2.0"},
			},
			want: "BSD-3-Clause AND (MIT OR Apache-2.0)",
		},
		{
			name: "already fully parenthesized expression is not double wrapped",
			lics: []CDXLicense{
				{Expression: "(MIT OR Apache-2.0)"},
				{License: &CDXLicenseID{ID: "GPL-3.0-only"}},
			},
			want: "(MIT OR Apache-2.0) AND GPL-3.0-only",
		},
		{
			name: "compound with WITH expression",
			lics: []CDXLicense{
				{Expression: "GPL-2.0-only WITH Classpath-exception-2.0"},
				{License: &CDXLicenseID{ID: "MIT"}},
			},
			want: "(GPL-2.0-only WITH Classpath-exception-2.0) AND MIT",
		},
		{
			name: "compound with internal parens but not fully enclosed",
			lics: []CDXLicense{
				{Expression: "(MIT AND BSD-3-Clause) OR Apache-2.0"},
				{License: &CDXLicenseID{ID: "GPL-3.0-only"}},
			},
			want: "((MIT AND BSD-3-Clause) OR Apache-2.0) AND GPL-3.0-only",
		},
		{
			name: "license by name containing spaces without operator is not parenthesized",
			lics: []CDXLicense{
				{License: &CDXLicenseID{Name: "Apache License 2.0"}},
				{License: &CDXLicenseID{ID: "MIT"}},
			},
			want: "Apache License 2.0 AND MIT",
		},
		{
			name: "license by name containing operator is parenthesized",
			lics: []CDXLicense{
				{License: &CDXLicenseID{Name: "Apache-2.0 or commercial"}},
				{License: &CDXLicenseID{ID: "MIT"}},
			},
			want: "(Apache-2.0 or commercial) AND MIT",
		},
		{
			name: "nested parens on each branch",
			lics: []CDXLicense{
				{Expression: "(MIT) OR (Apache-2.0)"},
				{License: &CDXLicenseID{ID: "GPL-3.0-only"}},
			},
			want: "((MIT) OR (Apache-2.0)) AND GPL-3.0-only",
		},
		{
			name: "newline separated compound expression",
			lics: []CDXLicense{
				{Expression: "MIT\nOR\nApache-2.0"},
				{License: &CDXLicenseID{ID: "GPL-3.0-only"}},
			},
			want: "(MIT\nOR\nApache-2.0) AND GPL-3.0-only",
		},
		{
			name: "compound without spaces around parentheses",
			lics: []CDXLicense{
				{Expression: "(MIT)OR(Apache-2.0)"},
				{License: &CDXLicenseID{ID: "GPL-3.0-only"}},
			},
			want: "((MIT)OR(Apache-2.0)) AND GPL-3.0-only",
		},
		{
			name: "padded compound expression",
			lics: []CDXLicense{
				{Expression: "  MIT OR Apache-2.0  "},
				{License: &CDXLicenseID{ID: "GPL-3.0-only"}},
			},
			want: "(MIT OR Apache-2.0) AND GPL-3.0-only",
		},
		{
			name: "empty license entries skipped",
			lics: []CDXLicense{
				{Expression: ""},
				{Expression: "   "},
				{License: &CDXLicenseID{ID: ""}},
				{License: &CDXLicenseID{ID: "MIT"}},
			},
			want: "MIT",
		},
		{
			name: "multiple compound expressions",
			lics: []CDXLicense{
				{Expression: "MIT OR Apache-2.0"},
				{Expression: "BSD-3-Clause OR ISC"},
				{License: &CDXLicenseID{ID: "GPL-3.0-only"}},
			},
			want: "(MIT OR Apache-2.0) AND (BSD-3-Clause OR ISC) AND GPL-3.0-only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLicense(tt.lics)
			if got != tt.want {
				t.Errorf("extractLicense() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParse_CompoundLicensePrecedencePreserved(t *testing.T) {
	cdxJSON := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		"version": 1,
		"metadata": {
			"timestamp": "2024-01-15T10:30:00Z",
			"component": {"type": "application", "name": "my-app", "version": "1.0.0"}
		},
		"components": [
			{
				"type": "library",
				"bom-ref": "pkg:npm/compound-lib@1.0.0",
				"name": "compound-lib",
				"version": "1.0.0",
				"purl": "pkg:npm/compound-lib@1.0.0",
				"licenses": [
					{"expression": "MIT OR Apache-2.0"},
					{"license": {"id": "GPL-3.0-only"}}
				]
			},
			{
				"type": "library",
				"bom-ref": "pkg:npm/nested-compound-lib@1.0.0",
				"name": "nested-compound-lib",
				"version": "1.0.0",
				"purl": "pkg:npm/nested-compound-lib@1.0.0",
				"licenses": [
					{"expression": "(MIT) OR (Apache-2.0)"},
					{"license": {"id": "GPL-3.0-only"}}
				]
			}
		]
	}`)

	result, err := Parse(cdxJSON, "test.cdx.json", "abc123hash")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(result.Packages.PackageLicenses) != 2 {
		t.Fatalf("expected 2 package licenses, got %d", len(result.Packages.PackageLicenses))
	}

	lic := result.Packages.PackageLicenses[0]
	wantLic := "(MIT OR Apache-2.0) AND GPL-3.0-only"
	if lic != wantLic {
		t.Errorf("extracted license 0 = %q, want %q", lic, wantLic)
	}

	// Verify that categorization preserves copyleft requirement.
	// Unparenthesized "MIT OR Apache-2.0 AND GPL-3.0-only" would parse as
	// "MIT OR (Apache-2.0 AND GPL-3.0-only)" which evaluates as Permissive because
	// the left branch of OR is MIT.
	cat := license.Categorize(lic)
	if cat != license.CategoryCopyleft {
		t.Errorf("Categorize(%q) = %q, want %q", lic, cat, license.CategoryCopyleft)
	}

	// Second component tests nesting logic: (MIT) OR (Apache-2.0) starts with ( and ends with ),
	// but is NOT fully enclosed by a single pair. It must be parenthesized to avoid
	// parsing as (MIT) OR ((Apache-2.0) AND GPL-3.0-only).
	lic2 := result.Packages.PackageLicenses[1]
	wantLic2 := "((MIT) OR (Apache-2.0)) AND GPL-3.0-only"
	if lic2 != wantLic2 {
		t.Errorf("extracted license 1 = %q, want %q", lic2, wantLic2)
	}
	cat2 := license.Categorize(lic2)
	if cat2 != license.CategoryCopyleft {
		t.Errorf("Categorize(%q) = %q, want %q", lic2, cat2, license.CategoryCopyleft)
	}
}

func TestParse_MetadataToolsFormats(t *testing.T) {
	tests := []struct {
		name      string
		toolsJSON string
		wantTools []string
		wantErr   bool
	}{
		{
			name:      "legacy array form",
			toolsJSON: `[{"vendor": "anchore", "name": "syft", "version": "0.100.0"}]`,
			wantTools: []string{"Tool: anchore syft 0.100.0"},
		},
		{
			name:      "legacy array missing vendor",
			toolsJSON: `[{"name": "trivy", "version": "0.50.0"}]`,
			wantTools: []string{"Tool: trivy 0.50.0"},
		},
		{
			name:      "object form syft component with author",
			toolsJSON: `{"components": [{"type": "application", "author": "anchore", "name": "syft", "version": "1.55.0"}]}`,
			wantTools: []string{"Tool: anchore syft 1.55.0"},
		},
		{
			name:      "object form component with manufacturer and manufacture",
			toolsJSON: `{"components": [{"type": "application", "manufacturer": {"name": "Aqua"}, "name": "trivy", "version": "0.58.0"}, {"type": "application", "manufacture": "VendorCo", "name": "scanner", "version": "2.0"}]}`,
			wantTools: []string{"Tool: Aqua trivy 0.58.0", "Tool: VendorCo scanner 2.0"},
		},
		{
			name:      "object form component with supplier publisher authors and group fallback",
			toolsJSON: `{"components": [{"supplier": {"name": "Supp"}, "name": "t1"}, {"publisher": "Pub", "name": "t2"}, {"authors": [{"name": "Auth"}], "name": "t3"}, {"group": "org.acme", "name": "t4", "version": "1.0"}]}`,
			wantTools: []string{"Tool: Supp t1", "Tool: Pub t2", "Tool: Auth t3", "Tool: org.acme t4 1.0"},
		},
		{
			name:      "object form services with provider and group",
			toolsJSON: `{"services": [{"provider": {"name": "acme"}, "name": "bom-signer", "version": "2.1.0"}, {"group": "sec", "name": "attestor"}]}`,
			wantTools: []string{"Tool: acme bom-signer 2.1.0", "Tool: sec attestor"},
		},
		{
			name:      "object form components and services combined",
			toolsJSON: `{"components": [{"type": "application", "author": "anchore", "name": "syft", "version": "1.55.0"}], "services": [{"provider": {"name": "ci"}, "name": "sbom-relay", "version": "1.2.0"}]}`,
			wantTools: []string{"Tool: anchore syft 1.55.0", "Tool: ci sbom-relay 1.2.0"},
		},
		{
			name:      "empty object",
			toolsJSON: `{}`,
			wantTools: nil,
		},
		{
			name:      "empty array",
			toolsJSON: `[]`,
			wantTools: nil,
		},
		{
			name:      "null tools",
			toolsJSON: `null`,
			wantTools: nil,
		},
		{
			name:      "empty component and null entries skipped cleanly",
			toolsJSON: `{"components": [{}, null]}`,
			wantTools: nil,
		},
		{
			name:      "invalid string tools fails decode",
			toolsJSON: `"syft"`,
			wantErr:   true,
		},
		{
			name:      "invalid number tools fails decode",
			toolsJSON: `42`,
			wantErr:   true,
		},
		{
			name:      "invalid components field type fails decode",
			toolsJSON: `{"components": "not-an-array"}`,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := []byte(`{
				"bomFormat": "CycloneDX",
				"specVersion": "1.6",
				"serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
				"version": 1,
				"metadata": {
					"timestamp": "2026-11-24T21:00:00Z",
					"tools": ` + tt.toolsJSON + `,
					"component": {"type": "application", "name": "app", "version": "1.0.0"}
				},
				"components": []
			}`)
			res, err := Parse(doc, "tools.cdx.json", "hash")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (tools=%v)", res.SBOM.CreatorTools)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(res.SBOM.CreatorTools, tt.wantTools) {
				t.Errorf("CreatorTools = %#v, want %#v", res.SBOM.CreatorTools, tt.wantTools)
			}
		})
	}
}

func TestParse_SyftFixtureObjectTools(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "syft_1.6_tools_object.cdx.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	res, err := Parse(data, "syft_1.6_tools_object.cdx.json", "fixture-hash")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if res.SBOM.SPDXVersion != "CycloneDX-1.6" {
		t.Errorf("SPDXVersion = %q, want CycloneDX-1.6", res.SBOM.SPDXVersion)
	}
	wantTools := []string{"Tool: anchore syft 1.55.0"}
	if !reflect.DeepEqual(res.SBOM.CreatorTools, wantTools) {
		t.Errorf("CreatorTools = %v, want %v", res.SBOM.CreatorTools, wantTools)
	}
	if res.SBOM.Supplier != "Alpine Linux" {
		t.Errorf("Supplier = %q, want Alpine Linux", res.SBOM.Supplier)
	}
	if len(res.Packages.PackageNames) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(res.Packages.PackageNames))
	}
	if len(res.Packages.DirectIndices) != 2 {
		t.Errorf("expected 2 direct dependency seeds, got %v", res.Packages.DirectIndices)
	}
}

func TestExtractTools(t *testing.T) {
	data := []byte(`  {"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"tools":{"components":[{"author":"anchore","name":"syft","version":"1.55.0"}]}}}`)
	got := ExtractTools(data)
	want := []string{"Tool: anchore syft 1.55.0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExtractTools = %v, want %v", got, want)
	}

	if xmlOut := ExtractTools([]byte(`<bom xmlns="http://cyclonedx.org/schema/bom/1.5"/>`)); xmlOut != nil {
		t.Errorf("expected nil for XML input, got %v", xmlOut)
	}
	if nonCDX := ExtractTools([]byte(`{"spdxVersion":"SPDX-2.3"}`)); nonCDX != nil {
		t.Errorf("expected nil for non-CycloneDX input, got %v", nonCDX)
	}
}
