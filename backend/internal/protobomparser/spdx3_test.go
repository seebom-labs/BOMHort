package protobomparser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// TestParse_SPDX3 verifies that protobom's SPDX 3 (JSON-LD) unserializer is
// wired up and that packages, PURLs, licences (declared and concluded via
// hasDeclaredLicense / hasConcludedLicense relationships) and dependsOn
// relationships are mapped into BOMHort's model.
func TestParse_SPDX3(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "demo-app.spdx3.json"))
	if err != nil {
		t.Fatal(err)
	}

	result, err := Parse(data, "demo-app.spdx3.json", "spdx3-hash")
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	if result.SBOM.SPDXVersion != "SPDX-3.0.1" {
		t.Errorf("SPDXVersion = %q, want SPDX-3.0.1", result.SBOM.SPDXVersion)
	}
	if result.SBOM.DocumentName != "demo-app" {
		t.Errorf("DocumentName = %q, want demo-app", result.SBOM.DocumentName)
	}
	if result.SBOM.CreationDate.Year() != 2026 {
		t.Errorf("CreationDate = %v, want 2026-09-01", result.SBOM.CreationDate)
	}

	pk := result.Packages
	if len(pk.PackageNames) != 3 {
		t.Fatalf("expected 3 packages, got %d: %v", len(pk.PackageNames), pk.PackageNames)
	}

	byName := map[string]int{}
	for i, n := range pk.PackageNames {
		byName[n] = i
	}
	want := []struct{ name, version, purl, license string }{
		{"demo-app", "1.2.3", "pkg:generic/demo-app@1.2.3", "Apache-2.0"},
		{"github.com/gin-gonic/gin", "v1.10.0", "pkg:golang/github.com/gin-gonic/gin@v1.10.0", "MIT"},
		{"lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "MIT"}, // concluded only
	}
	for _, w := range want {
		i, ok := byName[w.name]
		if !ok {
			t.Errorf("package %q missing", w.name)
			continue
		}
		if pk.PackageVersions[i] != w.version {
			t.Errorf("%s: version = %q, want %q", w.name, pk.PackageVersions[i], w.version)
		}
		if pk.PackagePURLs[i] != w.purl {
			t.Errorf("%s: purl = %q, want %q", w.name, pk.PackagePURLs[i], w.purl)
		}
		if pk.PackageLicenses[i] != w.license {
			t.Errorf("%s: license = %q, want %q", w.name, pk.PackageLicenses[i], w.license)
		}
	}

	// SPDX 3 element IDs are IRIs and must be kept verbatim.
	if got := pk.PackageSPDXIDs[byName["demo-app"]]; got != "https://example.com/sbom/demo-app#pkg-demo-app" {
		t.Errorf("SPDXID = %q", got)
	}

	// dependsOn: demo-app -> gin, demo-app -> lodash. Licence relationships must
	// not leak into the edge list.
	if len(pk.RelSourceIndices) != 2 {
		t.Fatalf("expected 2 relationships, got %d (%v)", len(pk.RelSourceIndices), pk.RelTypes)
	}
	root := uint32(byName["demo-app"])
	targets := map[uint32]bool{}
	for i := range pk.RelSourceIndices {
		if pk.RelSourceIndices[i] != root {
			t.Errorf("rel[%d] source = %d, want root %d", i, pk.RelSourceIndices[i], root)
		}
		if pk.RelTypes[i] != "dependsOn" {
			t.Errorf("rel[%d] type = %q, want dependsOn", i, pk.RelTypes[i])
		}
		targets[pk.RelTargetIndices[i]] = true
	}
	if !targets[uint32(byName["github.com/gin-gonic/gin"])] || !targets[uint32(byName["lodash"])] {
		t.Errorf("unexpected relationship targets: %v", pk.RelTargetIndices)
	}
}

func TestParse_SPDX3_Minimal(t *testing.T) {
	// A document with no packages must parse without error.
	data := []byte(`{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		"@graph": [
			{"type": "CreationInfo", "@id": "_:ci", "specVersion": "3.0.1",
			 "created": "2026-01-01T00:00:00Z",
			 "createdBy": ["https://spdx.org/rdf/3.0.1/terms/Core/SpdxOrganization"]},
			{"type": "SpdxDocument", "spdxId": "https://example.com/empty", "name": "empty",
			 "creationInfo": "_:ci", "profileConformance": ["core"], "rootElement": []}
		]
	}`)
	result, err := Parse(data, "empty.spdx3.json", "h")
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	if result.SBOM.SPDXVersion != "SPDX-3.0.1" || result.SBOM.DocumentName != "empty" {
		t.Errorf("got %q / %q", result.SBOM.SPDXVersion, result.SBOM.DocumentName)
	}
	if len(result.Packages.PackageNames) != 0 {
		t.Errorf("expected no packages, got %v", result.Packages.PackageNames)
	}
}

func TestParse_SPDX3ContentIdentifierImage(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "demo-app.spdx3.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	raw := strings.Replace(string(data),
		`"software_packageUrl": "pkg:generic/demo-app@1.2.3"`,
		`"software_packageUrl": "pkg:generic/demo-app@1.2.3", "contentIdentifier": "pkg:oci/acme/api@`+digest+`"`, 1)
	result, err := Parse([]byte(raw), "demo-app.spdx3.json", "spdx3-content-identifier")
	if err != nil {
		t.Fatal(err)
	}
	if result.SBOM.ImageRef != "acme/api" || result.SBOM.ImageDigest != digest {
		t.Errorf("image identity = (%q, %q)", result.SBOM.ImageRef, result.SBOM.ImageDigest)
	}
}

func TestParse_SPDX3RootImageWithoutDependencies(t *testing.T) {
	digest := "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	var result models.SBOM
	setRootImageIdentity(&result, []string{"pkg:oci/acme/api@" + digest}, []uint32{0})
	if result.RootPURL != "pkg:oci/acme/api@"+digest || result.ImageRef != "acme/api" || result.ImageDigest != digest {
		t.Fatalf("root image = (%q, %q, %q)", result.RootPURL, result.ImageRef, result.ImageDigest)
	}
}
