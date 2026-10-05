package sbom

import (
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func TestNormalizeNPMPURL(t *testing.T) {
	cases := []struct{ in, want string }{
		// Yarn Berry lockfile keys: the last entry is the resolved one.
		{"pkg:npm/ws@npm:^8.18.0, ws@8.20.0", "pkg:npm/ws@8.20.0"},
		{"pkg:npm/%40types/estree@npm:*, @types/estree@npm:1.0.8, @types/estree@npm:^1.0.0, @types/estree@1.0.8", "pkg:npm/%40types/estree@1.0.8"},
		{"pkg:npm/%40asyncapi/specs@npm:6.11.1, @asyncapi/specs@6.11.1", "pkg:npm/%40asyncapi/specs@6.11.1"},
		{"pkg:npm/%40backstage/cli-node@workspace:^, @backstage/cli-node@0.0.0-use.local", "pkg:npm/%40backstage/cli-node@0.0.0-use.local"},
		// Last entry still carrying the protocol prefix.
		{"pkg:npm/foo@npm:^1.0.0, foo@npm:1.2.3", "pkg:npm/foo@1.2.3"},
		// npm aliases resolve to the real package.
		{"pkg:npm/ajv@npm:@redocly/ajv@8.18.1", "pkg:npm/%40redocly/ajv@8.18.1"},
		{"pkg:npm/esbuild@npm:esbuild-wasm@0.23.1", "pkg:npm/esbuild-wasm@0.23.1"},
		// Qualifiers and subpath survive.
		{"pkg:npm/ws@npm:^8.18.0, ws@8.20.0?arch=x64#lib", "pkg:npm/ws@8.20.0?arch=x64#lib"},
		// Yarn "patch:" protocol: the resolved version follows the final '@'.
		{"pkg:npm/ast-types@patch:ast-types@0.16.1", "pkg:npm/ast-types@0.16.1"},
		{"pkg:npm/%40material-ui/pickers@patch:@material-ui/pickers@npm%3A3.3.11#./.yarn/patches/@3.3.11", "pkg:npm/%40material-ui/pickers@3.3.11"},
		{"pkg:npm/fsevents@patch:fsevents@npm%3A^2.3.3#optional!builtin<compat/fsevents>, fsevents@patch:fsevents@npm%3A~2.3.2#optional!builtin<compat/fsevents>, fsevents@patch:fsevents@2.3.3", "pkg:npm/fsevents@2.3.3"},
		{"pkg:npm/resolve@patch:resolve@npm%3A^1.1.7#optional!builtin<compat/resolve>, resolve@patch:resolve@1.22.11", "pkg:npm/resolve@1.22.11"},
		// Unresolvable patch keys are left alone rather than guessed.
		{"pkg:npm/foo@patch:foo@npm%3A^1.0.0#./p.patch", "pkg:npm/foo@patch:foo@npm%3A^1.0.0#./p.patch"},
		// Well-formed PURLs and other ecosystems are untouched.
		{"pkg:npm/%40angular/core@17.0.0", "pkg:npm/%40angular/core@17.0.0"},
		{"pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.21"},
		{"pkg:npm/lodash", "pkg:npm/lodash"},
		{"pkg:maven/a/b@1, c@2", "pkg:maven/a/b@1, c@2"},
		{"", ""},
	}
	for _, c := range cases {
		if got := NormalizeNPMPURL(c.in); got != c.want {
			t.Errorf("NormalizeNPMPURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeNPMIdentities(t *testing.T) {
	p := models.SBOMPackages{
		PackageNames: []string{
			"@asyncapi/parser@npm:^3.1.0, @asyncapi/parser@npm:^3.3.0, @asyncapi/parser",
			"ws@npm:^8.18.0, ws",
			"lodash",
			"guava",
		},
		PackageVersions: []string{"3.4.0", "8.20.0", "4.17.21", "33.0"},
		PackagePURLs: []string{
			"pkg:npm/%40asyncapi/parser@npm:^3.1.0, @asyncapi/parser@npm:^3.3.0, @asyncapi/parser@3.4.0",
			"pkg:npm/ws@npm:^8.18.0, ws@8.20.0",
			"pkg:npm/lodash@4.17.21",
			"pkg:maven/com.google.guava/guava@33.0",
		},
	}
	normalizeNPMIdentities(&p)

	wantNames := []string{"@asyncapi/parser", "ws", "lodash", "guava"}
	wantPURLs := []string{
		"pkg:npm/%40asyncapi/parser@3.4.0",
		"pkg:npm/ws@8.20.0",
		"pkg:npm/lodash@4.17.21",
		"pkg:maven/com.google.guava/guava@33.0",
	}
	for i := range wantNames {
		if p.PackageNames[i] != wantNames[i] {
			t.Errorf("name[%d] = %q, want %q", i, p.PackageNames[i], wantNames[i])
		}
		if p.PackagePURLs[i] != wantPURLs[i] {
			t.Errorf("purl[%d] = %q, want %q", i, p.PackagePURLs[i], wantPURLs[i])
		}
	}
}

func TestParse_NormalizesYarnLockfilePURLs(t *testing.T) {
	doc := `{
	  "spdxVersion": "SPDX-2.3",
	  "SPDXID": "SPDXRef-DOCUMENT",
	  "name": "yarn-app",
	  "packages": [{
	    "SPDXID": "SPDXRef-ws",
	    "name": "ws@npm:^8.18.0, ws",
	    "versionInfo": "8.20.0",
	    "licenseDeclared": "NOASSERTION",
	    "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
	      "referenceLocator": "pkg:npm/ws@npm:^8.18.0, ws@8.20.0"}]
	  }]
	}`
	res, err := Parse(strings.NewReader(doc), "yarn.spdx.json", "h")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := res.Packages.PackagePURLs; len(got) != 1 || got[0] != "pkg:npm/ws@8.20.0" {
		t.Fatalf("purls = %v, want [pkg:npm/ws@8.20.0]", got)
	}
	if got := res.Packages.PackageNames[0]; got != "ws" {
		t.Fatalf("name = %q, want ws", got)
	}
}

func TestNormalizeNPMName_YarnPatch(t *testing.T) {
	cases := map[string]string{
		"fsevents@patch:fsevents": "fsevents",
		"@material-ui/pickers@patch:@material-ui/pickers@npm%3A3.3.11#./.yarn/patches/": "@material-ui/pickers",
		"resolve@patch:resolve@npm%3A^1.1.7#optional!builtin<compat/resolve>, resolve":  "resolve",
		"lodash": "lodash",
	}
	for in, want := range cases {
		if got := normalizeNPMName(in); got != want {
			t.Errorf("normalizeNPMName(%q) = %q, want %q", in, got, want)
		}
	}
}
