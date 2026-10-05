package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/sbom"
)

// outcome is what a fake registry knows about one purl.
type outcome struct {
	license string
	reason  string // license.Reason* when license is ""
	latest  bool
}

// fakeRegistry is an offline stand-in for a real resolver, including the
// Explain contract (why a purl stayed unresolved, whether "latest" was used).
type fakeRegistry struct {
	prefixes []string
	known    map[string]outcome
}

func (f *fakeRegistry) handles(purl string) bool {
	for _, p := range f.prefixes {
		if strings.HasPrefix(purl, p) {
			return true
		}
	}
	return false
}

func (f *fakeRegistry) Resolve(_ context.Context, purl string) string {
	if !f.handles(purl) {
		return ""
	}
	return f.known[purl].license
}

func (f *fakeRegistry) Explain(purl string) (bool, string, bool) {
	if !f.handles(purl) {
		return false, "", false
	}
	o := f.known[purl]
	return true, o.reason, o.latest
}

func (f *fakeRegistry) PreloadCache(map[string]string)  {}
func (f *fakeRegistry) CacheEntries() map[string]string { return nil }

// TestLicensePipelineGolden runs a synthetic SBOM that contains every edge
// case the license pipeline has a rule for through the real parser, the real
// resolution/normalisation/provenance code (with offline registries) and the
// real categorisation, and pins the outcome per package. Each row is one
// decision documented on the "License Resolution" docs page; when a rule
// changes on purpose, this table and the docs change with it.
func TestLicensePipelineGolden(t *testing.T) {
	prevMode := license.GetExpressionMode()
	license.SetExpressionMode(license.ExpressionModeStrict)
	t.Cleanup(func() { license.SetExpressionMode(prevMode) })

	raw, err := os.ReadFile("testdata/license_golden.spdx.json")
	if err != nil {
		t.Fatal(err)
	}
	result, err := sbom.Parse(strings.NewReader(string(raw)), "license_golden.spdx.json", "sha")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pkgs := result.Packages

	github := func(_ context.Context, purl string) string {
		if strings.HasPrefix(purl, "pkg:golang/github.com/acme/lib@") {
			return "MIT"
		}
		return ""
	}
	resolvers := []registryResolver{
		{"npm", &fakeRegistry{prefixes: []string{"pkg:npm/"}, known: map[string]outcome{
			"pkg:npm/npm-pkg@2.0.0":     {license: "ISC"},
			"pkg:npm/npm-versionless":   {license: "MIT", latest: true},
			"pkg:npm/fsevents@2.3.3":    {license: "MIT"},
			"pkg:npm/internal-ui@1.0.0": {reason: license.ReasonNotPublished},
		}}},
		{"depsdev", &fakeRegistry{prefixes: []string{"pkg:maven/", "pkg:pypi/", "pkg:cargo/", "pkg:golang/"}, known: map[string]outcome{
			"pkg:maven/org.apache.commons/commons-lang3@3.14.0": {license: "Apache-2.0"},
			// deps.dev returns the raw POM text; step 2c normalises it.
			"pkg:maven/jakarta.xml.bind/jakarta.xml.bind-api@4.0.2": {license: "Eclipse Distribution License - v 1.0"},
			"pkg:pypi/typing-extensions@4.0.0":                      {reason: license.ReasonNoLicenseUpstream},
			"pkg:pypi/legacy-tool@0.1":                              {reason: license.ReasonNoLicenseUpstream},
			// A transport error leaves no reason.
			"pkg:cargo/flaky-crate@1.0.0": {},
		}}},
		{"packagist", &fakeRegistry{prefixes: []string{"pkg:composer/"}, known: map[string]outcome{
			"pkg:composer/monolog/monolog@dev-main": {license: "MIT", latest: true},
		}}},
		{"pypi", &fakeRegistry{prefixes: []string{"pkg:pypi/"}, known: map[string]outcome{
			"pkg:pypi/typing-extensions@4.0.0": {license: "PSF-2.0"},
			"pkg:pypi/legacy-tool@0.1":         {reason: license.ReasonNoLicenseUpstream},
		}}},
	}

	sources, _ := resolvePackageLicenses(context.Background(), github, resolvers,
		pkgs.PackagePURLs, pkgs.PackageLicenses, pkgs.RootIndices)

	skipped := map[int]bool{}
	for _, i := range licenseCheckSkips(pkgs.RootIndices, pkgs.PackagePURLs) {
		skipped[int(i)] = true
	}

	seen := map[string]bool{}
	for i, name := range pkgs.PackageNames {
		w, ok := licenseGolden[name]
		if !ok {
			t.Errorf("package %q (%s) has no golden row", name, pkgs.PackagePURLs[i])
			continue
		}
		seen[name] = true
		lic := pkgs.PackageLicenses[i]
		if lic != w.license {
			t.Errorf("%s: license %q, want %q", name, lic, w.license)
		}
		if sources[i] != w.source {
			t.Errorf("%s: source %q, want %q", name, sources[i], w.source)
		}
		if cat := license.Categorize(lic); cat != w.category {
			t.Errorf("%s: category %q, want %q", name, cat, w.category)
		}
		if skipped[i] != w.excluded {
			t.Errorf("%s: excluded from compliance = %v, want %v", name, skipped[i], w.excluded)
		}
	}
	for name := range licenseGolden {
		if !seen[name] {
			t.Errorf("golden row %q matches no package in the fixture", name)
		}
	}
}

type goldenWant struct {
	license  string
	source   string
	category license.Category
	excluded bool // not part of license compliance
}

// licenseGolden is the expected outcome per package of
// testdata/license_golden.spdx.json. The "Worked examples" table on the
// License Resolution docs page must list exactly these rows
// (TestDocsLicenseResolutionInSync).
var licenseGolden = map[string]goldenWant{
	// The product itself is not a dependency.
	"golden-app": {"NOASSERTION", license.ReasonFirstParty, license.CategoryUnknown, true},
	// Declared in the SBOM.
	"declared-mit":        {"MIT", "declared", license.CategoryPermissive, false},
	"declared-freetext":   {"Apache-2.0", "declared+normalized", license.CategoryPermissive, false},
	"declared-deprecated": {"GPL-2.0-or-later", "declared+normalized", license.CategoryCopyleft, false},
	"declared-or":         {"MIT OR GPL-3.0-only", "declared", license.CategoryPermissive, false},
	"declared-and":        {"MIT AND GPL-3.0-only", "declared", license.CategoryCopyleft, false},
	"declared-custom":     {"LicenseRef-Remix-Icon-License-1.0", "declared", license.CategoryUnapproved, false},
	// Resolved.
	"github.com/acme/lib":  {"MIT", "github", license.CategoryPermissive, false},
	"npm-pkg":              {"ISC", "npm", license.CategoryPermissive, false},
	"npm-versionless":      {"MIT", "npm+latest", license.CategoryPermissive, false},
	"fsevents":             {"MIT", "npm", license.CategoryPermissive, false}, // Yarn patch: purl repaired by the parser
	"commons-lang3":        {"Apache-2.0", "depsdev", license.CategoryPermissive, false},
	"jakarta.xml.bind-api": {"BSD-3-Clause", "depsdev+normalized", license.CategoryPermissive, false},
	"monolog/monolog":      {"MIT", "packagist+latest", license.CategoryPermissive, false},
	"typing-extensions":    {"PSF-2.0", "pypi", license.CategoryPermissive, false}, // deps.dev had nothing, PyPI did
	// Unresolved, with the reason.
	"internal-ui":   {"NOASSERTION", license.ReasonNotPublished, license.CategoryUnknown, false},
	"@golden/web":   {"NOASSERTION", license.ReasonFirstParty, license.CategoryUnknown, true},
	"golden-core":   {"NOASSERTION", license.ReasonFirstParty, license.CategoryUnknown, true},
	"legacy-tool":   {"NOASSERTION", license.ReasonNoLicenseUpstream, license.CategoryUnknown, false},
	"libc.so.6":     {"NOASSERTION", license.ReasonUnsupported, license.CategoryUnknown, false},
	"vendored-blob": {"NOASSERTION", license.ReasonNoPURL, license.CategoryUnknown, false},
	"flaky-crate":   {"NOASSERTION", license.ReasonUnresolved, license.CategoryUnknown, false},
}
