package main

import (
	"context"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/license"
)

// plainResolver resolves nothing and does not implement explainer.
type plainResolver struct{}

func (plainResolver) Resolve(context.Context, string) string { return "" }
func (plainResolver) PreloadCache(map[string]string)         {}
func (plainResolver) CacheEntries() map[string]string        { return nil }

func TestPurlType(t *testing.T) {
	tests := map[string]string{
		"pkg:npm/left-pad@1.0.0":       "npm",
		"pkg:Maven/org.x/y@1":          "maven",
		"pkg:generic/libc.so.6?x=1":    "generic",
		"pkg:golang":                   "golang",
		"npm/left-pad":                 "",
		"":                             "",
		"pkg:composer/vendor/name@dev": "composer",
	}
	for purl, want := range tests {
		if got := purlType(purl); got != want {
			t.Errorf("purlType(%q) = %q, want %q", purl, got, want)
		}
	}
}

func TestUnresolvedReasonPrecedence(t *testing.T) {
	depsdev := registryResolver{"depsdev", &fakeRegistry{prefixes: []string{"pkg:pypi/", "pkg:cargo/"}, known: map[string]outcome{
		"pkg:pypi/a@1": {reason: license.ReasonNoLicenseUpstream},
		"pkg:pypi/b@1": {reason: license.ReasonNoLicenseUpstream},
	}}}
	pypi := registryResolver{"pypi", &fakeRegistry{prefixes: []string{"pkg:pypi/"}, known: map[string]outcome{
		"pkg:pypi/a@1": {reason: license.ReasonNotPublished},
		"pkg:pypi/b@1": {}, // handled, but no reason: must not erase depsdev's
	}}}
	resolvers := []registryResolver{depsdev, {"plain", plainResolver{}}, pypi}

	tests := []struct {
		name   string
		purl   string
		isRoot bool
		want   string
	}{
		{"root beats everything", "pkg:pypi/a@1", true, license.ReasonFirstParty},
		{"root without purl", "", true, license.ReasonFirstParty},
		{"yarn workspace", "pkg:npm/%40acme/web@0.0.0-use.local", false, license.ReasonFirstParty},
		{"maven project module", "pkg:maven/${project.groupId}/core@1", false, license.ReasonFirstParty},
		{"no purl", "", false, license.ReasonNoPURL},
		{"uncovered ecosystem", "pkg:deb/debian/libc6@2.36", false, license.ReasonUnsupported},
		{"not a purl", "left-pad", false, license.ReasonUnsupported},
		{"later resolver is more specific", "pkg:pypi/a@1", false, license.ReasonNotPublished},
		{"empty reason does not override", "pkg:pypi/b@1", false, license.ReasonNoLicenseUpstream},
		{"covered but nobody explains", "pkg:cargo/c@1", false, license.ReasonUnresolved},
		{"covered, no resolver at all", "pkg:nuget/D@1", false, license.ReasonUnresolved},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unresolvedReason(resolvers, tt.purl, tt.isRoot); got != tt.want {
				t.Errorf("unresolvedReason(%q, root=%v) = %q, want %q", tt.purl, tt.isRoot, got, tt.want)
			}
		})
	}
}

func TestResolvePackageLicenses(t *testing.T) {
	purls := []string{
		"pkg:golang/github.com/acme/declared@v1",
		"pkg:golang/github.com/acme/lib@v1",
		"pkg:golang/github.com/acme/freetext@v1",
		"pkg:npm/from-npm@1.0.0",
		"",
	}
	licenses := []string{"Apache-2.0", "NOASSERTION", "", "NONE", "NOASSERTION", "NOASSERTION"} // one more license than purls

	githubCalls := map[string]int{}
	github := func(_ context.Context, purl string) string {
		githubCalls[purl]++
		switch purl {
		case "pkg:golang/github.com/acme/lib@v1":
			return "MIT"
		case "pkg:golang/github.com/acme/freetext@v1":
			return "Apache License 2.0"
		}
		return ""
	}
	npm := registryResolver{"npm", &fakeRegistry{prefixes: []string{"pkg:npm/"}, known: map[string]outcome{
		"pkg:npm/from-npm@1.0.0": {license: "ISC", latest: true},
	}}}

	sources, counts := resolvePackageLicenses(context.Background(), github, []registryResolver{npm}, purls, licenses, nil)

	wantLic := []string{"Apache-2.0", "MIT", "Apache-2.0", "ISC", "NOASSERTION", "NOASSERTION"}
	wantSrc := []string{"declared", "github", "github+normalized", "npm+latest", license.ReasonNoPURL, license.ReasonNoPURL}
	for i := range wantLic {
		if licenses[i] != wantLic[i] || sources[i] != wantSrc[i] {
			t.Errorf("package %d: (%q, %q), want (%q, %q)", i, licenses[i], sources[i], wantLic[i], wantSrc[i])
		}
	}
	if githubCalls["pkg:golang/github.com/acme/declared@v1"] != 0 {
		t.Error("GitHub was asked about a package with a declared license")
	}
	if counts["github"] != 2 || counts["npm"] != 1 {
		t.Errorf("counts = %v, want github:2 npm:1", counts)
	}
}

func TestResolvePackageLicensesWithoutGitHub(t *testing.T) {
	licenses := []string{"NOASSERTION", "GPL-2.0+"}
	sources, counts := resolvePackageLicenses(context.Background(), nil, nil,
		[]string{"pkg:cargo/c@1", "pkg:cargo/d@1"}, licenses, []uint32{})
	if sources[0] != license.ReasonUnresolved || sources[1] != "declared+normalized" || licenses[1] != "GPL-2.0-or-later" {
		t.Errorf("got licenses %v sources %v", licenses, sources)
	}
	if len(counts) != 0 {
		t.Errorf("counts = %v, want none", counts)
	}
}
