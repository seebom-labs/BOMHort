package vexsub

import (
	"slices"
	"testing"
)

func TestParsePURL(t *testing.T) {
	tests := []struct {
		raw      string
		wantOK   bool
		wantCore string
		wantVer  string
		wantArch string
	}{
		{
			raw:      "pkg:rpm/redhat/curl@7.61.1-22.el8?arch=x86_64&distro=rhel-8",
			wantOK:   true,
			wantCore: "pkg:rpm/redhat/curl",
			wantVer:  "7.61.1-22.el8",
			wantArch: "x86_64",
		},
		{
			raw:      "pkg:npm/%40babel/core@7.24.0",
			wantOK:   true,
			wantCore: "pkg:npm/@babel/core",
			wantVer:  "7.24.0",
		},
		{
			raw:      "pkg:npm/@babel/core@7.24.0",
			wantOK:   true,
			wantCore: "pkg:npm/@babel/core",
			wantVer:  "7.24.0",
		},
		{
			raw:      "pkg:golang/github.com/gin-gonic/gin",
			wantOK:   true,
			wantCore: "pkg:golang/github.com/gin-gonic/gin",
			wantVer:  "",
		},
		{
			raw:      "pkg:pypi/Requests@2.31.0",
			wantOK:   true,
			wantCore: "pkg:pypi/requests",
			wantVer:  "2.31.0",
		},
		{
			raw:    "not-a-purl",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		got, ok := ParsePURL(tc.raw)
		if ok != tc.wantOK {
			t.Errorf("ParsePURL(%q) ok = %v, want %v", tc.raw, ok, tc.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if got.Core() != tc.wantCore {
			t.Errorf("ParsePURL(%q) Core = %q, want %q", tc.raw, got.Core(), tc.wantCore)
		}
		if got.Version != tc.wantVer {
			t.Errorf("ParsePURL(%q) Version = %q, want %q", tc.raw, got.Version, tc.wantVer)
		}
		if tc.wantArch != "" && got.Qualifiers["arch"] != tc.wantArch {
			t.Errorf("ParsePURL(%q) arch = %q, want %q", tc.raw, got.Qualifiers["arch"], tc.wantArch)
		}
	}
}

func TestMatchKnownPURLs(t *testing.T) {
	known := []string{
		"pkg:rpm/redhat/curl@7.61.1-22.el8?arch=x86_64&distro=rhel-8",
		"pkg:rpm/redhat/curl@7.61.1-22.el8?arch=aarch64&distro=rhel-8",
		"pkg:rpm/redhat/curl@7.61.1-25.el8?arch=x86_64&distro=rhel-8",
		"pkg:golang/github.com/gin-gonic/gin@v1.9.1",
		"pkg:golang/github.com/gin-gonic/gin@v1.10.0",
	}

	// Statement with arch=x86_64 matches only x86_64 of version 7.61.1-22.el8.
	got := MatchKnownPURLs("pkg:rpm/redhat/curl@7.61.1-22.el8?arch=x86_64", known)
	want := []string{"pkg:rpm/redhat/curl@7.61.1-22.el8?arch=x86_64&distro=rhel-8"}
	if !slices.Equal(got, want) {
		t.Errorf("arch match = %v, want %v", got, want)
	}

	// Statement without qualifiers matches both arches of exact version, but not 7.61.1-25.el8.
	got = MatchKnownPURLs("pkg:rpm/redhat/curl@7.61.1-22.el8", known)
	want = []string{
		"pkg:rpm/redhat/curl@7.61.1-22.el8?arch=x86_64&distro=rhel-8",
		"pkg:rpm/redhat/curl@7.61.1-22.el8?arch=aarch64&distro=rhel-8",
	}
	if !slices.Equal(got, want) {
		t.Errorf("versioned match = %v, want %v", got, want)
	}

	// Versionless OpenVEX hub PURL matches all known versions of that package.
	got = MatchKnownPURLs("pkg:golang/github.com/gin-gonic/gin", known)
	want = []string{
		"pkg:golang/github.com/gin-gonic/gin@v1.9.1",
		"pkg:golang/github.com/gin-gonic/gin@v1.10.0",
	}
	if !slices.Equal(got, want) {
		t.Errorf("versionless match = %v, want %v", got, want)
	}
}
