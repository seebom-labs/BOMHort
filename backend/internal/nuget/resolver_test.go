package nuget

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtractNuGetPackage(t *testing.T) {
	tests := []struct {
		purl                string
		wantID, wantVersion string
		wantOK              bool
	}{
		{"pkg:nuget/Google.Protobuf@3.15.0", "Google.Protobuf", "3.15.0", true},
		{"pkg:nuget/Moq@4.13.1", "Moq", "4.13.1", true},
		{"pkg:nuget/Moq", "Moq", "", true},
		{"pkg:nuget/Newtonsoft.Json@13.0.1?foo=bar", "Newtonsoft.Json", "13.0.1", true},
		{"pkg:npm/lodash@1.0.0", "", "", false},
		{"pkg:nuget/", "", "", false},
		{"pkg:nuget/a/b@1.0", "", "", false},
		{"pkg:nuget/..@1.0", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			id, v, ok := ExtractNuGetPackage(tt.purl)
			if ok != tt.wantOK || id != tt.wantID || v != tt.wantVersion {
				t.Errorf("got (%q,%q,%v) want (%q,%q,%v)", id, v, ok, tt.wantID, tt.wantVersion, tt.wantOK)
			}
		})
	}
}

func TestLicenseFromURL(t *testing.T) {
	tests := map[string]string{
		"https://opensource.org/licenses/MIT":                              "MIT",
		"http://www.apache.org/licenses/LICENSE-2.0":                       "Apache-2.0",
		"https://www.apache.org/licenses/LICENSE-2.0.html/":                "Apache-2.0",
		"https://licenses.nuget.org/MIT":                                   "MIT",
		"https://aka.ms/deprecateLicenseUrl":                               "",
		"http://www.microsoft.com/web/webpi/eula/net_library_eula_enu.htm": "",
		"": "",
	}
	for in, want := range tests {
		if got := LicenseFromURL(in); got != want {
			t.Errorf("LicenseFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGitHubRepoFromURL(t *testing.T) {
	tests := []struct {
		in          string
		owner, repo string
		ok          bool
	}{
		{"https://github.com/protocolbuffers/protobuf/blob/master/LICENSE", "protocolbuffers", "protobuf", true},
		{"https://raw.githubusercontent.com/moq/moq4/master/License.txt", "moq", "moq4", true},
		{"https://github.com/microsoft/testfx", "microsoft", "testfx", true},
		{"https://github.com/microsoft/testfx.git", "microsoft", "testfx", true},
		{"https://gitlab.com/foo/bar", "", "", false},
		{"https://aka.ms/deprecateLicenseUrl", "", "", false},
		{"", "", "", false},
	}
	for _, tt := range tests {
		o, r, ok := GitHubRepoFromURL(tt.in)
		if ok != tt.ok || o != tt.owner || r != tt.repo {
			t.Errorf("GitHubRepoFromURL(%q) = (%q,%q,%v), want (%q,%q,%v)", tt.in, o, r, ok, tt.owner, tt.repo, tt.ok)
		}
	}
}

type fakeRepoResolver struct {
	calls []string
	m     map[string]string
}

func (f *fakeRepoResolver) Resolve(_ context.Context, purl string) string {
	f.calls = append(f.calls, purl)
	return f.m[purl]
}

func TestResolve(t *testing.T) {
	var srv *httptest.Server
	calls := 0
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		// Modern package with licenseExpression.
		case "/reg/newtonsoft.json/13.0.1.json":
			fmt.Fprintf(w, `{"catalogEntry":"%s/catalog/newtonsoft.json"}`, srv.URL)
		case "/catalog/newtonsoft.json":
			fmt.Fprint(w, `{"id":"Newtonsoft.Json","version":"13.0.1","licenseExpression":"MIT","licenseUrl":"https://licenses.nuget.org/MIT"}`)
		// Legacy package: well-known license URL.
		case "/reg/legacy.apache/1.0.0.json":
			fmt.Fprintf(w, `{"catalogEntry":"%s/catalog/legacy.apache"}`, srv.URL)
		case "/catalog/legacy.apache":
			fmt.Fprint(w, `{"id":"Legacy.Apache","version":"1.0.0","licenseUrl":"http://www.apache.org/licenses/LICENSE-2.0"}`)
		// Legacy package: GitHub license URL → repo resolver.
		case "/reg/google.protobuf/3.15.0.json":
			fmt.Fprintf(w, `{"catalogEntry":"%s/catalog/google.protobuf"}`, srv.URL)
		case "/catalog/google.protobuf":
			fmt.Fprint(w, `{"id":"Google.Protobuf","version":"3.15.0","licenseUrl":"https://github.com/protocolbuffers/protobuf/blob/master/LICENSE","projectUrl":"https://github.com/protocolbuffers/protobuf"}`)
		// Legacy package: deprecated license URL, GitHub project URL → repo resolver.
		case "/reg/mstest.testadapter/2.1.0.json":
			fmt.Fprintf(w, `{"catalogEntry":"%s/catalog/mstest"}`, srv.URL)
		case "/catalog/mstest":
			fmt.Fprint(w, `{"id":"MSTest.TestAdapter","version":"2.1.0","licenseUrl":"https://aka.ms/deprecateLicenseUrl","projectUrl":"https://github.com/microsoft/testfx"}`)
		// Proprietary EULA – unresolvable.
		case "/reg/microsoft.net.test.sdk/15.9.0.json":
			fmt.Fprintf(w, `{"catalogEntry":"%s/catalog/testsdk"}`, srv.URL)
		case "/catalog/testsdk":
			fmt.Fprint(w, `{"id":"Microsoft.NET.Test.Sdk","version":"15.9.0","licenseUrl":"http://www.microsoft.com/web/webpi/eula/net_library_eula_enu.htm","projectUrl":"https://github.com/microsoft/vstest/"}`)
		// Inline catalogEntry object.
		case "/reg/inline/1.0.0.json":
			fmt.Fprint(w, `{"catalogEntry":{"id":"Inline","version":"1.0.0","licenseExpression":"BSD-3-Clause"}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	repo := &fakeRepoResolver{m: map[string]string{
		"pkg:github/protocolbuffers/protobuf": "BSD-3-Clause",
		"pkg:github/microsoft/testfx":         "MIT",
		// microsoft/vstest intentionally unknown
	}}
	r := NewResolverWithBase(srv.URL+"/reg", repo)
	ctx := context.Background()

	cases := map[string]string{
		"pkg:nuget/Newtonsoft.Json@13.0.1":        "MIT",
		"pkg:nuget/Legacy.Apache@1.0.0":           "Apache-2.0",
		"pkg:nuget/Google.Protobuf@3.15.0":        "BSD-3-Clause",
		"pkg:nuget/MSTest.TestAdapter@2.1.0":      "MIT",
		"pkg:nuget/Microsoft.NET.Test.Sdk@15.9.0": "",
		"pkg:nuget/Inline@1.0.0":                  "BSD-3-Clause",
		"pkg:nuget/Missing@1.0.0":                 "",
		"pkg:nuget/NoVersion":                     "",
		"pkg:npm/lodash@1.0.0":                    "",
	}
	for purl, want := range cases {
		if got := r.Resolve(ctx, purl); got != want {
			t.Errorf("Resolve(%q) = %q, want %q", purl, got, want)
		}
	}

	// Repo resolver must only be consulted for GitHub URLs; vstest was asked but unknown.
	wantCalls := 3
	if len(repo.calls) != wantCalls {
		t.Errorf("expected %d repo resolver calls, got %d: %v", wantCalls, len(repo.calls), repo.calls)
	}

	// Cache hits – no further HTTP calls.
	before := calls
	r.Resolve(ctx, "pkg:nuget/Newtonsoft.Json@13.0.1")
	r.Resolve(ctx, "pkg:nuget/Missing@1.0.0")
	if calls != before {
		t.Errorf("expected cache hits, registry called %d more times", calls-before)
	}
	if e := r.CacheEntries(); e["newtonsoft.json@13.0.1"] != "MIT" {
		t.Errorf("cache export: %v", e)
	}
}

func TestResolve_NoRepoResolver(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reg/moq/4.13.1.json":
			fmt.Fprintf(w, `{"catalogEntry":"%s/catalog/moq"}`, srv.URL)
		case "/catalog/moq":
			fmt.Fprint(w, `{"id":"Moq","version":"4.13.1","licenseUrl":"https://raw.githubusercontent.com/moq/moq4/master/License.txt"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	r := NewResolverWithBase(srv.URL+"/reg", nil)
	if got := r.Resolve(context.Background(), "pkg:nuget/Moq@4.13.1"); got != "" {
		t.Errorf("without repo resolver expected empty, got %q", got)
	}
}

// A registration leaf larger than maxResponseSize is cut off and fails to
// decode, like any other unreadable response: no license, and nothing cached.
func TestOversizedResponseIsNotDecoded(t *testing.T) {
	padding := strings.Repeat("x", maxResponseSize)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"catalogEntry":{"id":"Huge","version":"1.0.0","licenseExpression":"MIT","description":%q}}`, padding)
	}))
	defer srv.Close()

	r := NewResolverWithBase(srv.URL, nil)
	if got := r.Resolve(context.Background(), "pkg:nuget/Huge@1.0.0"); got != "" {
		t.Fatalf("Resolve() = %q, want empty for an oversized response", got)
	}
	if _, found := r.LoadValue(CacheKey("Huge", "1.0.0")); found {
		t.Fatal("oversized response must not be cached")
	}
}
