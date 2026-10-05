package depsdev

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestExtractPackageVersion(t *testing.T) {
	tests := []struct {
		purl string
		want PackageVersion
		ok   bool
	}{
		{"pkg:maven/com.google.code.findbugs/jsr305@3.0.2", PackageVersion{"MAVEN", "com.google.code.findbugs:jsr305", "3.0.2"}, true},
		{"pkg:maven/com.google.code.findbugs/jsr305@3.0.2?classifier=sources#lib", PackageVersion{"MAVEN", "com.google.code.findbugs:jsr305", "3.0.2"}, true},
		{"pkg:npm/%40scope/name@1.2.3", PackageVersion{"NPM", "@scope/name", "1.2.3"}, true},
		{"pkg:npm/@scope/name@1.2.3", PackageVersion{"NPM", "@scope/name", "1.2.3"}, true},
		{"pkg:pypi/My_Pkg.Name@1.0.0", PackageVersion{"PYPI", "my-pkg-name", "1.0.0"}, true},
		{"pkg:golang/github.com/x/y@v1.2.3", PackageVersion{"GO", "github.com/x/y", "v1.2.3"}, true},
		{"pkg:cargo/unicode-ident@1.0.12", PackageVersion{"CARGO", "unicode-ident", "1.0.12"}, true},
		{"pkg:nuget/Newtonsoft.Json@13.0.3", PackageVersion{"NUGET", "newtonsoft.json", "13.0.3"}, true},
		{"pkg:composer/vendor/name@1.0.0", PackageVersion{}, false},
		{"pkg:maven/com.google.code.findbugs/jsr305", PackageVersion{}, false},
		{"pkg:cargo/foo@unknown", PackageVersion{}, false},
		{"pkg:cargo/foo@1.0,2.0", PackageVersion{}, false},
		{"pkg:cargo/foo@1.0 2.0", PackageVersion{}, false},
		{"pkg:npm/foo/bar@1.0.0", PackageVersion{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			got, ok := ExtractPackageVersion(tt.purl)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("ExtractPackageVersion(%q) = (%+v, %v), want (%+v, %v)", tt.purl, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestNormalizeLicenses(t *testing.T) {
	tests := []struct {
		name     string
		licenses []string
		want     string
	}{
		{"single", []string{"Apache-2.0"}, "Apache-2.0"},
		{"compound single", []string{"Unicode-DFS-2016 AND (Apache-2.0 OR MIT)"}, "Unicode-DFS-2016 AND (Apache-2.0 OR MIT)"},
		{"multiple", []string{"MIT OR Apache-2.0", "BSD-3-Clause"}, "(MIT OR Apache-2.0) AND BSD-3-Clause"},
		{"non-standard", []string{"non-standard"}, ""},
		{"empty entries", []string{"", "  "}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeLicenses(tt.licenses); got != tt.want {
				t.Fatalf("NormalizeLicenses(%v) = %q, want %q", tt.licenses, got, tt.want)
			}
		})
	}
}

func TestResolveAndCache(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		switch r.URL.Path {
		case "/v3/systems/maven/packages/com.google.code.findbugs:jsr305/versions/3.0.2", "/v3/systems/maven/packages/com.google.code.findbugs%3Ajsr305/versions/3.0.2":
			_, _ = w.Write([]byte(`{"licenses":["Apache-2.0"]}`))
		case "/v3/systems/cargo/packages/private/versions/1.0.0":
			_, _ = w.Write([]byte(`{"licenses":["non-standard"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	r := NewResolverWithBaseURL(srv.URL)
	ctx := context.Background()
	if got := r.Resolve(ctx, "pkg:maven/com.google.code.findbugs/jsr305@3.0.2"); got != "Apache-2.0" {
		t.Fatalf("maven resolve = %q, want Apache-2.0", got)
	}
	if got := r.Resolve(ctx, "pkg:cargo/private@1.0.0"); got != "" {
		t.Fatalf("non-standard resolve = %q, want empty", got)
	}
	if got := r.Resolve(ctx, "pkg:cargo/missing@1.0.0"); got != "" {
		t.Fatalf("missing resolve = %q, want empty", got)
	}
	before := calls
	r.Resolve(ctx, "pkg:maven/com.google.code.findbugs/jsr305@3.0.2")
	r.Resolve(ctx, "pkg:cargo/private@1.0.0")
	r.Resolve(ctx, "pkg:cargo/missing@1.0.0")
	if calls != before {
		t.Fatalf("expected cached positive and negative results, got %d extra calls", calls-before)
	}

	entries := r.CacheEntries()
	if entries["MAVEN:com.google.code.findbugs:jsr305@3.0.2"] != "Apache-2.0" {
		t.Fatalf("cache missing positive entry: %v", entries)
	}
	if v := entries["CARGO:missing@1.0.0"]; v != "!not-published" {
		t.Fatalf("404 must be cached with its reason, got %q", v)
	}
	if v := entries["CARGO:private@1.0.0"]; v != "!no-license-upstream" {
		t.Fatalf("license-less version must be cached with its reason, got %q", v)
	}
	for purl, want := range map[string]string{
		"pkg:cargo/missing@1.0.0":                         "not-published",
		"pkg:cargo/private@1.0.0":                         "no-license-upstream",
		"pkg:maven/com.google.code.findbugs/jsr305@3.0.2": "",
	} {
		if handled, reason, latest := r.Explain(purl); !handled || reason != want || latest {
			t.Errorf("Explain(%s) = (%v, %q, %v), want (true, %q, false)", purl, handled, reason, latest, want)
		}
	}
	if handled, _, _ := r.Explain("pkg:composer/vendor/name@1.0.0"); handled {
		t.Error("composer is not a deps.dev ecosystem")
	}
}

func TestPreloadCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("deps.dev must not be called for preloaded entries: %s", r.URL.Path)
	}))
	defer srv.Close()

	r := NewResolverWithBaseURL(srv.URL)
	r.PreloadCache(map[string]string{"PYPI:requests@2.31.0": "Apache-2.0"})
	if got := r.Resolve(context.Background(), "pkg:pypi/requests@2.31.0"); got != "Apache-2.0" {
		t.Fatalf("preloaded resolve = %q, want Apache-2.0", got)
	}
}

func TestResolveBatch(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v3alpha/versionbatch" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"responses":[
				{"request":{"versionKey":{"system":"MAVEN","name":"com.google.code.findbugs:jsr305","version":"3.0.2"}},"version":{"licenses":["Apache-2.0"]}},
				{"request":{"versionKey":{"system":"CARGO","name":"unicode-ident","version":"1.0.12"}},"version":{"licenses":["Unicode-DFS-2016 AND (Apache-2.0 OR MIT)"]}},
				{"request":{"versionKey":{"system":"PYPI","name":"unknown","version":"1.0.0"}},"version":{"licenses":[]}},
				{"request":{"versionKey":{"system":"NPM","name":"private-pkg","version":"1.0.0"}},"version":null},
				{"request":{"versionKey":{"system":"MAVEN","name":"jakarta.xml.bind:jakarta.xml.bind-api","version":"4.0.2"}},"version":{"licenses":["non-standard"],"licenseDetails":[{"license":"Eclipse Distribution License - v 1.0","spdx":"non-standard"}]}}
			]
		}`))
	}))
	defer srv.Close()

	r := NewResolverWithBaseURL(srv.URL)
	purls := []string{
		"pkg:maven/com.google.code.findbugs/jsr305@3.0.2",
		"pkg:cargo/unicode-ident@1.0.12",
		"pkg:pypi/unknown@1.0.0",
		"pkg:composer/vendor/name@1.0.0",
		"pkg:maven/jakarta.xml.bind/jakarta.xml.bind-api@4.0.2",
		"pkg:npm/private-pkg@1.0.0",
	}
	got := r.ResolveBatch(context.Background(), purls)
	want := map[string]string{
		"pkg:maven/com.google.code.findbugs/jsr305@3.0.2":       "Apache-2.0",
		"pkg:cargo/unicode-ident@1.0.12":                        "Unicode-DFS-2016 AND (Apache-2.0 OR MIT)",
		"pkg:pypi/unknown@1.0.0":                                "",
		"pkg:maven/jakarta.xml.bind/jakarta.xml.bind-api@4.0.2": "BSD-3-Clause",
		"pkg:npm/private-pkg@1.0.0":                             "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveBatch() = %v, want %v", got, want)
	}
	if _, reason, _ := r.Explain("pkg:npm/private-pkg@1.0.0"); reason != "not-published" {
		t.Errorf("null version in batch must mean not-published, got %q", reason)
	}
	if _, reason, _ := r.Explain("pkg:pypi/unknown@1.0.0"); reason != "no-license-upstream" {
		t.Errorf("empty licenses in batch must mean no-license-upstream, got %q", reason)
	}
	before := calls
	got = r.ResolveBatch(context.Background(), purls)
	if calls != before {
		t.Fatalf("expected batch cache hits, got %d extra calls", calls-before)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cached ResolveBatch() = %v, want %v", got, want)
	}
}

func TestNormalizeLicenseDetails(t *testing.T) {
	d := func(lic, spdx string) licenseDetail { return licenseDetail{License: lic, SPDX: spdx} }
	cases := []struct {
		name    string
		details []licenseDetail
		want    string
	}{
		{"mapped by deps.dev", []licenseDetail{d("Apache License 2.0", "Apache-2.0")}, "Apache-2.0"},
		{"raw text recovered", []licenseDetail{d("The MIT License", "non-standard")}, "MIT"},
		// One unmapped entry no longer discards the mapped one.
		{"mixed", []licenseDetail{d("Eclipse Public License - Version 2.0", "non-standard"), d("Apache Software License - Version 2.0", "Apache-2.0")}, "EPL-2.0 AND Apache-2.0"},
		{"deprecated SPDX from deps.dev", []licenseDetail{d("EPL 2.0", "non-standard"), d("GPL2 w/ CPE", "GPL-2.0-with-classpath-exception")}, "EPL-2.0 AND GPL-2.0-with-classpath-exception"},
		{"unrecognised name becomes LicenseRef", []licenseDetail{d("Remix Icon License 1.0", "non-standard")}, "LicenseRef-Remix-Icon-License-1.0"},
		{"or-expression in raw text", []licenseDetail{d("Universal Permissive License 1.0 or Apache License 2.0", "non-standard")}, "UPL-1.0 OR Apache-2.0"},
		{"compound parts are parenthesised", []licenseDetail{d("x", "MIT OR Apache-2.0"), d("BSD New license", "non-standard")}, "(MIT OR Apache-2.0) AND BSD-3-Clause"},
		{"duplicates collapse", []licenseDetail{d("MIT", "MIT"), d("The MIT License", "non-standard")}, "MIT"},
		// Nothing usable: stays unresolved (NOASSERTION).
		{"url only", []licenseDetail{d("https://aka.ms/deprecateLicenseUrl", "non-standard")}, ""},
		{"non-standard only", []licenseDetail{d("non-standard", "non-standard")}, ""},
		{"empty", nil, ""},
	}
	for _, c := range cases {
		if got := NormalizeLicenseDetails(c.details); got != c.want {
			t.Errorf("%s: NormalizeLicenseDetails() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestExtractPackage_Versionless(t *testing.T) {
	cases := []struct {
		purl string
		want PackageVersion
		ok   bool
	}{
		{"pkg:pypi/requests", PackageVersion{System: "PYPI", Name: "requests"}, true},
		{"pkg:maven/org.springframework.boot/spring-boot-starter-web@unknown", PackageVersion{System: "MAVEN", Name: "org.springframework.boot:spring-boot-starter-web"}, true},
		{"pkg:maven/org.example/app@${project.version}", PackageVersion{System: "MAVEN", Name: "org.example:app"}, true},
		{"pkg:pypi/flask@3.0.0", PackageVersion{System: "PYPI", Name: "flask", Version: "3.0.0"}, true},
		// A placeholder in the coordinates is not a real package.
		{"pkg:maven/${project.groupId}/svc@unknown", PackageVersion{}, false},
		{"pkg:composer/vendor/name", PackageVersion{}, false},
	}
	for _, c := range cases {
		got, ok := extractPackage(c.purl)
		if ok != c.ok || got != c.want {
			t.Errorf("extractPackage(%q) = %+v, %v; want %+v, %v", c.purl, got, ok, c.want, c.ok)
		}
		// The exact-version API keeps rejecting versionless purls.
		if _, ok := ExtractPackageVersion(c.purl); ok && c.want.Version == "" {
			t.Errorf("ExtractPackageVersion(%q) accepted a versionless purl", c.purl)
		}
	}
}

func TestResolveBatch_VersionlessUsesDefaultVersion(t *testing.T) {
	packageCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v3/systems/pypi/packages/requests":
			packageCalls++
			_, _ = w.Write([]byte(`{"versions":[
				{"versionKey":{"system":"PYPI","name":"requests","version":"2.31.0"},"isDefault":false},
				{"versionKey":{"system":"PYPI","name":"requests","version":"2.34.2"},"isDefault":true}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v3/systems/maven/packages/org.example:gone":
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && r.URL.Path == "/v3alpha/versionbatch":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"2.34.2"`) {
				t.Errorf("batch did not ask for the default version: %s", body)
			}
			_, _ = w.Write([]byte(`{"responses":[
				{"request":{"versionKey":{"system":"PYPI","name":"requests","version":"2.34.2"}},"version":{"licenses":["Apache-2.0"]}}]}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	r := NewResolverWithBaseURL(srv.URL)
	purls := []string{"pkg:pypi/requests", "pkg:pypi/Requests@unknown", "pkg:maven/org.example/gone@unknown"}
	got := r.ResolveBatch(context.Background(), purls)
	want := map[string]string{
		"pkg:pypi/requests":                  "Apache-2.0",
		"pkg:pypi/Requests@unknown":          "Apache-2.0",
		"pkg:maven/org.example/gone@unknown": "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveBatch() = %v, want %v", got, want)
	}
	if packageCalls != 1 {
		t.Fatalf("default version looked up %d times, want 1", packageCalls)
	}
	entries := r.CacheEntries()
	if entries["PYPI:requests@*"] != "Apache-2.0" || entries["PYPI:requests@2.34.2"] != "Apache-2.0" {
		t.Fatalf("cache missing wildcard or concrete entry: %v", entries)
	}
	if _, reason, latest := r.Explain("pkg:maven/org.example/gone@unknown"); reason != "not-published" || !latest {
		t.Errorf("unknown package without version: reason %q latest %v", reason, latest)
	}
	if _, reason, latest := r.Explain("pkg:pypi/requests"); reason != "" || !latest {
		t.Errorf("versionless resolved package: reason %q latest %v", reason, latest)
	}
	// Second call is served from the cache.
	if got := r.Resolve(context.Background(), "pkg:pypi/requests"); got != "Apache-2.0" || packageCalls != 1 {
		t.Fatalf("cached Resolve = %q (package calls %d)", got, packageCalls)
	}
}
