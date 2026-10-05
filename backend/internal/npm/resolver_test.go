package npm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"
)

func TestExtractNPMPackage(t *testing.T) {
	tests := []struct {
		purl        string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{"pkg:npm/%40istanbuljs/load-nyc-config@1.1.0", "@istanbuljs/load-nyc-config", "1.1.0", true},
		{"pkg:npm/%40js-sdsl/ordered-map@4.4.2", "@js-sdsl/ordered-map", "4.4.2", true},
		{"pkg:npm/@scope/name@1.0.0", "@scope/name", "1.0.0", true},
		{"pkg:npm/lodash@4.17.21", "lodash", "4.17.21", true},
		{"pkg:npm/lodash", "lodash", "", true},
		{"pkg:npm/lodash@4.17.21?vcs_url=git", "lodash", "4.17.21", true},
		{"pkg:npm/lodash@4.17.21#sub/path", "lodash", "4.17.21", true},
		{"pkg:golang/github.com/foo/bar@v1.0.0", "", "", false},
		{"pkg:npm/", "", "", false},
		{"pkg:npm/foo/bar@1.0.0", "", "", false},  // unscoped names cannot contain "/"
		{"pkg:npm/@a/b/c@1.0.0", "", "", false},   // scoped names have exactly one "/"
		{"pkg:npm/..%2Fetc@1.0.0", "", "", false}, // path traversal
		{"", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			name, version, ok := ExtractNPMPackage(tt.purl)
			if ok != tt.wantOK || name != tt.wantName || version != tt.wantVersion {
				t.Errorf("ExtractNPMPackage(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.purl, name, version, ok, tt.wantName, tt.wantVersion, tt.wantOK)
			}
		})
	}
}

func TestNormalizeLicense(t *testing.T) {
	tests := []struct {
		name     string
		license  string
		licenses string
		want     string
	}{
		{"string", `"MIT"`, ``, "MIT"},
		{"string with spaces", `"  ISC "`, ``, "ISC"},
		{"expression in parens", `"(MIT OR Apache-2.0)"`, ``, "MIT OR Apache-2.0"},
		{"object", `{"type":"BSD-3-Clause","url":"http://x"}`, ``, "BSD-3-Clause"},
		{"legacy licenses array", ``, `[{"type":"MIT"},{"type":"Apache-2.0"}]`, "MIT OR Apache-2.0"},
		{"license wins over licenses", `"ISC"`, `[{"type":"MIT"}]`, "ISC"},
		{"UNLICENSED", `"UNLICENSED"`, ``, ""},
		{"SEE LICENSE IN", `"SEE LICENSE IN LICENSE.md"`, ``, ""},
		{"null", `null`, `null`, ""},
		{"empty", ``, ``, ""},
		{"empty string", `""`, ``, ""},
		{"garbage", `12`, ``, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeLicense(json.RawMessage(tt.license), json.RawMessage(tt.licenses))
			if got != tt.want {
				t.Errorf("NormalizeLicense(%s, %s) = %q, want %q", tt.license, tt.licenses, got, tt.want)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		case "/@istanbuljs%2Fload-nyc-config/1.1.0", "/@istanbuljs/load-nyc-config/1.1.0":
			_, _ = w.Write([]byte(`{"name":"@istanbuljs/load-nyc-config","version":"1.1.0","license":"ISC"}`))
		case "/lodash/latest":
			_, _ = w.Write([]byte(`{"name":"lodash","license":{"type":"MIT"}}`))
		case "/private/1.0.0":
			_, _ = w.Write([]byte(`{"name":"private","license":"UNLICENSED"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	r := NewResolverWithRegistry(srv.URL)
	ctx := context.Background()

	if got := r.Resolve(ctx, "pkg:npm/%40istanbuljs/load-nyc-config@1.1.0"); got != "ISC" {
		t.Errorf("scoped: got %q, want ISC", got)
	}
	if got := r.Resolve(ctx, "pkg:npm/lodash"); got != "MIT" {
		t.Errorf("latest: got %q, want MIT", got)
	}
	if got := r.Resolve(ctx, "pkg:npm/private@1.0.0"); got != "" {
		t.Errorf("UNLICENSED: got %q, want empty", got)
	}
	if got := r.Resolve(ctx, "pkg:npm/missing@9.9.9"); got != "" {
		t.Errorf("404: got %q, want empty", got)
	}
	if got := r.Resolve(ctx, "pkg:golang/github.com/foo/bar@v1"); got != "" {
		t.Errorf("non-npm: got %q, want empty", got)
	}

	// Second round must be served from cache (including negative results).
	before := calls
	r.Resolve(ctx, "pkg:npm/%40istanbuljs/load-nyc-config@1.1.0")
	r.Resolve(ctx, "pkg:npm/missing@9.9.9")
	if calls != before {
		t.Errorf("expected cache hits, but registry was called %d more times", calls-before)
	}

	entries := r.CacheEntries()
	if entries["@istanbuljs/load-nyc-config@1.1.0"] != "ISC" {
		t.Errorf("cache export missing entry: %v", entries)
	}
	if v := entries["missing@9.9.9"]; v != "!not-published" {
		t.Errorf("404 should be cached with its reason, got %q", v)
	}
	if v := entries["private@1.0.0"]; v != "!no-license-upstream" {
		t.Errorf("license-less manifest should be cached with its reason, got %q", v)
	}

	explain := []struct {
		purl    string
		handled bool
		reason  string
		latest  bool
	}{
		{"pkg:npm/missing@9.9.9", true, "not-published", false},
		{"pkg:npm/private@1.0.0", true, "no-license-upstream", false},
		{"pkg:npm/lodash", true, "", true},
		{"pkg:npm/%40istanbuljs/load-nyc-config@1.1.0", true, "", false},
		{"pkg:golang/github.com/foo/bar@v1", false, "", false},
	}
	for _, tc := range explain {
		handled, reason, latest := r.Explain(tc.purl)
		if handled != tc.handled || reason != tc.reason || latest != tc.latest {
			t.Errorf("Explain(%s) = (%v, %q, %v), want (%v, %q, %v)",
				tc.purl, handled, reason, latest, tc.handled, tc.reason, tc.latest)
		}
	}
}

func TestPreloadedNegativeKeepsReason(t *testing.T) {
	r := NewResolverWithRegistry("http://127.0.0.1:0")
	r.PreloadCache(map[string]string{"gone@1.0.0": "!not-published", "legacy@1.0.0": ""})
	if got := r.Resolve(context.Background(), "pkg:npm/gone@1.0.0"); got != "" {
		t.Errorf("negative marker must not leak as a license, got %q", got)
	}
	if _, reason, _ := r.Explain("pkg:npm/gone@1.0.0"); reason != "not-published" {
		t.Errorf("reason lost across preload: %q", reason)
	}
	if _, reason, _ := r.Explain("pkg:npm/legacy@1.0.0"); reason != "" {
		t.Errorf("legacy negative has no reason, got %q", reason)
	}
}

func TestPreloadCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("registry must not be called for preloaded entries: %s", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := NewResolverWithRegistry(srv.URL)
	r.PreloadCache(map[string]string{"lodash@4.17.21": "MIT"})
	if got := r.Resolve(context.Background(), "pkg:npm/lodash@4.17.21"); got != "MIT" {
		t.Errorf("got %q, want MIT", got)
	}
}
