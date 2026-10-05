package packagist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"
)

func TestExtractComposerPackage(t *testing.T) {
	tests := []struct {
		purl, name, version string
		ok                  bool
	}{
		{"pkg:composer/monolog/monolog@dev-main", "monolog/monolog", "dev-main", true},
		{"pkg:composer/Nyholm/PSR7-Server@1.0.1", "nyholm/psr7-server", "1.0.1", true},
		{"pkg:composer/nikic/fast-route@v1.x-dev", "nikic/fast-route", "v1.x-dev", true},
		{"pkg:composer/psr/log", "psr/log", "", true},
		{"pkg:composer/psr/log@1.0?foo=bar", "psr/log", "1.0", true},
		{"pkg:composer/onlyname@1.0", "", "", false},
		{"pkg:composer/../etc@1.0", "", "", false},
		{"pkg:npm/lodash@4.17.21", "", "", false},
	}
	for _, tc := range tests {
		name, version, ok := ExtractComposerPackage(tc.purl)
		if name != tc.name || version != tc.version || ok != tc.ok {
			t.Errorf("ExtractComposerPackage(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.purl, name, version, ok, tc.name, tc.version, tc.ok)
		}
	}
}

func TestIsDevVersion(t *testing.T) {
	for v, want := range map[string]bool{
		"dev-main": true, "dev-master": true, "1.x-dev": true, "v1.x-dev": true, "1.2.x-dev": true,
		"1.0.0": false, "v1.0.0-rc.4": false, "": false,
	} {
		if got := IsDevVersion(v); got != want {
			t.Errorf("IsDevVersion(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestExpression(t *testing.T) {
	tests := []struct {
		in   []string
		want string
	}{
		{[]string{"MIT"}, "MIT"},
		{[]string{"LGPL-2.1-only", "GPL-3.0-or-later"}, "LGPL-2.1-only OR GPL-3.0-or-later"},
		{[]string{"proprietary"}, "LicenseRef-proprietary"},
		{[]string{"Apache License 2.0"}, "Apache-2.0"},
		{[]string{"MIT AND BSD-3-Clause", "GPL-2.0-only"}, "(MIT AND BSD-3-Clause) OR GPL-2.0-only"},
		{[]string{""}, ""},
		{nil, ""},
	}
	for _, tc := range tests {
		if got := Expression(tc.in); got != tc.want {
			t.Errorf("Expression(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExpand_MinifiedInheritance(t *testing.T) {
	raw := `[
		{"version":"1.1.0","license":["MIT"]},
		{"version":"1.0.2"},
		{"version":"1.0.1","license":"__unset"},
		{"version":"1.0.0","license":["BSD-3-Clause"]}
	]`
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		t.Fatal(err)
	}
	got := Expand(entries)
	want := []string{"MIT", "MIT", "", "BSD-3-Clause"}
	for i, v := range got {
		lic := ""
		if len(v.License) > 0 {
			lic = v.License[0]
		}
		if lic != want[i] {
			t.Errorf("entry %d (%s): license %q, want %q", i, v.Version, lic, want[i])
		}
	}
}

func TestResolve(t *testing.T) {
	calls := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls[r.URL.Path]++
		switch r.URL.Path {
		case "/p2/nyholm/psr7-server.json":
			_, _ = w.Write([]byte(`{"minified":"composer/2.0","packages":{"nyholm/psr7-server":[
				{"version":"1.1.0","license":["MIT"]},{"version":"1.0.2"},{"version":"1.0.1"}]}}`))
		case "/p2/psr/log~dev.json":
			_, _ = w.Write([]byte(`{"packages":{"psr/log":[{"version":"dev-master","license":["MIT"]}]}}`))
		case "/p2/psr/log.json":
			_, _ = w.Write([]byte(`{"packages":{"psr/log":[{"version":"3.0.0","license":["MIT"]}]}}`))
		case "/p2/monolog/monolog~dev.json":
			_, _ = w.Write([]byte(`{"packages":{"monolog/monolog":[{"version":"dev-2.x","license":["MIT"]}]}}`))
		case "/p2/monolog/monolog.json":
			_, _ = w.Write([]byte(`{"packages":{"monolog/monolog":[{"version":"3.9.0","license":["MIT"]}]}}`))
		case "/p2/acme/nolicense.json":
			_, _ = w.Write([]byte(`{"packages":{"acme/nolicense":[{"version":"1.0.0"}]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	r := NewResolverWithBaseURL(srv.URL)
	ctx := context.Background()
	tests := []struct {
		purl   string
		want   string
		reason string
		latest bool
	}{
		{"pkg:composer/nyholm/psr7-server@1.0.1", "MIT", "", false},  // inherited through minification
		{"pkg:composer/nyholm/psr7-server@v1.1.0", "MIT", "", false}, // "v" prefix tolerated
		{"pkg:composer/nyholm/psr7-server@9.9.9", "MIT", "", true},   // unknown release → latest
		{"pkg:composer/psr/log@dev-master", "MIT", "", false},        // branch found in dev file
		{"pkg:composer/monolog/monolog@dev-main", "MIT", "", true},   // deleted branch → latest release
		{"pkg:composer/acme/nolicense@1.0.0", "", "no-license-upstream", false},
		{"pkg:composer/private/thing@1.0.0", "", "not-published", false},
	}
	for _, tc := range tests {
		if got := r.Resolve(ctx, tc.purl); got != tc.want {
			t.Errorf("Resolve(%s) = %q, want %q", tc.purl, got, tc.want)
		}
		handled, reason, latest := r.Explain(tc.purl)
		if !handled || reason != tc.reason || latest != tc.latest {
			t.Errorf("Explain(%s) = (%v, %q, %v), want (true, %q, %v)",
				tc.purl, handled, reason, latest, tc.reason, tc.latest)
		}
	}
	if calls["/p2/nyholm/psr7-server.json"] != 1 {
		t.Errorf("package file fetched %d times, want 1", calls["/p2/nyholm/psr7-server.json"])
	}
	if handled, _, _ := r.Explain("pkg:npm/lodash@1.0.0"); handled {
		t.Error("npm purl must not be handled by Packagist")
	}

	// A fresh resolver preloaded from the persisted cache answers offline,
	// including the latest-release and reason markers.
	offline := NewResolverWithBaseURL("http://127.0.0.1:0")
	offline.PreloadCache(r.CacheEntries())
	if got := offline.Resolve(ctx, "pkg:composer/monolog/monolog@dev-main"); got != "MIT" {
		t.Errorf("preloaded Resolve = %q, want MIT", got)
	}
	if _, _, latest := offline.Explain("pkg:composer/monolog/monolog@dev-main"); !latest {
		t.Error("latest marker lost across persistence")
	}
	if _, reason, _ := offline.Explain("pkg:composer/private/thing@1.0.0"); reason != "not-published" {
		t.Errorf("reason lost across persistence: %q", reason)
	}
}
