// Package packagist resolves unknown Composer (PHP) package licenses via the
// Packagist metadata API.
//
// deps.dev does not cover Composer, and PHP SBOM generators often emit
// NOASSERTION or pin development branches ("dev-main", "1.x-dev"). Packagist
// serves every package's composer.json metadata without authentication:
//
//	https://repo.packagist.org/p2/{vendor}/{name}.json       tagged releases
//	https://repo.packagist.org/p2/{vendor}/{name}~dev.json   development branches
//
// Both files use the "composer/2.0" minified format: versions are listed newest
// first and each entry only carries the fields that changed since the previous
// one, so a release's license may be inherited from a newer entry above it.
package packagist

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/ratelimit"
)

const (
	// DefaultBaseURL is the public Packagist metadata mirror.
	DefaultBaseURL = "https://repo.packagist.org"

	defaultRate  = 5.0
	defaultBurst = 10

	// latestMarker prefixes cached licenses that were taken from the newest
	// stable release because Packagist does not list the requested version.
	latestMarker = "~"
)

// Resolver resolves Composer package licenses via Packagist.
type Resolver struct {
	baseURL    string
	httpClient *http.Client
	limiter    *ratelimit.TokenBucket
	// cache: "vendor/name@version" → license, latestMarker+license, or a
	// license.NegativeCacheValue. Persisted to registry_license_cache.
	cache sync.Map
	// files: p2 file → expanded versions (nil = not found). In-memory only, so
	// an SBOM listing several versions of one package costs one request.
	files sync.Map
}

// NewResolver creates a resolver against the public Packagist mirror.
func NewResolver() *Resolver { return NewResolverWithBaseURL(DefaultBaseURL) }

// NewResolverWithBaseURL creates a resolver against a custom mirror (or an
// httptest server).
func NewResolverWithBaseURL(baseURL string) *Resolver {
	return &Resolver{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 15 * time.Second},
		limiter:    ratelimit.NewTokenBucket(defaultRate, defaultBurst),
	}
}

// ExtractComposerPackage parses "pkg:composer/vendor/name@version". Names are
// lower-cased, as on Packagist.
func ExtractComposerPackage(purl string) (name, version string, ok bool) {
	const prefix = "pkg:composer/"
	if !strings.HasPrefix(purl, prefix) {
		return "", "", false
	}
	rest := purl[len(prefix):]
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest, version = rest[:i], rest[i+1:]
	}
	if decoded, err := url.PathUnescape(rest); err == nil {
		rest = decoded
	}
	if decoded, err := url.PathUnescape(version); err == nil {
		version = decoded
	}
	vendor, pkg, found := strings.Cut(strings.ToLower(strings.TrimSpace(rest)), "/")
	if !found || !validSegment(vendor) || !validSegment(pkg) {
		return "", "", false
	}
	return vendor + "/" + pkg, strings.TrimSpace(version), true
}

func validSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// IsDevVersion reports whether a Composer version names a development branch
// ("dev-main", "1.x-dev", "v2.3.x-dev") rather than a tagged release.
func IsDevVersion(version string) bool {
	v := strings.ToLower(version)
	return strings.HasPrefix(v, "dev-") || strings.HasSuffix(v, "-dev")
}

func cacheKey(name, version string) string {
	if version == "" {
		return name + "@*"
	}
	return name + "@" + version
}

// Resolve returns the license expression of a Composer package, or "".
//
// A tagged release is looked up in the release file, a development branch in
// the dev file. When Packagist does not list the exact version (deleted
// branch, unknown or missing version), the newest stable release's license is
// used: Composer names are vendor-namespaced, so unlike npm there is no risk of
// matching an unrelated package that happens to share the name.
func (r *Resolver) Resolve(ctx context.Context, purl string) string {
	name, version, ok := ExtractComposerPackage(purl)
	if !ok {
		return ""
	}
	key := cacheKey(name, version)
	if cached, found := r.cache.Load(key); found {
		lic, _ := splitValue(cached.(string))
		return lic
	}
	value := r.lookup(ctx, name, version)
	r.cache.Store(key, value)
	lic, latest := splitValue(value)
	if lic != "" {
		via := ""
		if latest {
			via = " (latest release)"
		}
		log.Printf("  Packagist license resolved: %s%s → %s", key, via, lic)
	}
	return lic
}

// Explain reports why a Composer purl stayed unresolved and whether its
// license is the newest release's. handled is false for other ecosystems.
func (r *Resolver) Explain(purl string) (handled bool, reason string, latest bool) {
	name, version, ok := ExtractComposerPackage(purl)
	if !ok {
		return false, "", false
	}
	cached, found := r.cache.Load(cacheKey(name, version))
	if !found {
		return true, "", false
	}
	v := cached.(string)
	if _, reason = license.SplitCacheValue(v); reason != "" {
		return true, reason, false
	}
	_, latest = splitValue(v)
	return true, "", latest
}

func splitValue(v string) (lic string, latest bool) {
	if strings.HasPrefix(v, latestMarker) {
		return strings.TrimPrefix(v, latestMarker), true
	}
	lic, _ = license.SplitCacheValue(v)
	return lic, false
}

// lookup returns the cache encoding for one package version.
func (r *Resolver) lookup(ctx context.Context, name, version string) string {
	if IsDevVersion(version) {
		dev, ok := r.versions(ctx, name+"~dev")
		if !ok {
			return ""
		}
		if v, found := findVersion(dev, version); found {
			return licenseValue(v.License)
		}
	}
	stable, ok := r.versions(ctx, name)
	if !ok {
		return ""
	}
	if stable == nil {
		return license.NegativeCacheValue(license.ReasonNotPublished)
	}
	if version != "" && !IsDevVersion(version) {
		if v, found := findVersion(stable, version); found {
			return licenseValue(v.License)
		}
	}
	if len(stable) == 0 {
		return license.NegativeCacheValue(license.ReasonNoLicenseUpstream)
	}
	value := licenseValue(stable[0].License)
	if _, reason := license.SplitCacheValue(value); reason != "" {
		return value
	}
	return latestMarker + value
}

func licenseValue(licenses []string) string {
	if lic := Expression(licenses); lic != "" {
		return lic
	}
	return license.NegativeCacheValue(license.ReasonNoLicenseUpstream)
}

// Expression folds composer.json's "license" array into one SPDX expression.
// Composer defines the array as disjunctive (the package is available under
// any of the listed licenses), so the entries are joined with OR. Each entry
// is recovered from free text ("proprietary" → LicenseRef-proprietary).
func Expression(licenses []string) string {
	var parts []string
	for _, l := range licenses {
		if lic := license.Recover(l); lic != "" {
			parts = append(parts, lic)
		}
	}
	if len(parts) > 1 {
		for i, p := range parts {
			if strings.Contains(p, " ") {
				parts[i] = "(" + p + ")"
			}
		}
	}
	return strings.Join(parts, " OR ")
}

func findVersion(versions []composerVersion, version string) (composerVersion, bool) {
	want := strings.TrimPrefix(strings.ToLower(version), "v")
	for _, v := range versions {
		if strings.TrimPrefix(strings.ToLower(v.Version), "v") == want {
			return v, true
		}
	}
	return composerVersion{}, false
}

type composerVersion struct {
	Version string
	License []string
}

// versions fetches and expands one p2 file. ok is false on transport errors;
// a nil slice with ok=true means Packagist does not know the package.
func (r *Resolver) versions(ctx context.Context, file string) ([]composerVersion, bool) {
	if cached, found := r.files.Load(file); found {
		return cached.([]composerVersion), true
	}
	if err := r.limiter.Wait(ctx); err != nil {
		return nil, false
	}
	u := fmt.Sprintf("%s/p2/%s.json", r.baseURL, file)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "bomhort-license-resolver")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		log.Printf("  Packagist request failed for %s: %v", file, err)
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		r.files.Store(file, []composerVersion(nil))
		return nil, true
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var body struct {
		Packages map[string][]map[string]json.RawMessage `json:"packages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, false
	}
	out := Expand(body.Packages[strings.TrimSuffix(file, "~dev")])
	if out == nil {
		out = []composerVersion{}
	}
	r.files.Store(file, out)
	return out, true
}

// Expand undoes the composer/2.0 minification for the fields the resolver
// needs: an entry without "license" inherits the previous entry's, and the
// string "__unset" removes it.
func Expand(entries []map[string]json.RawMessage) []composerVersion {
	var out []composerVersion
	var current []string
	for _, e := range entries {
		if raw, ok := e["license"]; ok {
			current = nil
			var s string
			if json.Unmarshal(raw, &s) == nil {
				if s != "__unset" && s != "" {
					current = []string{s}
				}
			} else {
				_ = json.Unmarshal(raw, &current)
			}
		}
		var version string
		if raw, ok := e["version"]; ok {
			_ = json.Unmarshal(raw, &version)
		}
		out = append(out, composerVersion{Version: version, License: current})
	}
	return out
}

// PreloadCache seeds the in-memory cache (e.g. from ClickHouse).
func (r *Resolver) PreloadCache(entries map[string]string) {
	for k, v := range entries {
		r.cache.Store(k, v)
	}
}

// CacheEntries exports the in-memory cache for persistence.
func (r *Resolver) CacheEntries() map[string]string {
	out := make(map[string]string)
	r.cache.Range(func(k, v any) bool {
		out[k.(string)] = v.(string)
		return true
	})
	return out
}
