// Package npm resolves unknown package licenses by querying the npm registry.
//
// SBOM generators frequently emit NOASSERTION for npm packages even though the
// registry knows the license from package.json. The public registry API
// (https://registry.npmjs.org/{name}/{version}) returns the version manifest
// including its "license" field – no authentication required.
package npm

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
	// DefaultRegistryURL is the public npm registry.
	DefaultRegistryURL = "https://registry.npmjs.org"

	// The public registry is generous, but stay polite: ~5 req/s sustained.
	defaultRate  = 5.0
	defaultBurst = 10
)

// Resolver resolves npm package licenses via the registry API.
type Resolver struct {
	baseURL    string
	httpClient *http.Client
	cache      sync.Map // map[string]string (cache key → SPDX expression or "")
	limiter    *ratelimit.TokenBucket
}

// NewResolver creates a resolver against the public npm registry.
func NewResolver() *Resolver {
	return NewResolverWithRegistry(DefaultRegistryURL)
}

// NewResolverWithRegistry creates a resolver against a custom registry
// (e.g. a corporate mirror or an httptest server).
func NewResolverWithRegistry(baseURL string) *Resolver {
	return &Resolver{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 15 * time.Second},
		limiter:    ratelimit.NewTokenBucket(defaultRate, defaultBurst),
	}
}

// CacheKey returns the cache key for an npm package version ("name@version").
func CacheKey(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

// Resolve returns the license expression for the npm package identified by purl,
// or "" if the purl is not an npm package, the registry has no license
// information, or the request fails. Results (including negative ones) are
// cached in memory to avoid repeated calls.
func (r *Resolver) Resolve(ctx context.Context, purl string) string {
	name, version, ok := ExtractNPMPackage(purl)
	if !ok {
		return ""
	}

	key := CacheKey(name, version)
	if cached, found := r.cache.Load(key); found {
		lic, _ := license.SplitCacheValue(cached.(string))
		return lic
	}

	if err := r.limiter.Wait(ctx); err != nil {
		return ""
	}

	lic, reason := r.fetchLicense(ctx, name, version)
	if lic == "" {
		r.cache.Store(key, license.NegativeCacheValue(reason))
	} else {
		r.cache.Store(key, lic)
	}

	if lic != "" {
		log.Printf("  npm license resolved: %s → %s", key, lic)
	}
	return lic
}

// Explain reports, for an npm purl, why it stayed unresolved (a license.Reason*
// value, "" when unknown) and whether the license is that of the "latest"
// dist-tag because the purl carries no version. handled is false for other
// ecosystems.
func (r *Resolver) Explain(purl string) (handled bool, reason string, latest bool) {
	name, version, ok := ExtractNPMPackage(purl)
	if !ok {
		return false, "", false
	}
	if cached, found := r.cache.Load(CacheKey(name, version)); found {
		_, reason = license.SplitCacheValue(cached.(string))
	}
	return true, reason, version == ""
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

// manifest is the subset of the npm version manifest we care about.
// "license" is a string in modern packages, but historically could be an
// object {"type": "MIT"} or the deprecated "licenses" array.
type manifest struct {
	License  json.RawMessage `json:"license"`
	Licenses json.RawMessage `json:"licenses"`
}

// fetchLicense fetches {registry}/{name}/{version}. If no version is given,
// the "latest" dist-tag is used. A negative result carries the reason when the
// registry gave a definite answer: 404 (not published) or a manifest without a
// usable license. Transport errors leave the reason empty.
func (r *Resolver) fetchLicense(ctx context.Context, name, version string) (string, string) {
	if version == "" {
		version = "latest"
	}
	// Scoped names must be encoded as "@scope%2Fname" – a plain path segment.
	u := fmt.Sprintf("%s/%s/%s", r.baseURL, url.PathEscape(name), url.PathEscape(version))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "bomhort-license-resolver")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		log.Printf("  npm registry request failed for %s: %v", CacheKey(name, version), err)
		return "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", license.ReasonNotPublished
	}
	if resp.StatusCode != http.StatusOK {
		return "", ""
	}

	var m manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return "", ""
	}
	if lic := NormalizeLicense(m.License, m.Licenses); lic != "" {
		return lic, ""
	}
	return "", license.ReasonNoLicenseUpstream
}

// NormalizeLicense converts the various historical shapes of the npm license
// field into a single SPDX-style expression:
//
//	"MIT"                                   → "MIT"
//	{"type": "MIT", "url": "..."}           → "MIT"
//	[{"type": "MIT"}, {"type": "Apache-2.0"}] → "MIT OR Apache-2.0"
//
// Values such as "UNLICENSED", "SEE LICENSE IN <file>" or empty strings are
// not usable license identifiers and yield "".
func NormalizeLicense(license, licenses json.RawMessage) string {
	if v := licenseFromRaw(license); v != "" {
		return v
	}
	return licenseFromRaw(licenses)
}

type licenseObject struct {
	Type string `json:"type"`
}

func licenseFromRaw(raw json.RawMessage) string {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return ""
		}
		return cleanExpression(s)
	case '{':
		var o licenseObject
		if err := json.Unmarshal(raw, &o); err != nil {
			return ""
		}
		return cleanExpression(o.Type)
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return ""
		}
		var parts []string
		for _, item := range arr {
			if v := licenseFromRaw(item); v != "" {
				parts = append(parts, v)
			}
		}
		return strings.Join(parts, " OR ")
	}
	return ""
}

func cleanExpression(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	upper := strings.ToUpper(s)
	if upper == "UNLICENSED" || upper == "NOASSERTION" || upper == "NONE" ||
		strings.HasPrefix(upper, "SEE LICENSE") {
		return ""
	}
	// Some packages wrap expressions in parentheses: "(MIT OR Apache-2.0)".
	if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

// ExtractNPMPackage parses an npm purl into package name and version.
//
//	pkg:npm/%40istanbuljs/load-nyc-config@1.1.0 → "@istanbuljs/load-nyc-config", "1.1.0"
//	pkg:npm/@scope/name@1.0.0                   → "@scope/name", "1.0.0"
//	pkg:npm/lodash@4.17.21                      → "lodash", "4.17.21"
//	pkg:npm/lodash                              → "lodash", ""
func ExtractNPMPackage(purl string) (name, version string, ok bool) {
	const prefix = "pkg:npm/"
	if !strings.HasPrefix(purl, prefix) {
		return "", "", false
	}
	rest := purl[len(prefix):]

	// Strip qualifiers and subpath.
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", "", false
	}

	// Split version at the last "@" that is not the scope marker at position 0.
	if i := strings.LastIndex(rest, "@"); i > 0 {
		name, version = rest[:i], rest[i+1:]
	} else {
		name = rest
	}

	// purl namespaces are percent-encoded ("%40scope").
	if decoded, err := url.PathUnescape(name); err == nil {
		name = decoded
	}
	if decoded, err := url.PathUnescape(version); err == nil {
		version = decoded
	}

	name = strings.TrimSpace(name)
	if name == "" || strings.Contains(name, "..") {
		return "", "", false
	}
	// Scoped packages must be exactly "@scope/name".
	if strings.HasPrefix(name, "@") && strings.Count(name, "/") != 1 {
		return "", "", false
	}
	if !strings.HasPrefix(name, "@") && strings.Contains(name, "/") {
		return "", "", false
	}
	return name, version, true
}
