// Package clearlydefined resolves unknown package licenses and detects
// concluded vs. declared license discrepancies using ClearlyDefined definitions (#530).
//
// ClearlyDefined (Linux Foundation) provides crowdsourced, scan-harvested CC0
// component definitions per package coordinate.
package clearlydefined

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	// DefaultRegistryURL is the public ClearlyDefined API.
	DefaultRegistryURL = "https://api.clearlydefined.io"

	defaultRate     = 5.0
	defaultBurst    = 10
	maxBatchSize    = 50
	maxResponseSize = 10 << 20
)

// Coordinate represents a ClearlyDefined component coordinate:
// type/provider/namespace/name/revision.
type Coordinate struct {
	Type      string
	Provider  string
	Namespace string
	Name      string
	Revision  string
}

// String returns the canonical ClearlyDefined coordinate string.
func (c Coordinate) String() string {
	ns := c.Namespace
	if ns == "" {
		ns = "-"
	}
	return fmt.Sprintf("%s/%s/%s/%s/%s", c.Type, c.Provider, ns, c.Name, c.Revision)
}

// Valid reports whether the coordinate has non-empty required fields and is
// safe for URL path construction (no dot segments, traversals, or invalid characters).
func (c Coordinate) Valid() bool {
	if c.Type == "" || c.Provider == "" || c.Name == "" || c.Revision == "" {
		return false
	}
	if !license.ValidVersion(c.Revision) || strings.ContainsAny(c.Revision, " \t\r\n") {
		return false
	}
	if c.Namespace == "." || c.Namespace == ".." || strings.Contains(c.Namespace, "..") || strings.ContainsAny(c.Namespace, "/\\ \t\r\n") {
		return false
	}
	if c.Name == "." || c.Name == ".." || strings.Contains(c.Name, "..") || strings.ContainsAny(c.Name, "/\\ \t\r\n") {
		return false
	}
	return true
}

// Path returns the URL path segment for querying the definition endpoint.
func (c Coordinate) Path() string {
	ns := c.Namespace
	if ns == "" {
		ns = "-"
	}
	return fmt.Sprintf("%s/%s/%s/%s/%s",
		url.PathEscape(c.Type),
		url.PathEscape(c.Provider),
		url.PathEscape(ns),
		url.PathEscape(c.Name),
		url.PathEscape(c.Revision),
	)
}

// CoordinateFromPURL maps a standard Package URL to a ClearlyDefined Coordinate.
func CoordinateFromPURL(purl string) (Coordinate, bool) {
	if !strings.HasPrefix(purl, "pkg:") {
		return Coordinate{}, false
	}
	raw := strings.TrimPrefix(purl, "pkg:")
	raw, _, _ = strings.Cut(raw, "?")
	raw, _, _ = strings.Cut(raw, "#")

	typ, rest, ok := strings.Cut(raw, "/")
	if !ok || typ == "" || rest == "" {
		return Coordinate{}, false
	}

	atIdx := strings.LastIndex(rest, "@")
	if atIdx <= 0 || atIdx >= len(rest)-1 {
		return Coordinate{}, false
	}
	namePart := rest[:atIdx]
	version := rest[atIdx+1:]

	// URL-decode name and version components before ecosystem inspection, so
	// percent-encoded characters like %40 (@) in scoped npm packages are decoded (#530).
	if decoded, err := url.PathUnescape(namePart); err == nil && decoded != "" {
		namePart = decoded
	}
	if decoded, err := url.PathUnescape(version); err == nil && decoded != "" {
		version = decoded
	}

	switch strings.ToLower(typ) {
	case "npm":
		// Scoped: @scope/name vs plain: name
		if strings.HasPrefix(namePart, "@") {
			scope, name, ok := strings.Cut(namePart, "/")
			if ok && scope != "" && name != "" {
				coord := Coordinate{Type: "npm", Provider: "npmjs", Namespace: scope, Name: name, Revision: version}
				return coord, coord.Valid()
			}
		}
		coord := Coordinate{Type: "npm", Provider: "npmjs", Namespace: "-", Name: namePart, Revision: version}
		return coord, coord.Valid()

	case "pypi":
		coord := Coordinate{Type: "pypi", Provider: "pypi", Namespace: "-", Name: namePart, Revision: version}
		return coord, coord.Valid()

	case "maven":
		group, artifact, ok := strings.Cut(namePart, "/")
		if ok && group != "" && artifact != "" {
			coord := Coordinate{Type: "maven", Provider: "mavencentral", Namespace: group, Name: artifact, Revision: version}
			return coord, coord.Valid()
		}
		return Coordinate{}, false

	case "nuget":
		coord := Coordinate{Type: "nuget", Provider: "nuget", Namespace: "-", Name: namePart, Revision: version}
		return coord, coord.Valid()

	case "cargo", "crate", "cratesio":
		coord := Coordinate{Type: "crate", Provider: "cratesio", Namespace: "-", Name: namePart, Revision: version}
		return coord, coord.Valid()

	case "gem", "rubygems":
		coord := Coordinate{Type: "gem", Provider: "rubygems", Namespace: "-", Name: namePart, Revision: version}
		return coord, coord.Valid()

	case "composer":
		vendor, pkg, ok := strings.Cut(namePart, "/")
		if ok && vendor != "" && pkg != "" {
			coord := Coordinate{Type: "composer", Provider: "packagist", Namespace: vendor, Name: pkg, Revision: version}
			return coord, coord.Valid()
		}
		return Coordinate{}, false

	case "golang", "go":
		// pkg:golang/github.com/owner/repo@v1.0.0
		if strings.HasPrefix(namePart, "github.com/") {
			parts := strings.Split(strings.TrimPrefix(namePart, "github.com/"), "/")
			if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
				coord := Coordinate{Type: "git", Provider: "github", Namespace: parts[0], Name: parts[1], Revision: version}
				return coord, coord.Valid()
			}
		}
		return Coordinate{}, false

	case "github":
		owner, repo, ok := strings.Cut(namePart, "/")
		if ok && owner != "" && repo != "" {
			coord := Coordinate{Type: "git", Provider: "github", Namespace: owner, Name: repo, Revision: version}
			return coord, coord.Valid()
		}
		return Coordinate{}, false

	default:
		return Coordinate{}, false
	}
}

// definitionResponse maps the subset of ClearlyDefined definition metadata we inspect.
type definitionResponse struct {
	Licensed struct {
		Declared string `json:"declared"`
		Facets   struct {
			Core struct {
				Attribution struct {
					Parties []string `json:"parties"`
				} `json:"attribution"`
				Discovered struct {
					Expressions []string `json:"expressions"`
				} `json:"discovered"`
			} `json:"core"`
		} `json:"facets"`
		Discovered struct {
			Expressions []string `json:"expressions"`
		} `json:"discovered"`
	} `json:"licensed"`
}

// cachedRecord represents a serialized ClearlyDefined record for persistence in
// registry_license_cache across worker restarts (#530).
type cachedRecord struct {
	License    string   `json:"lic,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Discovered []string `json:"discovered,omitempty"`
	Parties    []string `json:"parties,omitempty"`
}

// Resolver resolves licenses and discrepancies using ClearlyDefined definitions.
type Resolver struct {
	baseURL         string
	httpClient      *http.Client
	limiter         *ratelimit.TokenBucket
	licenseCache    sync.Map // cacheKey -> string (lic or NegativeCacheValue)
	attributions    sync.Map // cacheKey -> []string
	discovered      sync.Map // cacheKey -> []string (all discovered expressions)
	privatePrefixes []string
	newMu           sync.Mutex
	newKeys         map[string]struct{}
}

func (r *Resolver) recordNewKey(key string) {
	if key == "" {
		return
	}
	r.newMu.Lock()
	defer r.newMu.Unlock()
	if r.newKeys == nil {
		r.newKeys = make(map[string]struct{})
	}
	r.newKeys[key] = struct{}{}
}

// NewResolver creates a resolver against the public ClearlyDefined service.
func NewResolver() *Resolver {
	return NewResolverWithRegistry(DefaultRegistryURL)
}

// NewResolverWithRegistry creates a resolver against a custom registry URL.
func NewResolverWithRegistry(baseURL string) *Resolver {
	return &Resolver{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 15 * time.Second},
		limiter:    ratelimit.NewTokenBucket(defaultRate, defaultBurst),
	}
}

// CacheKey returns the cache key for a ClearlyDefined coordinate.
func CacheKey(coord Coordinate) string {
	return coord.String()
}

// SetPrivatePrefixes configures operator-controlled prefixes for internal/private packages.
func (r *Resolver) SetPrivatePrefixes(prefixes []string) {
	if r == nil {
		return
	}
	r.privatePrefixes = append([]string(nil), prefixes...)
}

// IsPrivate reports whether a PURL represents an internal or private package
// that must not be queried from external public services.
func (r *Resolver) IsPrivate(purl string) bool {
	if r == nil {
		return false
	}
	return IsPrivatePackage(purl, r.privatePrefixes)
}

// IsPrivatePackage reports whether a PURL represents a private package that must
// not be queried from external public services. It matches:
//  1. Yarn Berry workspace modules (*@0.0.0-use.local)
//  2. Maven project modules (unexpanded ${project.groupId} or ${project.*})
//  3. Any PURL or package prefix listed in operator-configured prefixes.
func IsPrivatePackage(purl string, prefixes []string) bool {
	if purl == "" {
		return false
	}
	if isYarnWorkspace(purl) {
		return true
	}
	if isMavenProjectModule(purl) {
		return true
	}
	if len(prefixes) == 0 {
		return false
	}

	unescaped, err := url.PathUnescape(purl)
	if err != nil {
		unescaped = purl
	}

	for _, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" {
			continue
		}
		if matchesPackagePrefix(purl, unescaped, prefix) {
			return true
		}
	}
	return false
}

func isYarnWorkspace(purl string) bool {
	if !strings.HasPrefix(purl, "pkg:npm/") {
		return false
	}
	base := purl
	if i := strings.IndexAny(base, "?#"); i >= 0 {
		base = base[:i]
	}
	return strings.HasSuffix(base, "@0.0.0-use.local")
}

func isMavenProjectModule(purl string) bool {
	if !strings.HasPrefix(purl, "pkg:maven/") {
		return false
	}
	rest := strings.TrimPrefix(purl, "pkg:maven/")
	rest = strings.ReplaceAll(rest, "%7B", "{")
	rest = strings.ReplaceAll(rest, "%7D", "}")
	rest = strings.ReplaceAll(rest, "%24", "$")
	return strings.HasPrefix(rest, "${project.")
}

func matchesPackagePrefix(rawPURL, unescapedPURL, prefix string) bool {
	unescapedPrefix, _ := url.PathUnescape(prefix)

	if strings.HasPrefix(prefix, "pkg:") || strings.HasPrefix(unescapedPrefix, "pkg:") {
		return hasPURLPrefix(rawPURL, prefix) ||
			hasPURLPrefix(unescapedPURL, prefix) ||
			hasPURLPrefix(rawPURL, unescapedPrefix) ||
			hasPURLPrefix(unescapedPURL, unescapedPrefix)
	}

	if strings.HasPrefix(prefix, "@") || strings.HasPrefix(prefix, "%40") || strings.HasPrefix(unescapedPrefix, "@") {
		cleanScope := strings.Trim(unescapedPrefix, "/")
		if !strings.HasPrefix(cleanScope, "@") {
			cleanScope = "@" + cleanScope
		}
		scopeInPURL := "pkg:npm/" + cleanScope + "/"
		scopeEncoded := "pkg:npm/%40" + strings.TrimPrefix(cleanScope, "@") + "/"
		return hasPURLPrefix(unescapedPURL, scopeInPURL) ||
			hasPURLPrefix(rawPURL, scopeEncoded) ||
			hasPURLPrefix(rawPURL, scopeInPURL)
	}

	cleanPrefix := strings.Trim(unescapedPrefix, "/")
	mavenPURL := "pkg:maven/" + cleanPrefix + "/"
	if hasPURLPrefix(rawPURL, mavenPURL) || hasPURLPrefix(unescapedPURL, mavenPURL) {
		return true
	}
	if strings.Contains(unescapedPURL, "/"+cleanPrefix+"/") || strings.Contains(rawPURL, "/"+cleanPrefix+"/") {
		return true
	}

	return hasPURLPrefix(rawPURL, prefix) || hasPURLPrefix(unescapedPURL, unescapedPrefix)
}

func hasPURLPrefix(p, prefix string) bool {
	if p == prefix {
		return true
	}
	if strings.HasPrefix(p, prefix) {
		if len(prefix) == 0 {
			return false
		}
		last := prefix[len(prefix)-1]
		if last == '/' || last == '@' || last == ':' || last == '?' || last == '#' {
			return true
		}
		if len(p) > len(prefix) {
			next := p[len(prefix)]
			if next == '/' || next == '@' || next == '?' || next == '#' || next == ':' {
				return true
			}
		}
	}
	return false
}

// PreloadCache seeds the cache from registry_license_cache across worker restarts (#530).
func (r *Resolver) PreloadCache(entries map[string]string) {
	for k, v := range entries {
		if strings.HasPrefix(v, "{") {
			var rec cachedRecord
			if err := json.Unmarshal([]byte(v), &rec); err == nil {
				if rec.License != "" {
					r.licenseCache.Store(k, rec.License)
				} else if rec.Reason != "" {
					r.licenseCache.Store(k, license.NegativeCacheValue(rec.Reason))
				}
				if len(rec.Discovered) > 0 {
					r.discovered.Store(k, rec.Discovered)
				}
				if len(rec.Parties) > 0 {
					r.attributions.Store(k, rec.Parties)
				}
				continue
			}
		}
		// Plain legacy encoding or standard NegativeCacheValue
		r.licenseCache.Store(k, v)
	}
}

func (r *Resolver) encodeEntry(k string) (string, bool) {
	lic, reason := "", ""
	if v, ok := r.licenseCache.Load(k); ok {
		lic, reason = license.SplitCacheValue(v.(string))
	}
	var disc, parties []string
	if dv, ok := r.discovered.Load(k); ok {
		disc = dv.([]string)
	}
	if pv, ok := r.attributions.Load(k); ok {
		parties = pv.([]string)
	}

	if len(disc) > 0 || len(parties) > 0 {
		rec := cachedRecord{
			License:    lic,
			Reason:     reason,
			Discovered: disc,
			Parties:    parties,
		}
		if b, err := json.Marshal(rec); err == nil {
			return string(b), true
		}
	}

	if lic != "" {
		return lic, true
	}
	if reason != "" {
		return license.NegativeCacheValue(reason), true
	}
	return "", false
}

// CacheEntries exports the in-memory cache for persistence in registry_license_cache (#530).
func (r *Resolver) CacheEntries() map[string]string {
	out := make(map[string]string)
	keys := make(map[string]bool)

	r.licenseCache.Range(func(k, v any) bool {
		keys[k.(string)] = true
		return true
	})
	r.discovered.Range(func(k, v any) bool {
		keys[k.(string)] = true
		return true
	})
	r.attributions.Range(func(k, v any) bool {
		keys[k.(string)] = true
		return true
	})

	for k := range keys {
		if encoded, ok := r.encodeEntry(k); ok {
			out[k] = encoded
		}
	}
	return out
}

// NewCacheEntries returns and drains cache entries added or updated since PreloadCache
// or the previous call, avoiding full cache rewrites on repeated scans.
func (r *Resolver) NewCacheEntries() map[string]string {
	r.newMu.Lock()
	if len(r.newKeys) == 0 {
		r.newMu.Unlock()
		return nil
	}
	keys := r.newKeys
	r.newKeys = nil
	r.newMu.Unlock()

	out := make(map[string]string, len(keys))
	for k := range keys {
		if encoded, ok := r.encodeEntry(k); ok {
			out[k] = encoded
		}
	}
	return out
}

// Load checks the in-memory license cache for a key.
func (r *Resolver) Load(key string) (lic, reason string, ok bool) {
	v, ok := r.licenseCache.Load(key)
	if !ok {
		return "", "", false
	}
	lic, reason = license.SplitCacheValue(v.(string))
	return lic, reason, true
}

// StoreResult stores a license or negative reason in the in-memory cache.
func (r *Resolver) StoreResult(key, lic, reason string) {
	if lic != "" {
		r.licenseCache.Store(key, lic)
		r.recordNewKey(key)
		return
	}
	if reason != "" {
		r.licenseCache.Store(key, license.NegativeCacheValue(reason))
		r.recordNewKey(key)
	}
}

// Resolve returns the declared license expression for the package identified by purl,
// or "" if not found, unresolved upstream, or the request fails.
func (r *Resolver) Resolve(ctx context.Context, purl string) string {
	if r.IsPrivate(purl) {
		return ""
	}
	coord, ok := CoordinateFromPURL(purl)
	if !ok {
		return ""
	}

	key := CacheKey(coord)
	if lic, _, found := r.Load(key); found {
		return lic
	}

	if err := r.limiter.Wait(ctx); err != nil {
		return ""
	}

	lic, reason := r.fetchDefinition(ctx, coord)
	r.StoreResult(key, lic, reason)

	if lic != "" {
		log.Printf("  clearlydefined license resolved: %s -> %s", key, lic)
	}
	return lic
}

// ResolveBatch resolves multiple PURLs in bulk using ClearlyDefined's definitions endpoint.
// Only actual resolved licenses are returned in the result map; negative cache markers
// remain in the cache for Explain so callers never write '!reason' into ClickHouse (#530).
func (r *Resolver) ResolveBatch(ctx context.Context, purls []string) map[string]string {
	out := make(map[string]string, len(purls))
	var uncached []Coordinate
	purlByCoord := make(map[string][]string)

	for _, p := range purls {
		if r.IsPrivate(p) {
			continue
		}
		coord, ok := CoordinateFromPURL(p)
		if !ok {
			continue
		}
		key := CacheKey(coord)
		if lic, _, found := r.Load(key); found {
			if lic != "" {
				out[p] = lic
			}
			continue
		}
		purlByCoord[key] = append(purlByCoord[key], p)
		if len(purlByCoord[key]) == 1 {
			uncached = append(uncached, coord)
		}
	}

	if len(uncached) > 0 {
		if err := r.fetchDefinitionsBatch(ctx, uncached); err != nil {
			log.Printf("ClearlyDefined license batch lookup failed: %v", err)
		}
		for key, plist := range purlByCoord {
			lic, _, _ := r.Load(key)
			if lic != "" {
				for _, p := range plist {
					out[p] = lic
				}
			}
		}
	}
	return out
}

// Explain reports why a package stayed unresolved in ClearlyDefined.
func (r *Resolver) Explain(purl string) (handled bool, reason string, latest bool) {
	coord, ok := CoordinateFromPURL(purl)
	if !ok {
		return false, "", false
	}
	key := CacheKey(coord)
	_, reason, _ = r.Load(key)
	return true, reason, false
}

// CheckDiscrepancy compares ClearlyDefined discovered scan expressions with the
// package's declared license. If discovered expressions exist and conflict with
// declaredLicense, returns the conflicting expression and true (#530).
func (r *Resolver) CheckDiscrepancy(ctx context.Context, purl, declaredLicense string) (string, bool) {
	if r.IsPrivate(purl) {
		return "", false
	}
	declaredLicense = strings.TrimSpace(declaredLicense)
	if declaredLicense == "" || declaredLicense == "NOASSERTION" || declaredLicense == "NONE" {
		return "", false
	}

	coord, ok := CoordinateFromPURL(purl)
	if !ok {
		return "", false
	}

	key := CacheKey(coord)

	// Check if discovered expressions are already cached.
	if discVal, ok := r.discovered.Load(key); ok {
		discovered := discVal.([]string)
		if conflict, found := hasDiscrepancy(declaredLicense, discovered); found {
			return conflict, true
		}
		return "", false
	}

	// Reuse definitive cached negative results (e.g. not-harvested) without re-querying.
	if _, reason, found := r.Load(key); found && reason != "" {
		return "", false
	}

	if err := r.limiter.Wait(ctx); err != nil {
		return "", false
	}
	lic, reason := r.fetchDefinition(ctx, coord)
	r.StoreResult(key, lic, reason)

	if discVal, ok := r.discovered.Load(key); ok {
		discovered := discVal.([]string)
		if conflict, found := hasDiscrepancy(declaredLicense, discovered); found {
			return conflict, true
		}
	}
	return "", false
}

// CheckDiscrepanciesBatch checks discrepancies for multiple packages in bulk (#530).
func (r *Resolver) CheckDiscrepanciesBatch(ctx context.Context, purls, declaredLicenses []string) []string {
	discrepancies := make([]string, len(declaredLicenses))
	var uncached []Coordinate
	coordIndices := make(map[string][]int)

	for i, purl := range purls {
		if i >= len(declaredLicenses) {
			break
		}
		if r.IsPrivate(purl) {
			continue
		}
		declared := strings.TrimSpace(declaredLicenses[i])
		if declared == "" || declared == "NOASSERTION" || declared == "NONE" {
			continue
		}
		coord, ok := CoordinateFromPURL(purl)
		if !ok {
			continue
		}
		key := CacheKey(coord)

		// Check if discovered expressions already cached:
		if discVal, ok := r.discovered.Load(key); ok {
			if conflict, found := hasDiscrepancy(declared, discVal.([]string)); found {
				discrepancies[i] = conflict
			}
			continue
		}

		// Definitive negative cache (not harvested): skip immediately!
		if _, reason, found := r.Load(key); found && reason != "" {
			continue
		}

		coordIndices[key] = append(coordIndices[key], i)
		if len(coordIndices[key]) == 1 {
			uncached = append(uncached, coord)
		}
	}

	if len(uncached) > 0 {
		if err := r.fetchDefinitionsBatch(ctx, uncached); err != nil {
			log.Printf("ClearlyDefined discrepancy batch lookup failed: %v", err)
		}
		for key, indices := range coordIndices {
			if discVal, ok := r.discovered.Load(key); ok {
				for _, idx := range indices {
					declared := declaredLicenses[idx]
					if conflict, found := hasDiscrepancy(declared, discVal.([]string)); found {
						discrepancies[idx] = conflict
					}
				}
			}
		}
	}

	return discrepancies
}

// hasDiscrepancy checks if any discovered expression conflicts with the declared license (#530).
func hasDiscrepancy(declaredLicense string, discovered []string) (string, bool) {
	var conflicts []string
	seen := make(map[string]bool)
	for _, disc := range discovered {
		disc = strings.TrimSpace(disc)
		if disc == "" || seen[disc] {
			continue
		}
		seen[disc] = true
		if !licensesAgree(declaredLicense, disc) {
			conflicts = append(conflicts, disc)
		}
	}
	if len(conflicts) > 0 {
		return strings.Join(conflicts, " AND "), true
	}
	return "", false
}

// GetAttributionParties returns any recorded copyright parties for the purl.
func (r *Resolver) GetAttributionParties(purl string) []string {
	coord, ok := CoordinateFromPURL(purl)
	if !ok {
		return nil
	}
	if v, ok := r.attributions.Load(CacheKey(coord)); ok {
		return v.([]string)
	}
	return nil
}

// fetchDefinition queries ClearlyDefined for a single coordinate's definition.
func (r *Resolver) fetchDefinition(ctx context.Context, coord Coordinate) (string, string) {
	key := CacheKey(coord)
	u := fmt.Sprintf("%s/definitions/%s", r.baseURL, coord.Path())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "bomhort-clearlydefined-resolver")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", license.ReasonNotHarvested
	}
	if resp.StatusCode != http.StatusOK {
		return "", ""
	}

	var def definitionResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&def); err != nil {
		return "", ""
	}

	// Capture attribution parties
	if len(def.Licensed.Facets.Core.Attribution.Parties) > 0 {
		r.attributions.Store(key, def.Licensed.Facets.Core.Attribution.Parties)
	}

	// Capture all discovered expressions (deduplicated)
	var discovered []string
	seenDisc := make(map[string]bool)
	for _, expr := range append(def.Licensed.Facets.Core.Discovered.Expressions, def.Licensed.Discovered.Expressions...) {
		expr = strings.TrimSpace(expr)
		if expr == "" {
			continue
		}
		if norm := license.Normalize(expr); norm != "" {
			expr = norm
		}
		if !seenDisc[expr] {
			seenDisc[expr] = true
			discovered = append(discovered, expr)
		}
	}
	if len(discovered) > 0 {
		r.discovered.Store(key, discovered)
	}

	// Return declared license ONLY if upstream actually declared one (never promote file scans).
	declared := strings.TrimSpace(def.Licensed.Declared)
	if declared != "" && declared != "OTHER" && declared != "NOASSERTION" {
		if norm := license.Normalize(declared); norm != "" {
			return norm, ""
		}
		return declared, ""
	}

	return "", license.ReasonNoLicenseUpstream
}

// fetchDefinitionsBatch queries ClearlyDefined in bulk using POST /definitions (#530).
// Batches are chunked by maxBatchSize (50 coordinates) to avoid giant payloads.
func (r *Resolver) fetchDefinitionsBatch(ctx context.Context, coords []Coordinate) error {
	for start := 0; start < len(coords); start += maxBatchSize {
		end := start + maxBatchSize
		if end > len(coords) {
			end = len(coords)
		}
		chunk := coords[start:end]
		if err := r.fetchDefinitionsChunk(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}

// fetchDefinitionsChunk requests a batch of definitions from POST /definitions.
// If the payload exceeds maxResponseSize (10 MiB) or fails to parse, it splits
// the chunk recursively into smaller slices (or falls back to single-definition GET)
// instead of silently dropping all definitions (#530).
func (r *Resolver) fetchDefinitionsChunk(ctx context.Context, chunk []Coordinate) error {
	if len(chunk) == 0 {
		return nil
	}

	if err := r.limiter.Wait(ctx); err != nil {
		return err
	}

	coordStrings := make([]string, len(chunk))
	for i, c := range chunk {
		coordStrings[i] = c.String()
	}

	u := fmt.Sprintf("%s/definitions", r.baseURL)
	body, err := json.Marshal(coordStrings)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "bomhort-clearlydefined-resolver")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if len(chunk) > 1 && (resp.StatusCode == http.StatusRequestEntityTooLarge || resp.StatusCode == http.StatusNotFound) {
			mid := len(chunk) / 2
			leftErr := r.fetchDefinitionsChunk(ctx, chunk[:mid])
			rightErr := r.fetchDefinitionsChunk(ctx, chunk[mid:])
			return errors.Join(leftErr, rightErr)
		}
		if resp.StatusCode == http.StatusNotFound && len(chunk) == 1 {
			r.StoreResult(CacheKey(chunk[0]), "", license.ReasonNotHarvested)
			return nil
		}
		return fmt.Errorf("ClearlyDefined definitions request returned HTTP %d", resp.StatusCode)
	}

	var res map[string]definitionResponse
	err = json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&res)
	if err != nil {
		// Body was truncated by LimitReader (>10 MiB) or JSON was malformed.
		// Split recursively if multiple coordinates; fall back to per-coordinate GET if single.
		if len(chunk) > 1 {
			mid := len(chunk) / 2
			leftErr := r.fetchDefinitionsChunk(ctx, chunk[:mid])
			rightErr := r.fetchDefinitionsChunk(ctx, chunk[mid:])
			return errors.Join(leftErr, rightErr)
		}
		lic, reason := r.fetchDefinition(ctx, chunk[0])
		r.StoreResult(CacheKey(chunk[0]), lic, reason)
		return nil
	}

	for _, c := range chunk {
		key := CacheKey(c)
		def, ok := res[key]
		if !ok {
			def, ok = res[c.String()]
		}
		if !ok {
			r.StoreResult(key, "", license.ReasonNotHarvested)
			continue
		}

		// Capture parties
		if len(def.Licensed.Facets.Core.Attribution.Parties) > 0 {
			r.attributions.Store(key, def.Licensed.Facets.Core.Attribution.Parties)
		}

		// Capture discovered expressions
		var discovered []string
		seenDisc := make(map[string]bool)
		for _, expr := range append(def.Licensed.Facets.Core.Discovered.Expressions, def.Licensed.Discovered.Expressions...) {
			expr = strings.TrimSpace(expr)
			if expr == "" {
				continue
			}
			if norm := license.Normalize(expr); norm != "" {
				expr = norm
			}
			if !seenDisc[expr] {
				seenDisc[expr] = true
				discovered = append(discovered, expr)
			}
		}
		if len(discovered) > 0 {
			r.discovered.Store(key, discovered)
		}

		// Declared license
		declared := strings.TrimSpace(def.Licensed.Declared)
		if declared != "" && declared != "OTHER" && declared != "NOASSERTION" {
			if norm := license.Normalize(declared); norm != "" {
				declared = norm
			}
			r.StoreResult(key, declared, "")
		} else {
			r.StoreResult(key, "", license.ReasonNoLicenseUpstream)
		}
	}
	return nil
}

// PopulateAttributions populates copyright parties for packages from ClearlyDefined (#530).
func (r *Resolver) PopulateAttributions(ctx context.Context, pkgs []NoticePackage) {
	if r == nil {
		return
	}
	var uncached []Coordinate
	for i := range pkgs {
		if len(pkgs[i].CopyrightParties) > 0 {
			continue
		}
		if r.IsPrivate(pkgs[i].PURL) {
			continue
		}
		coord, ok := CoordinateFromPURL(pkgs[i].PURL)
		if !ok {
			continue
		}
		key := CacheKey(coord)
		if parties, ok := r.attributions.Load(key); ok {
			pkgs[i].CopyrightParties = parties.([]string)
			continue
		}
		uncached = append(uncached, coord)
	}

	if len(uncached) > 0 {
		if err := r.fetchDefinitionsBatch(ctx, uncached); err != nil {
			log.Printf("ClearlyDefined attribution batch lookup failed: %v", err)
		}
		for i := range pkgs {
			if len(pkgs[i].CopyrightParties) > 0 {
				continue
			}
			coord, ok := CoordinateFromPURL(pkgs[i].PURL)
			if !ok {
				continue
			}
			if parties, ok := r.attributions.Load(CacheKey(coord)); ok {
				pkgs[i].CopyrightParties = parties.([]string)
			}
		}
	}
}

// GenerateNoticeWithFallback generates an attribution NOTICE file with complete
// component coverage, real ClearlyDefined copyright attribution where available,
// explicit missing copyright flags for manual review, and complete SPDX texts (#530).
func (r *Resolver) GenerateNoticeWithFallback(ctx context.Context, targetName string, pkgs []NoticePackage) string {
	if r != nil {
		fetchCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		r.PopulateAttributions(fetchCtx, pkgs)
	}
	return GenerateNotice(targetName, pkgs)
}

// licensesAgree checks if two license expressions are equivalent.
func licensesAgree(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if strings.EqualFold(a, b) {
		return true
	}
	normA := license.Normalize(a)
	normB := license.Normalize(b)
	return strings.EqualFold(normA, normB)
}
