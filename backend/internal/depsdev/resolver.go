// Package depsdev resolves unknown package licenses via the deps.dev API.
//
// deps.dev (Google Open Source Insights) exposes normalized SPDX license
// expressions for public package versions across several ecosystems. BOMHort
// uses it as a broad fallback after ecosystem-native resolvers have had a
// chance to resolve licenses first.
package depsdev

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/ratelimit"
)

const (
	// DefaultBaseURL is the public deps.dev API root.
	DefaultBaseURL = "https://api.deps.dev"

	defaultRate     = 2.0
	defaultBurst    = 4
	maxBatchSize    = 5000
	batchAPIVersion = "v3alpha"
	getAPIVersion   = "v3"

	// anyVersion stands in for the version in cache keys of purls that name
	// no usable version; those resolve via the package's default version.
	anyVersion = "*"
)

// Resolver resolves package licenses via deps.dev.
type Resolver struct {
	baseURL    string
	httpClient *http.Client
	cache      sync.Map // map[string]string (cache key → SPDX expression or "")
	limiter    *ratelimit.TokenBucket
}

// PackageVersion is the normalized deps.dev lookup key extracted from a purl.
type PackageVersion struct {
	System  string
	Name    string
	Version string
}

// NewResolver creates a resolver against the public deps.dev API.
func NewResolver() *Resolver {
	return NewResolverWithBaseURL(DefaultBaseURL)
}

// NewResolverWithBaseURL creates a resolver against a custom deps.dev API root.
func NewResolverWithBaseURL(baseURL string) *Resolver {
	return &Resolver{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 20 * time.Second},
		limiter:    ratelimit.NewTokenBucket(defaultRate, defaultBurst),
	}
}

// CacheKey returns the cache key for a deps.dev package version.
func CacheKey(pv PackageVersion) string {
	return pv.System + ":" + pv.Name + "@" + pv.Version
}

// Resolve returns the SPDX license expression for purl, or "" if deps.dev does
// not support the ecosystem or has no license data for it. A purl without a
// usable version ("pkg:pypi/requests", "…@unknown") resolves via the package's
// default (latest) version — licenses rarely change between versions, and a
// best guess beats NOASSERTION. Results, including negatives, are cached in
// memory.
func (r *Resolver) Resolve(ctx context.Context, purl string) string {
	pv, ok := extractPackage(purl)
	if !ok {
		return ""
	}
	if pv.Version != "" {
		return r.resolveOne(ctx, pv)
	}
	key := CacheKey(PackageVersion{System: pv.System, Name: pv.Name, Version: anyVersion})
	if cached, found := r.cache.Load(key); found {
		lic, _ := license.SplitCacheValue(cached.(string))
		return lic
	}
	v, reason := r.defaultVersion(ctx, pv)
	value := license.NegativeCacheValue(reason)
	if v != "" {
		value = r.resolveOneValue(ctx, PackageVersion{System: pv.System, Name: pv.Name, Version: v})
	}
	r.cache.Store(key, value)
	lic, _ := license.SplitCacheValue(value)
	return lic
}

// resolveOne resolves a single concrete package version, caching the result.
func (r *Resolver) resolveOne(ctx context.Context, pv PackageVersion) string {
	lic, _ := license.SplitCacheValue(r.resolveOneValue(ctx, pv))
	return lic
}

// resolveOneValue is resolveOne returning the cache encoding (license or
// negative marker with reason).
func (r *Resolver) resolveOneValue(ctx context.Context, pv PackageVersion) string {
	key := CacheKey(pv)
	if cached, found := r.cache.Load(key); found {
		return cached.(string)
	}

	if err := r.limiter.Wait(ctx); err != nil {
		return ""
	}

	value := r.fetchLicense(ctx, pv)
	r.cache.Store(key, value)
	if lic, _ := license.SplitCacheValue(value); lic != "" {
		log.Printf("  deps.dev license resolved: %s → %s", key, lic)
	}
	return value
}

// Explain reports, for a purl deps.dev covers, why it stayed unresolved (a
// license.Reason* value, "" when unknown) and whether the license is the
// default version's because the purl carries no usable version. handled is
// false for ecosystems deps.dev does not cover.
func (r *Resolver) Explain(purl string) (handled bool, reason string, latest bool) {
	pv, ok := extractPackage(purl)
	if !ok {
		return false, "", false
	}
	latest = pv.Version == ""
	if latest {
		pv.Version = anyVersion
	}
	if cached, found := r.cache.Load(CacheKey(pv)); found {
		_, reason = license.SplitCacheValue(cached.(string))
	}
	return true, reason, latest
}

// ResolveBatch returns SPDX license expressions for the provided purls. It uses
// deps.dev's v3alpha versionbatch endpoint for uncached package versions and
// falls back to per-version GETs if the batch request fails.
func (r *Resolver) ResolveBatch(ctx context.Context, purls []string) map[string]string {
	out := make(map[string]string, len(purls))
	pending := make(map[string]PackageVersion)
	purlsByKey := make(map[string][]string)

	for _, purl := range purls {
		pv, ok := extractPackage(purl)
		if !ok {
			continue
		}
		if pv.Version == "" {
			pv.Version = anyVersion
		}
		key := CacheKey(pv)
		if cached, found := r.cache.Load(key); found {
			out[purl], _ = license.SplitCacheValue(cached.(string))
			continue
		}
		if _, seen := pending[key]; !seen {
			pending[key] = pv
		}
		purlsByKey[key] = append(purlsByKey[key], purl)
	}
	if len(pending) == 0 {
		return out
	}

	resolved := make(map[string]string, len(pending))
	// Versionless purls borrow the license of the package's default version.
	defaultOf := make(map[string]string) // wildcard key → concrete key
	items := make([]PackageVersion, 0, len(pending))
	queued := make(map[string]bool, len(pending))
	for key, pv := range pending {
		if pv.Version == anyVersion {
			continue
		}
		items = append(items, pv)
		queued[key] = true
	}
	for key, pv := range pending {
		if pv.Version != anyVersion {
			continue
		}
		version, reason := r.defaultVersion(ctx, pv)
		if version == "" {
			resolved[key] = license.NegativeCacheValue(reason)
			continue
		}
		concrete := PackageVersion{System: pv.System, Name: pv.Name, Version: version}
		ck := CacheKey(concrete)
		defaultOf[key] = ck
		if cached, found := r.cache.Load(ck); found {
			resolved[ck] = cached.(string)
			continue
		}
		if !queued[ck] {
			items = append(items, concrete)
			queued[ck] = true
		}
	}

	for start := 0; start < len(items); start += maxBatchSize {
		end := start + maxBatchSize
		if end > len(items) {
			end = len(items)
		}
		batch, ok := r.fetchLicenseBatch(ctx, items[start:end])
		if ok {
			for key, lic := range batch {
				resolved[key] = lic
			}
			continue
		}
		for _, pv := range items[start:end] {
			if err := r.limiter.Wait(ctx); err != nil {
				resolved[CacheKey(pv)] = ""
				continue
			}
			resolved[CacheKey(pv)] = r.fetchLicense(ctx, pv)
		}
	}

	for _, pv := range items {
		ck := CacheKey(pv)
		if _, isPending := pending[ck]; !isPending {
			r.cache.Store(ck, resolved[ck])
		}
	}
	for key := range pending {
		value := resolved[key]
		via := ""
		if ck, ok := defaultOf[key]; ok {
			value = resolved[ck]
			via = " (default version " + strings.TrimPrefix(ck, strings.TrimSuffix(key, anyVersion)) + ")"
		}
		r.cache.Store(key, value)
		lic, _ := license.SplitCacheValue(value)
		if lic != "" {
			log.Printf("  deps.dev license resolved: %s%s → %s", key, via, lic)
		}
		for _, purl := range purlsByKey[key] {
			out[purl] = lic
		}
	}
	return out
}

type packageResponse struct {
	Versions []struct {
		VersionKey versionKey `json:"versionKey"`
		IsDefault  bool       `json:"isDefault"`
	} `json:"versions"`
}

// defaultVersion returns the version deps.dev marks as the package's default
// (normally the latest release). When there is none, reason says why if
// deps.dev gave a definite answer (license.ReasonNotPublished on 404).
func (r *Resolver) defaultVersion(ctx context.Context, pv PackageVersion) (version, reason string) {
	if err := r.limiter.Wait(ctx); err != nil {
		return "", ""
	}
	u := fmt.Sprintf("%s/%s/systems/%s/packages/%s",
		r.baseURL, getAPIVersion, strings.ToLower(pv.System), url.PathEscape(pv.Name))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "bomhort-license-resolver")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		log.Printf("  deps.dev package request failed for %s: %v", pv.System+":"+pv.Name, err)
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", license.ReasonNotPublished
	}
	if resp.StatusCode != http.StatusOK {
		return "", ""
	}
	var pr packageResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return "", ""
	}
	for _, v := range pr.Versions {
		if v.IsDefault {
			return v.VersionKey.Version, ""
		}
	}
	return "", ""
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

type versionResponse struct {
	Licenses       []string        `json:"licenses"`
	LicenseDetails []licenseDetail `json:"licenseDetails"`
}

// licenseDetail is one declared license: the raw text from the package
// metadata (POM <license><name>, PyPI classifier, …) and deps.dev's SPDX
// mapping of it, which is "non-standard" when deps.dev could not map it.
type licenseDetail struct {
	License string `json:"license"`
	SPDX    string `json:"spdx"`
}

// expression folds the response into one SPDX expression, preferring the
// per-license details over the flat licenses array.
func (v versionResponse) expression() string {
	if len(v.LicenseDetails) > 0 {
		return NormalizeLicenseDetails(v.LicenseDetails)
	}
	return NormalizeLicenses(v.Licenses)
}

type versionKey struct {
	System  string `json:"system"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type batchVersionRequest struct {
	VersionKey versionKey `json:"versionKey"`
}

type batchRequest struct {
	Requests  []batchVersionRequest `json:"requests"`
	PageToken string                `json:"pageToken,omitempty"`
}

type batchResponse struct {
	Responses []struct {
		Request struct {
			VersionKey versionKey `json:"versionKey"`
		} `json:"request"`
		// Version is null when deps.dev does not know the package version.
		Version *versionResponse `json:"version"`
	} `json:"responses"`
	NextPageToken string `json:"nextPageToken"`
}

// cacheValue encodes a version lookup: the license, or the reason there is
// none. deps.dev knowing the version but listing no license means the package
// metadata declares none.
func (v versionResponse) cacheValue() string {
	if lic := v.expression(); lic != "" {
		return lic
	}
	return license.NegativeCacheValue(license.ReasonNoLicenseUpstream)
}

// fetchLicense looks up one version and returns its cache encoding.
func (r *Resolver) fetchLicense(ctx context.Context, pv PackageVersion) string {
	u := fmt.Sprintf("%s/%s/systems/%s/packages/%s/versions/%s",
		r.baseURL, getAPIVersion, strings.ToLower(pv.System), url.PathEscape(pv.Name), url.PathEscape(pv.Version))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "bomhort-license-resolver")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		log.Printf("  deps.dev request failed for %s: %v", CacheKey(pv), err)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return license.NegativeCacheValue(license.ReasonNotPublished)
	}
	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var vr versionResponse
	if err := json.NewDecoder(resp.Body).Decode(&vr); err != nil {
		return ""
	}
	return vr.cacheValue()
}

func (r *Resolver) fetchLicenseBatch(ctx context.Context, versions []PackageVersion) (map[string]string, bool) {
	resolved := make(map[string]string, len(versions))
	for _, pv := range versions {
		resolved[CacheKey(pv)] = ""
	}

	pageToken := ""
	for {
		reqs := make([]batchVersionRequest, 0, len(versions))
		for _, pv := range versions {
			reqs = append(reqs, batchVersionRequest{VersionKey: versionKey{System: pv.System, Name: pv.Name, Version: pv.Version}})
		}
		body, err := json.Marshal(batchRequest{Requests: reqs, PageToken: pageToken})
		if err != nil {
			return nil, false
		}
		if err := r.limiter.Wait(ctx); err != nil {
			return resolved, true
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+"/"+batchAPIVersion+"/versionbatch", bytes.NewReader(body))
		if err != nil {
			return nil, false
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "bomhort-license-resolver")

		resp, err := r.httpClient.Do(req)
		if err != nil {
			log.Printf("  deps.dev batch request failed: %v", err)
			return nil, false
		}
		var br batchResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&br)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || decodeErr != nil {
			return nil, false
		}
		for _, item := range br.Responses {
			pv := PackageVersion{System: item.Request.VersionKey.System, Name: item.Request.VersionKey.Name, Version: item.Request.VersionKey.Version}
			if item.Version == nil {
				resolved[CacheKey(pv)] = license.NegativeCacheValue(license.ReasonNotPublished)
				continue
			}
			resolved[CacheKey(pv)] = item.Version.cacheValue()
		}
		if br.NextPageToken == "" {
			return resolved, true
		}
		pageToken = br.NextPageToken
	}
}

// NormalizeLicenseDetails turns deps.dev's per-license details into one SPDX
// expression. A detail deps.dev mapped is used as is. A "non-standard" one is
// recovered from its raw text: a recognisable spelling ("The MIT License",
// "Eclipse Public License - v 1.0") becomes its SPDX ID, anything else a
// LicenseRef, so the package keeps its declared license and is reported as
// unapproved rather than as NOASSERTION. Details without usable text (empty,
// "non-standard", a URL) are skipped. Several licenses are joined with AND:
// POMs list them without saying whether they are alternatives, and AND is
// the reading that never under-reports an obligation.
func NormalizeLicenseDetails(details []licenseDetail) string {
	parts := make([]string, 0, len(details))
	seen := make(map[string]bool, len(details))
	for _, d := range details {
		lic := cleanLicense(d.SPDX)
		if lic == "" {
			lic = recoverLicense(d.License)
		}
		if lic == "" || seen[lic] {
			continue
		}
		seen[lic] = true
		parts = append(parts, lic)
	}
	if len(parts) > 1 {
		for i, lic := range parts {
			parts[i] = parenthesizeIfCompound(lic)
		}
	}
	return strings.Join(parts, " AND ")
}

// recoverLicense maps the raw license text of a non-standard detail.
func recoverLicense(raw string) string {
	return license.Recover(cleanLicense(raw))
}

// NormalizeLicenses converts deps.dev's licenses array into a single SPDX
// expression. Non-standard and empty values are treated as unresolved.
func NormalizeLicenses(licenses []string) string {
	parts := make([]string, 0, len(licenses))
	for _, lic := range licenses {
		lic = cleanLicense(lic)
		if lic == "" {
			return ""
		}
		parts = append(parts, lic)
	}
	if len(parts) > 1 {
		for i, lic := range parts {
			parts[i] = parenthesizeIfCompound(lic)
		}
	}
	return strings.Join(parts, " AND ")
}

func cleanLicense(lic string) string {
	lic = strings.TrimSpace(lic)
	if lic == "" {
		return ""
	}
	upper := strings.ToUpper(lic)
	if upper == "NON-STANDARD" || upper == "NOASSERTION" || upper == "NONE" {
		return ""
	}
	return lic
}

func parenthesizeIfCompound(lic string) string {
	if !containsOperator(lic) || (strings.HasPrefix(lic, "(") && strings.HasSuffix(lic, ")")) {
		return lic
	}
	return "(" + lic + ")"
}

func containsOperator(lic string) bool {
	for _, field := range strings.FieldsFunc(lic, func(r rune) bool {
		return unicode.IsSpace(r) || r == '(' || r == ')'
	}) {
		switch strings.ToUpper(field) {
		case "AND", "OR", "WITH":
			return true
		}
	}
	return false
}

// ExtractPackageVersion maps supported package URLs to deps.dev version keys.
func ExtractPackageVersion(purl string) (PackageVersion, bool) {
	pv, ok := extractPackage(purl)
	if !ok || pv.Version == "" {
		return PackageVersion{}, false
	}
	return pv, true
}

// extractPackage is ExtractPackageVersion without the version requirement: a
// missing or placeholder version ("unknown", "${project.version}") yields an
// empty Version instead of a failure.
func extractPackage(purl string) (PackageVersion, bool) {
	const prefix = "pkg:"
	if !strings.HasPrefix(purl, prefix) {
		return PackageVersion{}, false
	}
	rest := purl[len(prefix):]
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 || slash == len(rest)-1 {
		return PackageVersion{}, false
	}
	typ := strings.ToLower(rest[:slash])
	packageAndVersion := rest[slash+1:]
	rawName, rawVersion := packageAndVersion, ""
	if at := strings.LastIndex(packageAndVersion, "@"); at > 0 {
		rawName, rawVersion = packageAndVersion[:at], packageAndVersion[at+1:]
	}
	name, ok := decodePath(rawName)
	if !ok || strings.Contains(name, "${") {
		return PackageVersion{}, false
	}
	version, ok := decodePath(rawVersion)
	if !ok {
		return PackageVersion{}, false
	}
	if !validVersion(version) {
		version = ""
	}

	var system string
	switch typ {
	case "maven":
		parts := strings.Split(name, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return PackageVersion{}, false
		}
		name = parts[0] + ":" + parts[1]
		system = "MAVEN"
	case "pypi":
		if strings.Contains(name, "/") {
			return PackageVersion{}, false
		}
		name = normalizePyPIName(name)
		system = "PYPI"
	case "npm":
		if !validNPMName(name) {
			return PackageVersion{}, false
		}
		system = "NPM"
	case "golang":
		if strings.ContainsAny(name, " \\") || name == "" {
			return PackageVersion{}, false
		}
		system = "GO"
	case "cargo":
		if strings.Contains(name, "/") || name == "" {
			return PackageVersion{}, false
		}
		system = "CARGO"
	case "nuget":
		if strings.Contains(name, "/") || name == "" {
			return PackageVersion{}, false
		}
		name = strings.ToLower(name)
		system = "NUGET"
	default:
		return PackageVersion{}, false
	}
	if strings.Contains(name, "..") {
		return PackageVersion{}, false
	}
	return PackageVersion{System: system, Name: strings.TrimSpace(name), Version: strings.TrimSpace(version)}, true
}

func decodePath(s string) (string, bool) {
	decoded, err := url.PathUnescape(s)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(decoded), true
}

func validVersion(version string) bool {
	version = strings.TrimSpace(version)
	if version == "" || strings.EqualFold(version, "unknown") || strings.Contains(version, "${") {
		return false
	}
	return !strings.ContainsAny(version, " \t\r\n,")
}

func validNPMName(name string) bool {
	if name == "" || strings.Contains(name, "..") {
		return false
	}
	if strings.HasPrefix(name, "@") {
		return strings.Count(name, "/") == 1
	}
	return !strings.Contains(name, "/")
}

func normalizePyPIName(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
			continue
		}
		b.WriteRune(r)
		lastDash = false
	}
	return b.String()
}
