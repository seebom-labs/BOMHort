// Package clearlydefined resolves unknown package licenses and detects
// concluded vs. declared license discrepancies using ClearlyDefined definitions (#530).
//
// ClearlyDefined (Linux Foundation) provides crowdsourced, scan-harvested CC0
// component definitions per package coordinate.
package clearlydefined

import (
	"context"
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

	switch strings.ToLower(typ) {
	case "npm":
		// Scoped: @scope/name vs plain: name
		if strings.HasPrefix(namePart, "@") {
			scope, name, ok := strings.Cut(namePart, "/")
			if ok && scope != "" && name != "" {
				return Coordinate{Type: "npm", Provider: "npmjs", Namespace: scope, Name: name, Revision: version}, true
			}
		}
		return Coordinate{Type: "npm", Provider: "npmjs", Namespace: "-", Name: namePart, Revision: version}, true

	case "pypi":
		return Coordinate{Type: "pypi", Provider: "pypi", Namespace: "-", Name: namePart, Revision: version}, true

	case "maven":
		group, artifact, ok := strings.Cut(namePart, "/")
		if ok && group != "" && artifact != "" {
			return Coordinate{Type: "maven", Provider: "mavencentral", Namespace: group, Name: artifact, Revision: version}, true
		}
		return Coordinate{}, false

	case "nuget":
		return Coordinate{Type: "nuget", Provider: "nuget", Namespace: "-", Name: namePart, Revision: version}, true

	case "cargo", "crate", "cratesio":
		return Coordinate{Type: "crate", Provider: "cratesio", Namespace: "-", Name: namePart, Revision: version}, true

	case "gem", "rubygems":
		return Coordinate{Type: "gem", Provider: "rubygems", Namespace: "-", Name: namePart, Revision: version}, true

	case "composer":
		vendor, pkg, ok := strings.Cut(namePart, "/")
		if ok && vendor != "" && pkg != "" {
			return Coordinate{Type: "composer", Provider: "packagist", Namespace: vendor, Name: pkg, Revision: version}, true
		}
		return Coordinate{}, false

	case "golang", "go":
		// pkg:golang/github.com/owner/repo@v1.0.0
		if strings.HasPrefix(namePart, "github.com/") {
			parts := strings.Split(strings.TrimPrefix(namePart, "github.com/"), "/")
			if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
				return Coordinate{Type: "git", Provider: "github", Namespace: parts[0], Name: parts[1], Revision: version}, true
			}
		}
		return Coordinate{}, false

	case "github":
		owner, repo, ok := strings.Cut(namePart, "/")
		if ok && owner != "" && repo != "" {
			return Coordinate{Type: "git", Provider: "github", Namespace: owner, Name: repo, Revision: version}, true
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

// Resolver resolves licenses and discrepancies using ClearlyDefined definitions.
type Resolver struct {
	baseURL    string
	httpClient *http.Client
	license.ResolverCache
	limiter      *ratelimit.TokenBucket
	attributions sync.Map // cacheKey -> []string
	discovered   sync.Map // cacheKey -> string (first discovered expression)
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

// Resolve returns the license expression for the package identified by purl,
// or "" if not found or the request fails.
func (r *Resolver) Resolve(ctx context.Context, purl string) string {
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

// Explain reports why a package stayed unresolved in ClearlyDefined.
func (r *Resolver) Explain(purl string) (handled bool, reason string, latest bool) {
	coord, ok := CoordinateFromPURL(purl)
	if !ok {
		return false, "", false
	}
	key := CacheKey(coord)
	return true, r.Reason(key), false
}

// CheckDiscrepancy compares ClearlyDefined discovered scan expressions with the
// package's declared license. If discovered expressions exist and conflict with
// declaredLicense, returns the discovered expression and true.
func (r *Resolver) CheckDiscrepancy(ctx context.Context, purl, declaredLicense string) (string, bool) {
	declaredLicense = strings.TrimSpace(declaredLicense)
	if declaredLicense == "" || declaredLicense == "NOASSERTION" || declaredLicense == "NONE" {
		return "", false
	}

	coord, ok := CoordinateFromPURL(purl)
	if !ok {
		return "", false
	}

	key := CacheKey(coord)
	// Check if already fetched and cached.
	if discVal, ok := r.discovered.Load(key); ok {
		discovered := discVal.(string)
		if discovered != "" && !licensesAgree(declaredLicense, discovered) {
			return discovered, true
		}
		return "", false
	}

	// Not yet loaded, fetch definition.
	if err := r.limiter.Wait(ctx); err != nil {
		return "", false
	}
	lic, reason := r.fetchDefinition(ctx, coord)
	r.StoreResult(key, lic, reason)

	if discVal, ok := r.discovered.Load(key); ok {
		discovered := discVal.(string)
		if discovered != "" && !licensesAgree(declaredLicense, discovered) {
			return discovered, true
		}
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

// fetchDefinition queries the ClearlyDefined API for a coordinate's definition.
func (r *Resolver) fetchDefinition(ctx context.Context, coord Coordinate) (string, string) {
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

	key := CacheKey(coord)
	parties := def.Licensed.Facets.Core.Attribution.Parties
	if len(parties) > 0 {
		r.attributions.Store(key, parties)
	}

	// Capture discovered expressions.
	var discoveredExprs []string
	discoveredExprs = append(discoveredExprs, def.Licensed.Facets.Core.Discovered.Expressions...)
	discoveredExprs = append(discoveredExprs, def.Licensed.Discovered.Expressions...)
	if len(discoveredExprs) > 0 {
		firstDisc := strings.TrimSpace(discoveredExprs[0])
		if norm := license.Normalize(firstDisc); norm != "" {
			firstDisc = norm
		}
		r.discovered.Store(key, firstDisc)
	}

	// Return declared license if available, otherwise discovered expression.
	declared := strings.TrimSpace(def.Licensed.Declared)
	if declared != "" && declared != "OTHER" && declared != "NOASSERTION" {
		if norm := license.Normalize(declared); norm != "" {
			return norm, ""
		}
		return declared, ""
	}

	if len(discoveredExprs) > 0 {
		firstDisc := strings.TrimSpace(discoveredExprs[0])
		if norm := license.Normalize(firstDisc); norm != "" {
			return norm, ""
		}
		return firstDisc, ""
	}

	return "", license.ReasonNoLicenseUpstream
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

type noticeRequest struct {
	Coordinates []string `json:"coordinates"`
}

type noticeResponse struct {
	Content string `json:"content"`
}

// FetchNotice calls ClearlyDefined's POST /notices endpoint to generate a notice file
// for the given canonical coordinates (#530).
func (r *Resolver) FetchNotice(ctx context.Context, coordinates []string) (string, error) {
	if len(coordinates) == 0 {
		return "", fmt.Errorf("no coordinates provided")
	}
	u := fmt.Sprintf("%s/notices", r.baseURL)
	body, err := json.Marshal(noticeRequest{Coordinates: coordinates})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "bomhort-clearlydefined-resolver")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("clearlydefined notices returned status %d", resp.StatusCode)
	}

	var res noticeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&res); err != nil {
		return "", err
	}
	if strings.TrimSpace(res.Content) == "" {
		return "", fmt.Errorf("empty notice content returned")
	}
	return res.Content, nil
}

// GenerateNoticeWithFallback attempts to fetch the notice from ClearlyDefined's
// notice endpoint for packages with valid coordinates, falling back to local
// generation using embedded SPDX license texts and attribution parties (#530).
func (r *Resolver) GenerateNoticeWithFallback(ctx context.Context, targetName string, pkgs []NoticePackage) string {
	if r != nil && r.baseURL != "" {
		var coords []string
		for _, p := range pkgs {
			if coord, ok := CoordinateFromPURL(p.PURL); ok {
				coords = append(coords, coord.String())
			}
		}
		if len(coords) > 0 && len(coords) <= 100 {
			fetchCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
			defer cancel()
			if content, err := r.FetchNotice(fetchCtx, coords); err == nil && strings.TrimSpace(content) != "" {
				return content
			}
		}
	}
	return GenerateNotice(targetName, pkgs)
}
