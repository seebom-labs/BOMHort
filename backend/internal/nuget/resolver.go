// Package nuget resolves unknown package licenses via the NuGet V3 API.
//
// Resolution strategy for pkg:nuget/{id}@{version}:
//  1. Registration leaf  GET {registration}/{id-lowercase}/{version}.json → catalogEntry URL
//  2. Catalog entry      GET {catalogEntry}                              → licenseExpression
//  3. Fallbacks for legacy packages without licenseExpression:
//     a) licenseUrl that is a well-known OSI license URL       → mapped SPDX ID
//     b) licenseUrl or projectUrl pointing at a GitHub repo    → delegated to the
//     GitHub license resolver (repository license)
//
// Packages whose license is only shipped as a file inside the .nupkg
// (licenseUrl = https://aka.ms/deprecateLicenseUrl) and proprietary EULAs
// cannot be resolved and yield "".
package nuget

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/ratelimit"
)

const (
	// DefaultRegistrationBase is the public nuget.org registration hive.
	DefaultRegistrationBase = "https://api.nuget.org/v3/registration5-semver1"

	defaultRate  = 5.0
	defaultBurst = 10

	// maxResponseSize bounds a registration or catalog response (same cap as
	// rulesource.MaxSize). A larger body is cut off and fails to decode, so a
	// broken or hostile hive cannot make the worker allocate without limit.
	maxResponseSize = 10 << 20
)

// RepoResolver resolves a license from a source repository purl (pkg:github/owner/repo).
// Satisfied by *github.Resolver.
type RepoResolver interface {
	Resolve(ctx context.Context, purl string) string
}

// wellKnownLicenseURLs maps canonical license URLs (lower-cased, scheme and
// trailing slash stripped) to SPDX IDs.
var wellKnownLicenseURLs = map[string]string{
	"opensource.org/licenses/mit":                      "MIT",
	"opensource.org/licenses/mit-license.php":          "MIT",
	"opensource.org/licenses/apache-2.0":               "Apache-2.0",
	"apache.org/licenses/license-2.0":                  "Apache-2.0",
	"apache.org/licenses/license-2.0.html":             "Apache-2.0",
	"apache.org/licenses/license-2.0.txt":              "Apache-2.0",
	"opensource.org/licenses/bsd-2-clause":             "BSD-2-Clause",
	"opensource.org/licenses/bsd-3-clause":             "BSD-3-Clause",
	"opensource.org/licenses/isc":                      "ISC",
	"opensource.org/licenses/mpl-2.0":                  "MPL-2.0",
	"mozilla.org/mpl/2.0":                              "MPL-2.0",
	"opensource.org/licenses/lgpl-2.1":                 "LGPL-2.1-only",
	"opensource.org/licenses/lgpl-3.0":                 "LGPL-3.0-only",
	"gnu.org/licenses/lgpl-2.1.html":                   "LGPL-2.1-only",
	"gnu.org/licenses/lgpl-3.0.html":                   "LGPL-3.0-only",
	"gnu.org/licenses/gpl-2.0.html":                    "GPL-2.0-only",
	"gnu.org/licenses/gpl-3.0.html":                    "GPL-3.0-only",
	"opensource.org/licenses/gpl-2.0":                  "GPL-2.0-only",
	"opensource.org/licenses/gpl-3.0":                  "GPL-3.0-only",
	"unlicense.org":                                    "Unlicense",
	"creativecommons.org/publicdomain/zero/1.0":        "CC0-1.0",
	"licenses.nuget.org/mit":                           "MIT",
	"licenses.nuget.org/apache-2.0":                    "Apache-2.0",
	"licenses.nuget.org/bsd-3-clause":                  "BSD-3-Clause",
	"licenses.nuget.org/bsd-2-clause":                  "BSD-2-Clause",
	"go.microsoft.com/fwlink/?linkid=2028464":          "MIT", // dotnet repos MIT license shortlink
	"github.com/dotnet/corefx/blob/master/license.txt": "MIT",
}

// githubURLRe extracts owner/repo from github.com or raw.githubusercontent.com URLs.
var githubURLRe = regexp.MustCompile(`(?i)^(?:https?://)?(?:www\.)?(?:raw\.)?github(?:usercontent)?\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)`)

// Resolver resolves NuGet package licenses.
type Resolver struct {
	registrationBase string
	httpClient       *http.Client
	license.ResolverCache
	limiter      *ratelimit.TokenBucket
	repoResolver RepoResolver // optional
}

// NewResolver creates a resolver against nuget.org. repoResolver may be nil.
func NewResolver(repoResolver RepoResolver) *Resolver {
	return NewResolverWithBase(DefaultRegistrationBase, repoResolver)
}

// NewResolverWithBase creates a resolver against a custom registration base URL.
func NewResolverWithBase(registrationBase string, repoResolver RepoResolver) *Resolver {
	return &Resolver{
		registrationBase: strings.TrimRight(registrationBase, "/"),
		httpClient:       &http.Client{Timeout: 15 * time.Second},
		limiter:          ratelimit.NewTokenBucket(defaultRate, defaultBurst),
		repoResolver:     repoResolver,
	}
}

// CacheKey returns the cache key for a NuGet package ("id@version", id lower-cased).
func CacheKey(id, version string) string {
	id = strings.ToLower(id)
	if version == "" {
		return id
	}
	return id + "@" + strings.ToLower(version)
}

// Resolve returns the SPDX license expression for a pkg:nuget purl, or "".
func (r *Resolver) Resolve(ctx context.Context, purl string) string {
	id, version, ok := ExtractNuGetPackage(purl)
	if !ok || version == "" {
		// The registration leaf requires an exact version.
		return ""
	}

	key := CacheKey(id, version)
	if lic, _, found := r.Load(key); found {
		return lic
	}

	if err := r.limiter.Wait(ctx); err != nil {
		return ""
	}

	lic, reason := r.fetchLicense(ctx, id, version)
	r.StoreResult(key, lic, reason)

	if lic != "" {
		log.Printf("  NuGet license resolved: %s → %s", key, lic)
	}
	return lic
}

type registrationLeaf struct {
	CatalogEntry json.RawMessage `json:"catalogEntry"`
}

// CatalogEntry is the subset of the NuGet catalog entry we use.
type CatalogEntry struct {
	ID                string `json:"id"`
	Version           string `json:"version"`
	LicenseExpression string `json:"licenseExpression"`
	LicenseURL        string `json:"licenseUrl"`
	ProjectURL        string `json:"projectUrl"`
}

// fetchLicense returns the license and, when there is none, the reason if
// nuget.org gave a definite answer: 404 (not published) or a catalog entry
// that declares no license at all. Transport errors, unmapped license URLs and
// an unanswered repository lookup leave the reason empty so they are retried.
func (r *Resolver) fetchLicense(ctx context.Context, id, version string) (string, string) {
	leafURL := fmt.Sprintf("%s/%s/%s.json", r.registrationBase,
		url.PathEscape(strings.ToLower(id)), url.PathEscape(strings.ToLower(version)))

	var leaf registrationLeaf
	switch err := r.getJSON(ctx, leafURL, &leaf); {
	case errors.Is(err, errNotFound):
		return "", license.ReasonNotPublished
	case err != nil:
		return "", ""
	}

	// catalogEntry is normally a URL string; some hives inline the object.
	var entry CatalogEntry
	raw := strings.TrimSpace(string(leaf.CatalogEntry))
	switch {
	case strings.HasPrefix(raw, `"`):
		var catalogURL string
		if err := json.Unmarshal(leaf.CatalogEntry, &catalogURL); err != nil || catalogURL == "" {
			return "", ""
		}
		if !strings.HasPrefix(catalogURL, "https://") && !strings.HasPrefix(catalogURL, "http://") {
			return "", ""
		}
		if err := r.limiter.Wait(ctx); err != nil {
			return "", ""
		}
		if err := r.getJSON(ctx, catalogURL, &entry); err != nil {
			return "", ""
		}
	case strings.HasPrefix(raw, `{`):
		if err := json.Unmarshal(leaf.CatalogEntry, &entry); err != nil {
			return "", ""
		}
	default:
		return "", ""
	}

	if lic := r.licenseFromEntry(ctx, &entry); lic != "" {
		return lic, ""
	}
	if strings.TrimSpace(entry.LicenseURL) == "" && strings.TrimSpace(entry.ProjectURL) == "" {
		return "", license.ReasonNoLicenseUpstream
	}
	return "", ""
}

// licenseFromEntry applies the resolution strategy documented at the top of the file.
func (r *Resolver) licenseFromEntry(ctx context.Context, e *CatalogEntry) string {
	if expr := strings.TrimSpace(e.LicenseExpression); expr != "" {
		return expr
	}
	if spdx := LicenseFromURL(e.LicenseURL); spdx != "" {
		return spdx
	}
	if r.repoResolver != nil {
		for _, u := range []string{e.LicenseURL, e.ProjectURL} {
			if owner, repo, ok := GitHubRepoFromURL(u); ok {
				if spdx := r.repoResolver.Resolve(ctx, "pkg:github/"+owner+"/"+repo); spdx != "" {
					return spdx
				}
			}
		}
	}
	return ""
}

var errNotFound = errors.New("not found")

func (r *Resolver) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "bomhort-license-resolver")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		log.Printf("  NuGet request failed for %s: %v", u, err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(out)
}

// LicenseFromURL maps a well-known license URL to an SPDX ID, or "".
func LicenseFromURL(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "www.")
	raw = strings.TrimRight(raw, "/")
	return wellKnownLicenseURLs[raw]
}

// GitHubRepoFromURL extracts owner/repo from a github.com or
// raw.githubusercontent.com URL.
func GitHubRepoFromURL(raw string) (owner, repo string, ok bool) {
	m := githubURLRe.FindStringSubmatch(strings.TrimSpace(raw))
	if m == nil {
		return "", "", false
	}
	owner, repo = m[1], strings.TrimSuffix(m[2], ".git")
	if owner == "" || repo == "" {
		return "", "", false
	}
	return owner, repo, true
}

// ExtractNuGetPackage parses a NuGet purl into package id and version.
//
//	pkg:nuget/Google.Protobuf@3.15.0 → "Google.Protobuf", "3.15.0"
//	pkg:nuget/Moq                    → "Moq", ""
func ExtractNuGetPackage(purl string) (id, version string, ok bool) {
	const prefix = "pkg:nuget/"
	if !strings.HasPrefix(purl, prefix) {
		return "", "", false
	}
	rest := purl[len(prefix):]
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i > 0 {
		id, version = rest[:i], rest[i+1:]
	} else {
		id = rest
	}
	if decoded, err := url.PathUnescape(id); err == nil {
		id = decoded
	}
	if decoded, err := url.PathUnescape(version); err == nil {
		version = decoded
	}
	id = strings.TrimSpace(id)
	if id == "" || strings.ContainsAny(id, "/\\ ") || strings.Contains(id, "..") {
		return "", "", false
	}
	return id, strings.TrimSpace(version), true
}
