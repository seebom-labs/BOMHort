// Package pypi resolves unknown Python package licenses via the PyPI JSON API.
//
// deps.dev covers PyPI but only maps licenses it can match to SPDX; packages
// that declare their license as free text ("PSF license", "BSD") or only as a
// trove classifier come back empty there. This resolver runs after deps.dev
// and reads the package metadata directly:
//
//	https://pypi.org/pypi/{name}/{version}/json   a release
//	https://pypi.org/pypi/{name}/json             the latest release
package pypi

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/ratelimit"
)

const (
	// DefaultBaseURL is the public PyPI JSON API.
	DefaultBaseURL = "https://pypi.org/pypi"

	defaultRate  = 5.0
	defaultBurst = 10

	// maxLicenseText bounds the "license" field: older packages paste the
	// whole license text there, which is not a name to normalise.
	maxLicenseText = 100
)

// Resolver resolves PyPI package licenses.
type Resolver struct {
	baseURL    string
	httpClient *http.Client
	limiter    *ratelimit.TokenBucket
	cache      sync.Map // "name@version" / "name@*" → license or negative marker
}

// NewResolver creates a resolver against pypi.org.
func NewResolver() *Resolver { return NewResolverWithBaseURL(DefaultBaseURL) }

// NewResolverWithBaseURL creates a resolver against a custom index (or an
// httptest server).
func NewResolverWithBaseURL(baseURL string) *Resolver {
	return &Resolver{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 15 * time.Second},
		limiter:    ratelimit.NewTokenBucket(defaultRate, defaultBurst),
	}
}

var nameSeparators = regexp.MustCompile(`[-_.]+`)

// ExtractPyPIPackage parses "pkg:pypi/name@version" and normalises the name
// as PEP 503 does. A missing or placeholder version ("unknown") yields "",
// meaning the latest release.
func ExtractPyPIPackage(purl string) (name, version string, ok bool) {
	const prefix = "pkg:pypi/"
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
	name = nameSeparators.ReplaceAllString(strings.ToLower(strings.TrimSpace(rest)), "-")
	if name == "" || strings.ContainsAny(name, "/\\ ") {
		return "", "", false
	}
	version = strings.TrimSpace(version)
	switch strings.ToLower(version) {
	case "unknown", "noassertion", "none", "*", "latest":
		version = ""
	}
	if strings.ContainsAny(version, "/\\ ") || strings.Contains(version, "${") {
		return "", "", false
	}
	return name, version, true
}

func cacheKey(name, version string) string {
	if version == "" {
		return name + "@*"
	}
	return name + "@" + version
}

// Resolve returns the license expression of a PyPI package, or "". A purl
// without a version resolves via the latest release. A release PyPI does not
// list is not looked up under another version: PyPI names are global, so a
// private package may share its name with an unrelated public one.
func (r *Resolver) Resolve(ctx context.Context, purl string) string {
	name, version, ok := ExtractPyPIPackage(purl)
	if !ok {
		return ""
	}
	key := cacheKey(name, version)
	if cached, found := r.cache.Load(key); found {
		lic, _ := license.SplitCacheValue(cached.(string))
		return lic
	}
	if err := r.limiter.Wait(ctx); err != nil {
		return ""
	}
	value := r.fetch(ctx, name, version)
	r.cache.Store(key, value)
	lic, _ := license.SplitCacheValue(value)
	if lic != "" {
		log.Printf("  PyPI license resolved: %s → %s", key, lic)
	}
	return lic
}

// Explain reports why a PyPI purl stayed unresolved and whether its license is
// the latest release's. handled is false for other ecosystems.
func (r *Resolver) Explain(purl string) (handled bool, reason string, latest bool) {
	name, version, ok := ExtractPyPIPackage(purl)
	if !ok {
		return false, "", false
	}
	if cached, found := r.cache.Load(cacheKey(name, version)); found {
		_, reason = license.SplitCacheValue(cached.(string))
	}
	return true, reason, version == ""
}

type projectInfo struct {
	Info struct {
		LicenseExpression string   `json:"license_expression"`
		License           string   `json:"license"`
		Classifiers       []string `json:"classifiers"`
	} `json:"info"`
}

func (r *Resolver) fetch(ctx context.Context, name, version string) string {
	u := fmt.Sprintf("%s/%s/json", r.baseURL, url.PathEscape(name))
	if version != "" {
		u = fmt.Sprintf("%s/%s/%s/json", r.baseURL, url.PathEscape(name), url.PathEscape(version))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "bomhort-license-resolver")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		log.Printf("  PyPI request failed for %s: %v", cacheKey(name, version), err)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return license.NegativeCacheValue(license.ReasonNotPublished)
	}
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var p projectInfo
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return ""
	}
	if lic := Expression(p.Info.LicenseExpression, p.Info.License, p.Info.Classifiers); lic != "" {
		return lic
	}
	return license.NegativeCacheValue(license.ReasonNoLicenseUpstream)
}

// classifierSPDX maps the license trove classifiers that name exactly one
// license version onto SPDX IDs. Classifiers without a version ("BSD
// License", "Apache Software License", "GNU General Public License (GPL)",
// "Zope Public License", "Artistic License") are deliberately absent: they
// fit several SPDX IDs with different obligations, and guessing would turn an
// unapproved license into an approved one without anyone having decided so.
var classifierSPDX = map[string]string{
	"MIT License":                                             "MIT",
	"MIT No Attribution License (MIT-0)":                      "MIT-0",
	"ISC License (ISCL)":                                      "ISC",
	"Python Software Foundation License":                      "PSF-2.0",
	"Mozilla Public License 1.0 (MPL)":                        "MPL-1.0",
	"Mozilla Public License 1.1 (MPL 1.1)":                    "MPL-1.1",
	"Mozilla Public License 2.0 (MPL 2.0)":                    "MPL-2.0",
	"GNU General Public License v2 (GPLv2)":                   "GPL-2.0-only",
	"GNU General Public License v2 or later (GPLv2+)":         "GPL-2.0-or-later",
	"GNU General Public License v3 (GPLv3)":                   "GPL-3.0-only",
	"GNU General Public License v3 or later (GPLv3+)":         "GPL-3.0-or-later",
	"GNU Lesser General Public License v2 (LGPLv2)":           "LGPL-2.0-only",
	"GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
	"GNU Lesser General Public License v3 (LGPLv3)":           "LGPL-3.0-only",
	"GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
	"GNU Affero General Public License v3":                    "AGPL-3.0-only",
	"GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
	"Eclipse Public License 1.0 (EPL-1.0)":                    "EPL-1.0",
	"Eclipse Public License 2.0 (EPL-2.0)":                    "EPL-2.0",
	"Boost Software License 1.0 (BSL-1.0)":                    "BSL-1.0",
	"The Unlicense (Unlicense)":                               "Unlicense",
	"Universal Permissive License (UPL)":                      "UPL-1.0",
	"European Union Public Licence 1.1 (EUPL 1.1)":            "EUPL-1.1",
	"European Union Public Licence 1.2 (EUPL 1.2)":            "EUPL-1.2",
	"CC0 1.0 Universal (CC0 1.0) Public Domain Dedication":    "CC0-1.0",
	"Historical Permission Notice and Disclaimer (HPND)":      "HPND",
	"zlib/libpng License":                                     "Zlib",
	"PostgreSQL License":                                      "PostgreSQL",
	"Python License (CNRI Python License)":                    "CNRI-Python",
	"Microsoft Public License":                                "MS-PL",
	"Apache Software License 2.0 (Apache-2.0)":                "Apache-2.0",
	"Other/Proprietary License":                               "LicenseRef-proprietary",
}

// Expression picks the license from PyPI metadata, most authoritative first:
//
//  1. license_expression (PEP 639, already SPDX)
//  2. "License ::" trove classifiers listed in classifierSPDX, joined with
//     AND (PyPI does not say whether several are alternatives; AND is the
//     conservative reading, as for deps.dev)
//  3. the free-text "license" field, normalised, when it is a short name
//     rather than pasted license text
//  4. the first other license classifier as a LicenseRef, so a declared but
//     unmappable license is reported as unapproved, not NOASSERTION
//
// Classifiers that name no license ("License :: OSI Approved") are ignored.
func Expression(licenseExpression, licenseField string, classifiers []string) string {
	if lic := license.Recover(licenseExpression); lic != "" {
		return lic
	}
	var mapped []string
	firstRef := ""
	seen := map[string]bool{}
	for _, c := range classifiers {
		name, ok := classifierLicense(c)
		if !ok {
			continue
		}
		lic, known := classifierSPDX[name]
		if !known {
			if firstRef == "" {
				firstRef = license.LicenseRef(name)
			}
			continue
		}
		if !seen[lic] {
			seen[lic] = true
			mapped = append(mapped, lic)
		}
	}
	if len(mapped) > 0 {
		return strings.Join(mapped, " AND ")
	}
	if t := strings.TrimSpace(licenseField); t != "" && len(t) <= maxLicenseText && !strings.Contains(t, "\n") {
		if lic := license.Recover(t); lic != "" {
			return lic
		}
	}
	return firstRef
}

// classifierLicense extracts the license name from a trove classifier:
// "License :: OSI Approved :: MIT License" → "MIT License". Classifiers that
// stop at a category ("License :: OSI Approved") name no license.
func classifierLicense(c string) (string, bool) {
	parts := strings.Split(c, "::")
	if len(parts) < 2 || strings.TrimSpace(parts[0]) != "License" {
		return "", false
	}
	switch last := strings.TrimSpace(parts[len(parts)-1]); last {
	case "", "OSI Approved", "DFSG approved", "Freely Distributable", "Freeware":
		return "", false
	default:
		return last, true
	}
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
