// Package github extracts GitHub owner/repo from Package URLs (PURLs).
package github

import (
	"sort"
	"strings"
)

// wellKnownGoModules maps non-github.com Go module prefixes to their GitHub owner/repo.
// This covers popular Go packages that are hosted on GitHub but use custom import paths.
var wellKnownGoModules = map[string][2]string{
	// Go standard library (emitted as pkg:golang/stdlib by syft, waybill, etc.)
	// is licensed together with the Go distribution.
	"stdlib": {"golang", "go"},
	// golang.org/x/* → github.com/golang/*
	"golang.org/x/crypto":  {"golang", "crypto"},
	"golang.org/x/net":     {"golang", "net"},
	"golang.org/x/sys":     {"golang", "sys"},
	"golang.org/x/text":    {"golang", "text"},
	"golang.org/x/sync":    {"golang", "sync"},
	"golang.org/x/tools":   {"golang", "tools"},
	"golang.org/x/mod":     {"golang", "mod"},
	"golang.org/x/oauth2":  {"golang", "oauth2"},
	"golang.org/x/term":    {"golang", "term"},
	"golang.org/x/time":    {"golang", "time"},
	"golang.org/x/exp":     {"golang", "exp"},
	"golang.org/x/image":   {"golang", "image"},
	"golang.org/x/xerrors": {"golang", "xerrors"},
	"golang.org/x/vuln":    {"golang", "vuln"},

	// gopkg.in/* and go.yaml.in/* → various GitHub repos
	"gopkg.in/yaml.v2":                 {"go-yaml", "yaml"},
	"gopkg.in/yaml.v3":                 {"go-yaml", "yaml"},
	"go.yaml.in/yaml":                  {"go-yaml", "yaml"},
	"gopkg.in/inf.v0":                  {"go-inf", "inf"},
	"gopkg.in/check.v1":                {"go-check", "check"},
	"gopkg.in/natefinch/lumberjack.v2": {"natefinch", "lumberjack"},
	"gopkg.in/tomb.v1":                 {"go-tomb", "tomb"},
	"gopkg.in/square/go-jose.v2":       {"square", "go-jose"},

	// Other well-known Go modules
	"google.golang.org/grpc":            {"grpc", "grpc-go"},
	"google.golang.org/protobuf":        {"protocolbuffers", "protobuf-go"},
	"google.golang.org/genproto":        {"googleapis", "go-genproto"},
	"google.golang.org/api":             {"googleapis", "google-api-go-client"},
	"go.uber.org/zap":                   {"uber-go", "zap"},
	"go.uber.org/atomic":                {"uber-go", "atomic"},
	"go.uber.org/multierr":              {"uber-go", "multierr"},
	"go.uber.org/goleak":                {"uber-go", "goleak"},
	"go.etcd.io/etcd":                   {"etcd-io", "etcd"},
	"go.etcd.io/bbolt":                  {"etcd-io", "bbolt"},
	"go.opentelemetry.io/otel":          {"open-telemetry", "opentelemetry-go"},
	"k8s.io/api":                        {"kubernetes", "api"},
	"k8s.io/apimachinery":               {"kubernetes", "apimachinery"},
	"k8s.io/client-go":                  {"kubernetes", "client-go"},
	"k8s.io/klog":                       {"kubernetes", "klog"},
	"k8s.io/utils":                      {"kubernetes", "utils"},
	"sigs.k8s.io/yaml":                  {"kubernetes-sigs", "yaml"},
	"sigs.k8s.io/controller-runtime":    {"kubernetes-sigs", "controller-runtime"},
	"sigs.k8s.io/structured-merge-diff": {"kubernetes-sigs", "structured-merge-diff"},
	"oras.land/oras-go":                 {"oras-project", "oras-go"},
	"dario.cat/mergo":                   {"darccio", "mergo"},
}

// ExtractGitHubRepo extracts the GitHub owner and repo name from a PURL.
// Supports:
//   - pkg:golang/github.com/{owner}/{repo}[/subpath][@version]
//   - pkg:github/{owner}/{repo}[@version]
//   - Well-known Go modules (golang.org/x/*, gopkg.in/*, etc.) via static mapping
//
// Returns empty strings and false if the PURL is not a recognizable GitHub package.
func ExtractGitHubRepo(purl string) (owner, repo string, ok bool) {
	if purl == "" {
		return "", "", false
	}

	// Strip version qualifier.
	if idx := strings.Index(purl, "@"); idx > 0 {
		purl = purl[:idx]
	}

	// Strip qualifiers (?...) and subpath (#...).
	if idx := strings.Index(purl, "?"); idx > 0 {
		purl = purl[:idx]
	}
	if idx := strings.Index(purl, "#"); idx > 0 {
		purl = purl[:idx]
	}

	// pkg:golang/github.com/{owner}/{repo}[/subpath...]
	if strings.HasPrefix(purl, "pkg:golang/github.com/") {
		rest := strings.TrimPrefix(purl, "pkg:golang/github.com/")
		return splitOwnerRepo(rest)
	}

	// pkg:github/{owner}/{repo}
	if strings.HasPrefix(purl, "pkg:github/") {
		rest := strings.TrimPrefix(purl, "pkg:github/")
		return splitOwnerRepo(rest)
	}

	// Well-known Go module mappings (golang.org/x/*, gopkg.in/*, etc.)
	if strings.HasPrefix(purl, "pkg:golang/") {
		modulePath := strings.TrimPrefix(purl, "pkg:golang/")
		// Try exact match first, then try progressively shorter prefixes
		// to handle versioned paths like "gopkg.in/yaml.v3" or subpackages.
		for prefix, ownerRepo := range wellKnownGoModules {
			if modulePath == prefix || strings.HasPrefix(modulePath, prefix+"/") {
				return ownerRepo[0], ownerRepo[1], true
			}
		}
		// Try matching by stripping /vN version suffixes (e.g. "oras.land/oras-go/v2" → "oras.land/oras-go")
		stripped := stripGoVersionSuffix(modulePath)
		if stripped != modulePath {
			for prefix, ownerRepo := range wellKnownGoModules {
				if stripped == prefix || strings.HasPrefix(stripped, prefix+"/") {
					return ownerRepo[0], ownerRepo[1], true
				}
			}
		}
	}

	return "", "", false
}

// stripGoVersionSuffix removes Go major version suffixes like "/v2", "/v3" from a module path.
func stripGoVersionSuffix(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) >= 2 {
		last := parts[len(parts)-1]
		if len(last) >= 2 && last[0] == 'v' && last[1] >= '0' && last[1] <= '9' {
			return strings.Join(parts[:len(parts)-1], "/")
		}
	}
	return path
}

// splitOwnerRepo splits "owner/repo[/subpath...]" into owner and repo.
func splitOwnerRepo(s string) (string, string, bool) {
	parts := strings.SplitN(s, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// RepoKey returns the lowercase "owner/repo" key for cache lookups.
func RepoKey(owner, repo string) string {
	return strings.ToLower(owner + "/" + repo)
}

// WellKnownModuleMappings returns the wellKnownGoModules table as two parallel
// slices — module path prefix and the "owner/repo" key it maps to — sorted
// longest prefix first.
//
// It exists so the query layer can reproduce ExtractGitHubRepo's mapping in
// SQL. Going the other way (matching a purl against a repo name with LIKE)
// cannot work: gopkg.in/yaml.v3 belongs to go-yaml/yaml and shares not a
// single character with it, so a substring match silently drops every package
// whose import path differs from its repository — which is precisely what the
// well-known table exists to translate.
//
// The longest-first order makes the lookup deterministic. Go map iteration is
// randomised, so with overlapping prefixes ExtractGitHubRepo could otherwise
// return a different repo from one call to the next.
func WellKnownModuleMappings() (prefixes, repoKeys []string) {
	prefixes = make([]string, 0, len(wellKnownGoModules))
	for prefix := range wellKnownGoModules {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if len(prefixes[i]) != len(prefixes[j]) {
			return len(prefixes[i]) > len(prefixes[j])
		}
		return prefixes[i] < prefixes[j]
	})

	repoKeys = make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		ownerRepo := wellKnownGoModules[prefix]
		repoKeys = append(repoKeys, RepoKey(ownerRepo[0], ownerRepo[1]))
	}
	return prefixes, repoKeys
}

