package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/seebom-labs/bomhort/backend/internal/license"
)

// githubLookup returns the license GitHub reports for a purl's repository, or
// "". nil disables the GitHub step. A non-nil error means GitHub could not be
// asked at all (rate limit); resolution then aborts rather than letting a
// later step answer a question GitHub was never able to see.
type githubLookup func(ctx context.Context, purl string) (string, error)

// resolvePackageLicenses runs the license resolution steps of the parsing
// pipeline on one SBOM's parallel package arrays, in place, and returns the
// per-package license source (sbom_packages.package_license_sources):
//
//  2. GitHub repository license for packages without one
//     2b. package registries (npm, NuGet, deps.dev, Packagist, PyPI), in order
//     2c. free-text spellings normalised to SPDX ("MPL 2.0" → "MPL-2.0")
//     2d. every package still without a license gets the reason why
//
// Every heuristic involved is documented on the "License Resolution" docs
// page; golden_test.go pins the end-to-end outcome.
//
// The GitHub step is all-or-nothing: if the lookup reports an error the
// function returns it and the caller must not insert anything — licenses may
// already be partially rewritten. Resolution runs before every ClickHouse
// insert, so aborting here leaves no trace of the SBOM.
func resolvePackageLicenses(ctx context.Context, github githubLookup, resolvers []registryResolver, purls, licenses []string, roots []uint32) (sources []string, counts map[string]int, err error) {
	sources = make([]string, len(licenses))
	for i, lic := range licenses {
		if !isUnknownLicense(lic) {
			sources[i] = license.SourceDeclared
		}
	}

	counts = map[string]int{}
	if github != nil {
		for i, lic := range licenses {
			if !isUnknownLicense(lic) || i >= len(purls) || purls[i] == "" {
				continue
			}
			spdx, err := github(ctx, purls[i])
			if err != nil {
				return nil, nil, fmt.Errorf("github lookup for %s: %w", purls[i], err)
			}
			if spdx != "" {
				licenses[i] = spdx
				sources[i] = license.SourceGitHub
				counts[license.SourceGitHub]++
			}
		}
	}

	for name, n := range applyRegistryResolvers(ctx, resolvers, purls, licenses, sources) {
		counts[name] += n
	}

	for i, lic := range licenses {
		if norm := license.Normalize(lic); norm != lic {
			licenses[i] = norm
			sources[i] = license.WithModifier(sources[i], license.ModifierNormalized)
		}
	}

	explainUnresolved(resolvers, purls, licenses, sources, roots)
	return sources, counts, nil
}

// coveredPURLTypes are the ecosystems at least one resolver looks up. A
// package of any other type ("generic", "deb", "apk", "oci", …) has nowhere
// to be looked up.
var coveredPURLTypes = map[string]bool{
	"npm": true, "nuget": true, "maven": true, "pypi": true, "cargo": true,
	"golang": true, "github": true, "composer": true,
}

// explainUnresolved records, for every package whose license is still
// unknown, why: first-party code, no purl, an ecosystem no resolver covers,
// or what the last resolver that covers it found out (not published, no
// license declared upstream). Anything else is "unresolved".
func explainUnresolved(resolvers []registryResolver, purls, licenses, sources []string, roots []uint32) {
	firstParty := make(map[int]bool, len(roots))
	for _, r := range roots {
		firstParty[int(r)] = true
	}
	for i, lic := range licenses {
		if !isUnknownLicense(lic) {
			continue
		}
		purl := ""
		if i < len(purls) {
			purl = purls[i]
		}
		sources[i] = unresolvedReason(resolvers, purl, firstParty[i])
	}
}

func unresolvedReason(resolvers []registryResolver, purl string, isRoot bool) string {
	if isRoot || isFirstPartyPURL(purl) {
		return license.ReasonFirstParty
	}
	if purl == "" {
		return license.ReasonNoPURL
	}
	if !coveredPURLTypes[purlType(purl)] {
		return license.ReasonUnsupported
	}
	reason := ""
	for _, rr := range resolvers {
		ex, ok := rr.resolver.(explainer)
		if !ok {
			continue
		}
		if handled, r, _ := ex.Explain(purl); handled && r != "" {
			reason = r // later resolvers are more specific to the ecosystem
		}
	}
	if reason == "" {
		return license.ReasonUnresolved
	}
	return reason
}

func purlType(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	typ, _, _ := strings.Cut(rest, "/")
	return strings.ToLower(typ)
}
