package license

import "strings"

// License provenance (sbom_packages.package_license_sources).
//
// Every package carries one source string next to its license. A resolved
// license names where it came from, optionally followed by "+"-joined
// modifiers:
//
//	declared              the SBOM itself stated the license
//	github                GitHub repository license API
//	npm / nuget / depsdev / packagist / pypi
//	                      the package registry of that name
//	…+latest              the registry knew no license for the exact version
//	                      (or the SBOM had none) and the newest release's
//	                      license was used instead
//	…+normalized          free text ("Apache License 2.0") was rewritten to an
//	                      SPDX expression
//
// A package whose license is still unknown carries the reason instead, so the
// UI can tell an actionable gap from one where looking further makes no sense.
const (
	SourceDeclared = "declared"
	SourceGitHub   = "github"

	ModifierLatest     = "latest"
	ModifierNormalized = "normalized"

	// ReasonFirstParty: the project's own module (SBOM root, Yarn workspace,
	// Maven ${project.*} placeholder). Excluded from license compliance.
	ReasonFirstParty = "first-party"
	// ReasonNotPublished: the registry does not know the package (private,
	// unpublished or deleted).
	ReasonNotPublished = "not-published"
	// ReasonNoLicenseUpstream: the registry knows the package, but its
	// author declared no license. Legally "all rights reserved".
	ReasonNoLicenseUpstream = "no-license-upstream"
	// ReasonNoPURL: the SBOM gives no package URL to look the package up by.
	ReasonNoPURL = "no-purl"
	// ReasonUnsupported: no resolver covers the ecosystem (generic binaries,
	// OS packages, …).
	ReasonUnsupported = "unsupported-ecosystem"
	// ReasonUnresolved: a resolver covers the package but gave no answer
	// (disabled, rate-limited, network error, or a negative result cached
	// before reasons were recorded).
	ReasonUnresolved = "unresolved"
)

// negativeMarker prefixes negative cache values in registry_license_cache so a
// resolver can tell, after a restart, why a package stayed unresolved. "!" can
// never start an SPDX expression. A plain "" is a legacy negative without a
// reason.
const negativeMarker = "!"

// NegativeCacheValue encodes an unresolved outcome with its reason.
func NegativeCacheValue(reason string) string {
	if reason == "" {
		return ""
	}
	return negativeMarker + reason
}

// SplitCacheValue decodes a cached resolver value into the license (empty for
// negative results) and, for negative results, the recorded reason.
func SplitCacheValue(v string) (lic, reason string) {
	if strings.HasPrefix(v, negativeMarker) {
		return "", strings.TrimPrefix(v, negativeMarker)
	}
	return v, ""
}

// WithModifier appends a "+modifier" to a source unless it is already there.
func WithModifier(source, modifier string) string {
	if source == "" || modifier == "" {
		return source
	}
	for _, part := range strings.Split(source, "+")[1:] {
		if part == modifier {
			return source
		}
	}
	return source + "+" + modifier
}

// UnresolvedReasons lists every reason a package can be left without a
// license, in the order the pipeline checks them.
var UnresolvedReasons = []string{
	ReasonFirstParty, ReasonNoPURL, ReasonUnsupported,
	ReasonNotPublished, ReasonNoLicenseUpstream, ReasonUnresolved,
}

// IsUnresolvedReason reports whether a source string is a reason for a missing
// license rather than the origin of a resolved one.
func IsUnresolvedReason(source string) bool {
	for _, r := range UnresolvedReasons {
		if source == r {
			return true
		}
	}
	return false
}
