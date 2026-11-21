package evaluate

import "strings"

// yarnWorkspaceVersion is the version Yarn Berry gives packages of the
// project's own workspace in its lockfile, and SBOM generators copy it.
const yarnWorkspaceVersion = "0.0.0-use.local"

// LicenseCheckSkips returns the package indices that are excluded from the
// license compliance check: the SBOM's root package(s) and every package
// IsFirstPartyPURL recognises. They are the project's own code, not
// dependencies - no registry knows their license, so checking them only adds
// NOASSERTION noise.
func LicenseCheckSkips(roots []uint32, purls []string) []uint32 {
	skips := append([]uint32(nil), roots...)
	for i, purl := range purls {
		if IsFirstPartyPURL(purl) {
			skips = append(skips, uint32(i))
		}
	}
	return skips
}

// IsFirstPartyPURL reports whether a purl unambiguously names the project's
// own module rather than a dependency.
func IsFirstPartyPURL(purl string) bool {
	return isYarnWorkspacePURL(purl) || isMavenProjectModulePURL(purl)
}

func isYarnWorkspacePURL(purl string) bool {
	if !strings.HasPrefix(purl, "pkg:npm/") {
		return false
	}
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	return strings.HasSuffix(purl, "@"+yarnWorkspaceVersion)
}

func isMavenProjectModulePURL(purl string) bool {
	rest, ok := strings.CutPrefix(purl, "pkg:maven/")
	if !ok {
		return false
	}
	rest = strings.ReplaceAll(rest, "%7B", "{")
	rest = strings.ReplaceAll(rest, "%7D", "}")
	rest = strings.ReplaceAll(rest, "%24", "$")
	return strings.HasPrefix(rest, "${project.")
}

// ExcludeIndices returns names and licenses with elements at skip indices removed.
func ExcludeIndices(names, licenses []string, skip []uint32) ([]string, []string) {
	if len(skip) == 0 {
		return names, licenses
	}
	skipSet := make(map[uint32]bool, len(skip))
	for _, i := range skip {
		skipSet[i] = true
	}
	outNames := make([]string, 0, len(names))
	outLics := make([]string, 0, len(licenses))
	for i := range names {
		if skipSet[uint32(i)] {
			continue
		}
		outNames = append(outNames, names[i])
		if i < len(licenses) {
			outLics = append(outLics, licenses[i])
		} else {
			outLics = append(outLics, "")
		}
	}
	return outNames, outLics
}
