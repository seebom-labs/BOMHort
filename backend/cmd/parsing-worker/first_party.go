package main

import "strings"

// yarnWorkspaceVersion is the version Yarn Berry gives packages of the
// project's own workspace in its lockfile, and SBOM generators copy it.
const yarnWorkspaceVersion = "0.0.0-use.local"

// licenseCheckSkips returns the package indices that are excluded from the
// license compliance check: the SBOM's root package(s) and every package
// isFirstPartyPURL recognises. They are the project's own code, not
// dependencies — no registry knows their license, so checking them only adds
// NOASSERTION noise. They stay in sbom_packages (with license source
// "first-party"); only the compliance rows ignore them.
func licenseCheckSkips(roots []uint32, purls []string) []uint32 {
	skips := append([]uint32(nil), roots...)
	for i, purl := range purls {
		if isFirstPartyPURL(purl) {
			skips = append(skips, uint32(i))
		}
	}
	return skips
}

// isFirstPartyPURL reports whether a purl unambiguously names the project's
// own module rather than a dependency:
//
//   - pkg:npm/…@0.0.0-use.local: a Yarn Berry workspace package
//   - pkg:maven/${project.groupId}/…: a Maven module whose groupId is the
//     building project's own, left as an unexpanded property by the generator
//
// Other unexpanded properties ("scalatest_${scala.compat.version}") are not
// first-party: they are third-party packages with an unresolved name.
func isFirstPartyPURL(purl string) bool {
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
