package sbom

import (
	"strings"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

const npmPURLPrefix = "pkg:npm/"

// normalizeNPMIdentities repairs npm package identities that SBOM generators
// copied verbatim from Yarn Berry lockfile keys. A key such as
//
//	"ws@npm:^8.18.0, ws@npm:^8.2.3"  resolved to  ws@8.20.0
//
// ends up as name "ws@npm:^8.18.0, ws" and PURL
// "pkg:npm/ws@npm:^8.18.0, ws@8.20.0". Neither the npm registry nor OSV can
// match that, so the license stays NOASSERTION and vulnerabilities are
// silently missed. The last comma-separated entry is the resolved one.
func normalizeNPMIdentities(p *models.SBOMPackages) {
	for i, purl := range p.PackagePURLs {
		if !strings.HasPrefix(purl, npmPURLPrefix) {
			continue
		}
		p.PackagePURLs[i] = NormalizeNPMPURL(purl)
		if i < len(p.PackageNames) {
			p.PackageNames[i] = normalizeNPMName(p.PackageNames[i])
		}
	}
}

// NormalizeNPMPURL rewrites a Yarn-lockfile-shaped npm PURL into a canonical
// one. Well-formed PURLs are returned unchanged.
//
//	pkg:npm/ws@npm:^8.18.0, ws@8.20.0                  → pkg:npm/ws@8.20.0
//	pkg:npm/%40types/estree@npm:*, @types/estree@1.0.8 → pkg:npm/%40types/estree@1.0.8
//	pkg:npm/ajv@npm:@redocly/ajv@8.18.1                → pkg:npm/%40redocly/ajv@8.18.1 (alias → real package)
func NormalizeNPMPURL(purl string) string {
	if !strings.HasPrefix(purl, npmPURLPrefix) {
		return purl
	}
	rest := purl[len(npmPURLPrefix):]
	if strings.Contains(rest, "@patch:") {
		if out, ok := normalizeYarnPatchPURL(rest); ok {
			return out
		}
		return purl
	}
	suffix := ""
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest, suffix = rest[:i], rest[i:]
	}
	if !strings.Contains(rest, ",") && !strings.Contains(rest, "@npm:") {
		return purl
	}
	if i := strings.LastIndex(rest, ","); i >= 0 {
		rest = strings.TrimSpace(rest[i+1:])
	}
	if strings.HasPrefix(rest, "%40") {
		rest = "@" + rest[3:]
	}
	if rest == "" {
		return purl
	}

	name, version := rest, ""
	if at := strings.Index(rest[1:], "@"); at >= 0 {
		name, version = rest[:at+1], rest[at+2:]
	}
	// "npm:" is Yarn's protocol prefix. What follows is either a version or,
	// for an alias, "<real-package>@<version>".
	if v, ok := strings.CutPrefix(version, "npm:"); ok {
		version = v
		if j := strings.LastIndex(v, "@"); j > 0 {
			name, version = v[:j], v[j+1:]
		}
	}
	if name == "" || strings.ContainsAny(name, " ,") {
		return purl
	}
	if strings.HasPrefix(name, "@") {
		name = "%40" + name[1:]
	}
	out := npmPURLPrefix + name
	if version != "" {
		out += "@" + version
	}
	return out + suffix
}

// normalizeYarnPatchPURL handles Yarn's "patch:" protocol, where the lockfile
// key embeds the patched package, its range and a patch path that may itself
// contain '#', '@' and ', '. In every shape the generators emit, the resolved
// version is the text after the final '@':
//
//	ast-types@patch:ast-types@0.16.1                                   → ast-types@0.16.1
//	%40material-ui/pickers@patch:@material-ui/pickers@npm%3A3.3.11#./.yarn/patches/@3.3.11
//	                                                                   → %40material-ui/pickers@3.3.11
//	fsevents@patch:fsevents@npm%3A^2.3.3#optional!builtin<compat/fsevents>, fsevents@patch:fsevents@2.3.3
//	                                                                   → fsevents@2.3.3
func normalizeYarnPatchPURL(rest string) (string, bool) {
	if i := strings.LastIndex(rest, ","); i >= 0 {
		rest = strings.TrimSpace(rest[i+1:])
	}
	i := strings.Index(rest, "@patch:")
	if i <= 0 {
		return "", false
	}
	name := rest[:i]
	version := rest[strings.LastIndex(rest, "@")+1:]
	if strings.HasPrefix(version, "patch:") {
		return "", false
	}
	version = strings.TrimPrefix(strings.TrimPrefix(version, "npm%3A"), "npm:")
	if version == "" || strings.ContainsAny(version, " ,#/^~*<>") || strings.ContainsAny(name, " ,") {
		return "", false
	}
	if strings.HasPrefix(name, "@") {
		name = "%40" + name[1:]
	}
	return npmPURLPrefix + name + "@" + version, true
}

// normalizeNPMName applies the same repair to the package name:
// "@asyncapi/parser@npm:^3.1.0, @asyncapi/parser" → "@asyncapi/parser",
// "fsevents@patch:fsevents" → "fsevents".
func normalizeNPMName(name string) string {
	if !strings.Contains(name, ",") && !strings.Contains(name, "@npm:") && !strings.Contains(name, "@patch:") {
		return name
	}
	if i := strings.LastIndex(name, ","); i >= 0 {
		name = strings.TrimSpace(name[i+1:])
	}
	for _, proto := range []string{"@npm:", "@patch:"} {
		if i := strings.Index(name, proto); i > 0 {
			name = name[:i]
		}
	}
	return name
}
