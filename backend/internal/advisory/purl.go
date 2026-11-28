package advisory

import (
	"net/url"
	"strings"
)

// purl is the part of a Package URL that advisory matching needs.
type purl struct {
	typ        string
	key        string // "type/namespace/name", lower-cased, no version
	version    string
	qualifiers map[string]string
}

// parsePURL reads pkg:type/namespace/name@version?qualifiers#subpath. It
// returns false for anything that is not a PURL.
func parsePURL(s string) (purl, bool) {
	var p purl
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "pkg:")
	if !ok {
		return p, false
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		p.qualifiers = map[string]string{}
		for _, kv := range strings.Split(rest[i+1:], "&") {
			k, v, _ := strings.Cut(kv, "=")
			if dv, err := url.QueryUnescape(v); err == nil {
				v = dv
			}
			p.qualifiers[strings.ToLower(k)] = v
		}
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		v := rest[i+1:]
		if dv, err := url.PathUnescape(v); err == nil {
			v = dv
		}
		p.version, rest = v, rest[:i]
	}
	rest = strings.Trim(rest, "/")
	typ, path, ok := strings.Cut(rest, "/")
	if !ok || typ == "" || path == "" {
		return p, false
	}
	if dp, err := url.PathUnescape(path); err == nil {
		path = dp
	}
	p.typ = strings.ToLower(typ)
	p.key = p.typ + "/" + strings.ToLower(path)
	return p, true
}

// ecosystemPURL maps an OSV ecosystem (without its ":release" suffix) to the
// PURL type and namespace of its packages, for records that name a package
// by ecosystem and name only. Ecosystems missing here are matched through
// affected[].package.purl or not at all — never by guessing a namespace.
var ecosystemPURL = map[string]string{
	"alpine":         "apk/alpine",
	"wolfi":          "apk/wolfi",
	"chainguard":     "apk/chainguard",
	"debian":         "deb/debian",
	"ubuntu":         "deb/ubuntu",
	"almalinux":      "rpm/almalinux",
	"rocky linux":    "rpm/rocky-linux",
	"red hat":        "rpm/redhat",
	"opensuse":       "rpm/opensuse",
	"suse":           "rpm/suse",
	"mageia":         "rpm/mageia",
	"openeuler":      "rpm/openeuler",
	"azure linux":    "rpm/azurelinux",
	"npm":            "npm",
	"pypi":           "pypi",
	"go":             "golang",
	"crates.io":      "cargo",
	"rubygems":       "gem",
	"nuget":          "nuget",
	"packagist":      "composer",
	"hex":            "hex",
	"pub":            "pub",
	"maven":          "maven",
	"swifturl":       "swift",
	"github actions": "github",
}

var debianCodenames = map[string]string{
	"buzz":     "1.1",
	"rex":      "1.2",
	"bo":       "1.3",
	"hamm":     "2.0",
	"slink":    "2.1",
	"potato":   "2.2",
	"woody":    "3.0",
	"sarge":    "3.1",
	"etch":     "4.0",
	"lenny":    "5.0",
	"squeeze":  "6.0",
	"wheezy":   "7",
	"jessie":   "8",
	"stretch":  "9",
	"buster":   "10",
	"bullseye": "11",
	"bookworm": "12",
	"trixie":   "13",
	"forky":    "14",
	"sid":      "unstable",
}

var ubuntuCodenames = map[string]string{
	"bionic":   "18.04",
	"focal":    "20.04",
	"jammy":    "22.04",
	"lunar":    "23.04",
	"mantic":   "23.10",
	"noble":    "24.04",
	"oracular": "24.10",
	"plucky":   "25.04",
	"resolute": "26.04",
}

// parseEcosystemRelease parses an OSV ecosystem string and extracts the base
// ecosystem and the distro release. For Red Hat, ecosystems look like
// "Red Hat:enterprise_linux:9::baseos", "Red Hat:rhel_e4s:8.0::baseos" or
// "Red Hat:enterprise_linux:10.0", where the release token is the third part.
func parseEcosystemRelease(ecosystem string) (eco, release string) {
	parts := strings.Split(ecosystem, ":")
	eco = strings.TrimSpace(parts[0])
	if len(parts) < 2 {
		return eco, ""
	}
	if strings.EqualFold(eco, "Red Hat") && len(parts) >= 3 {
		ver, _, _ := strings.Cut(parts[2], "::")
		return eco, strings.TrimSpace(ver)
	}
	ver, _, _ := strings.Cut(parts[1], ":")
	ver = strings.TrimPrefix(strings.TrimSpace(ver), "v")
	return eco, strings.TrimSpace(ver)
}

// affectedKey returns the package key ("type/namespace/name") an affected
// entry describes, and the distro release its ecosystem names ("3.18" for
// "Alpine:v3.18"), if any.
func affectedKey(pkgPURL, ecosystem, name string) (key, release string) {
	eco, rel := parseEcosystemRelease(ecosystem)
	release = rel
	if p, ok := parsePURL(pkgPURL); ok {
		return p.key, release
	}
	prefix, ok := ecosystemPURL[strings.ToLower(strings.TrimSpace(eco))]
	if !ok || name == "" {
		return "", release
	}
	n := strings.ToLower(name)
	if prefix == "maven" {
		n = strings.Replace(n, ":", "/", 1)
	}
	return prefix + "/" + n, release
}

// releaseMatches reports whether a PURL's distro qualifier is compatible with
// the release an affected entry is scoped to. A PURL without the qualifier
// matches every release: the finding is kept rather than dropped.
func releaseMatches(p purl, release string) bool {
	if release == "" {
		return true
	}
	distro := p.qualifiers["distro"]
	if distro == "" {
		return true
	}
	// "debian-12", "alpine-3.18.4", "rhel-9.9", "bookworm".
	distro = strings.ToLower(strings.TrimSpace(distro))
	if i := strings.LastIndexByte(distro, '-'); i >= 0 {
		distro = distro[i+1:]
	}
	distro = strings.TrimPrefix(distro, "v")

	switch p.typ {
	case "deb":
		if rel, ok := debianCodenames[distro]; ok {
			distro = rel
		} else if rel, ok := ubuntuCodenames[distro]; ok {
			distro = rel
		}
	}

	if distro == "" {
		return true
	}
	if distro[0] < '0' || distro[0] > '9' {
		return strings.EqualFold(distro, release)
	}
	return distro == release || strings.HasPrefix(distro, release+".") || strings.HasPrefix(release, distro+".")
}

// purlVersion returns the version of p to use for range comparisons,
// including epoch for RPM packages when specified via the epoch qualifier.
func purlVersion(p purl) string {
	if p.typ == "rpm" && p.qualifiers["epoch"] != "" && !strings.Contains(p.version, ":") {
		return p.qualifiers["epoch"] + ":" + p.version
	}
	return p.version
}
