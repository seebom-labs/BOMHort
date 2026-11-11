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

// affectedKey returns the package key ("type/namespace/name") an affected
// entry describes, and the distro release its ecosystem names ("3.18" for
// "Alpine:v3.18"), if any.
func affectedKey(pkgPURL, ecosystem, name string) (key, release string) {
	eco, rel, _ := strings.Cut(ecosystem, ":")
	release = strings.TrimPrefix(strings.TrimSpace(rel), "v")
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
	// "debian-12", "alpine-3.18.4", "3.18.4", "bookworm".
	if i := strings.LastIndexByte(distro, '-'); i >= 0 {
		distro = distro[i+1:]
	}
	distro = strings.TrimPrefix(distro, "v")
	if distro == "" || distro[0] < '0' || distro[0] > '9' {
		return true // a codename: not comparable with a release number
	}
	return distro == release || strings.HasPrefix(distro, release+".")
}
