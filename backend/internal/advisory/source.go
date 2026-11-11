// Package advisory adds OSV-format advisory feeds next to osv.dev: a distro
// or vendor feed is authoritative for the PURLs it names, so its verdict on
// a backported fix wins over the upstream range match osv.dev reports.
//
// A feed is an index document — a JSON array of {id, modified} — plus one
// OSV record per id next to it (<dir>/<id>.json). The cve-refresher keeps
// the records in ClickHouse (Sync); the parsing worker and the refresher
// match them against SBOM packages (Matcher).
package advisory

import (
	"fmt"
	"regexp"
	"strings"
)

// OSVSource is the advisory_source of a finding that came from osv.dev
// alone. It is reserved: no feed may use the name.
const OSVSource = "osv"

// Source is one configured advisory feed.
type Source struct {
	// Name identifies the feed in findings (advisory_source), logs and VEX
	// statements it authors.
	Name string
	// Index locates the index document: https://…/all.json,
	// s3://bucket/key or file:///path. Records are read from the same
	// directory.
	Index string
	// Prefixes are the PURL prefixes the feed is authoritative for
	// (pkg:apk/wolfi). For a matching PURL the feed's verdict replaces
	// osv.dev's for every flaw the feed has a record of. A feed without
	// prefixes only adds findings; it never suppresses one.
	Prefixes []string
}

var sourceNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ParseSources reads ADVISORY_SOURCES: entries separated by ",", each
// "name|index[|prefix…]". Example:
//
//	wolfi|https://packages.example.dev/osv/all.json|pkg:apk/wolfi,
//	private|s3://advisories/all.json
func ParseSources(raw string) ([]Source, error) {
	var out []Source
	seen := map[string]bool{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		fields := strings.Split(entry, "|")
		if len(fields) < 2 {
			return nil, fmt.Errorf("advisory source %q: want name|index[|purl-prefix…]", entry)
		}
		s := Source{Name: strings.ToLower(strings.TrimSpace(fields[0])), Index: strings.TrimSpace(fields[1])}
		if !sourceNameRe.MatchString(s.Name) {
			return nil, fmt.Errorf("advisory source name %q: want lower-case letters, digits, '.', '_' or '-'", s.Name)
		}
		if s.Name == OSVSource {
			return nil, fmt.Errorf("advisory source name %q is reserved for osv.dev", s.Name)
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("advisory source %q is configured twice", s.Name)
		}
		seen[s.Name] = true
		if _, err := recordLocation(s.Index, "x"); err != nil {
			return nil, fmt.Errorf("advisory source %q: %w", s.Name, err)
		}
		for _, p := range fields[2:] {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "" {
				continue
			}
			if !strings.HasPrefix(p, "pkg:") || !strings.Contains(p, "/") {
				return nil, fmt.Errorf("advisory source %q: prefix %q is not a PURL prefix such as pkg:apk/wolfi", s.Name, p)
			}
			s.Prefixes = append(s.Prefixes, p)
		}
		out = append(out, s)
	}
	return out, nil
}

// authority returns the length of the longest prefix of s that p starts
// with, or 0 when s is not authoritative for p. A prefix matches at a path
// boundary only: pkg:apk/wolfi covers pkg:apk/wolfi/openssl, not
// pkg:apk/wolfish/openssl.
func (s Source) authority(p string) int {
	p = strings.ToLower(p)
	best := 0
	for _, pre := range s.Prefixes {
		if !strings.HasPrefix(p, pre) {
			continue
		}
		if len(p) > len(pre) && !strings.ContainsRune("/@?#", rune(p[len(pre)])) && !strings.HasSuffix(pre, "/") {
			continue
		}
		best = max(best, len(pre))
	}
	return best
}

// recordLocation returns where the record id of a feed lives: next to the
// index document.
func recordLocation(index, id string) (string, error) {
	switch {
	case strings.HasPrefix(index, "https://"), strings.HasPrefix(index, "http://"),
		strings.HasPrefix(index, "s3://"), strings.HasPrefix(index, "file://"):
	default:
		return "", fmt.Errorf("index %q: want an https://, s3:// or file:// location", index)
	}
	if strings.HasPrefix(index, "http://") {
		return "", fmt.Errorf("index %q: plain http is not accepted, use https://", index)
	}
	base := index
	if i := strings.IndexAny(base, "?#"); i >= 0 {
		base = base[:i]
	}
	i := strings.LastIndexByte(base, '/')
	if i < len("s3://") {
		return "", fmt.Errorf("index %q has no directory", index)
	}
	if strings.ContainsAny(id, "/\\") || id == "" || id == "." || id == ".." {
		return "", fmt.Errorf("record id %q is not a plain name", id)
	}
	return base[:i+1] + id + ".json", nil
}
