package vexsub

import (
	"net/url"
	"strings"
)

// ParsedPURL holds the structural components of a Package URL for matching
// upstream VEX statements against SBOM package PURLs.
type ParsedPURL struct {
	Raw        string
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
	Subpath    string
}

// ParsePURL parses a pkg:... URL into type, namespace, name, version, and
// qualifiers. Returns ok=false if raw does not start with "pkg:".
func ParsePURL(raw string) (ParsedPURL, bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "pkg:") {
		return ParsedPURL{}, false
	}

	body := strings.TrimPrefix(raw, "pkg:")
	body = strings.TrimLeft(body, "/")

	var subpath string
	if idx := strings.IndexByte(body, '#'); idx >= 0 {
		subpath = body[idx+1:]
		body = body[:idx]
	}

	qualifiers := map[string]string{}
	if idx := strings.IndexByte(body, '?'); idx >= 0 {
		qStr := body[idx+1:]
		body = body[:idx]
		for _, pair := range strings.Split(qStr, "&") {
			if pair == "" {
				continue
			}
			k, v, hasEq := strings.Cut(pair, "=")
			if !hasEq || k == "" {
				continue
			}
			k = strings.ToLower(unescapeSegment(k))
			v = unescapeSegment(v)
			qualifiers[k] = v
		}
	}

	slashIdx := strings.IndexByte(body, '/')
	if slashIdx <= 0 || slashIdx == len(body)-1 {
		return ParsedPURL{}, false
	}

	purlType := strings.ToLower(body[:slashIdx])
	rest := strings.TrimLeft(body[slashIdx+1:], "/")
	if rest == "" {
		return ParsedPURL{}, false
	}

	// Split version at the last '@' inside the final path segment so scoped npm
	// namespaces like @babel/core remain intact.
	lastSlash := strings.LastIndexByte(rest, '/')
	lastSeg := rest[lastSlash+1:]
	var version string
	if atIdx := strings.LastIndexByte(lastSeg, '@'); atIdx > 0 {
		version = unescapeSegment(lastSeg[atIdx+1:])
		rest = rest[:lastSlash+1] + lastSeg[:atIdx]
	}

	lastSlash = strings.LastIndexByte(rest, '/')
	var namespace, name string
	if lastSlash >= 0 {
		namespace = unescapeSegment(strings.Trim(rest[:lastSlash], "/"))
		name = unescapeSegment(rest[lastSlash+1:])
	} else {
		name = unescapeSegment(rest)
	}
	if name == "" {
		return ParsedPURL{}, false
	}

	return ParsedPURL{
		Raw:        raw,
		Type:       purlType,
		Namespace:  namespace,
		Name:       name,
		Version:    version,
		Qualifiers: qualifiers,
		Subpath:    subpath,
	}, true
}

func unescapeSegment(s string) string {
	if !strings.ContainsRune(s, '%') {
		return s
	}
	u, err := url.PathUnescape(s)
	if err != nil {
		return s
	}
	return u
}

// Core returns the versionless canonical package path ("pkg:<type>/<ns>/<name>").
func (p ParsedPURL) Core() string {
	ns := p.Namespace
	name := p.Name
	if p.Type == "pypi" || p.Type == "npm" {
		ns = strings.ToLower(ns)
		name = strings.ToLower(name)
	}
	if ns != "" {
		return "pkg:" + p.Type + "/" + ns + "/" + name
	}
	return "pkg:" + p.Type + "/" + name
}

// Matches reports whether an upstream statement PURL (receiver) applies to a
// concrete SBOM package PURL (target).
//
// Rules:
//   - Core package identity (type, namespace, name) must match.
//   - If the statement specifies a version, target must have the exact same version.
//   - If the statement is versionless (as in OpenVEX hub indexes), it matches any
//     version of that core package unless qualifiers conflict.
//   - Any qualifier key present on both sides must have the same value; extra
//     distinction qualifiers on the SBOM package (for example ?distro=rhel-8
//     when upstream specifies only ?arch=x86_64) are allowed.
func (p ParsedPURL) Matches(target ParsedPURL) bool {
	if p.Core() != target.Core() {
		return false
	}
	if p.Version != "" && p.Version != target.Version {
		return false
	}
	for k, v := range p.Qualifiers {
		if tv, ok := target.Qualifiers[k]; ok && !strings.EqualFold(v, tv) {
			return false
		}
	}
	return true
}

// MatchKnownPURLs returns all PURLs from knownPURLs that match stmtPURL.
// Matching preserves exact PURL hits first and also resolves compatible
// qualifiers or versionless OpenVEX hub PURLs to concrete SBOM PURLs.
func MatchKnownPURLs(stmtPURL string, knownPURLs []string) []string {
	if stmtPURL == "" || stmtPURL == "*" {
		return nil
	}
	var out []string
	seen := make(map[string]struct{})
	parsedStmt, okStmt := ParsePURL(stmtPURL)
	for _, known := range knownPURLs {
		if known == "" {
			continue
		}
		matched := known == stmtPURL
		if !matched && okStmt {
			if parsedKnown, okKnown := ParsePURL(known); okKnown {
				matched = parsedStmt.Matches(parsedKnown)
			}
		}
		if matched {
			if _, dup := seen[known]; !dup {
				seen[known] = struct{}{}
				out = append(out, known)
			}
		}
	}
	return out
}
