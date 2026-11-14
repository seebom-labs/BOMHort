// Package imagedigest implements image reference and digest extraction and
// normalization (#457) for container image identity.
package imagedigest

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	// hexOnly matches a raw 64-character hex string (sha256 without prefix).
	hex64Only = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	// validDigest matches an algorithm:encoded digest (e.g. sha256:<64 hex>).
	validDigestRegex = regexp.MustCompile(`^[a-z0-9_+.-]+:[a-f0-9]{32,}$`)
)

// NormalizeDigest normalizes a container image digest string.
// Trims whitespace, unescapes %3A, lowercases, and prefixes sha256: if a bare
// 64-char hex string is provided.
func NormalizeDigest(d string) string {
	d = strings.TrimSpace(d)
	if d == "" {
		return ""
	}
	// Decode URL-encoded colon if present (%3A or %3a).
	d = strings.ReplaceAll(d, "%3A", ":")
	d = strings.ReplaceAll(d, "%3a", ":")
	d = strings.ToLower(d)

	// If bare 64-char hex with no algorithm, default to sha256.
	if hex64Only.MatchString(d) {
		return "sha256:" + d
	}

	return d
}

// IsValidDigest reports whether d is a valid algorithm:encoded digest.
func IsValidDigest(d string) bool {
	norm := NormalizeDigest(d)
	if norm == "" {
		return false
	}
	return validDigestRegex.MatchString(norm)
}

// ExtractFromPURL extracts image reference and image digest from a Package URL.
// If purl is not a pkg:oci URL, it returns empty strings.
func ExtractFromPURL(purl string) (imageRef, imageDigest string) {
	p := strings.TrimSpace(purl)
	if len(p) < 8 || !strings.EqualFold(p[:8], "pkg:oci/") {
		return "", ""
	}
	p = p[8:] // strip pkg:oci/

	// Strip subpath after '#'
	p, _, _ = strings.Cut(p, "#")

	// Split qualifiers after '?'
	purlPath, rawQualifiers, _ := strings.Cut(p, "?")

	var qualifiers url.Values
	if rawQualifiers != "" {
		qualifiers, _ = url.ParseQuery(rawQualifiers)
	}

	// Split path and version after '@'
	var path, version string
	if at := strings.LastIndex(purlPath, "@"); at != -1 {
		path = purlPath[:at]
		version = purlPath[at+1:]
	} else {
		path = purlPath
	}

	// URL-decode path
	if decoded, err := url.PathUnescape(path); err == nil && decoded != "" {
		path = decoded
	}

	// Check if version is a digest
	normVersion := NormalizeDigest(version)
	if IsValidDigest(normVersion) {
		imageDigest = normVersion
	} else if qualifiers != nil && qualifiers.Get("digest") != "" {
		normQual := NormalizeDigest(qualifiers.Get("digest"))
		if IsValidDigest(normQual) {
			imageDigest = normQual
		}
	}

	// Determine tag
	tag := ""
	if qualifiers != nil && qualifiers.Get("tag") != "" {
		tag = qualifiers.Get("tag")
	} else if version != "" && !IsValidDigest(normVersion) {
		tag = version
	}

	// Determine repository base
	baseRepo := ""
	if qualifiers != nil && qualifiers.Get("repository_url") != "" {
		baseRepo = qualifiers.Get("repository_url")
	} else {
		baseRepo = path
	}

	// Assemble imageRef
	if baseRepo != "" {
		if tag != "" {
			imageRef = baseRepo + ":" + tag
		} else if imageDigest != "" {
			imageRef = baseRepo + "@" + imageDigest
		} else {
			imageRef = baseRepo
		}
	}

	return imageRef, imageDigest
}

// ExtractFromRef parses a reference string that might contain a digest after '@'
// (e.g. "ghcr.io/org/app:v1@sha256:..." or "ubuntu@sha256:...").
func ExtractFromRef(ref string) (imageRef, imageDigest string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", ""
	}
	if at := strings.LastIndex(ref, "@"); at != -1 {
		digestCandidate := NormalizeDigest(ref[at+1:])
		if IsValidDigest(digestCandidate) {
			return ref[:at], digestCandidate
		}
	}
	return ref, ""
}
