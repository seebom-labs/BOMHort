package imageid

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// ParseRef validates an OCI image reference pinned by a SHA-256 digest.
func ParseRef(value string) (string, string, error) {
	if len(value) > 1024 || strings.ContainsAny(value, " \t\r\n") {
		return "", "", fmt.Errorf("invalid image reference")
	}
	ref, digest, ok := strings.Cut(value, "@")
	if !ok || ref == "" || !digestPattern.MatchString(digest) {
		return "", "", fmt.Errorf("image reference must end with @sha256:<64 lowercase hex characters>")
	}
	return ref, digest, nil
}

// FromPURL extracts an OCI image reference and digest from an OCI package URL.
func FromPURL(purl string) (string, string) {
	if !strings.HasPrefix(purl, "pkg:oci/") {
		return "", ""
	}
	path, query, _ := strings.Cut(strings.TrimPrefix(purl, "pkg:oci/"), "?")
	name, digest, _ := strings.Cut(path, "@")
	digest, err := url.PathUnescape(digest)
	if err != nil || !digestPattern.MatchString(digest) {
		return "", ""
	}
	ref := name
	if query != "" {
		values, err := url.ParseQuery(query)
		if err != nil {
			return "", ""
		}
		if repository := values.Get("repository_url"); repository != "" {
			ref = repository
		}
	}
	ref, err = url.PathUnescape(ref)
	if err != nil || ref == "" {
		return "", ""
	}
	return ref, digest
}

// ValidDigest reports whether value is a supported OCI SHA-256 digest.
func ValidDigest(value string) bool { return digestPattern.MatchString(value) }

// ValidRefPrefix checks a user-supplied image reference prefix before querying.
func ValidRefPrefix(value string) bool {
	return value != "" && len(value) <= 1024 && !strings.ContainsAny(value, " \t\r\n")
}
