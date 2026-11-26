package license

import "strings"

// ValidVersion reports whether a package version string is safe for registry URL
// paths. It rejects empty strings, dot segments ("." and ".."), path traversal
// sequences, path separators ("/" and "\"), whitespace, and template injection
// sequences ("${").
func ValidVersion(version string) bool {
	version = strings.TrimSpace(version)
	if version == "" || version == "." || strings.Contains(version, "..") || strings.Contains(version, "${") {
		return false
	}
	return !strings.ContainsAny(version, "/\\ \t\r\n")
}
