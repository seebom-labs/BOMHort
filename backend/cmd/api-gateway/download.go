package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// contentDispositionAttachment formats an RFC 6266 Content-Disposition header
// for an attachment, escaping quotes and backslashes, stripping control characters,
// and adding an RFC 5987 filename* parameter when non-ASCII runes are present.
func contentDispositionAttachment(filename string) string {
	filename = sanitizeHeaderParam(filename)
	if filename == "" {
		filename = "download"
	}

	if isASCII(filename) {
		return fmt.Sprintf(`attachment; filename="%s"`, escapeQuotes(filename))
	}

	asciiFallback := escapeQuotes(toASCIIFallback(filename))
	encoded := rfc5987Encode(filename)
	return fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, asciiFallback, encoded)
}

// safeLocalSBOMPath validates and resolves a relative sourceFile path within baseDir.
// It rejects empty baseDir, absolute paths, and paths attempting directory traversal.
func safeLocalSBOMPath(baseDir, sourceFile string) (string, error) {
	if baseDir == "" {
		return "", errors.New("local storage not configured")
	}
	if strings.TrimSpace(sourceFile) == "" {
		return "", errors.New("empty source file path")
	}
	clean := filepath.Clean(sourceFile)
	if clean == "." || clean == "/" || filepath.IsAbs(clean) || !filepath.IsLocal(clean) {
		return "", fmt.Errorf("invalid source file path %q", sourceFile)
	}
	absPath := filepath.Join(baseDir, clean)
	rel, err := filepath.Rel(baseDir, absPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("path traversal attempt: %q", sourceFile)
	}
	return absPath, nil
}

// sanitizeHeaderParam removes CR, LF, and NUL characters to prevent HTTP response splitting.
func sanitizeHeaderParam(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, s)
}

// escapeQuotes escapes backslashes and double-quotes per RFC 2616 / RFC 6266 quoted-string rules.
func escapeQuotes(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// isASCII returns true if all bytes in s are <= 127.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// toASCIIFallback converts non-ASCII runes to '_' for legacy HTTP clients.
func toASCIIFallback(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r <= 126 && r != '"' && r != '\\' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	res := b.String()
	if strings.Trim(res, "_") == "" {
		return "download"
	}
	return res
}

// rfc5987Encode percent-encodes a UTF-8 string per RFC 5987 Section 3.2.1 attr-char rules.
func rfc5987Encode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			c == '!' || c == '#' || c == '$' || c == '&' || c == '+' || c == '-' ||
			c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
