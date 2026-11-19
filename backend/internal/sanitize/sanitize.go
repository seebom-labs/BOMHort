package sanitize

import (
	"strings"
	"unicode"
)

// LogParam strips control characters (C0, C1, and DEL) to prevent log injection
// (CWE-117) and ANSI escape sequence injection. Strings exceeding 200 runes
// are safely truncated with an ellipsis ("...") to prevent log flooding.
func LogParam(s string) string {
	return LogParamLimit(s, 200)
}

// LogParamLimit strips control characters (C0, C1, and DEL) and truncates strings
// exceeding maxRunes with an ellipsis. If maxRunes <= 0, no truncation is applied.
func LogParamLimit(s string, maxRunes int) string {
	var b strings.Builder
	count := 0
	truncated := false
	for _, r := range s {
		if unicode.IsControl(r) {
			continue
		}
		if maxRunes > 0 && count >= maxRunes {
			truncated = true
			break
		}
		b.WriteRune(r)
		count++
	}
	if truncated {
		b.WriteString("...")
	}
	return b.String()
}
