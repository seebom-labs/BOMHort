package clickhouse

import "strings"

// escapeLikePattern escapes ClickHouse ILIKE wildcards so user input is
// matched literally instead of acting as a wildcard. Backslash must be
// escaped first to avoid double-escaping the added escape characters.
func escapeLikePattern(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}
