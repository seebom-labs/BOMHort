package origin

import "strings"

var values = map[string]struct{}{
	"cluster-scan": {},
	"ci":           {},
	"registry":     {},
	"vendor":       {},
	"manual":       {},
}

func Normalize(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func IsValid(value string) bool {
	_, ok := values[value]
	return ok
}
