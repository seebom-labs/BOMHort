package main

import (
	"net/url"
	"strings"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/extrafields"
)

// parseExtraFieldFilter reads ?extra_field= and ?extra_value= for the
// SBOM listing. The name must be a well-formed field name; a value needs a
// name and is matched exactly, so it is length-capped like the stored values
// rather than sanitised. msg is non-empty for a request to reject with 400.
func parseExtraFieldFilter(q url.Values) (f clickhouse.ExtraFieldFilter, msg string) {
	name := strings.TrimSpace(q.Get("extra_field"))
	value := strings.TrimSpace(q.Get("extra_value"))
	if name == "" {
		if value != "" {
			return f, "extra_value requires extra_field"
		}
		return f, ""
	}
	if !extrafields.ValidName(name) {
		return f, "Invalid extra_field"
	}
	if len(value) > extrafields.MaxValueLen {
		return f, "extra_value too long"
	}
	return clickhouse.ExtraFieldFilter{Name: name, Value: value}, ""
}
