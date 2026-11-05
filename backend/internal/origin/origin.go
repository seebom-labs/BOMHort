// Package origin defines the origin dimension vocabulary (#455) recording how
// an SBOM was produced.
//
// An SBOM inventory fed by several kinds of producers needs to answer "where
// did this document come from?" — scanned from a running container, produced
// by a CI build, pulled from a registry referrer, delivered by a vendor, or
// uploaded by hand.
//
// Unlike tags, origin is a fixed, validated vocabulary, not free-form text.
// Any unknown value is rejected with 400 Bad Request at ingest time.
package origin

import (
	"fmt"
	"strings"
)

// Allowed origin constants.
const (
	ClusterScan = "cluster-scan" // Generated from a running workload/image by a runtime scanner
	CI          = "ci"           // Produced by a build / CI pipeline
	Registry    = "registry"     // Pulled from an OCI referrer or attached artifact
	Vendor      = "vendor"       // Delivered by a third-party vendor
	Manual      = "manual"       // Ad-hoc or manual upload
)

// ValidOrigins lists all supported non-empty origin values.
var ValidOrigins = []string{
	ClusterScan,
	CI,
	Registry,
	Vendor,
	Manual,
}

var validSet = map[string]struct{}{
	ClusterScan: {},
	CI:          {},
	Registry:    {},
	Vendor:      {},
	Manual:      {},
}

// IsValid reports whether the origin string is one of the allowed vocabulary
// entries, or empty ("" = legacy/unassigned rows).
func IsValid(o string) bool {
	o = strings.TrimSpace(o)
	if o == "" {
		return true
	}
	_, ok := validSet[o]
	return ok
}

// Validate checks whether o is an allowed origin. It returns nil for empty or
// valid origin strings, and an error describing the allowed set for unknown values.
func Validate(o string) error {
	o = strings.TrimSpace(o)
	if o == "" {
		return nil
	}
	if _, ok := validSet[o]; !ok {
		return fmt.Errorf("invalid origin %q: must be one of %s or empty", o, strings.Join(ValidOrigins, ", "))
	}
	return nil
}

// Normalize trims whitespace from the origin.
func Normalize(o string) string {
	return strings.TrimSpace(o)
}
