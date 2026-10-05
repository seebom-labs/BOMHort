// Package sbom provides multi-format SBOM parsing with automatic format detection.
// Supported formats: SPDX 2.x JSON (plain + in-toto envelopes), SPDX 3 JSON-LD
// (always via protobom), CycloneDX JSON.
//
// Two parser backends are available:
//   - Built-in (default): Lightweight, high-performance parsers using goccy/go-json.
//   - Protobom (opt-in): Uses github.com/protobom/protobom for broader format support.
//     Enable via SetUseProtobom(true) or the USE_PROTOBOM=true environment variable.
package sbom

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/internal/cyclonedx"
	"github.com/seebom-labs/bomhort/backend/internal/protobomparser"
	"github.com/seebom-labs/bomhort/backend/internal/spdx"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// ParseResult contains the extracted data from an SBOM document, ready for ClickHouse insertion.
type ParseResult struct {
	SBOM     models.SBOM
	Packages models.SBOMPackages
}

var (
	useProtobom     bool
	useProtobomOnce sync.Once
)

// UseProtobom returns whether the protobom backend is enabled.
func UseProtobom() bool {
	useProtobomOnce.Do(func() {
		if v := os.Getenv("USE_PROTOBOM"); strings.EqualFold(v, "true") || v == "1" {
			useProtobom = true
		}
	})
	return useProtobom
}

// SetUseProtobom enables or disables the protobom backend programmatically.
// Must be called before any Parse() calls for consistent behavior.
func SetUseProtobom(enabled bool) {
	useProtobom = enabled
}

// formatProbe is used to peek at JSON fields for format detection without full parsing.
type formatProbe struct {
	BomFormat   string `json:"bomFormat"`
	SPDXVersion string `json:"spdxVersion"`
	// in-toto envelope detection
	PredicateType string `json:"predicateType"`
	// SPDX 3 JSON-LD detection: "@context" is a string or an array of strings.
	Context json.RawMessage `json:"@context"`
}

// isSPDX3Context reports whether a JSON-LD @context value references the
// SPDX 3 context (e.g. "https://spdx.org/rdf/3.0.1/spdx-context.jsonld").
func isSPDX3Context(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return strings.Contains(single, "spdx.org/rdf/3")
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		for _, c := range many {
			if strings.Contains(c, "spdx.org/rdf/3") {
				return true
			}
		}
	}
	return false
}

// Parse reads an SBOM document from a reader, auto-detects the format, and dispatches
// to the appropriate parser. Supported formats:
//   - SPDX JSON (plain documents)
//   - SPDX JSON wrapped in in-toto attestation envelopes
//   - SPDX 3 JSON-LD (@context https://spdx.org/rdf/3.x/...) via protobom
//   - CycloneDX JSON (bomFormat: "CycloneDX")
//
// If USE_PROTOBOM=true, all parsing is delegated to protobom for maximum format coverage.
func Parse(r io.Reader, sourceFile, sha256Hash string) (*ParseResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM data: %w", err)
	}
	result, err := dispatch(data, sourceFile, sha256Hash)
	if err != nil {
		return nil, err
	}
	normalizeNPMIdentities(&result.Packages)
	return result, nil
}

// dispatch routes the raw document to the parser backend for its format.
func dispatch(data []byte, sourceFile, sha256Hash string) (*ParseResult, error) {
	// If protobom backend is enabled, delegate everything to it.
	if UseProtobom() {
		return parseWithProtobom(data, sourceFile, sha256Hash)
	}

	// Detect format by probing JSON fields.
	var probe formatProbe
	_ = json.Unmarshal(data, &probe)

	switch {
	case isSPDX3Context(probe.Context):
		// SPDX 3 is JSON-LD without a spdxVersion field; only protobom understands it.
		return parseWithProtobom(data, sourceFile, sha256Hash)
	case probe.BomFormat == "CycloneDX":
		return parseCycloneDX(data, sourceFile, sha256Hash)
	case probe.SPDXVersion != "":
		return parseSPDX(data, sourceFile, sha256Hash)
	case probe.PredicateType != "":
		// Likely an in-toto envelope wrapping SPDX or CycloneDX.
		return parseSPDX(data, sourceFile, sha256Hash)
	default:
		// Fall back to SPDX parser (handles unknown gracefully).
		return parseSPDX(data, sourceFile, sha256Hash)
	}
}

// parseSPDX delegates to the existing SPDX parser.
func parseSPDX(data []byte, sourceFile, sha256Hash string) (*ParseResult, error) {
	result, err := spdx.Parse(bytes.NewReader(data), sourceFile, sha256Hash)
	if err != nil {
		return nil, err
	}
	return &ParseResult{
		SBOM:     result.SBOM,
		Packages: result.Packages,
	}, nil
}

// parseCycloneDX delegates to the CycloneDX parser.
func parseCycloneDX(data []byte, sourceFile, sha256Hash string) (*ParseResult, error) {
	result, err := cyclonedx.Parse(data, sourceFile, sha256Hash)
	if err != nil {
		return nil, err
	}
	return &ParseResult{
		SBOM:     result.SBOM,
		Packages: result.Packages,
	}, nil
}

// parseWithProtobom delegates parsing to the protobom library for maximum format coverage.
// This supports SPDX 2.2/2.3, SPDX 3.0.1, CycloneDX 1.4–1.7, and any future formats protobom adds.
func parseWithProtobom(data []byte, sourceFile, sha256Hash string) (*ParseResult, error) {
	result, err := protobomparser.Parse(data, sourceFile, sha256Hash)
	if err != nil {
		return nil, err
	}
	return &ParseResult{
		SBOM:     result.SBOM,
		Packages: result.Packages,
	}, nil
}
