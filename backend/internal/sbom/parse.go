// Package sbom provides multi-format SBOM parsing with automatic format detection.
// Supported formats: SPDX JSON (plain + in-toto envelopes), CycloneDX JSON.
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

	"github.com/seebom-labs/seebom/backend/internal/cyclonedx"
	"github.com/seebom-labs/seebom/backend/internal/protobomparser"
	"github.com/seebom-labs/seebom/backend/internal/spdx"
	"github.com/seebom-labs/seebom/backend/pkg/models"
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
}

// Parse reads an SBOM document from a reader, auto-detects the format, and dispatches
// to the appropriate parser. Supported formats:
//   - SPDX JSON (plain documents)
//   - SPDX JSON wrapped in in-toto attestation envelopes
//   - CycloneDX JSON (bomFormat: "CycloneDX")
//
// If USE_PROTOBOM=true, all parsing is delegated to protobom for maximum format coverage.
func Parse(r io.Reader, sourceFile, sha256Hash string) (*ParseResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM data: %w", err)
	}

	// If protobom backend is enabled, delegate everything to it.
	if UseProtobom() {
		return parseWithProtobom(data, sourceFile, sha256Hash)
	}

	// Detect format by probing JSON fields.
	var probe formatProbe
	_ = json.Unmarshal(data, &probe)

	switch {
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
// This supports SPDX 2.3, CycloneDX 1.0–1.7, and any future formats protobom adds.
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




