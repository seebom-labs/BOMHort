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
	stdjson "encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	json "github.com/goccy/go-json"
	"github.com/protobom/protobom/pkg/formats"

	"github.com/seebom-labs/bomhort/backend/internal/cyclonedx"
	"github.com/seebom-labs/bomhort/backend/internal/depgraph"
	"github.com/seebom-labs/bomhort/backend/internal/protobomparser"
	"github.com/seebom-labs/bomhort/backend/internal/spdx"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// ParseResult contains the extracted data from an SBOM document, ready for ClickHouse insertion.
type ParseResult struct {
	SBOM     models.SBOM
	Packages models.SBOMPackages
	// CycloneDXMetadata is captured during format detection, before parsing.
	CycloneDXMetadata json.RawMessage
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
	SpecVersion string `json:"specVersion"`
	SPDXVersion string `json:"spdxVersion"`
	// in-toto envelope detection
	PredicateType json.RawMessage `json:"predicateType"`
	// SPDX 3 JSON-LD detection: "@context" is a string or an array of strings.
	Context json.RawMessage `json:"@context"`
}

type probeWithMetadata struct {
	formatProbe
	Metadata  json.RawMessage `json:"metadata"`
	Predicate struct {
		BomFormat string          `json:"bomFormat"`
		Metadata  json.RawMessage `json:"metadata"`
	} `json:"predicate"`
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
// captureMetadata retains CycloneDX metadata for optional extra-field extraction.
func Parse(r io.Reader, sourceFile, sha256Hash string, captureMetadata bool) (*ParseResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM data: %w", err)
	}
	result, err := dispatch(data, sourceFile, sha256Hash, captureMetadata)
	if err != nil {
		return nil, err
	}
	normalizeNPMIdentities(&result.Packages)
	assignDepths(&result.Packages)
	result.SBOM.QualityScore, result.SBOM.QualityFlags = EvaluateQuality(&result.SBOM, &result.Packages)
	return result, nil
}

// assignDepths derives each package's distance from the described product
// (direct vs. transitive) from the relationship graph. Done here, after the
// format-specific parsers, so every backend yields the same column.
func assignDepths(p *models.SBOMPackages) {
	p.PackageDepths = depgraph.Compute(len(p.PackageNames),
		p.RelSourceIndices, p.RelTargetIndices, p.RelTypes,
		p.RootIndices, p.DirectIndices)
}

// dispatch routes the raw document to the parser backend for its format.
func dispatch(data []byte, sourceFile, sha256Hash string, captureMetadata bool) (*ParseResult, error) {
	useProto := UseProtobom()
	unmarshal := json.Unmarshal
	if useProto {
		unmarshal = stdjson.Unmarshal
	}

	var probe probeWithMetadata
	var validProbe bool
	if captureMetadata {
		validProbe = unmarshal(data, &probe) == nil
		if !validProbe {
			// An unrelated, non-object predicate must not make format detection fail.
			var root struct {
				formatProbe
				Metadata json.RawMessage `json:"metadata"`
			}
			validProbe = unmarshal(data, &root) == nil
			probe = probeWithMetadata{formatProbe: root.formatProbe, Metadata: root.Metadata}
		}
	} else {
		validProbe = unmarshal(data, &probe.formatProbe) == nil
	}

	var result *ParseResult
	var err error
	spdxVersion := probe.SPDXVersion
	var predicateType string
	_ = json.Unmarshal(probe.PredicateType, &predicateType)
	if !useProto && !validProbe {
		var legacy struct {
			BomFormat     string          `json:"bomFormat"`
			SPDXVersion   string          `json:"spdxVersion"`
			PredicateType string          `json:"predicateType"`
			Context       json.RawMessage `json:"@context"`
		}
		_ = json.Unmarshal(data, &legacy)
		probe.BomFormat, probe.Context = legacy.BomFormat, legacy.Context
		spdxVersion, predicateType = legacy.SPDXVersion, legacy.PredicateType
	}

	switch {
	case useProto:
		format := formats.EmptyFormat
		if validProbe {
			format, err = sniffProtobomFormat(probe.formatProbe)
			if err != nil {
				return nil, err
			}
		}
		result, err = parseWithProtobom(data, sourceFile, sha256Hash, format)
	case isSPDX3Context(probe.Context):
		// SPDX 3 is JSON-LD without a spdxVersion field; only protobom understands it.
		result, err = parseWithProtobom(data, sourceFile, sha256Hash, formats.EmptyFormat)
	case probe.BomFormat == "CycloneDX":
		result, err = parseCycloneDX(data, sourceFile, sha256Hash)
	case spdxVersion != "":
		result, err = parseSPDX(data, sourceFile, sha256Hash)
	case predicateType != "":
		// Likely an in-toto envelope wrapping SPDX or CycloneDX.
		result, err = parseSPDX(data, sourceFile, sha256Hash)
	default:
		// Fall back to SPDX parser (handles unknown gracefully).
		result, err = parseSPDX(data, sourceFile, sha256Hash)
	}
	if err != nil {
		return nil, err
	}
	if captureMetadata && validProbe {
		switch {
		case probe.BomFormat == "CycloneDX":
			result.CycloneDXMetadata = probe.Metadata
		case probe.Predicate.BomFormat == "CycloneDX":
			result.CycloneDXMetadata = probe.Predicate.Metadata
		}
	} else if captureMetadata {
		result.CycloneDXMetadata = metadataFromDocument(data)
	}
	return result, nil
}

// Preserve the lenient extraction behavior when unrelated format fields are malformed.
func metadataFromDocument(data []byte) json.RawMessage {
	var doc struct {
		BomFormat string          `json:"bomFormat"`
		Metadata  json.RawMessage `json:"metadata"`
		Predicate json.RawMessage `json:"predicate"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	if doc.BomFormat == "CycloneDX" {
		return doc.Metadata
	}
	var predicate struct {
		BomFormat string          `json:"bomFormat"`
		Metadata  json.RawMessage `json:"metadata"`
	}
	if json.Unmarshal(doc.Predicate, &predicate) == nil && predicate.BomFormat == "CycloneDX" {
		return predicate.Metadata
	}
	return nil
}

// Reuse protobom's own format detection on the fields already read above.
// Unknown formats fall back to protobom's normal detection on the full input.
func sniffProtobomFormat(probe formatProbe) (formats.Format, error) {
	header, err := stdjson.Marshal(struct {
		BomFormat   string          `json:"bomFormat"`
		SpecVersion string          `json:"specVersion"`
		SPDXVersion string          `json:"spdxVersion"`
		Context     json.RawMessage `json:"@context"`
	}{probe.BomFormat, probe.SpecVersion, probe.SPDXVersion, probe.Context})
	if err != nil {
		return formats.EmptyFormat, fmt.Errorf("encode SBOM format probe: %w", err)
	}
	format, err := (&formats.Sniffer{}).SniffReader(bytes.NewReader(header))
	if err != nil {
		return formats.EmptyFormat, nil
	}
	return format, nil
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
func parseWithProtobom(data []byte, sourceFile, sha256Hash string, format formats.Format) (*ParseResult, error) {
	result, err := protobomparser.Parse(data, sourceFile, sha256Hash, format)
	if err != nil {
		return nil, err
	}
	return &ParseResult{
		SBOM:     result.SBOM,
		Packages: result.Packages,
	}, nil
}
