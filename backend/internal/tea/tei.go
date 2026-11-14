package tea

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

var (
	// ErrInvalidTEI is returned when a TEI string cannot be parsed.
	ErrInvalidTEI = errors.New("invalid TEI format")

	// ErrUnsupportedTEIType is returned when the TEI identifier type is unsupported.
	ErrUnsupportedTEIType = errors.New("unsupported TEI identifier type")
)

// ParsedTEI represents a decoded Transparency Exchange Identifier.
type ParsedTEI struct {
	Scheme   string // "tei" or "urn:tei"
	Domain   string // Authoritative domain (from tei://<domain>/...)
	Type     string // Identifier scheme: "purl", "uuid", etc.
	RawValue string // Encoded path segment or payload
	PURL     string // Decoded canonical PURL if Type == "purl"
	UUID     string // Parsed UUID string if Type == "uuid"
}

// EncodePURLTEI formats a canonical PURL into a tei:// URI using Base64URL
// encoding without padding, per ECMA TC54-TG1 TEI type purl specification.
func EncodePURLTEI(domain, purl string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		domain = "bomhort.local"
	}
	encoded := base64.RawURLEncoding.EncodeToString([]byte(purl))
	return fmt.Sprintf("tei://%s/purl/%s", domain, encoded)
}

// EncodeURNTEI formats a PURL into a URN style tei identifier: urn:tei:purl:<base64url>.
func EncodeURNTEI(purl string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(purl))
	return fmt.Sprintf("urn:tei:purl:%s", encoded)
}

// ParseTEI parses and validates a TEI string in either URI form:
//   - tei://<domain>/<type>/<unique-identifier>
//   - urn:tei:<type>:<unique-identifier>
//
// For type 'purl', it automatically attempts unpadded Base64URL decoding,
// padded Base64URL fallback, and direct raw PURL fallback.
func ParseTEI(raw string) (*ParsedTEI, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: empty string", ErrInvalidTEI)
	}

	// 1. tei:// URI scheme
	if strings.HasPrefix(raw, "tei://") {
		trimmed := strings.TrimPrefix(raw, "tei://")
		parts := strings.Split(trimmed, "/")
		if len(parts) < 3 {
			return nil, fmt.Errorf("%w: expected tei://<domain>/<type>/<identifier>", ErrInvalidTEI)
		}

		domain := parts[0]
		idType := strings.ToLower(parts[1])
		val := strings.Join(parts[2:], "/")

		parsed := &ParsedTEI{
			Scheme:   "tei",
			Domain:   domain,
			Type:     idType,
			RawValue: val,
		}

		if err := decodeTEIValue(parsed); err != nil {
			return nil, err
		}
		return parsed, nil
	}

	// 2. urn:tei: URN scheme
	if strings.HasPrefix(raw, "urn:tei:") {
		trimmed := strings.TrimPrefix(raw, "urn:tei:")
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) < 2 {
			return nil, fmt.Errorf("%w: expected urn:tei:<type>:<identifier>", ErrInvalidTEI)
		}

		idType := strings.ToLower(parts[0])
		val := parts[1]

		parsed := &ParsedTEI{
			Scheme:   "urn:tei",
			Type:     idType,
			RawValue: val,
		}

		if err := decodeTEIValue(parsed); err != nil {
			return nil, err
		}
		return parsed, nil
	}

	return nil, fmt.Errorf("%w: unrecognized scheme in %q", ErrInvalidTEI, raw)
}

func decodeTEIValue(p *ParsedTEI) error {
	switch p.Type {
	case "purl":
		// Try unpadded Base64URL (spec canonical form)
		decodedBytes, err := base64.RawURLEncoding.DecodeString(p.RawValue)
		if err == nil && len(decodedBytes) > 0 {
			p.PURL = string(decodedBytes)
			return nil
		}

		// Try padded Base64URL
		decodedBytes, err = base64.URLEncoding.DecodeString(p.RawValue)
		if err == nil && len(decodedBytes) > 0 {
			p.PURL = string(decodedBytes)
			return nil
		}

		// Try standard base64
		decodedBytes, err = base64.StdEncoding.DecodeString(p.RawValue)
		if err == nil && len(decodedBytes) > 0 && strings.HasPrefix(string(decodedBytes), "pkg:") {
			p.PURL = string(decodedBytes)
			return nil
		}

		// If value already starts with pkg: (or percent-encoded pkg%3A), accept directly
		val := p.RawValue
		if unescaped, uErr := url.QueryUnescape(val); uErr == nil && strings.HasPrefix(unescaped, "pkg:") {
			val = unescaped
		}
		if strings.HasPrefix(val, "pkg:") {
			p.PURL = val
			return nil
		}

		return fmt.Errorf("%w: invalid purl encoding in %q", ErrInvalidTEI, p.RawValue)

	case "uuid":
		u, err := uuid.Parse(p.RawValue)
		if err != nil {
			return fmt.Errorf("%w: invalid uuid %q: %v", ErrInvalidTEI, p.RawValue, err)
		}
		p.UUID = u.String()
		return nil

	default:
		// Accept other types as opaque identifier values
		return nil
	}
}

// CleanPURL trims whitespace and optional percent-encoding from a PURL string.
func CleanPURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if unescaped, err := url.QueryUnescape(raw); err == nil && strings.HasPrefix(unescaped, "pkg:") {
		return unescaped
	}
	return raw
}
