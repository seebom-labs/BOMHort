package vex

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// OpenVEXDocument represents the top-level structure of an OpenVEX document.
// Spec: https://github.com/openvex/spec
type OpenVEXDocument struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Role       string         `json:"role"`
	Timestamp  string         `json:"timestamp"`
	Version    int            `json:"version"`
	Statements []VEXStatement `json:"statements"`
}

// VEXStatement represents a single VEX statement in an OpenVEX document.
type VEXStatement struct {
	Vulnerability   VEXVulnerability `json:"vulnerability"`
	Products        []VEXProduct     `json:"products"`
	Status          string           `json:"status"`
	Justification   string           `json:"justification,omitempty"`
	ImpactStatement string           `json:"impact_statement,omitempty"`
	ActionStatement string           `json:"action_statement,omitempty"`
	Timestamp       string           `json:"timestamp,omitempty"`
}

// VEXVulnerability references a vulnerability by ID.
type VEXVulnerability struct {
	ID          string   `json:"@id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
}

// VEXProduct identifies a product, typically by PURL.
type VEXProduct struct {
	ID          string            `json:"@id"`
	Identifiers map[string]string `json:"identifiers,omitempty"`
}

// ParseResult holds extracted VEX statements ready for ClickHouse insertion.
type ParseResult struct {
	DocumentID string
	Statements []models.VEXStatement
}

// ParseFile opens and parses an OpenVEX JSON file.
func ParseFile(path, sourceFile string) (*ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open VEX file %s: %w", path, err)
	}
	defer f.Close()

	return Parse(f, sourceFile)
}

// Parse reads an OpenVEX JSON document from a reader and extracts models.
//
// Parse is hardened against malformed input: the underlying goccy/go-json
// decoder can panic on adversarial byte sequences. We recover from any
// panic and surface it as a regular error so callers — including the
// FuzzParse harness — observe deterministic, non-fatal failures.
func Parse(r io.Reader, sourceFile string) (out *ParseResult, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			out = nil
			err = fmt.Errorf("panic while parsing OpenVEX JSON: %v", rec)
		}
	}()

	var doc OpenVEXDocument

	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode OpenVEX JSON: %w", err)
	}

	// Validate it's actually a VEX document.
	if doc.Context == "" && len(doc.Statements) == 0 {
		return nil, fmt.Errorf("not a valid OpenVEX document: missing @context and statements")
	}

	now := time.Now()
	var result []models.VEXStatement

	for _, stmt := range doc.Statements {
		// Determine the vulnerability ID.
		vulnID := stmt.Vulnerability.Name
		if vulnID == "" {
			vulnID = stmt.Vulnerability.ID
		}
		if vulnID == "" && len(stmt.Vulnerability.Aliases) > 0 {
			vulnID = stmt.Vulnerability.Aliases[0]
		}
		if vulnID == "" {
			continue // Skip statements without a vulnerability reference
		}

		// Normalize: if vulnID is a URL, extract the last path segment.
		// e.g. "https://pkg.go.dev/vuln/GO-2025-4188" → "GO-2025-4188"
		// e.g. "https://github.com/advisories/GHSA-xxxx" → "GHSA-xxxx"
		vulnID = normalizeVulnID(vulnID)

		// Parse statement timestamp.
		stmtTime := now
		if stmt.Timestamp != "" {
			if t, err := time.Parse(time.RFC3339, stmt.Timestamp); err == nil {
				stmtTime = t
			}
		} else if doc.Timestamp != "" {
			if t, err := time.Parse(time.RFC3339, doc.Timestamp); err == nil {
				stmtTime = t
			}
		}

		// Create a VEX statement for each product.
		for _, product := range stmt.Products {
			purl := extractPURL(product)
			if purl == "" {
				continue // Skip products without a PURL
			}

			// Generate a deterministic VEX ID from the document, vulnerability, and product.
			vexID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(doc.ID+"|"+vulnID+"|"+purl))

			result = append(result, models.VEXStatement{
				IngestedAt:      now,
				VEXID:           vexID,
				DocumentID:      doc.ID,
				SourceFile:      sourceFile,
				ProductPURL:     purl,
				VulnID:          vulnID,
				Status:          stmt.Status,
				Justification:   stmt.Justification,
				ImpactStatement: stmt.ImpactStatement,
				ActionStatement: stmt.ActionStatement,
				VEXTimestamp:    stmtTime,
			})
		}
	}

	return &ParseResult{
		DocumentID: doc.ID,
		Statements: result,
	}, nil
}

// extractPURL extracts the PURL from a VEX product.
// Products can specify PURLs in @id directly or in identifiers.purl.
func extractPURL(p VEXProduct) string {
	// Check identifiers map first (explicit purl key).
	if purl, ok := p.Identifiers["purl"]; ok && purl != "" {
		return purl
	}
	// Fall back to @id if it looks like a PURL.
	if len(p.ID) > 4 && p.ID[:4] == "pkg:" {
		return p.ID
	}
	return p.ID // Return @id as-is; may be a PURL or other identifier
}

// normalizeVulnID extracts a vulnerability ID from a URL or returns it as-is.
// Examples:
//
//	"https://pkg.go.dev/vuln/GO-2025-4188"            → "GO-2025-4188"
//	"https://github.com/advisories/GHSA-xxxx-yyyy"    → "GHSA-xxxx-yyyy"
//	"https://nvd.nist.gov/vuln/detail/CVE-2024-1234"  → "CVE-2024-1234"
//	"GO-2025-4188"                                     → "GO-2025-4188"
func normalizeVulnID(id string) string {
	if strings.HasPrefix(id, "http://") || strings.HasPrefix(id, "https://") {
		// Extract last path segment.
		if idx := strings.LastIndex(id, "/"); idx >= 0 && idx < len(id)-1 {
			return id[idx+1:]
		}
	}
	return id
}
