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
	Tooling    string         `json:"tooling"`
	Timestamp  string         `json:"timestamp"`
	Version    int            `json:"version"`
	Statements []VEXStatement `json:"statements"`
}

// VEXStatement represents a single VEX statement in an OpenVEX document.
type VEXStatement struct {
	Vulnerability   VEXVulnerability `json:"vulnerability"`
	Products        []VEXProduct     `json:"products"`
	Status          string           `json:"status"`
	StatusNotes     string           `json:"status_notes,omitempty"`
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

// VEXProduct identifies a product, typically by PURL or IRI. Per the OpenVEX
// spec the product is the deliverable an SBOM describes; the vulnerable
// library inside it is listed under subcomponents.
type VEXProduct struct {
	ID            string            `json:"@id"`
	Identifiers   map[string]string `json:"identifiers,omitempty"`
	Subcomponents []VEXSubcomponent `json:"subcomponents,omitempty"`
}

// VEXSubcomponent references the vulnerable component within a product.
type VEXSubcomponent struct {
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

		// Create VEX statements per product. Three shapes exist in the wild
		// (#350):
		//
		//  1. Spec shape with components: product = the deliverable (what an
		//     SBOM describes), subcomponents = the vulnerable libraries. The
		//     subcomponent purl is what matches vulnerabilities.purl; the
		//     product @id identifies the SBOM.
		//  2. Spec shape without components: product only, no subcomponents.
		//     The status covers the product as a whole — "this application is
		//     not affected", whichever library carries the flaw. There is no
		//     component purl to match, so the statement is flagged product-wide
		//     and the worker rewrites ProductPURL to models.VEXProductWide once
		//     the product resolves to an SBOM. Without this the statement was
		//     stored with product_purl = the product IRI, which no
		//     vulnerabilities.purl can ever equal, and it suppressed nothing.
		//  3. Component shape (Trivy et al.): product = the vulnerable
		//     component purl directly, no subcomponents.
		//
		// Shapes 2 and 3 are told apart by the worker, not here: only the
		// sboms lookup can say whether a ref names a product or a component.
		for _, product := range stmt.Products {
			// The product's identity is its @id (the purl identifier only
			// when it has none): it scopes the statement to an SBOM and keeps
			// two products apart that share a purl identifier.
			productRef := productIdentity(product)
			// Without subcomponents the product itself is what the statement
			// names: product-wide if the ref resolves to an SBOM, otherwise
			// the matched component, preferring its purl identifier.
			matchPURLs := []string{extractPURL(product)}
			productWide := true
			if len(product.Subcomponents) > 0 {
				productWide = false
				matchPURLs = matchPURLs[:0]
				for _, sub := range product.Subcomponents {
					if p := extractSubcomponentPURL(sub); p != "" {
						matchPURLs = append(matchPURLs, p)
					}
				}
			}
			for _, purl := range matchPURLs {
				if purl == "" {
					continue // Skip products without a PURL
				}

				// Deterministic VEX ID from the document, vulnerability,
				// product and component. The product is part of it because
				// vex_id is part of the table's ReplacingMergeTree key: one
				// document stating the same vulnerability for the same
				// component in two products (two versions, two images) would
				// otherwise produce one key, and ClickHouse would keep only
				// one of the two statements.
				vexID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(doc.ID+"|"+vulnID+"|"+productRef+"|"+purl))

				result = append(result, models.VEXStatement{
					IngestedAt:      now,
					VEXID:           vexID,
					DocumentID:      doc.ID,
					SourceFile:      sourceFile,
					ProductRef:      productRef,
					ProductWide:     productWide,
					ProductPURL:     purl,
					VulnID:          vulnID,
					Status:          stmt.Status,
					Justification:   stmt.Justification,
					ImpactStatement: stmt.ImpactStatement,
					ActionStatement: stmt.ActionStatement,
					VEXTimestamp:    stmtTime,
					// Provenance (#334): author/role/tooling live on the
					// document in OpenVEX; status_notes on the statement.
					Author:      doc.Author,
					Role:        doc.Role,
					Tooling:     doc.Tooling,
					StatusNotes: stmt.StatusNotes,
				})
			}
		}
	}

	return &ParseResult{
		DocumentID: doc.ID,
		Statements: newestPerKey(result),
	}, nil
}

// newestPerKey keeps one statement per id. A document may state the same
// vulnerability for the same product and component more than once, as its
// assessment changed; all of them share an id, and so a storage key
// (vex_statements orders by vuln_id, product_purl, vex_id), and they are
// ingested with the same ingested_at, which leaves the ReplacingMergeTree to
// keep whichever row was inserted last rather than the newest decision. The
// statement with the latest timestamp is kept; on equal timestamps the later
// one in the document.
func newestPerKey(stmts []models.VEXStatement) []models.VEXStatement {
	out := make([]models.VEXStatement, 0, len(stmts))
	at := make(map[uuid.UUID]int, len(stmts))
	for _, s := range stmts {
		i, seen := at[s.VEXID]
		if !seen {
			at[s.VEXID] = len(out)
			out = append(out, s)
			continue
		}
		if !s.VEXTimestamp.Before(out[i].VEXTimestamp) {
			out[i] = s
		}
	}
	return out
}

// productIdentity is the product's @id, or its purl identifier when it has
// no @id.
func productIdentity(p VEXProduct) string {
	if id := strings.TrimSpace(p.ID); id != "" {
		return id
	}
	return p.Identifiers["purl"]
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

// extractSubcomponentPURL extracts the PURL from a VEX subcomponent.
func extractSubcomponentPURL(sc VEXSubcomponent) string {
	if purl, ok := sc.Identifiers["purl"]; ok && purl != "" {
		return purl
	}
	return sc.ID
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
