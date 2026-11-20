package vex

import (
	"sort"
	"time"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

const (
	openVEXContext = "https://openvex.dev/ns/v0.2.0"
	// exportAuthor is the document author when the exported statements do
	// not share one: the document is then BOMHort's compilation.
	exportAuthor = "BOMHort"

	// OpenVEX requires an action statement for affected and a justification
	// or impact statement for not_affected. A stored decision without one is
	// exported with these, so the document stays valid and says plainly that
	// nothing was recorded.
	missingActionStatement = "No action statement was recorded."
	missingImpactStatement = "No justification or impact statement was recorded."
)

// openVEXStatuses are the statuses OpenVEX v0.2.0 defines.
var openVEXStatuses = map[string]bool{
	models.VEXStatusNotAffected: true,
	"affected":                  true,
	"fixed":                     true,
	"under_investigation":       true,
}

// ExportStatement is one effective VEX decision to hand out (#533).
type ExportStatement struct {
	// Product is the OpenVEX product @id, unique per SBOM
	// (urn:uuid:<sbom_id>), so the document resolves back to exactly that
	// SBOM when it is uploaded again.
	Product string
	// ProductPURL identifies the product for downstream consumers (the
	// SBOM's root purl); exported as identifiers.purl when known.
	ProductPURL string
	// PURL is the component; models.VEXProductWide means the statement covers
	// the whole product.
	PURL            string
	VulnID          string
	Aliases         []string
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
	StatusNotes     string
	Timestamp       time.Time
	Author          string
	Role            string
	Tooling         string
}

type exportDocument struct {
	Context    string            `json:"@context"`
	ID         string            `json:"@id"`
	Author     string            `json:"author"`
	Role       string            `json:"role,omitempty"`
	Tooling    string            `json:"tooling,omitempty"`
	Timestamp  string            `json:"timestamp"`
	Version    int               `json:"version"`
	Statements []exportStatement `json:"statements"`
}

type exportStatement struct {
	Vulnerability   exportVulnerability `json:"vulnerability"`
	Timestamp       string              `json:"timestamp"`
	Products        []exportProduct     `json:"products"`
	Status          string              `json:"status"`
	StatusNotes     string              `json:"status_notes,omitempty"`
	Justification   string              `json:"justification,omitempty"`
	ImpactStatement string              `json:"impact_statement,omitempty"`
	ActionStatement string              `json:"action_statement,omitempty"`
}

type exportVulnerability struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

type exportProduct struct {
	ID            string            `json:"@id"`
	Identifiers   map[string]string `json:"identifiers,omitempty"`
	Subcomponents []exportComponent `json:"subcomponents,omitempty"`
}

type exportComponent struct {
	ID string `json:"@id"`
}

// Export renders statements as one OpenVEX v0.2.0 document.
//
// The document always carries a timestamp: the newest statement's, or
// issued when there are none (the caller passes a stable time, such as the
// newest ingest of the exported SBOMs). Every statement carries its own
// timestamp, so the document timestamp is never a fallback for one.
// Statements with a status OpenVEX does not define are left out.
//
// The output depends only on its input: statements are sorted, and @id is a
// UUIDv5 of the whole document without it, so any change to an emitted field
// (provenance included) yields a new @id, while unchanged data yields the
// same bytes.
//
// OpenVEX records author, role and tooling per document, not per statement.
// When every statement shares a value it is kept; otherwise author is
// "BOMHort" and role/tooling are left out. The per-statement provenance
// stays available in the JSON statement listing.
func Export(stmts []ExportStatement, issued time.Time) ([]byte, error) {
	kept := make([]ExportStatement, 0, len(stmts))
	for _, s := range stmts {
		if openVEXStatuses[s.Status] {
			kept = append(kept, s)
		}
	}

	out := make([]exportStatement, len(kept))
	latest := issued
	for i, s := range kept {
		product := exportProduct{ID: s.Product}
		if s.ProductPURL != "" {
			product.Identifiers = map[string]string{"purl": s.ProductPURL}
		}
		if s.PURL != "" && s.PURL != models.VEXProductWide {
			product.Subcomponents = []exportComponent{{ID: s.PURL}}
		}
		st := exportStatement{
			Vulnerability:   exportVulnerability{Name: s.VulnID, Aliases: aliasesWithout(s.Aliases, s.VulnID)},
			Timestamp:       s.Timestamp.UTC().Format(time.RFC3339),
			Products:        []exportProduct{product},
			Status:          s.Status,
			StatusNotes:     s.StatusNotes,
			Justification:   s.Justification,
			ImpactStatement: s.ImpactStatement,
			ActionStatement: s.ActionStatement,
		}
		switch st.Status {
		case "affected":
			if st.ActionStatement == "" {
				st.ActionStatement = missingActionStatement
			}
		case models.VEXStatusNotAffected:
			if st.Justification == "" && st.ImpactStatement == "" {
				st.ImpactStatement = missingImpactStatement
			}
		}
		out[i] = st
		if i == 0 || s.Timestamp.After(latest) {
			latest = s.Timestamp
		}
	}

	// Sort on the encoded statement so the order does not depend on the
	// query's; the encoding starts with the vulnerability name.
	keys := make([]string, len(out))
	for i := range out {
		b, err := json.Marshal(out[i])
		if err != nil {
			return nil, err
		}
		keys[i] = string(b)
	}
	order := make([]int, len(out))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool { return keys[order[i]] < keys[order[j]] })
	sorted := make([]exportStatement, len(out))
	for i, idx := range order {
		sorted[i] = out[idx]
	}

	doc := exportDocument{
		Context:    openVEXContext,
		Author:     shared(kept, func(s ExportStatement) string { return s.Author }),
		Role:       shared(kept, func(s ExportStatement) string { return s.Role }),
		Tooling:    shared(kept, func(s ExportStatement) string { return s.Tooling }),
		Timestamp:  latest.UTC().Format(time.RFC3339),
		Version:    1,
		Statements: sorted,
	}
	if doc.Author == "" {
		doc.Author = exportAuthor
	}
	identity, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	doc.ID = "urn:uuid:" + uuid.NewSHA1(uuid.NameSpaceURL, identity).String()
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// shared returns the value every statement has, or "" when they differ or
// there are none.
func shared(stmts []ExportStatement, field func(ExportStatement) string) string {
	if len(stmts) == 0 {
		return ""
	}
	v := field(stmts[0])
	for _, s := range stmts[1:] {
		if field(s) != v {
			return ""
		}
	}
	return v
}

func aliasesWithout(aliases []string, id string) []string {
	seen := map[string]bool{id: true}
	var out []string
	for _, a := range aliases {
		if a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}
