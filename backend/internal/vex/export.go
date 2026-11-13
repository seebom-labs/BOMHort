package vex

import (
	"sort"
	"strings"
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
)

// ExportStatement is one effective VEX decision to hand out (#533): the
// newest statement BOMHort holds for a vulnerability in one component of one
// SBOM.
type ExportStatement struct {
	// Product is the OpenVEX product @id: the SBOM's document namespace, or
	// its sbom_id when it has none. Both resolve back to the same SBOM when
	// the document is uploaded again.
	Product string
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
	Timestamp  string            `json:"timestamp,omitempty"`
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
	Subcomponents []exportComponent `json:"subcomponents,omitempty"`
}

type exportComponent struct {
	ID string `json:"@id"`
}

// Export renders statements as one OpenVEX document.
//
// The output depends only on the statements: they are sorted, @id is a
// UUIDv5 of their content, and the document timestamp is the newest
// statement's. Every statement carries its own timestamp, so the document
// timestamp is never a fallback for one that has none. Exporting unchanged
// data twice therefore yields the same bytes.
//
// OpenVEX records author, role and tooling per document, not per statement.
// When every statement shares a value it is kept; otherwise author is
// "BOMHort" and role/tooling are left out. The per-statement provenance
// stays available in the JSON statement listing.
func Export(stmts []ExportStatement) ([]byte, error) {
	out := make([]exportStatement, len(stmts))
	var latest time.Time
	for i, s := range stmts {
		product := exportProduct{ID: s.Product}
		if s.PURL != "" && s.PURL != models.VEXProductWide {
			product.Subcomponents = []exportComponent{{ID: s.PURL}}
		}
		out[i] = exportStatement{
			Vulnerability:   exportVulnerability{Name: s.VulnID, Aliases: aliasesWithout(s.Aliases, s.VulnID)},
			Timestamp:       s.Timestamp.UTC().Format(time.RFC3339),
			Products:        []exportProduct{product},
			Status:          s.Status,
			StatusNotes:     s.StatusNotes,
			Justification:   s.Justification,
			ImpactStatement: s.ImpactStatement,
			ActionStatement: s.ActionStatement,
		}
		if s.Timestamp.After(latest) {
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
	var content strings.Builder
	for i, idx := range order {
		sorted[i] = out[idx]
		content.WriteString(keys[idx])
		content.WriteByte('\n')
	}

	doc := exportDocument{
		Context:    openVEXContext,
		ID:         "urn:uuid:" + uuid.NewSHA1(uuid.NameSpaceURL, []byte(content.String())).String(),
		Author:     shared(stmts, func(s ExportStatement) string { return s.Author }),
		Role:       shared(stmts, func(s ExportStatement) string { return s.Role }),
		Tooling:    shared(stmts, func(s ExportStatement) string { return s.Tooling }),
		Version:    1,
		Statements: sorted,
	}
	if doc.Author == "" {
		doc.Author = exportAuthor
	}
	// An empty export has no decision whose time it could carry.
	if !latest.IsZero() {
		doc.Timestamp = latest.UTC().Format(time.RFC3339)
	}
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
	var out []string
	for _, a := range aliases {
		if a != "" && a != id {
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}
