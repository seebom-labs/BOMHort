package tea

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

type openVEXDoc struct {
	Context    string             `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Timestamp  string             `json:"timestamp"`
	Version    int                `json:"version"`
	Tooling    string             `json:"tooling,omitempty"`
	Statements []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability   openVEXVuln  `json:"vulnerability"`
	Products        []vexProduct `json:"products"`
	Status          string       `json:"status"`
	Justification   string       `json:"justification,omitempty"`
	ImpactStatement string       `json:"impact_statement,omitempty"`
	ActionStatement string       `json:"action_statement,omitempty"`
	StatusNotes     string       `json:"status_notes,omitempty"`
}

type openVEXVuln struct {
	Name string `json:"name"`
}

type vexProduct struct {
	ID            string            `json:"@id"`
	Identifiers   map[string]string `json:"identifiers,omitempty"`
	Subcomponents []vexSubcomponent `json:"subcomponents,omitempty"`
}

type vexSubcomponent struct {
	ID          string            `json:"@id"`
	Identifiers map[string]string `json:"identifiers,omitempty"`
}

func buildOpenVEXArtifactData(sbomID string, stmts []models.VEXStatement, authority string, version int) (*ArtifactData, error) {
	if authority == "" {
		authority = "bomhort.local"
	}
	if version <= 0 {
		version = 1
	}

	// Deterministic timestamp from stored statements (never time.Now() so hashes are stable #534)
	var maxTime time.Time
	for _, s := range stmts {
		if s.VEXTimestamp.After(maxTime) {
			maxTime = s.VEXTimestamp
		}
		if s.IngestedAt.After(maxTime) {
			maxTime = s.IngestedAt
		}
	}
	if maxTime.IsZero() {
		maxTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	doc := openVEXDoc{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         fmt.Sprintf("https://%s/vex/%s", authority, sbomID),
		Author:     "BOMHort",
		Timestamp:  maxTime.UTC().Format(time.RFC3339),
		Version:    version,
		Tooling:    "BOMHort TEA Server",
		Statements: make([]openVEXStatement, 0, len(stmts)),
	}

	// Stable sort statements to guarantee identical serialization across downloads
	sorted := make([]models.VEXStatement, len(stmts))
	copy(sorted, stmts)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].VulnID != sorted[j].VulnID {
			return sorted[i].VulnID < sorted[j].VulnID
		}
		if sorted[i].ProductPURL != sorted[j].ProductPURL {
			return sorted[i].ProductPURL < sorted[j].ProductPURL
		}
		return sorted[i].Status < sorted[j].Status
	})

	for _, s := range sorted {
		prodRef := strings.TrimSpace(s.ProductRef)
		if prodRef == "" {
			prodRef = fmt.Sprintf("https://%s/sbom/%s", authority, sbomID)
		}

		var products []vexProduct
		if s.ProductWide || s.ProductPURL == models.VEXProductWide || s.ProductPURL == "*" || s.ProductPURL == prodRef {
			// Product-wide scope without subcomponents
			products = []vexProduct{
				{
					ID: prodRef,
				},
			}
		} else {
			// Deliverable product with specific vulnerable subcomponent
			products = []vexProduct{
				{
					ID: prodRef,
					Subcomponents: []vexSubcomponent{
						{
							ID: s.ProductPURL,
						},
					},
				},
			}
		}

		stmt := openVEXStatement{
			Vulnerability:   openVEXVuln{Name: s.VulnID},
			Products:        products,
			Status:          s.Status,
			Justification:   s.Justification,
			ImpactStatement: s.ImpactStatement,
			ActionStatement: s.ActionStatement,
			StatusNotes:     s.StatusNotes,
		}
		doc.Statements = append(doc.Statements, stmt)
	}

	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling openvex: %w", err)
	}

	h := sha256.Sum256(raw)
	shaHex := hex.EncodeToString(h[:])

	return &ArtifactData{
		Filename:    fmt.Sprintf("%s.openvex.json", sbomID),
		ContentType: MediaTypeOpenVEXJSON,
		SHA256Hash:  shaHex,
		SizeBytes:   uint64(len(raw)),
		Body:        io.NopCloser(bytes.NewReader(raw)),
	}, nil
}
