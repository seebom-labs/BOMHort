package tea

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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
	Vulnerability   openVEXVuln `json:"vulnerability"`
	Products        []string    `json:"products"`
	Status          string      `json:"status"`
	Justification   string      `json:"justification,omitempty"`
	ImpactStatement string      `json:"impact_statement,omitempty"`
	ActionStatement string      `json:"action_statement,omitempty"`
	StatusNotes     string      `json:"status_notes,omitempty"`
}

type openVEXVuln struct {
	Name string `json:"name"`
}

func buildOpenVEXArtifactData(sbomID string, stmts []models.VEXStatement) (*ArtifactData, error) {
	doc := openVEXDoc{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         fmt.Sprintf("https://bomhort.local/vex/%s", sbomID),
		Author:     "BOMHort",
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Version:    1,
		Tooling:    "BOMHort TEA Server",
		Statements: make([]openVEXStatement, 0, len(stmts)),
	}

	for _, s := range stmts {
		stmt := openVEXStatement{
			Vulnerability:   openVEXVuln{Name: s.VulnID},
			Products:        []string{s.ProductPURL},
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
