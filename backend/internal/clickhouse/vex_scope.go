package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// ResolveSBOMByProductRef maps an OpenVEX product identifier to an SBOM (#350).
//
// A VEX statement's product @id names the deliverable an SBOM describes.
// Producers use different identity schemes, so the lookup tries, in order of
// trustworthiness:
//
//  1. sbom_id — the caller already knows the SBOM (explicit upload mapping).
//  2. source_repo — the normalised repository URL (#332); VEXViper and other
//     repo-scoped producers emit the repo URL as the product IRI.
//  3. document_namespace / document_name — SPDX document identity, for
//     producers that reference the SBOM document itself.
//
// Returns "" when nothing matches — the statement is then stored unscoped
// (global), preserving pre-#350 behaviour for component-style VEX documents.
func (c *Client) ResolveSBOMByProductRef(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return "", nil
	}
	var sbomID string
	err := c.Conn.QueryRow(ctx, `
		SELECT toString(sbom_id)
		FROM sboms FINAL
		WHERE toString(sbom_id) = ?
		   OR (source_repo != '' AND source_repo = ?)
		   OR (document_namespace != '' AND document_namespace = ?)
		   OR (document_name != '' AND document_name = ?)
		ORDER BY ingested_at DESC
		LIMIT 1
	`, ref, ref, ref, ref).Scan(&sbomID)
	if err != nil {
		// No rows is not an error for the caller: it means "global".
		if isNoRows(err) {
			return "", nil
		}
		// clickhouse-go returns io.EOF-ish errors for empty result sets
		// depending on the protocol path; treat scan failures on empty
		// results as "no match" and let real connection errors surface.
		return "", fmt.Errorf("failed to resolve SBOM for product ref %q: %w", ref, err)
	}
	return sbomID, nil
}

// QuerySBOMVEXStatements lists the VEX statements scoped to one SBOM (#350).
// Unscoped ("global") statements are not returned: a statement without a
// resolved product scope says nothing about this SBOM.
func (c *Client) QuerySBOMVEXStatements(ctx context.Context, sbomID string) ([]dto.VEXStatementItem, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT vex_id, document_id, source_file, sbom_id, product_purl,
			   vuln_id, status, justification, impact_statement,
			   action_statement, vex_timestamp, ingested_at,
			   author, role, tooling, status_notes
		FROM vex_statements FINAL
		WHERE sbom_id = ?
		ORDER BY vex_timestamp DESC
	`, sbomID)
	if err != nil {
		return nil, fmt.Errorf("failed to query vex statements for sbom %s: %w", sbomID, err)
	}
	defer rows.Close()

	var items []dto.VEXStatementItem
	for rows.Next() {
		var item dto.VEXStatementItem
		var vexTimestamp, ingestedAt time.Time
		if err := rows.Scan(
			&item.VEXID, &item.DocumentID, &item.SourceFile, &item.SBOMID, &item.ProductPURL,
			&item.VulnID, &item.Status, &item.Justification, &item.ImpactStatement,
			&item.ActionStatement, &vexTimestamp, &ingestedAt,
			&item.Author, &item.Role, &item.Tooling, &item.StatusNotes,
		); err != nil {
			return nil, fmt.Errorf("failed to scan vex row: %w", err)
		}
		item.VEXTimestamp = vexTimestamp.Format(time.RFC3339)
		item.IngestedAt = ingestedAt.Format(time.RFC3339)
		items = append(items, item)
	}
	if items == nil {
		items = []dto.VEXStatementItem{}
	}
	return items, nil
}
