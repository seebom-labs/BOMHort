package clickhouse

import (
	"context"
	"fmt"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// QueryUnscopedVEXStatements returns every statement without an SBOM scope
// (sbom_id = ”), fully hydrated so the caller can re-insert corrected copies.
//
// These are the statements whose product @id did not resolve at ingest time —
// typically because the VEX document arrived before the SBOM it talks about.
// They suppress nothing until rescued (#350).
func (c *Client) QueryUnscopedVEXStatements(ctx context.Context) ([]models.VEXStatement, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT ingested_at, vex_id, document_id, source_file,
			   product_ref, product_purl, vuln_id, status, justification,
			   impact_statement, action_statement, vex_timestamp,
			   author, role, tooling, status_notes,
			   cluster, namespace, project
		FROM vex_statements FINAL
		WHERE sbom_id = ''
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query unscoped vex statements: %w", err)
	}
	defer rows.Close()

	var stmts []models.VEXStatement
	for rows.Next() {
		var s models.VEXStatement
		if err := rows.Scan(
			&s.IngestedAt, &s.VEXID, &s.DocumentID, &s.SourceFile,
			&s.ProductRef, &s.ProductPURL, &s.VulnID, &s.Status, &s.Justification,
			&s.ImpactStatement, &s.ActionStatement, &s.VEXTimestamp,
			&s.Author, &s.Role, &s.Tooling, &s.StatusNotes,
			&s.Cluster, &s.Namespace, &s.Project,
		); err != nil {
			return nil, fmt.Errorf("failed to scan unscoped vex statement: %w", err)
		}
		// Rows written before migration 020 carry no product_ref; for the
		// shapes that can be rescued at all (product-wide and component) the
		// ref equals the stored purl.
		if s.ProductRef == "" {
			s.ProductRef = s.ProductPURL
		}
		stmts = append(stmts, s)
	}
	return stmts, rows.Err()
}

// VEXDocumentUnscopedCount reports how many of a document's statements are
// still unscoped. The idempotency guard uses it: a fully scoped document is
// skipped on re-encounter, one with unscoped statements is re-processed so a
// now-present SBOM can pick them up.
func (c *Client) VEXDocumentUnscopedCount(ctx context.Context, documentID string) (uint64, error) {
	var count uint64
	if err := c.Conn.QueryRow(ctx,
		"SELECT count() FROM vex_statements FINAL WHERE document_id = ? AND sbom_id = ''",
		documentID,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count unscoped statements for %s: %w", documentID, err)
	}
	return count, nil
}

// DeleteVEXDocument removes every statement of one document, so a re-processed
// document replaces its rows instead of accumulating stale unscoped copies.
// vex_ids are deterministic (SHA1 of doc|vuln|purl), so a racing worker that
// re-inserts concurrently converges on the same rows.
func (c *Client) DeleteVEXDocument(ctx context.Context, documentID string) error {
	if err := c.Conn.Exec(ctx,
		"ALTER TABLE vex_statements DELETE WHERE document_id = ? SETTINGS mutations_sync = 1",
		documentID,
	); err != nil {
		return fmt.Errorf("failed to delete vex document %s: %w", documentID, err)
	}
	return nil
}

// DeleteUnscopedVEXStatements removes the unscoped rows for the given vex_ids.
// Used by the rescue pass after re-inserting the scoped copies: product_purl
// is part of the ORDER BY key, so the corrected row does not replace the old
// one and the unscoped original has to go explicitly. The sbom_id = ”
// predicate makes the delete idempotent — it can never touch a scoped row.
func (c *Client) DeleteUnscopedVEXStatements(ctx context.Context, vexIDs []string) error {
	if len(vexIDs) == 0 {
		return nil
	}
	if err := c.Conn.Exec(ctx,
		"ALTER TABLE vex_statements DELETE WHERE sbom_id = '' AND toString(vex_id) IN (?) SETTINGS mutations_sync = 1",
		vexIDs,
	); err != nil {
		return fmt.Errorf("failed to delete %d unscoped vex statements: %w", len(vexIDs), err)
	}
	return nil
}
