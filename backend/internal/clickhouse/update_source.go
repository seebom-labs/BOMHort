package clickhouse

import (
	"context"
	"fmt"
)

// UpdateSBOMSource sets source_repo/source_ref on an existing SBOM row (#332,
// PATCH /api/v1/sboms/{id}).
//
// This is a ClickHouse mutation (ALTER TABLE … UPDATE), deliberately not the
// ReplacingMergeTree insert-a-newer-version idiom used elsewhere: sboms is
// versioned by ingested_at, so a replacement row would need a fresh
// ingested_at to win the merge — silently rewriting *when the SBOM was
// ingested* just to change *where its source lives*. Reporting keyed on
// ingest time would drift with every PATCH.
//
// Mutations are heavyweight per statement but PATCHes are rare (manual pins
// for the documents whose extraction failed), and mutations_sync=1 makes the
// change durable before the handler responds — a client that PATCHes and
// immediately GETs must see its own write, eventual consistency here would
// look like data loss.
func (c *Client) UpdateSBOMSource(ctx context.Context, sbomID, sourceRepo, sourceRef string) error {
	// Existence check first: a mutation on a non-existent sbom_id succeeds
	// as a no-op, and the handler needs a 404 to tell the caller they typoed
	// the ID rather than a 200 that changed nothing.
	var count uint64
	if err := c.Conn.QueryRow(ctx,
		"SELECT count() FROM sboms FINAL WHERE sbom_id = ?", sbomID,
	).Scan(&count); err != nil {
		return fmt.Errorf("failed to check sbom %s: %w", sbomID, err)
	}
	if count == 0 {
		return ErrSBOMNotFound
	}

	if err := c.Conn.Exec(ctx, `
		ALTER TABLE sboms
		UPDATE source_repo = ?, source_ref = ?
		WHERE sbom_id = ?
		SETTINGS mutations_sync = 1`,
		sourceRepo, sourceRef, sbomID,
	); err != nil {
		return fmt.Errorf("failed to update source for sbom %s: %w", sbomID, err)
	}
	return nil
}

// ErrSBOMNotFound signals a PATCH against an unknown sbom_id.
var ErrSBOMNotFound = fmt.Errorf("sbom not found")

// QuerySBOMSource reads the current source attribution of one SBOM, so a
// partial PATCH can preserve whichever field the caller did not send.
func (c *Client) QuerySBOMSource(ctx context.Context, sbomID string) (repo, ref string, err error) {
	err = c.Conn.QueryRow(ctx,
		"SELECT source_repo, source_ref FROM sboms FINAL WHERE sbom_id = ? LIMIT 1", sbomID,
	).Scan(&repo, &ref)
	if err != nil {
		if isNoRows(err) {
			return "", "", ErrSBOMNotFound
		}
		return "", "", fmt.Errorf("failed to read source for sbom %s: %w", sbomID, err)
	}
	return repo, ref, nil
}
