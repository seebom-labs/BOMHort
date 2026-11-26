package clickhouse

import (
	"context"
	"fmt"
	"strings"
)

// UpdateSBOMSource sets source_repo, source_ref, and/or tags on an existing SBOM row (#332, #636,
// PATCH /api/v1/sboms/{id}).
//
// Only non-nil columns are updated, which prevents concurrent partial PATCH requests from
// overwriting each other in a read-modify-write race.
//
// This is a ClickHouse mutation (ALTER TABLE … UPDATE), deliberately not the
// ReplacingMergeTree insert-a-newer-version idiom used elsewhere: sboms is
// versioned by ingested_at, so a replacement row would need a fresh
// ingested_at to win the merge — silently rewriting *when the SBOM was
// ingested* just to change *where its source lives*. Reporting keyed on
// ingest time would drift with every PATCH.
//
// Mutations are heavyweight per statement but PATCHes are rare (manual pins
// for the documents whose extraction failed or tag updates), and mutations_sync=1 makes the
// change durable before the handler responds — a client that PATCHes and
// immediately GETs must see its own write, eventual consistency here would
// look like data loss.
func (c *Client) UpdateSBOMSource(ctx context.Context, sbomID string, sourceRepo, sourceRef *string, tags *[]string) error {
	if sourceRepo == nil && sourceRef == nil && tags == nil {
		return nil
	}

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

	var setClauses []string
	var args []any

	if sourceRepo != nil {
		setClauses = append(setClauses, "source_repo = ?")
		args = append(args, *sourceRepo)
	}
	if sourceRef != nil {
		setClauses = append(setClauses, "source_ref = ?")
		args = append(args, *sourceRef)
	}
	if tags != nil {
		tagVals := *tags
		if tagVals == nil {
			tagVals = []string{}
		}
		setClauses = append(setClauses, "tags = ?")
		args = append(args, tagVals)
	}

	if len(setClauses) == 0 {
		return nil
	}

	args = append(args, sbomID)
	query := fmt.Sprintf(`
		ALTER TABLE sboms
		UPDATE %s
		WHERE sbom_id = ?
		SETTINGS mutations_sync = 1`,
		strings.Join(setClauses, ", "),
	)

	if err := c.Conn.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("failed to update source for sbom %s: %w", sbomID, err)
	}
	return nil
}

// ErrSBOMNotFound signals a PATCH against an unknown sbom_id.
var ErrSBOMNotFound = fmt.Errorf("sbom not found")

// QuerySBOMSource reads the current source attribution and tags of one SBOM, so a
// partial PATCH can preserve whichever fields the caller did not send.
func (c *Client) QuerySBOMSource(ctx context.Context, sbomID string) (repo, ref string, tags []string, err error) {
	err = c.Conn.QueryRow(ctx,
		"SELECT source_repo, source_ref, tags FROM sboms FINAL WHERE sbom_id = ? LIMIT 1", sbomID,
	).Scan(&repo, &ref, &tags)
	if err != nil {
		if isNoRows(err) {
			return "", "", nil, ErrSBOMNotFound
		}
		return "", "", nil, fmt.Errorf("failed to read source for sbom %s: %w", sbomID, err)
	}
	return repo, ref, tags, nil
}
