package clickhouse

import (
	"context"
	"errors"
	"fmt"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// ErrDocumentNotStored is returned by QueryStoredDocument when no original
// has been captured for the SBOM (ingested before #256 or with the store
// disabled).
var ErrDocumentNotStored = errors.New("no stored original for sbom")

// InsertStoredDocument records the reference to an original SBOM document
// captured by the parsing worker (#256). ReplacingMergeTree(stored_at) on
// sbom_id means a re-capture simply supersedes the previous row.
func (c *Client) InsertStoredDocument(ctx context.Context, doc *models.StoredDocument) error {
	batch, err := c.Conn.PrepareBatch(ctx,
		`INSERT INTO document_store (
			stored_at, sbom_id, cluster, namespace, project, source_file,
			storage_backend, storage_ref, sha256_hash, size_bytes, content_type,
			content_encoding, stored_size_bytes
		)`)
	if err != nil {
		return fmt.Errorf("failed to prepare document_store batch: %w", err)
	}

	if err := batch.Append(
		doc.StoredAt,
		doc.SBOMID,
		doc.Cluster,
		doc.Namespace,
		doc.Project,
		doc.SourceFile,
		doc.StorageBackend,
		doc.StorageRef,
		doc.SHA256Hash,
		doc.SizeBytes,
		doc.ContentType,
		doc.ContentEncoding,
		doc.StoredSizeBytes,
	); err != nil {
		return fmt.Errorf("failed to append document_store row: %w", err)
	}

	return batch.Send()
}

// QueryStoredDocument returns the latest stored-original reference for an
// SBOM, or ErrDocumentNotStored when none exists.
func (c *Client) QueryStoredDocument(ctx context.Context, sbomID string) (*models.StoredDocument, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT stored_at, sbom_id, cluster, namespace, project, source_file,
		       storage_backend, storage_ref, sha256_hash, size_bytes, content_type,
		       content_encoding, stored_size_bytes
		FROM document_store FINAL
		WHERE sbom_id = ?
		ORDER BY stored_at DESC
		LIMIT 1`, sbomID)
	if err != nil {
		return nil, fmt.Errorf("failed to query document_store for sbom %s: %w", sbomID, err)
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("failed to read document_store row for sbom %s: %w", sbomID, err)
		}
		return nil, ErrDocumentNotStored
	}

	var doc models.StoredDocument
	if err := rows.Scan(
		&doc.StoredAt,
		&doc.SBOMID,
		&doc.Cluster,
		&doc.Namespace,
		&doc.Project,
		&doc.SourceFile,
		&doc.StorageBackend,
		&doc.StorageRef,
		&doc.SHA256Hash,
		&doc.SizeBytes,
		&doc.ContentType,
		&doc.ContentEncoding,
		&doc.StoredSizeBytes,
	); err != nil {
		return nil, fmt.Errorf("failed to scan document_store row for sbom %s: %w", sbomID, err)
	}
	return &doc, nil
}
