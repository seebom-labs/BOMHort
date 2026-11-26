package clickhouse

import (
	"context"
	"fmt"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

type TEASnapshotRef struct {
	CollectionVersion uint64
	VEXVersion        uint64
	StorageRef        string
	SHA256Hash        string
}

func (c *Client) InsertTEASnapshot(ctx context.Context, sbom *models.SBOM, ref TEASnapshotRef) error {
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO tea_snapshots
		(sbom_id, cluster, namespace, project, collection_version, vex_version, storage_ref, sha256_hash)`)
	if err != nil {
		return fmt.Errorf("prepare TEA snapshot index: %w", err)
	}
	if err := batch.Append(sbom.SBOMID, sbom.Cluster, sbom.Namespace, sbom.Project,
		ref.CollectionVersion, ref.VEXVersion, ref.StorageRef, ref.SHA256Hash); err != nil {
		return fmt.Errorf("append TEA snapshot index: %w", err)
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("insert TEA snapshot index: %w", err)
	}
	return nil
}

func (c *Client) QueryTEASnapshot(ctx context.Context, sbomID string, collectionVersion, vexVersion uint64) (*TEASnapshotRef, error) {
	query := `SELECT collection_version, vex_version, storage_ref, sha256_hash FROM tea_snapshots WHERE sbom_id = ?`
	args := []any{sbomID}
	if collectionVersion != 0 {
		query += ` AND collection_version = ?`
		args = append(args, collectionVersion)
	}
	if vexVersion != 0 {
		query += ` AND vex_version = ?`
		args = append(args, vexVersion)
	}
	query += ` ORDER BY collection_version DESC LIMIT 1`
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query TEA snapshot index: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	var ref TEASnapshotRef
	if err := rows.Scan(&ref.CollectionVersion, &ref.VEXVersion, &ref.StorageRef, &ref.SHA256Hash); err != nil {
		return nil, fmt.Errorf("read TEA snapshot index: %w", err)
	}
	return &ref, nil
}

func (c *Client) QueryTEASnapshotPage(ctx context.Context, sbomID string, maxVersion, limit, offset uint64) ([]TEASnapshotRef, error) {
	rows, err := c.Conn.Query(ctx, `SELECT DISTINCT collection_version, vex_version, storage_ref, sha256_hash
		FROM tea_snapshots WHERE sbom_id = ? AND collection_version <= ?
		ORDER BY collection_version DESC LIMIT ? OFFSET ?`, sbomID, maxVersion, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query TEA snapshot page: %w", err)
	}
	defer rows.Close()
	var refs []TEASnapshotRef
	for rows.Next() {
		var ref TEASnapshotRef
		if err := rows.Scan(&ref.CollectionVersion, &ref.VEXVersion, &ref.StorageRef, &ref.SHA256Hash); err != nil {
			return nil, fmt.Errorf("read TEA snapshot page: %w", err)
		}
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read TEA snapshot page: %w", err)
	}
	return refs, nil
}
