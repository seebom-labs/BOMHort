package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/docstore"
	"github.com/seebom-labs/bomhort/backend/internal/tea"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func (a *teaStoreAdapter) snapshotRef(sbomID string, version int, previous *tea.Snapshot) (string, error) {
	if a.docStore == nil {
		return "", fmt.Errorf("%w: not configured", tea.ErrSnapshotUnavailable)
	}
	if previous == nil {
		ref, err := docstore.ImmutableRef(a.docStore, fmt.Sprintf("tea/%s/%d.json", sbomID, version))
		if err != nil {
			return "", fmt.Errorf("%w: %w", tea.ErrSnapshotUnavailable, err)
		}
		return ref, nil
	}
	i := strings.LastIndexByte(previous.StorageRef, '/')
	if i < 0 {
		return "", errors.New("invalid TEA snapshot reference")
	}
	return fmt.Sprintf("%s/%d.json.gz", previous.StorageRef[:i], version), nil
}

func (a *teaStoreAdapter) readSnapshot(ctx context.Context, sbomID, ref, expectedHash string, version int) (*tea.Snapshot, []byte, error) {
	if a.docStore == nil {
		return nil, nil, fmt.Errorf("%w: not configured", tea.ErrSnapshotUnavailable)
	}
	rc, err := a.docStore.Get(ctx, ref)
	if err != nil {
		if errors.Is(err, docstore.ErrNotFound) {
			if expectedHash == "" {
				return nil, nil, err
			}
			return nil, nil, fmt.Errorf("%w: indexed snapshot is missing", tea.ErrSnapshotUnavailable)
		}
		return nil, nil, fmt.Errorf("%w: %w", tea.ErrSnapshotUnavailable, err)
	}
	defer rc.Close()
	raw, err := io.ReadAll(rc)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read: %w", tea.ErrSnapshotUnavailable, err)
	}
	if expectedHash != "" && docstore.SHA256Hex(raw) != expectedHash {
		return nil, nil, errors.New("TEA snapshot integrity check failed")
	}
	var snapshot tea.Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, nil, fmt.Errorf("decode TEA snapshot: %w", err)
	}
	if snapshot.Collection.UUID != sbomID || snapshot.Collection.Version != version {
		return nil, nil, errors.New("TEA snapshot identity does not match its index")
	}
	snapshot.StorageRef = ref
	return &snapshot, raw, nil
}

func (a *teaStoreAdapter) indexSnapshot(ctx context.Context, sbom *models.SBOM, snapshot *tea.Snapshot, raw []byte) error {
	vexVersion := 0
	if len(snapshot.VEXBytes) != 0 {
		vexVersion = snapshot.LastVEXVersion
	}
	return a.ch.InsertTEASnapshot(ctx, sbom, clickhouse.TEASnapshotRef{
		CollectionVersion: uint64(snapshot.Collection.Version),
		VEXVersion:        uint64(vexVersion),
		StorageRef:        snapshot.StorageRef,
		SHA256Hash:        docstore.SHA256Hex(raw),
	})
}

func (a *teaStoreAdapter) LatestSnapshot(ctx context.Context, sbom *models.SBOM) (*tea.Snapshot, error) {
	sbomID := sbom.SBOMID.String()
	ref, err := a.ch.QueryTEASnapshot(ctx, sbomID, 0, 0)
	if err != nil {
		return nil, err
	}
	var latest *tea.Snapshot
	if ref != nil {
		latest, _, err = a.readSnapshot(ctx, sbomID, ref.StorageRef, ref.SHA256Hash, int(ref.CollectionVersion))
		if err != nil {
			return nil, err
		}
	}
	for {
		version := 1
		if latest != nil {
			version = latest.Collection.Version + 1
		}
		nextRef, err := a.snapshotRef(sbomID, version, latest)
		if err != nil {
			return nil, err
		}
		next, raw, err := a.readSnapshot(ctx, sbomID, nextRef, "", version)
		if errors.Is(err, docstore.ErrNotFound) {
			return latest, nil
		}
		if err != nil {
			return nil, err
		}
		if err := docstore.SyncImmutable(a.docStore, nextRef); err != nil {
			return nil, fmt.Errorf("%w: %w", tea.ErrSnapshotUnavailable, err)
		}
		if err := a.indexSnapshot(ctx, sbom, next, raw); err != nil {
			return nil, err
		}
		latest = next
	}
}

func (a *teaStoreAdapter) GetSnapshot(ctx context.Context, sbomID string, collectionVersion, vexVersion int) (*tea.Snapshot, error) {
	ref, err := a.ch.QueryTEASnapshot(ctx, sbomID, uint64(collectionVersion), uint64(vexVersion))
	if err != nil {
		return nil, err
	}
	if ref == nil {
		return nil, tea.ErrNotFound
	}
	snapshot, _, err := a.readSnapshot(ctx, sbomID, ref.StorageRef, ref.SHA256Hash, int(ref.CollectionVersion))
	if err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (a *teaStoreAdapter) ListSnapshots(ctx context.Context, sbomID string, maxVersion, limit, offset uint64) ([]tea.Snapshot, error) {
	refs, err := a.ch.QueryTEASnapshotPage(ctx, sbomID, maxVersion, limit, offset)
	if err != nil {
		return nil, err
	}
	snapshots := make([]tea.Snapshot, 0, len(refs))
	for _, ref := range refs {
		snapshot, _, err := a.readSnapshot(ctx, sbomID, ref.StorageRef, ref.SHA256Hash, int(ref.CollectionVersion))
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, *snapshot)
	}
	return snapshots, nil
}

func (a *teaStoreAdapter) PublishSnapshot(ctx context.Context, sbom *models.SBOM, previous, next *tea.Snapshot) (bool, error) {
	ref, err := a.snapshotRef(sbom.SBOMID.String(), next.Collection.Version, previous)
	if err != nil {
		return false, err
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return false, fmt.Errorf("encode TEA snapshot: %w", err)
	}
	created, err := docstore.PutIfAbsent(ctx, a.docStore, ref, raw)
	if err != nil {
		return false, fmt.Errorf("%w: %w", tea.ErrSnapshotUnavailable, err)
	}
	if !created {
		return false, nil
	}
	next.StorageRef = ref
	if err := a.indexSnapshot(ctx, sbom, next, raw); err != nil {
		return false, err
	}
	return true, nil
}
