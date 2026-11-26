package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/docstore"
	"github.com/seebom-labs/bomhort/backend/internal/tea"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func TestTEASnapshotRecoveryIntegration(t *testing.T) {
	host := os.Getenv("CLICKHOUSE_HOST")
	if host == "" {
		t.Skip("CLICKHOUSE_HOST not set")
	}
	port, err := strconv.Atoi(os.Getenv("CLICKHOUSE_PORT"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{ClickHouseHost: host, ClickHousePort: port, ClickHouseDatabase: "bomhort", ClickHouseUser: "default"}
	ch, err := clickhouse.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	ds, err := docstore.NewFSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sbom := &models.SBOM{SBOMID: uuid.New(), Project: "tea-test"}
	ctx := context.Background()
	store := &teaStoreAdapter{ch: ch, docStore: ds}
	vexTime := time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC)
	ingestTime := vexTime.Add(time.Hour)
	if err := ch.Conn.Exec(ctx, `INSERT INTO vex_statements
		(vex_id, product_purl, vuln_id, status, vex_timestamp, ingested_at, sbom_id, product_ref, status_notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		uuid.New(), "pkg:golang/example/lib@1", "CVE-2026-1234", "affected", vexTime, ingestTime,
		sbom.SBOMID.String(), "pkg:golang/example/product@1", "reviewed"); err != nil {
		t.Fatal(err)
	}
	statements, err := store.QueryVEXStatements(ctx, sbom.SBOMID.String())
	if err != nil || len(statements) != 1 {
		t.Fatalf("VEX statements = %+v, err %v", statements, err)
	}
	stmt := statements[0]
	if stmt.ProductRef != "pkg:golang/example/product@1" || stmt.ProductPURL != "pkg:golang/example/lib@1" ||
		stmt.StatusNotes != "reviewed" || !stmt.VEXTimestamp.Equal(vexTime) || !stmt.IngestedAt.Equal(ingestTime) {
		t.Fatalf("VEX scope or timestamps lost: %+v", stmt)
	}

	failed, err := clickhouse.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := failed.Close(); err != nil {
		t.Fatal(err)
	}
	writer := &teaStoreAdapter{ch: failed, docStore: ds}
	first := &tea.Snapshot{
		Collection:     tea.Collection{UUID: sbom.SBOMID.String(), Version: 1},
		LastVEXVersion: 1, LastVEXFingerprint: "first", VEXBytes: []byte("first"),
	}
	if _, err := writer.PublishSnapshot(ctx, sbom, nil, first); err == nil {
		t.Fatal("index failure was not reported")
	}
	recovered, err := store.LatestSnapshot(ctx, sbom)
	if err != nil || recovered == nil || string(recovered.VEXBytes) != "first" {
		t.Fatalf("recovery = %+v, err %v", recovered, err)
	}
	byVersion, err := store.GetSnapshot(ctx, sbom.SBOMID.String(), 1, 0)
	if err != nil || string(byVersion.VEXBytes) != "first" {
		t.Fatalf("indexed recovery = %+v, err %v", byVersion, err)
	}

	const writers = 16
	type result struct {
		created bool
		err     error
	}
	results := make(chan result, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			next := &tea.Snapshot{Collection: tea.Collection{UUID: sbom.SBOMID.String(), Version: 2}}
			created, err := store.PublishSnapshot(ctx, sbom, recovered, next)
			results <- result{created, err}
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.created {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("expected one winner, got %d", winners)
	}
	recovered, err = store.LatestSnapshot(ctx, sbom)
	if err != nil || recovered.Collection.Version != 2 {
		t.Fatalf("latest = %+v, err %v", recovered, err)
	}
	page, err := store.ListSnapshots(ctx, sbom.SBOMID.String(), 2, 1, 1)
	if err != nil || len(page) != 1 || page[0].Collection.Version != 1 {
		t.Fatalf("snapshot page = %+v, err %v", page, err)
	}

	disabled := &teaStoreAdapter{ch: ch}
	_, err = disabled.LatestSnapshot(ctx, sbom)
	if !errors.Is(err, tea.ErrSnapshotUnavailable) {
		t.Fatalf("disabled store error = %v", err)
	}
	if err := ds.Delete(ctx, recovered.StorageRef); err != nil {
		t.Fatal(err)
	}
	_, err = store.LatestSnapshot(ctx, sbom)
	if !errors.Is(err, tea.ErrSnapshotUnavailable) {
		t.Fatalf("missing snapshot error = %v", err)
	}
}
