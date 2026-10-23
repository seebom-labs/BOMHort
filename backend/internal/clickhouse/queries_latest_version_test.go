package clickhouse

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// "Latest" is the highest version, not the last ingest (#494): a backfill
// ingests versions in arbitrary order.
func TestProjectLatestIsHighestVersion(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	suffix := uuid.New().String()[:8]
	now := time.Now().UTC().Truncate(time.Second)

	type sb struct {
		id, version string
		at          time.Time
	}
	cases := []struct {
		name     string
		sboms    []sb
		wantIdx  int
		wantNote string
	}{
		{"highest number wins over last ingest", []sb{
			{uuid.NewString(), "v0.18.0", now.Add(-3 * time.Hour)},
			{uuid.NewString(), "v0.22.0", now.Add(-2 * time.Hour)},
			{uuid.NewString(), "v0.17.2", now.Add(-1 * time.Hour)},
		}, 1, "v0.22.0"},
		{"release beats its pre-release", []sb{
			{uuid.NewString(), "v1.0.0", now.Add(-2 * time.Hour)},
			{uuid.NewString(), "v1.0.0-rc.1", now.Add(-1 * time.Hour)},
		}, 0, "v1.0.0"},
		{"unparseable versions fall back to ingest time", []sb{
			{uuid.NewString(), "abc", now.Add(-2 * time.Hour)},
			{uuid.NewString(), "", now.Add(-1 * time.Hour)},
		}, 1, ""},
	}

	var ids []string
	for i, tc := range cases {
		project := fmt.Sprintf("fx-latest-%d-%s", i, suffix)
		for _, s := range tc.sboms {
			ids = append(ids, s.id)
			hash := s.id + suffix
			for len(hash) < 64 {
				hash += "0"
			}
			if err := c.Conn.Exec(ctx, `
				INSERT INTO sboms (ingested_at, sbom_id, source_file, spdx_version, document_name,
					document_namespace, sha256_hash, creation_date, creator_tools,
					cluster, namespace, project, source_repo, source_ref, document_version, tags)
				VALUES (?, ?, ?, 'SPDX-2.3', ?, '', ?, ?, [], '', '', ?, '', '', ?, [])`,
				s.at, s.id, "fixtures/"+project+"/"+s.version+".spdx.json", project+" "+s.version,
				hash[:64], s.at, project, s.version); err != nil {
				t.Fatalf("insert sbom fixture: %v", err)
			}
		}
	}
	t.Cleanup(func() {
		_ = c.Conn.Exec(context.Background(),
			"ALTER TABLE sboms DELETE WHERE sbom_id IN (?) SETTINGS mutations_sync = 1", ids)
	})

	for i, tc := range cases {
		project := fmt.Sprintf("fx-latest-%d-%s", i, suffix)
		d, err := c.QueryProjectDetail(ctx, project)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		want := tc.sboms[tc.wantIdx]
		if d.LatestSBOMID != want.id || d.LatestVersion != want.version {
			t.Errorf("%s: latest = %q/%s, want %q/%s", tc.name, d.LatestVersion, d.LatestSBOMID, want.version, want.id)
		}
		list, err := c.QueryProjects(ctx, 1, 10, project, "")
		if err != nil {
			t.Fatalf("%s: list: %v", tc.name, err)
		}
		if len(list.Data) != 1 || list.Data[0].LatestSBOMID != want.id {
			t.Errorf("%s: list latest_sbom_id = %+v, want %s", tc.name, list.Data, want.id)
		}
	}
}
