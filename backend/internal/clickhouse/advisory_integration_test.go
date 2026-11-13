package clickhouse

// Integration test for the advisory feed tables and columns. Skipped without
// CLICKHOUSE_HOST like the other query tests.

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/advisory"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func TestAdvisoryRecordsRoundTrip(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	n := rand.Intn(900000) + 100000
	source := fmt.Sprintf("fx-feed-%d", n)
	key := fmt.Sprintf("apk/fx%d/openssl", n)
	mod := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	rec := fmt.Sprintf(`{"id":"FX-%d","modified":"2026-03-01T12:00:00Z","related":["CVE-2099-%d"],"affected":[{"package":{"purl":"pkg:%s"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0-r1"}]}]}]}`, n, n, key)
	if err := c.InsertAdvisoryRecords(ctx, []advisory.Row{{
		Source: source, ID: fmt.Sprintf("FX-%d", n), Modified: mod, PackageKeys: []string{key}, RecordJSON: rec,
	}}); err != nil {
		t.Fatal(err)
	}

	versions, err := c.AdvisoryRecordVersions(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if got := versions[fmt.Sprintf("FX-%d", n)]; !got.Equal(mod) {
		t.Errorf("stored modified = %v, want %v", got, mod)
	}

	got, err := c.LookupAdvisoryRecords(ctx, []string{source}, []string{"apk/other/x", key})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Record.ID != fmt.Sprintf("FX-%d", n) || got[0].Record.Related[0] != fmt.Sprintf("CVE-2099-%d", n) {
		t.Fatalf("lookup = %+v", got)
	}
	if none, _ := c.LookupAdvisoryRecords(ctx, []string{"another-feed"}, []string{key}); len(none) != 0 {
		t.Errorf("lookup ignored the source filter: %+v", none)
	}

	// A feed-decided finding reads back with its source, status and location.
	sbomID := uuid.New()
	purl := fmt.Sprintf("pkg:%s@1.0-r0", key)
	if err := c.InsertVulnerabilities(ctx, []models.Vulnerability{{
		DiscoveredAt: time.Now(), SBOMID: sbomID, SourceFile: "fx.json", PURL: purl,
		VulnID: fmt.Sprintf("FX-%d", n), Severity: "HIGH", AffectedVersions: []string{},
		AdvisorySource: source, AdvisoryStatus: advisory.StatusPendingUpstreamFix,
		ComponentLocation: `[{"location":"/usr/lib/libssl.so.3","architecture":"x86_64"}]`,
	}}); err != nil {
		t.Fatal(err)
	}
	items, err := c.QuerySBOMVulnerabilities(ctx, sbomID.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].AdvisorySource != source || items[0].AdvisoryStatus != advisory.StatusPendingUpstreamFix ||
		len(items[0].AdvisoryComponents) != 1 || items[0].AdvisoryComponents[0].Location != "/usr/lib/libssl.so.3" {
		t.Fatalf("items = %+v", items)
	}

	// The stored finding is found under its prefix and closed by key.
	stored, err := c.QueryFindingsUnderPrefixes(ctx, []string{"pkg:" + key})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].SBOMID != sbomID || stored[0].AdvisoryStatus != advisory.StatusPendingUpstreamFix {
		t.Fatalf("stored = %+v", stored)
	}
	if err := c.CloseFindings(ctx, []string{fmt.Sprintf("FX-%d", n) + "\x00" + purl}); err != nil {
		t.Fatal(err)
	}
	if items, _ := c.QuerySBOMVulnerabilities(ctx, sbomID.String(), ""); len(items) != 0 {
		t.Errorf("closed finding still listed: %+v", items)
	}

	// A tombstone retires the record: no lookup hit, no stored version.
	time.Sleep(10 * time.Millisecond) // a strictly newer synced_at
	if err := c.InsertAdvisoryRecords(ctx, []advisory.Row{{
		Source: source, ID: fmt.Sprintf("FX-%d", n), Modified: time.Unix(0, 0), PackageKeys: []string{},
	}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.LookupAdvisoryRecords(ctx, []string{source}, []string{key}); len(got) != 0 {
		t.Errorf("tombstoned record still returned: %+v", got)
	}
	if versions, _ := c.AdvisoryRecordVersions(ctx, source); len(versions) != 0 {
		t.Errorf("tombstoned record still has a version: %v", versions)
	}
}
