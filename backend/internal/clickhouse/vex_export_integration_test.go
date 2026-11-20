package clickhouse

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/vex"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// TestVEXExportSeeded runs the OpenVEX export (#533) against real tables
// (#592 review):
//   - two CycloneDX revisions sharing a serialNumber: the exported product of
//     the older one resolves back to the older one;
//   - the export picks the decision the vulnerability view shows, across
//     aliases and product-wide statements;
//   - export → ingest of a two-version project keeps both scoped rows;
//   - an SBOM without decisions still gets a timestamped document.
func TestVEXExportSeeded(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	run := uuid.NewString()[:8]
	project := "vex-export-" + run
	serial := "urn:uuid:" + uuid.NewString() // shared by both revisions
	const component = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	ghsa, cve := "GHSA-test-"+run, "CVE-test-"+run

	t0 := time.Now().UTC().Truncate(time.Second)
	older, newer, empty := uuid.New(), uuid.New(), uuid.New()
	seedSBOM := func(id uuid.UUID, at time.Time, proj, version string) {
		t.Helper()
		if err := c.InsertSBOM(ctx, &models.SBOM{
			IngestedAt: at, SBOMID: id, SourceFile: "export-" + id.String() + ".cdx.json",
			SPDXVersion: "CycloneDX-1.5", DocumentName: "payments " + version, DocumentNamespace: serial,
			DocumentVersion: version, SHA256Hash: strings.Repeat("e", 64), CreationDate: at,
			CreatorTools: []string{}, Tags: []string{}, QualityFlags: []string{},
			Project: proj, RootPURL: "pkg:oci/payments@" + version,
		}); err != nil {
			t.Fatal(err)
		}
	}
	seedSBOM(older, t0.Add(-2*time.Hour), project, "3.2.0")
	seedSBOM(newer, t0.Add(-time.Hour), project, "3.3.0")
	seedSBOM(empty, t0, "vex-export-empty-"+run, "1.0.0")
	t.Cleanup(func() {
		bg := context.Background()
		for _, table := range []string{"sboms", "vulnerabilities"} {
			_ = c.Conn.Exec(bg, "ALTER TABLE "+table+" DELETE WHERE sbom_id IN (?) SETTINGS mutations_sync = 1",
				[]string{older.String(), newer.String(), empty.String()})
		}
		_ = c.Conn.Exec(bg, "ALTER TABLE vex_statements DELETE WHERE sbom_id IN (?) SETTINGS mutations_sync = 1",
			[]string{older.String(), newer.String()})
	})

	var vulns []models.Vulnerability
	for _, id := range []uuid.UUID{older, newer} {
		vulns = append(vulns, models.Vulnerability{
			DiscoveredAt: t0, SBOMID: id, SourceFile: "export.cdx.json", PURL: component,
			VulnID: ghsa, Aliases: []string{cve}, Severity: "CRITICAL", CWEIDs: []string{}, Project: project,
		})
	}
	if err := c.InsertVulnerabilities(ctx, vulns); err != nil {
		t.Fatal(err)
	}
	stmt := func(sbomID uuid.UUID, vuln, purl, status string, at time.Time) models.VEXStatement {
		return models.VEXStatement{
			IngestedAt: t0, VEXID: uuid.New(), DocumentID: "seed-" + run, SourceFile: "seed.openvex.json",
			SBOMID: sbomID.String(), ProductRef: serial, ProductPURL: purl, VulnID: vuln,
			Status: status, Justification: "vulnerable_code_not_present", ActionStatement: "Upgrade.", VEXTimestamp: at,
		}
	}
	if err := c.InsertVEXStatements(ctx, []models.VEXStatement{
		// Older revision: an older component not_affected for the CVE, then a
		// newer product-wide affected for its GHSA alias. The view says affected.
		stmt(older, cve, component, models.VEXStatusNotAffected, t0.Add(-48*time.Hour)),
		stmt(older, ghsa, models.VEXProductWide, "affected", t0.Add(-24*time.Hour)),
		// Newer revision: not_affected.
		stmt(newer, ghsa, component, models.VEXStatusNotAffected, t0.Add(-24*time.Hour)),
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("the decision of the vulnerability view", func(t *testing.T) {
		view, err := c.QuerySBOMVulnerabilities(ctx, older.String(), "", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if len(view) != 1 || view[0].VEXStatus != "affected" {
			t.Fatalf("vulnerability view = %+v, want the finding as affected", view)
		}
		export, found, err := c.QuerySBOMVEXExport(ctx, older.String())
		if err != nil || !found {
			t.Fatalf("export: found %v, %v", found, err)
		}
		if len(export.Statements) != 1 {
			t.Fatalf("export = %+v, want one decision for the one finding", export.Statements)
		}
		s := export.Statements[0]
		if s.Status != "affected" || s.VulnID != ghsa || s.PURL != component {
			t.Errorf("exported %s for %s on %s, want the view's affected for %s on %s", s.Status, s.VulnID, s.PURL, ghsa, component)
		}
		if s.Product != ExportProductRef(older.String()) || s.ProductPURL != "pkg:oci/payments@3.2.0" {
			t.Errorf("product %q / %q", s.Product, s.ProductPURL)
		}
	})

	t.Run("export, then ingest, of a two-version project", func(t *testing.T) {
		export, found, err := c.QueryProjectVEXExport(ctx, project)
		if err != nil || !found {
			t.Fatalf("export: found %v, %v", found, err)
		}
		data, err := vex.Export(export.Statements, export.Issued)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := vex.Parse(bytes.NewReader(data), "project.openvex.json")
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{older.String(): "affected", newer.String(): "not_affected"}
		for i := range parsed.Statements {
			// The worker's first-pass scoping: the product @id resolves to
			// exactly its SBOM although both revisions share a namespace.
			sbomID, err := c.ResolveSBOMByProductRef(ctx, parsed.Statements[i].ProductRef)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := want[sbomID]; !ok {
				t.Fatalf("product %q resolved to %q, want one of the two revisions", parsed.Statements[i].ProductRef, sbomID)
			}
			parsed.Statements[i].SBOMID = sbomID
		}
		if err := c.InsertVEXStatements(ctx, parsed.Statements); err != nil {
			t.Fatal(err)
		}
		rows, err := c.Conn.Query(ctx,
			"SELECT sbom_id, status FROM vex_statements FINAL WHERE document_id = ?", parsed.DocumentID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		got := map[string]string{}
		for rows.Next() {
			var sbomID, status string
			if err := rows.Scan(&sbomID, &status); err != nil {
				t.Fatal(err)
			}
			got[sbomID] = status
		}
		if len(got) != 2 || got[older.String()] != want[older.String()] || got[newer.String()] != want[newer.String()] {
			t.Errorf("ingested rows = %v, want %v", got, want)
		}
	})

	t.Run("an SBOM without decisions", func(t *testing.T) {
		export, found, err := c.QuerySBOMVEXExport(ctx, empty.String())
		if err != nil || !found {
			t.Fatalf("export: found %v, %v", found, err)
		}
		data, err := vex.Export(export.Statements, export.Issued)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Timestamp  string            `json:"timestamp"`
			Statements []json.RawMessage `json:"statements"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Timestamp != t0.Format(time.RFC3339) || len(doc.Statements) != 0 {
			t.Errorf("empty export: timestamp %q, %d statements; want the SBOM's ingest time", doc.Timestamp, len(doc.Statements))
		}
	})
}
