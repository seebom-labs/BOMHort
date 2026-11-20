package clickhouse

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/vex"
)

// TestVEXStatementKeysSeeded runs parsed OpenVEX statements through the real
// vex_statements storage key (ReplacingMergeTree ORDER BY vuln_id,
// product_purl, vex_id) and reads them back with FINAL (#591 review):
//   - successive statements for one product and component keep the newest,
//     whichever comes first in the document;
//   - products that share a purl identifier but have different @ids keep
//     one row each.
func TestVEXStatementKeysSeeded(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	run := uuid.NewString()

	parseAndInsert := func(t *testing.T, docID, statements string) {
		t.Helper()
		doc := `{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "` + docID + `", "statements": [` + statements + `]}`
		res, err := vex.Parse(strings.NewReader(doc), "keys.openvex.json")
		if err != nil {
			t.Fatal(err)
		}
		for i := range res.Statements {
			res.Statements[i].SBOMID = uuid.NewSHA1(uuid.NameSpaceURL, []byte(res.Statements[i].ProductRef)).String()
		}
		if err := c.InsertVEXStatements(ctx, res.Statements); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = c.Conn.Exec(context.Background(),
				"ALTER TABLE vex_statements DELETE WHERE document_id = ? SETTINGS mutations_sync = 1", docID)
		})
	}
	stored := func(t *testing.T, docID string) []string {
		t.Helper()
		rows, err := c.Conn.Query(ctx,
			"SELECT concat(product_ref, ' ', status) FROM vex_statements FINAL WHERE document_id = ? ORDER BY product_ref", docID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		return out
	}

	const (
		newer = `{"vulnerability": {"name": "CVE-2021-45046"}, "timestamp": "2024-03-01T09:00:00Z",
			"products": [{"@id": "urn:uuid:p", "subcomponents": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}],
			"status": "affected", "action_statement": "Upgrade."}`
		older = `{"vulnerability": {"name": "CVE-2021-45046"}, "timestamp": "2024-01-10T10:00:00Z",
			"products": [{"@id": "urn:uuid:p", "subcomponents": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}],
			"status": "not_affected", "justification": "vulnerable_code_not_present"}`
	)
	for name, stmts := range map[string]string{"newer-first": newer + "," + older, "older-first": older + "," + newer} {
		t.Run(name, func(t *testing.T) {
			docID := "https://example.com/vex/" + run + "/" + name
			parseAndInsert(t, docID, stmts)
			if got := stored(t, docID); len(got) != 1 || got[0] != "urn:uuid:p affected" {
				t.Errorf("stored %v, want only the newer affected statement", got)
			}
		})
	}

	t.Run("shared purl identifier", func(t *testing.T) {
		docID := "https://example.com/vex/" + run + "/images"
		parseAndInsert(t, docID, `{"vulnerability": {"name": "CVE-2021-44228"},
			"products": [
				{"@id": "urn:uuid:a", "identifiers": {"purl": "pkg:oci/app"},
				 "subcomponents": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]},
				{"@id": "urn:uuid:b", "identifiers": {"purl": "pkg:oci/app"},
				 "subcomponents": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}],
			"status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"}`)
		if got := stored(t, docID); len(got) != 2 {
			t.Errorf("stored %v, want one row per product", got)
		}
	})
}
