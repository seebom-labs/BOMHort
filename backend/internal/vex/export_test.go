package vex

import (
	"bytes"
	"strings"
	"testing"
	"time"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

var (
	t1 = time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC)
	t2 = time.Date(2025, 6, 1, 8, 30, 0, 0, time.UTC)
)

func exportFixture() []ExportStatement {
	return []ExportStatement{
		{
			Product: "urn:uuid:6b4b3f6e-1d7a-4c38-9a51-0f4a2e9d7c11", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			VulnID: "CVE-2021-44228", Aliases: []string{"GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"},
			Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path",
			ImpactStatement: "JNDI lookups are disabled.", StatusNotes: "Reviewed by the security team.",
			Timestamp: t1, Author: "security@example.com", Role: "Document Creator", Tooling: "VEXViper",
		},
		{
			Product: "urn:uuid:6b4b3f6e-1d7a-4c38-9a51-0f4a2e9d7c11", PURL: models.VEXProductWide,
			VulnID: "GHSA-7rjr-3q55-vv33", Status: "affected", ActionStatement: "Upgrade to 2.17.1.",
			Timestamp: t2, Author: "security@example.com", Role: "Document Creator", Tooling: "VEXViper",
		},
	}
}

// The exported document must read back, through the same parser that
// ingests uploads, as the decisions it was built from.
func TestExport_RoundTripsThroughParse(t *testing.T) {
	data, err := Export(exportFixture())
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(bytes.NewReader(data), "export.openvex.json")
	if err != nil {
		t.Fatalf("export does not parse: %v\n%s", err, data)
	}
	if len(res.Statements) != 2 {
		t.Fatalf("parsed %d statements, want 2\n%s", len(res.Statements), data)
	}
	byVuln := map[string]models.VEXStatement{}
	for _, s := range res.Statements {
		byVuln[s.VulnID] = s
	}

	c := byVuln["CVE-2021-44228"]
	if c.ProductRef != "urn:uuid:6b4b3f6e-1d7a-4c38-9a51-0f4a2e9d7c11" || c.ProductWide ||
		c.ProductPURL != "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" {
		t.Errorf("component statement product = %q wide=%v purl=%q", c.ProductRef, c.ProductWide, c.ProductPURL)
	}
	if c.Status != "not_affected" || c.Justification != "vulnerable_code_not_in_execute_path" ||
		c.ImpactStatement != "JNDI lookups are disabled." || c.StatusNotes != "Reviewed by the security team." {
		t.Errorf("component statement = %+v", c)
	}
	if !c.VEXTimestamp.Equal(t1) {
		t.Errorf("statement timestamp = %v, want its own %v", c.VEXTimestamp, t1)
	}
	if c.Author != "security@example.com" || c.Role != "Document Creator" || c.Tooling != "VEXViper" {
		t.Errorf("shared provenance not kept: %q %q %q", c.Author, c.Role, c.Tooling)
	}

	// A product-wide decision stays product-wide: no subcomponent is invented.
	g := byVuln["GHSA-7rjr-3q55-vv33"]
	if !g.ProductWide || g.Status != "affected" || g.ActionStatement != "Upgrade to 2.17.1." || !g.VEXTimestamp.Equal(t2) {
		t.Errorf("product-wide statement = %+v", g)
	}

	var doc exportDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Timestamp != "2025-06-01T08:30:00Z" {
		t.Errorf("document timestamp = %q, want the newest statement's", doc.Timestamp)
	}
	if got := doc.Statements[0].Vulnerability.Aliases; len(got) != 1 || got[0] != "GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("aliases = %v, want the other names without the statement's own id", got)
	}
}

func TestExport_IsDeterministic(t *testing.T) {
	stmts := exportFixture()
	first, err := Export(stmts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Export([]ExportStatement{stmts[1], stmts[0]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("output depends on input order:\n%s\n%s", first, second)
	}

	stmts[0].Status = "affected"
	stmts[0].ActionStatement = "Patch."
	changed, err := Export(stmts)
	if err != nil {
		t.Fatal(err)
	}
	if documentID(t, changed) == documentID(t, first) {
		t.Error("a changed decision kept the same document @id")
	}
}

// OpenVEX has no per-statement author: mixed provenance must not be
// attributed to one of the authors.
func TestExport_MixedProvenance(t *testing.T) {
	stmts := exportFixture()
	stmts[1].Author, stmts[1].Tooling = "imported", "bomhort-import"
	data, err := Export(stmts)
	if err != nil {
		t.Fatal(err)
	}
	var doc exportDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Author != "BOMHort" || doc.Tooling != "" || doc.Role != "Document Creator" {
		t.Errorf("author/role/tooling = %q/%q/%q, want BOMHort, the shared role, no tooling", doc.Author, doc.Role, doc.Tooling)
	}
	if strings.Contains(string(data), `"tooling"`) {
		t.Errorf("an empty tooling was written:\n%s", data)
	}
}

func TestExport_Empty(t *testing.T) {
	data, err := Export(nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(bytes.NewReader(data), "empty.openvex.json")
	if err != nil {
		t.Fatalf("empty export does not parse: %v\n%s", err, data)
	}
	if len(res.Statements) != 0 || !strings.Contains(string(data), `"statements": []`) || strings.Contains(string(data), `"timestamp"`) {
		t.Errorf("empty export:\n%s", data)
	}
}

func documentID(t *testing.T, data []byte) string {
	t.Helper()
	res, err := Parse(bytes.NewReader(data), "x.openvex.json")
	if err != nil {
		t.Fatal(err)
	}
	return res.DocumentID
}
