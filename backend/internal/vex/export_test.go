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
	t1     = time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC)
	t2     = time.Date(2025, 6, 1, 8, 30, 0, 0, time.UTC)
	issued = time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC)
)

const (
	productA = "urn:uuid:7d808005-e78c-5708-8db2-07fbbe2fefa6"
	productB = "urn:uuid:8d979e45-05c6-5c67-9456-4d90d71f317d"
	appPURL  = "pkg:oci/payments?repository_url=registry.example/payments"
	log4j    = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
)

func exportFixture() []ExportStatement {
	return []ExportStatement{
		{
			Product: productA, ProductPURL: appPURL, PURL: log4j,
			VulnID: "CVE-2021-44228", Aliases: []string{"GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"},
			Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path",
			ImpactStatement: "JNDI lookups are disabled.", StatusNotes: "Reviewed by the security team.",
			Timestamp: t1, Author: "security@example.com", Role: "Document Creator", Tooling: "VEXViper",
		},
		{
			Product: productA, ProductPURL: appPURL, PURL: models.VEXProductWide,
			VulnID: "GHSA-7rjr-3q55-vv33", Status: "affected", ActionStatement: "Upgrade to 2.17.1.",
			Timestamp: t2, Author: "security@example.com", Role: "Document Creator", Tooling: "VEXViper",
		},
	}
}

// validateOpenVEX checks the MUST requirements of the OpenVEX v0.2.0
// specification that a consumer validating documents enforces.
func validateOpenVEX(t *testing.T, data []byte) exportDocument {
	t.Helper()
	var doc exportDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if doc.Context != openVEXContext || doc.ID == "" || doc.Author == "" || doc.Version < 1 {
		t.Errorf("document fields: context %q, @id %q, author %q, version %d", doc.Context, doc.ID, doc.Author, doc.Version)
	}
	if _, err := time.Parse(time.RFC3339, doc.Timestamp); err != nil {
		t.Errorf("document timestamp %q: %v", doc.Timestamp, err)
	}
	if !strings.Contains(string(data), `"statements"`) {
		t.Error("statements missing")
	}
	for i, s := range doc.Statements {
		if s.Vulnerability.Name == "" || len(s.Products) == 0 {
			t.Errorf("statement %d: vulnerability %q, %d products", i, s.Vulnerability.Name, len(s.Products))
		}
		for _, p := range s.Products {
			if p.ID == "" {
				t.Errorf("statement %d: product without @id", i)
			}
		}
		if !openVEXStatuses[s.Status] {
			t.Errorf("statement %d: status %q", i, s.Status)
		}
		if s.Status == "not_affected" && s.Justification == "" && s.ImpactStatement == "" {
			t.Errorf("statement %d: not_affected without justification or impact statement", i)
		}
		if s.Status == "affected" && s.ActionStatement == "" {
			t.Errorf("statement %d: affected without action statement", i)
		}
		if _, err := time.Parse(time.RFC3339, s.Timestamp); err != nil {
			t.Errorf("statement %d timestamp %q: %v", i, s.Timestamp, err)
		}
	}
	return doc
}

// The exported document must read back, through the same parser that
// ingests uploads, as the decisions it was built from.
func TestExport_RoundTripsThroughParse(t *testing.T) {
	data, err := Export(exportFixture(), issued)
	if err != nil {
		t.Fatal(err)
	}
	doc := validateOpenVEX(t, data)
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
	if c.ProductRef != productA || c.ProductWide || c.ProductPURL != log4j {
		t.Errorf("component statement: ref %q wide %v purl %q", c.ProductRef, c.ProductWide, c.ProductPURL)
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

	// A product-wide decision stays product-wide: no subcomponent is
	// invented, and the product ref is the SBOM's, which the worker resolves.
	g := byVuln["GHSA-7rjr-3q55-vv33"]
	if g.ProductRef != productA || !g.ProductWide || g.Status != "affected" || !g.VEXTimestamp.Equal(t2) {
		t.Errorf("product-wide statement = %+v", g)
	}

	if doc.Timestamp != "2025-06-01T08:30:00Z" {
		t.Errorf("document timestamp = %q, want the newest statement's", doc.Timestamp)
	}
	if got := doc.Statements[0].Vulnerability.Aliases; len(got) != 1 || got[0] != "GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("aliases = %v, want the other names without the statement's own id", got)
	}
}

// A consumer that matches products by purl, as image scanners do, finds the
// product identifier next to BOMHort's own @id.
func TestExport_CarriesTheProductPURL(t *testing.T) {
	data, err := Export(exportFixture(), issued)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range validateOpenVEX(t, data).Statements {
		if got := s.Products[0].Identifiers["purl"]; got != appPURL {
			t.Errorf("%s: identifiers.purl = %q, want the product purl", s.Vulnerability.Name, got)
		}
	}

	stmts := exportFixture()
	for i := range stmts {
		stmts[i].ProductPURL = ""
	}
	data, err = Export(stmts, issued)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"identifiers"`) {
		t.Errorf("an unknown product purl was written:\n%s", data)
	}
}

func TestExport_IsDeterministic(t *testing.T) {
	stmts := exportFixture()
	first, err := Export(stmts, issued)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Export([]ExportStatement{stmts[1], stmts[0]}, issued)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("output depends on input order:\n%s\n%s", first, second)
	}

	stmts[0].Status = "affected"
	stmts[0].ActionStatement = "Patch."
	changed, err := Export(stmts, issued)
	if err != nil {
		t.Fatal(err)
	}
	if documentID(t, changed) == documentID(t, first) {
		t.Error("a changed decision kept the same document @id")
	}
}

// The worker skips a document whose @id it has already ingested, so a
// change to any emitted field, provenance included, needs a new @id (#592
// review).
func TestExport_ProvenanceChangesTheID(t *testing.T) {
	stmts := exportFixture()
	first, err := Export(stmts, issued)
	if err != nil {
		t.Fatal(err)
	}
	for i := range stmts {
		stmts[i].Author = "psirt@example.com"
	}
	changed, err := Export(stmts, issued)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, changed) || documentID(t, changed) == documentID(t, first) {
		t.Error("a document whose author changed kept its @id")
	}
}

// OpenVEX has no per-statement author: mixed provenance must not be
// attributed to one of the authors.
func TestExport_MixedProvenance(t *testing.T) {
	stmts := exportFixture()
	stmts[1].Author, stmts[1].Tooling = "imported", "bomhort-import"
	data, err := Export(stmts, issued)
	if err != nil {
		t.Fatal(err)
	}
	doc := validateOpenVEX(t, data)
	if doc.Author != "BOMHort" || doc.Tooling != "" || doc.Role != "Document Creator" {
		t.Errorf("author/role/tooling = %q/%q/%q, want BOMHort, the shared role, no tooling", doc.Author, doc.Role, doc.Tooling)
	}
	if strings.Contains(string(data), `"tooling"`) {
		t.Errorf("an empty tooling was written:\n%s", data)
	}
}

// OpenVEX requires a document timestamp even without decisions (#592 review);
// it is the stable issuance time the caller passes.
func TestExport_EmptyIsValid(t *testing.T) {
	data, err := Export(nil, issued)
	if err != nil {
		t.Fatal(err)
	}
	doc := validateOpenVEX(t, data)
	if doc.Timestamp != "2025-07-01T00:00:00Z" || len(doc.Statements) != 0 || !strings.Contains(string(data), `"statements": []`) {
		t.Errorf("empty export:\n%s", data)
	}
	again, err := Export(nil, issued)
	if err != nil || !bytes.Equal(data, again) {
		t.Errorf("empty export is not stable (%v)", err)
	}
	if _, err := Parse(bytes.NewReader(data), "empty.openvex.json"); err != nil {
		t.Errorf("empty export does not parse: %v", err)
	}
}

// A stored decision may lack a field OpenVEX requires, or carry a status it
// does not define; the export stays valid either way.
func TestExport_StaysValidForIncompleteDecisions(t *testing.T) {
	data, err := Export([]ExportStatement{
		{Product: productA, PURL: log4j, VulnID: "CVE-1", Status: "affected", Timestamp: t1},
		{Product: productA, PURL: log4j, VulnID: "CVE-2", Status: "not_affected", Timestamp: t1},
		{Product: productA, PURL: log4j, VulnID: "CVE-3", Status: "investigating", Timestamp: t1},
	}, issued)
	if err != nil {
		t.Fatal(err)
	}
	doc := validateOpenVEX(t, data)
	if len(doc.Statements) != 2 {
		t.Fatalf("got %d statements, want the unknown status left out", len(doc.Statements))
	}
	if doc.Statements[0].ActionStatement != missingActionStatement || doc.Statements[1].ImpactStatement != missingImpactStatement {
		t.Errorf("required fields not filled: %+v", doc.Statements)
	}
}

// A project export states the same vulnerability and component for each
// version; after #591 each keeps its own storage key on ingest.
func TestExport_MultiVersionKeysSurviveIngest(t *testing.T) {
	data, err := Export([]ExportStatement{
		{Product: productA, ProductPURL: appPURL, PURL: log4j, VulnID: "CVE-2021-44228", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: t1},
		{Product: productB, ProductPURL: appPURL, PURL: log4j, VulnID: "CVE-2021-44228", Status: "affected", ActionStatement: "Upgrade.", Timestamp: t1},
	}, issued)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(bytes.NewReader(data), "project.openvex.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Statements) != 2 || res.Statements[0].VEXID == res.Statements[1].VEXID {
		t.Fatalf("versions share a storage key: %+v", res.Statements)
	}
	refs := map[string]string{}
	for _, s := range res.Statements {
		refs[s.ProductRef] = s.Status
	}
	if refs[productA] != "not_affected" || refs[productB] != "affected" {
		t.Errorf("per-version decisions = %v", refs)
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
