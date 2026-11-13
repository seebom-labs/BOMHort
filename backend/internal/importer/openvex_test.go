package importer

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/vex"
)

const testSerial = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"

func TestBuildVEX_MapsStatesAndJustifications(t *testing.T) {
	tests := []struct {
		name                         string
		a                            Analysis
		status, justification        string
		impact, action, notesContain string
	}{
		{
			name:          "not_affected keeps the detail as impact statement",
			a:             Analysis{State: "not_affected", Justification: "code_not_reachable", Detail: "Only the client is used."},
			status:        "not_affected",
			justification: "vulnerable_code_not_in_execute_path",
			impact:        "Only the client is used.",
			notesContain:  "state=not_affected, justification=code_not_reachable",
		},
		{
			name:          "upper-case vocabulary is accepted",
			a:             Analysis{State: "NOT_AFFECTED", Justification: "PROTECTED_AT_RUNTIME"},
			status:        "not_affected",
			justification: "inline_mitigations_already_exist",
		},
		{
			name:         "false_positive without detail gets a fallback impact statement",
			a:            Analysis{State: "false_positive"},
			status:       "not_affected",
			impact:       "Marked false_positive in the imported analysis.",
			notesContain: "state=false_positive",
		},
		{
			name:   "resolved is fixed",
			a:      Analysis{State: "resolved"},
			status: "fixed",
		},
		{
			name:         "exploitable is affected with the detail as action",
			a:            Analysis{State: "exploitable", Responses: []string{"update", "workaround_available"}, Detail: "Upgrade to 2.17.1."},
			status:       "affected",
			action:       "Upgrade to 2.17.1.",
			notesContain: "response=update,workaround_available",
		},
		{
			name:   "exploitable without detail still has an action statement",
			a:      Analysis{State: "exploitable"},
			status: "affected",
			action: "No action recorded in the imported analysis.",
		},
		{
			name:         "in_triage keeps the detail in the notes",
			a:            Analysis{State: "in_triage", Detail: "Waiting for the vendor."},
			status:       "under_investigation",
			notesContain: "Waiting for the vendor.",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.a.VulnID = "CVE-2021-44228"
			tc.a.PURLs = []string{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}
			got, err := BuildVEX(testSerial, []Analysis{tc.a})
			if err != nil {
				t.Fatalf("BuildVEX: %v", err)
			}
			stmts := parseVEX(t, got.Data)
			if len(stmts) != 1 {
				t.Fatalf("parsed %d statements, want 1", len(stmts))
			}
			s := stmts[0]
			if s.Status != tc.status || s.Justification != tc.justification {
				t.Errorf("status/justification = %q/%q, want %q/%q", s.Status, s.Justification, tc.status, tc.justification)
			}
			if s.ImpactStatement != tc.impact || s.ActionStatement != tc.action {
				t.Errorf("impact/action = %q/%q, want %q/%q", s.ImpactStatement, s.ActionStatement, tc.impact, tc.action)
			}
			if !strings.Contains(s.StatusNotes, tc.notesContain) {
				t.Errorf("status_notes = %q, want it to contain %q", s.StatusNotes, tc.notesContain)
			}
			if s.Author != importAuthor || s.Tooling != importTooling {
				t.Errorf("author/tooling = %q/%q", s.Author, s.Tooling)
			}
		})
	}
}

// The worker must scope the statements to the SBOM through its serialNumber
// and match findings on the component purl.
func TestBuildVEX_ScopedToSBOMBySerial(t *testing.T) {
	got, err := BuildVEX(testSerial, []Analysis{{
		VulnID:  "CVE-2022-42889",
		Aliases: []string{"GHSA-599f-7c49-w659"},
		PURLs:   []string{"pkg:maven/org.apache.commons/commons-text@1.9", "pkg:maven/org.apache.commons/commons-text@1.9", "pkg:maven/other/lib@1.0"},
		State:   "not_affected", Justification: "code_not_present",
	}})
	if err != nil {
		t.Fatal(err)
	}
	stmts := parseVEX(t, got.Data)
	if len(stmts) != 2 {
		t.Fatalf("parsed %d statements, want one per distinct purl (2)", len(stmts))
	}
	for _, s := range stmts {
		if s.ProductRef != testSerial || s.ProductWide {
			t.Errorf("product = %q (wide=%v), want the serial as a component-scoped product", s.ProductRef, s.ProductWide)
		}
		if s.VulnID != "CVE-2022-42889" {
			t.Errorf("vuln = %q", s.VulnID)
		}
	}
	if stmts[0].ProductPURL != "pkg:maven/org.apache.commons/commons-text@1.9" || stmts[1].ProductPURL != "pkg:maven/other/lib@1.0" {
		t.Errorf("purls = %q, %q", stmts[0].ProductPURL, stmts[1].ProductPURL)
	}
}

func TestBuildVEX_IsDeterministic(t *testing.T) {
	updated := time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC)
	a := Analysis{VulnID: "CVE-1", PURLs: []string{"pkg:npm/a@1"}, State: "not_affected", Justification: "code_not_present", Updated: updated}
	b := Analysis{VulnID: "CVE-2", PURLs: []string{"pkg:npm/b@1"}, State: "resolved"}

	first, err := BuildVEX(testSerial, []Analysis{a, b})
	if err != nil {
		t.Fatal(err)
	}
	// Same analyses in a different order: same bytes, so a rerun is a hash
	// duplicate on upload.
	second, err := BuildVEX(testSerial, []Analysis{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Data, second.Data) {
		t.Fatalf("output depends on input order:\n%s\n%s", first.Data, second.Data)
	}
	if !bytes.Contains(first.Data, []byte(`"timestamp": "2025-03-01T12:00:00Z"`)) {
		t.Errorf("the dated statement lost its analysis time:\n%s", first.Data)
	}

	// A changed decision must produce a new document (new @id), or the worker
	// would skip it as already ingested.
	a.Justification = "code_not_reachable"
	changed, err := BuildVEX(testSerial, []Analysis{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if docID(t, changed.Data) == docID(t, first.Data) {
		t.Error("a changed analysis kept the same @id")
	}
}

// An undated analysis must not inherit the date of another one in the same
// document: the VEX parser falls back to the document timestamp for a
// statement without its own, so the document must not carry one.
func TestBuildVEX_UndatedStatementDoesNotInheritADate(t *testing.T) {
	dated := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err := BuildVEX(testSerial, []Analysis{
		{VulnID: "CVE-1", PURLs: []string{"pkg:npm/a@1"}, State: "not_affected", Justification: "code_not_present", Updated: dated},
		{VulnID: "CVE-2", PURLs: []string{"pkg:npm/b@1"}, State: "not_affected", Justification: "code_not_present"},
	})
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	res, err := vex.Parse(bytes.NewReader(got.Data), "import.openvex.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Statements {
		switch s.VulnID {
		case "CVE-1":
			if !s.VEXTimestamp.Equal(dated) {
				t.Errorf("dated statement: timestamp %v, want %v", s.VEXTimestamp, dated)
			}
		case "CVE-2":
			if s.VEXTimestamp.Equal(dated) || s.VEXTimestamp.Before(before.Add(-time.Minute)) {
				t.Errorf("undated statement got %v; want the ingest time, not another finding's date", s.VEXTimestamp)
			}
		}
	}
	if len(res.Statements) != 2 {
		t.Fatalf("parsed %d statements, want 2", len(res.Statements))
	}
}

func TestBuildVEX_NoTimestampsLeavesThemOut(t *testing.T) {
	got, err := BuildVEX(testSerial, []Analysis{{VulnID: "CVE-1", PURLs: []string{"pkg:npm/a@1"}, State: "resolved"}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got.Data, []byte(`"timestamp"`)) {
		t.Errorf("invented a timestamp:\n%s", got.Data)
	}
}

func TestBuildVEX_SkipsWhatItCannotMap(t *testing.T) {
	got, err := BuildVEX(testSerial, []Analysis{
		{VulnID: "CVE-1", PURLs: []string{"pkg:npm/a@1"}, State: "not_set"},
		{VulnID: "CVE-2", PURLs: []string{"pkg:npm/b@1"}, State: "resolved"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Statements() != 1 || len(got.Notes) != 1 || !strings.Contains(got.Notes[0], "CVE-1") {
		t.Errorf("statements = %d, notes = %v", got.Statements(), got.Notes)
	}

	none, err := BuildVEX(testSerial, nil)
	if err != nil || none.Data != nil {
		t.Errorf("no analyses: data = %q, err = %v; want no document", none.Data, err)
	}
}

func TestBuildVEX_RequiresSerial(t *testing.T) {
	got, err := BuildVEX("", []Analysis{{VulnID: "CVE-1", PURLs: []string{"pkg:npm/a@1"}, State: "resolved"}})
	if !errors.Is(err, errNoSerial) {
		t.Fatalf("err = %v, want errNoSerial", err)
	}
	if got.Data != nil || got.Statements() != 1 {
		t.Errorf("data = %q, statements = %d; want no document but the count", got.Data, got.Statements())
	}
}

func parseVEX(t *testing.T, data []byte) []vexParsed {
	t.Helper()
	res, err := vex.Parse(bytes.NewReader(data), "import.openvex.json")
	if err != nil {
		t.Fatalf("generated VEX does not parse: %v\n%s", err, data)
	}
	out := make([]vexParsed, len(res.Statements))
	for i, s := range res.Statements {
		out[i] = vexParsed{
			ProductRef: s.ProductRef, ProductWide: s.ProductWide, ProductPURL: s.ProductPURL,
			VulnID: s.VulnID, Status: s.Status, Justification: s.Justification,
			ImpactStatement: s.ImpactStatement, ActionStatement: s.ActionStatement,
			StatusNotes: s.StatusNotes, Author: s.Author, Tooling: s.Tooling,
		}
	}
	return out
}

type vexParsed struct {
	ProductRef, ProductPURL, VulnID, Status, Justification string
	ImpactStatement, ActionStatement, StatusNotes          string
	Author, Tooling                                        string
	ProductWide                                            bool
}

func docID(t *testing.T, data []byte) string {
	t.Helper()
	res, err := vex.Parse(bytes.NewReader(data), "x.openvex.json")
	if err != nil {
		t.Fatal(err)
	}
	return res.DocumentID
}
