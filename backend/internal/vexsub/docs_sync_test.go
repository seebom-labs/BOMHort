package vexsub

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

var upstreamVEXDoc = filepath.Join("..", "..", "..", "docs", "content", "docs", "upstream-vex", "_index.md")

func docTable(t *testing.T, doc, name string) [][]string {
	t.Helper()
	start, end := "<!-- "+name+":start -->", "<!-- "+name+":end -->"
	i, j := strings.Index(doc, start), strings.Index(doc, end)
	if i < 0 || j < i {
		t.Fatalf("docs table %q: markers not found", name)
	}
	var rows [][]string
	for _, line := range strings.Split(doc[i+len(start):j], "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for k, c := range cells {
			cells[k] = strings.Trim(strings.TrimSpace(c), "`")
		}
		rows = append(rows, cells)
	}
	if len(rows) < 3 {
		t.Fatalf("docs table %q: no rows", name)
	}
	return rows[2:] // header and separator
}

func TestDocsUpstreamVEXInSync(t *testing.T) {
	raw, err := os.ReadFile(upstreamVEXDoc)
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}
	doc := string(raw)

	t.Run("no em-dashes", func(t *testing.T) {
		if strings.Contains(doc, "\u2014") {
			t.Errorf("upstream-vex docs contain prohibited em-dash")
		}
	})

	t.Run("source types", func(t *testing.T) {
		var types []string
		for _, row := range docTable(t, doc, "vex-source-types") {
			types = append(types, row[0])
		}
		wantTypes := []string{SourceTypeOpenVEXHub, SourceTypeCSAFProvider, SourceTypeOCIReferrers}
		if !slices.Equal(types, wantTypes) {
			t.Errorf("documented types %v, code has %v", types, wantTypes)
		}
	})

	t.Run("csaf status mapping", func(t *testing.T) {
		wantStatus := map[string]string{
			"known_not_affected":  models.VEXStatusNotAffected,
			"known_affected":      models.VEXStatusAffected,
			"fixed":               models.VEXStatusFixed,
			"under_investigation": models.VEXStatusUnderInvestigation,
		}
		for _, row := range docTable(t, doc, "csaf-status-mapping") {
			csafStatus, openvexStatus := row[0], row[1]
			want, ok := wantStatus[csafStatus]
			if !ok {
				t.Errorf("unexpected CSAF status %q in docs", csafStatus)
				continue
			}
			if openvexStatus != want {
				t.Errorf("CSAF status %q: docs say %q, want %q", csafStatus, openvexStatus, want)
			}
		}
	})

	t.Run("csaf justification mapping", func(t *testing.T) {
		for _, row := range docTable(t, doc, "csaf-justification-mapping") {
			flag, just := row[0], row[1]
			got := mapCSAFFlagToJustification(flag)
			if got != just {
				t.Errorf("mapCSAFFlagToJustification(%q) = %q, docs say %q", flag, got, just)
			}
		}
	})
}
