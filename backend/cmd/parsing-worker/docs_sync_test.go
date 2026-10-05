package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/license"
)

// licenseResolutionDoc is the user-facing record of every license heuristic.
// Its tables are asserted against the code so the documentation cannot drift.
var licenseResolutionDoc = filepath.Join("..", "..", "..", "docs", "content", "docs", "license-resolution", "_index.md")

// docTable returns the body rows of the markdown table between
// <!-- name:start --> and <!-- name:end -->, cells trimmed and unquoted.
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

func TestDocsLicenseResolutionInSync(t *testing.T) {
	raw, err := os.ReadFile(licenseResolutionDoc)
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}
	doc := string(raw)

	prevMode := license.GetExpressionMode()
	license.SetExpressionMode(license.ExpressionModeStrict)
	t.Cleanup(func() { license.SetExpressionMode(prevMode) })

	t.Run("vocabulary", func(t *testing.T) {
		var origins, modifiers, reasons []string
		for _, row := range docTable(t, doc, "license-sources") {
			switch row[1] {
			case "origin":
				origins = append(origins, row[0])
			case "modifier":
				modifiers = append(modifiers, row[0])
			case "reason":
				reasons = append(reasons, row[0])
			default:
				t.Errorf("source %q: unknown kind %q", row[0], row[1])
			}
		}

		// Registry origins are listed in chain order.
		wantOrigins := []string{license.SourceDeclared, license.SourceGitHub}
		for _, rr := range buildRegistryResolvers(&config.Config{}, nil) {
			wantOrigins = append(wantOrigins, rr.name)
		}
		if !slices.Equal(origins, wantOrigins) {
			t.Errorf("documented origins %v, code has %v (in resolver order)", origins, wantOrigins)
		}
		wantModifiers := []string{license.ModifierLatest, license.ModifierNormalized}
		if !slices.Equal(modifiers, wantModifiers) {
			t.Errorf("documented modifiers %v, code has %v", modifiers, wantModifiers)
		}
		if !slices.Equal(reasons, license.UnresolvedReasons) {
			t.Errorf("documented reasons %v, code has %v (in check order)", reasons, license.UnresolvedReasons)
		}
	})

	t.Run("normalization examples", func(t *testing.T) {
		for _, row := range docTable(t, doc, "normalize-examples") {
			in, want, cat := row[0], row[1], license.Category(row[2])
			got := license.Recover(in)
			if got == "" {
				got = "NOASSERTION"
			}
			if got != want {
				t.Errorf("Recover(%q) = %q, docs say %q", in, got, want)
			}
			if c := license.Categorize(got); c != cat {
				t.Errorf("Categorize(%q) = %q, docs say %q", got, c, cat)
			}
			// Declared values keep unmatched names verbatim but must land in
			// the same category.
			if want != "NOASSERTION" {
				if c := license.Categorize(license.Normalize(in)); c != cat {
					t.Errorf("declared %q categorizes as %q, docs say %q", in, c, cat)
				}
			}
		}
	})

	t.Run("worked examples", func(t *testing.T) {
		seen := map[string]bool{}
		for _, row := range docTable(t, doc, "golden") {
			name := row[0]
			w, ok := licenseGolden[name]
			if !ok {
				t.Errorf("docs row %q is not in licenseGolden", name)
				continue
			}
			seen[name] = true
			excluded := map[string]bool{"excluded": true, "checked": false}
			ex, okEx := excluded[row[5]]
			if row[2] != w.license || row[3] != w.source || license.Category(row[4]) != w.category || !okEx || ex != w.excluded {
				t.Errorf("docs row %q = %v, golden test expects %+v", name, row[2:], w)
			}
		}
		for name := range licenseGolden {
			if !seen[name] {
				t.Errorf("golden row %q is missing from the docs", name)
			}
		}
	})
}
