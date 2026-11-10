package main

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/sbom"
)

var qualityDoc = filepath.Join("..", "..", "..", "docs", "content", "docs", "sbom-quality", "_index.md")

func TestDocsSBOMQualityInSync(t *testing.T) {
	raw, err := os.ReadFile(qualityDoc)
	if err != nil {
		t.Fatalf("read quality docs: %v", err)
	}
	doc := string(raw)

	t.Run("flags vocabulary", func(t *testing.T) {
		var docFlags []string
		for _, row := range docTable(t, doc, "quality-flags") {
			docFlags = append(docFlags, row[0])
		}
		if !slices.Equal(docFlags, sbom.AllQualityFlags) {
			t.Errorf("documented quality flags %v, code has %v", docFlags, sbom.AllQualityFlags)
		}
	})

	t.Run("weights total 100", func(t *testing.T) {
		total := 0
		for _, row := range docTable(t, doc, "quality-weights") {
			pts, err := strconv.Atoi(row[1])
			if err != nil {
				t.Fatalf("invalid weight %q: %v", row[1], err)
			}
			total += pts
		}
		if total != 100 {
			t.Errorf("documented weights sum to %d, want 100", total)
		}
	})
}
