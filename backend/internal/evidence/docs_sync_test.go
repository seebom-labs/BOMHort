package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func TestDocsReachabilityInSync(t *testing.T) {
	docPath := filepath.Join("..", "..", "..", "docs", "content", "docs", "reachability", "_index.md")
	raw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("failed to read reachability doc at %s: %v", docPath, err)
	}
	content := string(raw)

	// Verify all vocabulary constants are documented.
	vocab := []string{
		models.ReachabilityReachable,
		models.ReachabilityNotReachable,
		models.ReachabilityUnknown,
	}
	for _, v := range vocab {
		if !strings.Contains(content, "`"+v+"`") {
			t.Errorf("reachability documentation missing vocabulary constant %q", v)
		}
	}

	// Verify the ingest endpoint is documented.
	if !strings.Contains(content, "POST /api/v1/sboms/{id}/evidence") {
		t.Errorf("reachability documentation missing POST /api/v1/sboms/{id}/evidence")
	}

	// Verify govulncheck -json is documented.
	if !strings.Contains(content, "govulncheck -json") {
		t.Errorf("reachability documentation missing govulncheck -json reference")
	}
}

