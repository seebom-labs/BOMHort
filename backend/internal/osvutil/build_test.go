package osvutil

import (
	"testing"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/osv"
)

func TestBuildVulnerability(t *testing.T) {
	id := uuid.New()
	entry := osv.VulnEntry{
		ID:      "GHSA-xxxx-yyyy-zzzz",
		Summary: "bad thing",
		Aliases: []string{"CVE-2024-1"},
	}
	v := BuildVulnerability(entry, id, "a.json", "pkg:golang/x@1", 3)

	if v.SBOMID != id || v.PURL != "pkg:golang/x@1" || v.SourceFile != "a.json" || v.DependencyDepth != 3 {
		t.Fatalf("identity fields not carried over: %+v", v)
	}
	if v.VulnID != entry.ID || v.Summary != entry.Summary || len(v.Aliases) != 1 {
		t.Fatalf("OSV fields not carried over: %+v", v)
	}
	if v.Severity != ClassifySeverity(entry) || v.OSVJSON == "" {
		t.Fatalf("derived fields missing: %+v", v)
	}
}
