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
		DatabaseSpecific: map[string]interface{}{
			"cwe_ids":  []interface{}{"CWE-79"},
			"severity": "HIGH",
		},
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
	// CWE ids survive into the row (#409), not just into the raw osv_json blob.
	if len(v.CWEIDs) != 1 || v.CWEIDs[0] != "CWE-79" {
		t.Fatalf("cwe_ids not carried over: %+v", v.CWEIDs)
	}
	if v.FindingKind != "vulnerability" {
		t.Fatalf("expected finding_kind 'vulnerability', got %q", v.FindingKind)
	}

	malEntry := osv.VulnEntry{
		ID:      "MAL-2024-1234",
		Summary: "Malicious package backdoor",
	}
	malV := BuildVulnerability(malEntry, id, "b.json", "pkg:npm/evil@1.0.0", 1)
	if malV.FindingKind != "malicious" {
		t.Fatalf("expected finding_kind 'malicious', got %q", malV.FindingKind)
	}
	if malV.Severity != "CRITICAL" {
		t.Fatalf("expected severity 'CRITICAL' for MAL- entry, got %q", malV.Severity)
	}
	}
}
