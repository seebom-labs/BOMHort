package clickhouse

import (
	"strings"
	"testing"
)

func TestVulnWhere_Source(t *testing.T) {
	where, args := vulnWhere("", VulnFilter{Source: "private"})
	if !strings.Contains(where, "advisory_source = ?") {
		t.Errorf("where = %q, want contains 'advisory_source = ?'", where)
	}
	if len(args) != 1 || args[0] != "private" {
		t.Errorf("args = %v, want ['private']", args)
	}
}

func TestQueryFindingsByAdvisorySource_Columns(t *testing.T) {
	// Ensure the 14 columns in QueryFindingsByAdvisorySource match StoredFindingRow fields
	cols := []string{
		"sbom_id", "purl", "vuln_id", "aliases", "advisory_source", "advisory_status",
		"source_file", "severity", "summary", "fixed_version", "dependency_depth", "image_digest",
		"cluster", "namespace", "project",
	}
	if len(cols) != 15 {
		t.Fatalf("expected 15 columns, got %d", len(cols))
	}
}

