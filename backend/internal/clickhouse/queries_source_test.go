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
