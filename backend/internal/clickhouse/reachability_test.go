package clickhouse

import (
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/evidence"
)

func TestClassifySBOMFindings_PURLScoping(t *testing.T) {
	// One CVE affecting two PURLs in the same SBOM: one is called/reachable, one is uncalled.
	existing := []SBOMVulnRow{
		{
			VulnID:  "CVE-2023-39325",
			PURL:    "pkg:golang/golang.org/x/net@v0.16.0",
			Aliases: []string{"GO-2023-2102", "GHSA-4374-p667-p6c8"},
		},
		{
			VulnID:  "CVE-2023-39325",
			PURL:    "pkg:golang/google.golang.org/grpc@v1.58.0",
			Aliases: []string{"GO-2023-2102", "GHSA-4374-p667-p6c8"},
		},
	}

	report := []evidence.FindingEvidence{
		{
			OSV:       "GO-2023-2102",
			Aliases:   []string{"CVE-2023-39325"},
			Module:    "golang.org/x/net",
			Reachable: true,
		},
		{
			OSV:       "GO-2023-2102",
			Aliases:   []string{"CVE-2023-39325"},
			Module:    "google.golang.org/grpc",
			Reachable: false,
		},
	}

	reachable, notReachable := ClassifySBOMFindings(existing, report)

	if len(reachable) != 1 {
		t.Fatalf("expected 1 reachable finding, got %d: %+v", len(reachable), reachable)
	}
	if reachable[0].PURL != "pkg:golang/golang.org/x/net@v0.16.0" {
		t.Errorf("reachable PURL = %q, want golang.org/x/net", reachable[0].PURL)
	}

	if len(notReachable) != 1 {
		t.Fatalf("expected 1 not_reachable finding, got %d: %+v", len(notReachable), notReachable)
	}
	if notReachable[0].PURL != "pkg:golang/google.golang.org/grpc@v1.58.0" {
		t.Errorf("not_reachable PURL = %q, want google.golang.org/grpc", notReachable[0].PURL)
	}
}

func TestClassifySBOMFindings_UnreportedFindingsUntouched(t *testing.T) {
	// A report covering Go code must NOT mark non-Go or unanalyzed dependencies not_reachable (#535).
	existing := []SBOMVulnRow{
		{
			VulnID:  "CVE-2021-44228",
			PURL:    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			Aliases: []string{"GHSA-j2ge-4vd9-799q"},
		},
		{
			VulnID:  "GHSA-p6mc-m468-83gw",
			PURL:    "pkg:npm/lodash@4.17.20",
			Aliases: []string{"CVE-2021-23337"},
		},
		{
			VulnID:  "CVE-2023-1495",
			PURL:    "pkg:golang/example.com/mod@v0.1.0",
			Aliases: []string{"GO-2023-1495"},
		},
	}

	report := []evidence.FindingEvidence{
		{
			OSV:       "GO-2023-1495",
			Aliases:   []string{"CVE-2023-1495"},
			Module:    "example.com/mod",
			Reachable: false,
		},
	}

	reachable, notReachable := ClassifySBOMFindings(existing, report)

	if len(reachable) != 0 {
		t.Errorf("expected 0 reachable findings, got %d", len(reachable))
	}
	if len(notReachable) != 1 {
		t.Fatalf("expected exactly 1 not_reachable finding, got %d", len(notReachable))
	}
	if notReachable[0].PURL != "pkg:golang/example.com/mod@v0.1.0" {
		t.Errorf("expected not_reachable for example.com/mod, got %q", notReachable[0].PURL)
	}
}

func TestBuildKeyFilter(t *testing.T) {
	keys := []VulnKey{
		{VulnID: "CVE-1", PURL: "pkg:golang/a@1"},
		{VulnID: "CVE-2", PURL: "pkg:golang/b@2"},
	}

	clause, args := buildKeyFilter(keys)
	wantClause := "((vuln_id = ? AND purl = ?) OR (vuln_id = ? AND purl = ?))"
	if clause != wantClause {
		t.Errorf("clause = %q, want %q", clause, wantClause)
	}
	if len(args) != 4 {
		t.Fatalf("args len = %d, want 4", len(args))
	}
	if args[0] != "CVE-1" || args[1] != "pkg:golang/a@1" || args[2] != "CVE-2" || args[3] != "pkg:golang/b@2" {
		t.Errorf("unexpected args: %+v", args)
	}

	emptyClause, emptyArgs := buildKeyFilter(nil)
	if emptyClause != "0" || len(emptyArgs) != 0 {
		t.Errorf("unexpected empty filter: clause=%q, args=%v", emptyClause, emptyArgs)
	}
}

func TestPurlMatchesModule(t *testing.T) {
	tests := []struct {
		purl   string
		module string
		want   bool
	}{
		{"pkg:golang/golang.org/x/net@v0.16.0", "golang.org/x/net", true},
		{"pkg:golang/golang.org/x/net/http2@v0.16.0", "golang.org/x/net", true},
		{"pkg:golang/google.golang.org/grpc@v1.58.0", "golang.org/x/net", false},
		{"pkg:golang/example.com/foo@v1.0.0", "example.com/foo", true},
		{"pkg:golang/example.com/foo/subpkg@v1.0.0", "example.com/foo", true},
		{"pkg:golang/example.com/foobar@v1.0.0", "example.com/foo", false},
		{"pkg:golang/example.com/foo-client@v1.0.0", "example.com/foo", false},
		{"pkg:golang/stdlib@v1.25.12", "stdlib", true},
		{"pkg:golang/go@v1.25.12", "stdlib", true},
		{"stdlib", "stdlib", true},
	}

	for _, tc := range tests {
		got := purlMatchesModule(tc.purl, tc.module)
		if got != tc.want {
			t.Errorf("purlMatchesModule(%q, %q) = %v, want %v", tc.purl, tc.module, got, tc.want)
		}
	}
}
