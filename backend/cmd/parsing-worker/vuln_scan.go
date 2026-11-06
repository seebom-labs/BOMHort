package main

import (
	"context"

	"github.com/seebom-labs/bomhort/backend/internal/advisory"
	"github.com/seebom-labs/bomhort/backend/internal/evaluate"
)

// vulnSource is the part of the OSV client the scan needs.
type vulnSource = evaluate.OSVClient

// scanVulnerabilities returns the findings for purls: osv.dev's, combined
// with the advisory feeds when matcher is non-nil (feed first for the PURL
// prefixes a feed is authoritative for).
//
// osv.dev ids hydration does not return are skipped, not stubbed: the
// cve-refresher inserts them once osv.dev answers. A failed feed lookup is
// an error, so the job is retried rather than storing upstream matches the
// feed may have closed - the refresher never revisits a stored finding.
func scanVulnerabilities(ctx context.Context, src vulnSource, matcher *advisory.Matcher, purls []string) ([]advisory.Finding, error) {
	return evaluate.ScanVulnerabilities(ctx, src, matcher, purls, false)
}
