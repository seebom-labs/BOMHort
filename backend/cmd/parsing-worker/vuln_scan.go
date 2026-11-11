package main

import (
	"context"
	"log"

	"github.com/seebom-labs/bomhort/backend/internal/advisory"
	"github.com/seebom-labs/bomhort/backend/internal/osv"
)

// osvChunkSize is the most PURLs one /v1/querybatch request takes.
const osvChunkSize = 1000

// vulnSource is the part of the OSV client the scan needs.
type vulnSource interface {
	QueryBatch(ctx context.Context, purls []string) (*osv.BatchResponse, error)
	HydrateVulns(ctx context.Context, ids []string) (map[string]*osv.VulnEntry, error)
}

// scanVulnerabilities returns the findings for purls: osv.dev's, combined
// with the advisory feeds when matcher is non-nil (feed first for the PURL
// prefixes a feed is authoritative for).
//
// osv.dev ids hydration does not return are skipped, not stubbed: the
// cve-refresher inserts them once osv.dev answers. A failed feed lookup is
// an error, so the job is retried rather than storing upstream matches the
// feed may have closed — the refresher never revisits a stored finding.
func scanVulnerabilities(ctx context.Context, src vulnSource, matcher *advisory.Matcher, purls []string) ([]advisory.Finding, error) {
	type vulnPURL struct{ id, purl string }
	var discovered []vulnPURL
	for i := 0; i < len(purls); i += osvChunkSize {
		chunk := purls[i:min(i+osvChunkSize, len(purls))]
		resp, err := src.QueryBatch(ctx, chunk)
		if err != nil {
			log.Printf("  WARNING: OSV query failed for chunk %d-%d: %v", i, i+len(chunk), err)
			continue
		}
		for j, qr := range resp.Results {
			if j >= len(chunk) {
				break
			}
			for _, v := range qr.Vulns {
				discovered = append(discovered, vulnPURL{id: v.ID, purl: chunk[j]})
			}
		}
	}

	hits := map[string][]osv.VulnEntry{}
	var order []string
	if len(discovered) > 0 {
		var ids []string
		seen := map[string]struct{}{}
		for _, d := range discovered {
			if _, ok := seen[d.id]; !ok {
				seen[d.id] = struct{}{}
				ids = append(ids, d.id)
			}
		}
		hydrated, err := src.HydrateVulns(ctx, ids)
		if err != nil {
			log.Printf("  WARNING: Hydration failed: %v", err)
		}
		var skipped []string
		for _, d := range discovered {
			h, ok := hydrated[d.id]
			if !ok || h == nil {
				skipped = append(skipped, d.id)
				continue
			}
			if _, ok := hits[d.purl]; !ok {
				order = append(order, d.purl)
			}
			hits[d.purl] = append(hits[d.purl], *h)
		}
		if len(skipped) > 0 {
			log.Printf("  WARNING: %d findings skipped (hydration failed), e.g. %v; cve-refresher will add them",
				len(skipped), skipped[:min(5, len(skipped))])
		}
	}

	if matcher == nil {
		var out []advisory.Finding
		for _, p := range order {
			out = append(out, advisory.FromOSV(p, hits[p])...)
		}
		return out, nil
	}

	findings, err := matcher.Match(ctx, purls, hits)
	if err != nil {
		return nil, err
	}
	if err := advisory.Enrich(ctx, findings, src.HydrateVulns); err != nil {
		log.Printf("  WARNING: severity lookup for advisory-feed findings failed: %v", err)
	}
	return findings, nil
}
