package clickhouse

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/evidence"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// VulnKey identifies a distinct vulnerability finding by vulnerability ID and PURL (#535).
type VulnKey struct {
	VulnID string
	PURL   string
}

// SBOMVulnRow represents an existing vulnerability row queried from ClickHouse.
type SBOMVulnRow struct {
	VulnID  string
	PURL    string
	Aliases []string
}

// ApplyReachabilityEvidence applies call-graph or scanner reachability findings
// to the vulnerabilities recorded for an SBOM (#535).
//
// Findings are evaluated and updated per (vuln_id, purl) pair:
//   - Findings represented in the report with active execution traces are marked 'reachable'.
//   - Findings represented in the report without execution traces are marked 'not_reachable'.
//   - Findings not represented in the report (e.g. non-Go dependencies or unanalyzed packages)
//     are left unchanged.
func (c *Client) ApplyReachabilityEvidence(
	ctx context.Context,
	sbomID string,
	tool string,
	ref string,
	reportFindings []evidence.FindingEvidence,
) (*dto.ReachabilitySummary, error) {
	// 1. Verify that the SBOM exists.
	var count uint64
	if err := c.Conn.QueryRow(ctx, "SELECT count() FROM sboms FINAL WHERE sbom_id = ?", sbomID).Scan(&count); err != nil {
		return nil, fmt.Errorf("failed to check sbom %s: %w", sbomID, err)
	}
	if count == 0 {
		return nil, ErrSBOMNotFound
	}

	// 2. Fetch all vulnerability findings for this SBOM.
	rows, err := c.Conn.Query(ctx, "SELECT vuln_id, purl, aliases FROM vulnerabilities FINAL WHERE sbom_id = ?", sbomID)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities for sbom %s: %w", sbomID, err)
	}
	defer rows.Close()

	var existing []SBOMVulnRow
	for rows.Next() {
		var r SBOMVulnRow
		if err := rows.Scan(&r.VulnID, &r.PURL, &r.Aliases); err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability row: %w", err)
		}
		existing = append(existing, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed reading vulnerability rows: %w", err)
	}

	reachableKeys, notReachableKeys := ClassifySBOMFindings(existing, reportFindings)

	now := time.Now().UTC()
	totalUpdated := len(reachableKeys) + len(notReachableKeys)

	// 3. Mutate vulnerabilities table with evidence per (vuln_id, purl).
	if len(reachableKeys) > 0 {
		filter, filterArgs := buildKeyFilter(reachableKeys)
		query := fmt.Sprintf(`
			ALTER TABLE vulnerabilities
			UPDATE
				reachability = 'reachable',
				evidence_source = ?,
				evidence_ref = ?,
				evidence_at = ?
			WHERE sbom_id = ? AND %s
			SETTINGS mutations_sync = 1`, filter)
		args := append([]any{tool, ref, now, sbomID}, filterArgs...)
		if err := c.Conn.Exec(ctx, query, args...); err != nil {
			return nil, fmt.Errorf("failed to update reachable evidence for sbom %s: %w", sbomID, err)
		}
	}

	if len(notReachableKeys) > 0 {
		filter, filterArgs := buildKeyFilter(notReachableKeys)
		query := fmt.Sprintf(`
			ALTER TABLE vulnerabilities
			UPDATE
				reachability = 'not_reachable',
				evidence_source = ?,
				evidence_ref = ?,
				evidence_at = ?
			WHERE sbom_id = ? AND %s
			SETTINGS mutations_sync = 1`, filter)
		args := append([]any{tool, ref, now, sbomID}, filterArgs...)
		if err := c.Conn.Exec(ctx, query, args...); err != nil {
			return nil, fmt.Errorf("failed to update not_reachable evidence for sbom %s: %w", sbomID, err)
		}
	}

	return &dto.ReachabilitySummary{
		SBOMID:        sbomID,
		Tool:          tool,
		Ref:           ref,
		TotalFindings: totalUpdated,
		Reachable:     len(reachableKeys),
		NotReachable:  len(notReachableKeys),
		Timestamp:     now.Format(time.RFC3339),
	}, nil
}

// ClassifySBOMFindings partitions the SBOM's vulnerability rows into reachable and
// not_reachable findings based on the evidence in reportFindings (#535).
// Unreported findings are omitted so their reachability remains unchanged.
func ClassifySBOMFindings(existing []SBOMVulnRow, reportFindings []evidence.FindingEvidence) (reachable []VulnKey, notReachable []VulnKey) {
	for _, row := range existing {
		matched := false
		isReachable := false

		for _, ev := range reportFindings {
			if matchesFinding(row, ev) {
				matched = true
				if ev.Reachable {
					isReachable = true
					break
				}
			}
		}

		if !matched {
			// Unreported findings are not proof of non-reachability; leave unchanged.
			continue
		}

		k := VulnKey{VulnID: row.VulnID, PURL: row.PURL}
		if isReachable {
			reachable = append(reachable, k)
		} else {
			notReachable = append(notReachable, k)
		}
	}
	return reachable, notReachable
}

func matchesFinding(row SBOMVulnRow, ev evidence.FindingEvidence) bool {
	// 1. Check vulnerability ID or aliases
	idMatch := row.VulnID == ev.OSV
	if !idMatch {
		for _, a := range ev.Aliases {
			if row.VulnID == a {
				idMatch = true
				break
			}
		}
	}
	if !idMatch {
		for _, rowAlias := range row.Aliases {
			if rowAlias == ev.OSV {
				idMatch = true
				break
			}
			for _, a := range ev.Aliases {
				if rowAlias == a {
					idMatch = true
					break
				}
			}
			if idMatch {
				break
			}
		}
	}
	if !idMatch {
		return false
	}

	// 2. Check PURL / module
	if ev.Module != "" {
		return purlMatchesModule(row.PURL, ev.Module)
	}

	return false
}

func purlMatchesModule(purl, module string) bool {
	if module == "" {
		return false
	}
	if module == "stdlib" {
		return purl == "pkg:golang/stdlib" ||
			strings.HasPrefix(purl, "pkg:golang/stdlib@") ||
			strings.HasPrefix(purl, "pkg:golang/stdlib/") ||
			strings.HasPrefix(purl, "pkg:golang/stdlib?") ||
			strings.HasPrefix(purl, "pkg:golang/go@") ||
			strings.HasPrefix(purl, "pkg:golang/go/") ||
			purl == "stdlib"
	}
	prefix := "pkg:golang/" + module
	if purl == prefix || strings.HasPrefix(purl, prefix+"@") || strings.HasPrefix(purl, prefix+"/") || strings.HasPrefix(purl, prefix+"?") {
		return true
	}
	if purl == module || strings.HasPrefix(purl, module+"@") || strings.HasPrefix(purl, module+"/") || strings.HasPrefix(purl, module+"?") {
		return true
	}
	return false
}

func buildKeyFilter(keys []VulnKey) (string, []any) {
	if len(keys) == 0 {
		return "0", nil
	}
	clauses := make([]string, len(keys))
	args := make([]any, 0, len(keys)*2)
	for i, k := range keys {
		clauses[i] = "(vuln_id = ? AND purl = ?)"
		args = append(args, k.VulnID, k.PURL)
	}
	return "(" + strings.Join(clauses, " OR ") + ")", args
}

// ApplyVEXReachability updates reachability evidence on matching findings for an
// SBOM based on an OpenVEX statement with reachability justification (#535).
func (c *Client) ApplyVEXReachability(ctx context.Context, sbomID string, vulnID string, purl string, reachability string, tooling string, ref string, at time.Time) error {
	if sbomID == "" || vulnID == "" {
		return nil
	}
	if reachability == "" {
		reachability = models.ReachabilityNotReachable
	}
	if tooling == "" {
		tooling = "OpenVEX"
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}

	if err := c.Conn.Exec(ctx, `
		ALTER TABLE vulnerabilities
		UPDATE
			reachability = ?,
			evidence_source = ?,
			evidence_ref = ?,
			evidence_at = ?
		WHERE sbom_id = ?
		  AND (vuln_id = ? OR has(aliases, ?))
		  AND (? = '*' OR ? = '' OR purl = ?)
		SETTINGS mutations_sync = 1`,
		reachability, tooling, ref, at, sbomID, vulnID, vulnID, purl, purl, purl,
	); err != nil {
		return fmt.Errorf("failed to apply VEX reachability for sbom %s, vuln %s: %w", sbomID, vulnID, err)
	}

	return nil
}
