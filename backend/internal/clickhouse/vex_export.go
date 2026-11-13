package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/vex"
)

// QuerySBOMVEXExport returns the effective VEX decisions of one SBOM for the
// OpenVEX export (#533). found is false when the SBOM does not exist.
func (c *Client) QuerySBOMVEXExport(ctx context.Context, sbomID string) (stmts []vex.ExportStatement, found bool, err error) {
	return c.queryVEXExport(ctx, "sbom_id = ?", sbomID)
}

// QueryProjectVEXExport returns the effective VEX decisions of every SBOM of
// a project, each under its own product: a decision for one version says
// nothing about another. found is false when the project has no SBOMs.
func (c *Client) QueryProjectVEXExport(ctx context.Context, name string) (stmts []vex.ExportStatement, found bool, err error) {
	return c.queryVEXExport(ctx, "sbom_id IN (SELECT s.sbom_id FROM "+projectSBOMs+" AS s WHERE s.project_name = ?)", name)
}

// queryVEXExport reads the statements scoped to the SBOMs matching filter (a
// predicate over sboms). Per (SBOM, vulnerability, component) the newest
// statement wins (#335), with ingest time and vex_id breaking ties so the
// export is stable. Unscoped statements are not read: they apply to no SBOM.
func (c *Client) queryVEXExport(ctx context.Context, filter string, arg any) ([]vex.ExportStatement, bool, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT toString(sbom_id), document_namespace
		FROM sboms FINAL
		WHERE `+filter, arg)
	if err != nil {
		return nil, false, fmt.Errorf("failed to query vex export scope: %w", err)
	}
	products := make(map[string]string)
	var ids []string
	for rows.Next() {
		var id, namespace string
		if err := rows.Scan(&id, &namespace); err != nil {
			rows.Close()
			return nil, false, fmt.Errorf("failed to scan vex export scope: %w", err)
		}
		// The namespace is what the document calls itself; sbom_id is the
		// fallback. Both resolve back to this SBOM on re-upload.
		products[id] = id
		if namespace != "" {
			products[id] = namespace
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("failed to read vex export scope: %w", err)
	}
	if len(ids) == 0 {
		return nil, false, nil
	}

	rows, err = c.Conn.Query(ctx, `
		SELECT sbom_id, vuln_id, product_purl,
			argMax(status, k), argMax(justification, k), argMax(impact_statement, k),
			argMax(action_statement, k), argMax(status_notes, k), max(vex_timestamp),
			argMax(author, k), argMax(role, k), argMax(tooling, k)
		FROM (
			SELECT *, (vex_timestamp, ingested_at, toString(vex_id)) AS k
			FROM vex_statements FINAL
			WHERE sbom_id IN (?)
		)
		GROUP BY sbom_id, vuln_id, product_purl
	`, ids)
	if err != nil {
		return nil, false, fmt.Errorf("failed to query vex export: %w", err)
	}
	defer rows.Close()

	var out []vex.ExportStatement
	vulnIDs := make(map[string]struct{})
	for rows.Next() {
		var sbomID string
		var s vex.ExportStatement
		var ts time.Time
		if err := rows.Scan(&sbomID, &s.VulnID, &s.PURL,
			&s.Status, &s.Justification, &s.ImpactStatement,
			&s.ActionStatement, &s.StatusNotes, &ts,
			&s.Author, &s.Role, &s.Tooling,
		); err != nil {
			return nil, false, fmt.Errorf("failed to scan vex export row: %w", err)
		}
		s.Product = products[sbomID]
		s.Timestamp = ts
		out = append(out, s)
		vulnIDs[s.VulnID] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("failed to read vex export rows: %w", err)
	}

	// The other names of each flaw (GHSA ↔ CVE) help consumers whose scanner
	// reports a different id than the statement's author used.
	ids = ids[:0]
	for id := range vulnIDs {
		ids = append(ids, id)
	}
	aliases, err := c.lookupAliases(ctx, ids)
	if err != nil {
		return nil, false, err
	}
	for i := range out {
		out[i].Aliases = aliases[out[i].VulnID]
	}
	return out, true, nil
}
