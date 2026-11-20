package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/vex"
)

// VEXExport is what the OpenVEX export (#533) renders: the effective
// decisions and a stable issuance time for a document without any.
type VEXExport struct {
	Statements []vex.ExportStatement
	// Issued is the newest ingest of the exported SBOMs.
	Issued time.Time
}

// ExportProductRef is the OpenVEX product @id of an SBOM in the export. It
// names exactly one SBOM, unlike its document namespace, which CycloneDX
// revisions of a product share; ResolveSBOMByProductRef resolves it back.
func ExportProductRef(sbomID string) string {
	return "urn:uuid:" + sbomID
}

// QuerySBOMVEXExport returns the effective VEX decisions of one SBOM for the
// OpenVEX export (#533). found is false when the SBOM does not exist.
func (c *Client) QuerySBOMVEXExport(ctx context.Context, sbomID string) (export *VEXExport, found bool, err error) {
	return c.queryVEXExport(ctx, "sbom_id = ?", sbomID)
}

// QueryProjectVEXExport returns the effective VEX decisions of every SBOM of
// a project, each under its own product: a decision for one version says
// nothing about another. found is false when the project has no SBOMs.
func (c *Client) QueryProjectVEXExport(ctx context.Context, name string) (export *VEXExport, found bool, err error) {
	return c.queryVEXExport(ctx, "sbom_id IN (SELECT s.sbom_id FROM "+projectSBOMs+" AS s WHERE s.project_name = ?)", name)
}

// queryVEXExport collects the decisions for the SBOMs matching filter (a
// predicate over sboms), in two parts:
//
//   - For every finding, the decision the vulnerability view shows for it:
//     the newest statement scoped to the SBOM whose vulnerability is the
//     finding's id or one of its aliases and whose component is the finding's
//     purl or the whole product (#335, #350). It is exported for the finding's
//     id and purl, so a superseded statement for an alias, or a component
//     statement a newer product-wide one overrides, is not handed out.
//   - Statements that match no finding (a vulnerability BOMHort has not
//     detected): the newest per vulnerability and component, as stated.
//
// Ties on the timestamp are broken by ingest time and vex_id, so the export
// is stable. Unscoped statements are not read: they apply to no SBOM.
func (c *Client) queryVEXExport(ctx context.Context, filter string, arg any) (*VEXExport, bool, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT toString(sbom_id), root_purl, ingested_at
		FROM sboms FINAL
		WHERE `+filter, arg)
	if err != nil {
		return nil, false, fmt.Errorf("failed to query vex export scope: %w", err)
	}
	rootPURL := make(map[string]string)
	var ids []string
	var issued time.Time
	for rows.Next() {
		var id, root string
		var ingested time.Time
		if err := rows.Scan(&id, &root, &ingested); err != nil {
			rows.Close()
			return nil, false, fmt.Errorf("failed to scan vex export scope: %w", err)
		}
		rootPURL[id] = root
		ids = append(ids, id)
		if ingested.After(issued) {
			issued = ingested
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("failed to read vex export scope: %w", err)
	}
	if len(ids) == 0 {
		return nil, false, nil
	}

	export := &VEXExport{Issued: issued}
	product := func(sbomID string) (string, string) { return ExportProductRef(sbomID), rootPURL[sbomID] }

	// Part 1: the decision per finding.
	rows, err = c.Conn.Query(ctx, `
		SELECT
			toString(v.sbom_id), v.vuln_id, v.purl, any(v.aliases),
			argMax(vx.vuln_id, k), argMax(vx.status, k), argMax(vx.justification, k),
			argMax(vx.impact_statement, k), argMax(vx.action_statement, k), argMax(vx.status_notes, k),
			max(vx.vex_timestamp), argMax(vx.author, k), argMax(vx.role, k), argMax(vx.tooling, k),
			groupUniqArray(concat(vx.vuln_id, '\n', vx.product_purl))
		FROM (
			SELECT sbom_id, vuln_id, purl, aliases,
				arrayJoin(arrayConcat([vuln_id], aliases)) AS match_id
			FROM vulnerabilities FINAL
			WHERE sbom_id IN (?)
		) AS v
		INNER JOIN (
			SELECT *, (vex_timestamp, ingested_at, toString(vex_id)) AS k
			FROM vex_statements FINAL
			WHERE sbom_id IN (?)
		) AS vx ON vx.vuln_id = v.match_id AND vx.sbom_id = toString(v.sbom_id)
		WHERE vx.product_purl = v.purl OR vx.product_purl = '*'
		GROUP BY v.sbom_id, v.vuln_id, v.purl
	`, ids, ids)
	if err != nil {
		return nil, false, fmt.Errorf("failed to query vex export decisions: %w", err)
	}
	// Statement keys (sbom, vulnerability, component) that some finding
	// matched: they are covered by part 1.
	matched := make(map[string]bool)
	for rows.Next() {
		var sbomID, stmtVuln string
		var s vex.ExportStatement
		var aliases, keys []string
		if err := rows.Scan(&sbomID, &s.VulnID, &s.PURL, &aliases,
			&stmtVuln, &s.Status, &s.Justification,
			&s.ImpactStatement, &s.ActionStatement, &s.StatusNotes,
			&s.Timestamp, &s.Author, &s.Role, &s.Tooling, &keys,
		); err != nil {
			rows.Close()
			return nil, false, fmt.Errorf("failed to scan vex export decision: %w", err)
		}
		s.Product, s.ProductPURL = product(sbomID)
		s.Aliases = append(aliases, stmtVuln)
		export.Statements = append(export.Statements, s)
		for _, k := range keys {
			matched[sbomID+"\n"+k] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("failed to read vex export decisions: %w", err)
	}

	// Part 2: statements no finding matched.
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
		return nil, false, fmt.Errorf("failed to query vex export statements: %w", err)
	}
	defer rows.Close()
	var unmatched []vex.ExportStatement
	vulnIDs := make(map[string]struct{})
	for rows.Next() {
		var sbomID string
		var s vex.ExportStatement
		if err := rows.Scan(&sbomID, &s.VulnID, &s.PURL,
			&s.Status, &s.Justification, &s.ImpactStatement,
			&s.ActionStatement, &s.StatusNotes, &s.Timestamp,
			&s.Author, &s.Role, &s.Tooling,
		); err != nil {
			return nil, false, fmt.Errorf("failed to scan vex export statement: %w", err)
		}
		if matched[sbomID+"\n"+s.VulnID+"\n"+s.PURL] {
			continue
		}
		s.Product, s.ProductPURL = product(sbomID)
		unmatched = append(unmatched, s)
		vulnIDs[s.VulnID] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("failed to read vex export statements: %w", err)
	}

	// No finding carries their aliases; look them up across all findings,
	// as the statement listing does.
	lookup := make([]string, 0, len(vulnIDs))
	for id := range vulnIDs {
		lookup = append(lookup, id)
	}
	aliases, err := c.lookupAliases(ctx, lookup)
	if err != nil {
		return nil, false, err
	}
	for i := range unmatched {
		unmatched[i].Aliases = aliases[unmatched[i].VulnID]
	}
	export.Statements = append(export.Statements, unmatched...)
	return export, true, nil
}
