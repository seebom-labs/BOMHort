package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// QueryDashboardStats fetches aggregated dashboard statistics.
func (c *Client) QueryDashboardStats(ctx context.Context) (*dto.DashboardStats, error) {
	stats := &dto.DashboardStats{
		LicenseBreakdown: make(map[string]uint64),
	}

	// Total SBOMs
	if err := c.Conn.QueryRow(ctx, "SELECT count() FROM sboms FINAL").Scan(&stats.TotalSBOMs); err != nil {
		return nil, fmt.Errorf("failed to query total sboms: %w", err)
	}

	// Total Packages (sum of array lengths)
	if err := c.Conn.QueryRow(ctx,
		"SELECT sum(length(package_names)) FROM sbom_packages FINAL").Scan(&stats.TotalPackages); err != nil {
		return nil, fmt.Errorf("failed to query total packages: %w", err)
	}

	// Vulnerability counts by severity
	if err := c.Conn.QueryRow(ctx, "SELECT count() FROM vulnerabilities FINAL").Scan(&stats.TotalVulnerabilities); err != nil {
		return nil, fmt.Errorf("failed to query total vulnerabilities: %w", err)
	}

	rows, err := c.Conn.Query(ctx,
		"SELECT severity, count() AS cnt FROM vulnerabilities FINAL GROUP BY severity")
	if err != nil {
		return nil, fmt.Errorf("failed to query severity breakdown: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var severity string
		var cnt uint64
		if err := rows.Scan(&severity, &cnt); err != nil {
			return nil, fmt.Errorf("failed to scan severity row: %w", err)
		}
		switch severity {
		case "CRITICAL":
			stats.CriticalVulns = cnt
		case "HIGH":
			stats.HighVulns = cnt
		case "MEDIUM":
			stats.MediumVulns = cnt
		case "LOW":
			stats.LowVulns = cnt
		}
	}

	// License breakdown
	licRows, err := c.Conn.Query(ctx,
		"SELECT category, sum(package_count) AS cnt FROM license_compliance FINAL GROUP BY category")
	if err != nil {
		return nil, fmt.Errorf("failed to query license breakdown: %w", err)
	}
	defer licRows.Close()

	for licRows.Next() {
		var category string
		var cnt uint64
		if err := licRows.Scan(&category, &cnt); err != nil {
			return nil, fmt.Errorf("failed to scan license row: %w", err)
		}
		stats.LicenseBreakdown[category] = cnt
	}

	// Count exempted packages (packages covered by blanket or per-package exceptions).
	_ = c.Conn.QueryRow(ctx,
		"SELECT sum(length(exempted_packages)) FROM license_compliance FINAL").Scan(&stats.ExemptedPackages)

	// Subtract exempted from copyleft so the dashboard shows the real violation count.
	if stats.LicenseBreakdown["copyleft"] > stats.ExemptedPackages {
		stats.LicenseBreakdown["copyleft"] -= stats.ExemptedPackages
	} else {
		stats.LicenseBreakdown["copyleft"] = 0
	}

	// VEX: count suppressed vulnerabilities (not_affected) and total statements.
	_ = c.Conn.QueryRow(ctx,
		"SELECT count() FROM vex_statements FINAL").Scan(&stats.TotalVEXStatements)

	// Scope-aware (#350): a statement only suppresses a finding in the SBOM
	// it is scoped to; there is no global/fleet-wide VEX scope.
	//
	// Deliberately a JOIN rather than WHERE EXISTS (...v.vuln_id...): ClickHouse
	// rejects a correlated subquery referencing an outer column ("Resolve
	// identifier from parent scope only supported for constants and CTE",
	// UNSUPPORTED_METHOD), so the EXISTS form errored on every single call - and
	// with the error discarded the dashboard reported 0 suppressed findings
	// forever. The error is returned now instead of silently yielding a wrong 0.
	//
	// Counted per (sbom_id, vuln_id, purl), not per (vuln_id, purl):
	// total_vulnerabilities counts one row per SBOM, so a statement scoped to one
	// SBOM must subtract exactly that SBOM's finding, or effective_vulnerabilities
	// drifts. Latest-wins (#335) is applied before the not_affected test: a newer
	// "affected" statement un-suppresses the finding.
	//
	// The purl match accepts '*' (models.VEXProductWide) alongside an exact
	// match: a statement naming a product with no subcomponents covers every
	// component of it. The match therefore has to be a WHERE predicate rather
	// than a JOIN key — and the argMax runs *after* it, so a product-wide and a
	// component-scoped statement for the same finding compete on timestamp like
	// any other pair.
	var suppressedByVEX uint64
	if err := c.Conn.QueryRow(ctx, `
		SELECT count()
		FROM (
			SELECT
				v.sbom_id AS sbom_id, v.vuln_id AS vuln_id, v.purl AS purl,
				argMax(vx.status, vx.vex_timestamp) AS winning_status
			FROM (
				SELECT sbom_id, vuln_id, purl,
					arrayJoin(arrayConcat([vuln_id], aliases)) AS match_id
				FROM vulnerabilities FINAL
			) AS v
			INNER JOIN (
				SELECT sbom_id, vuln_id, product_purl, status, vex_timestamp
				FROM vex_statements FINAL
				WHERE sbom_id != ''
			) AS vx ON vx.vuln_id = v.match_id
				AND vx.sbom_id = toString(v.sbom_id)
			WHERE vx.product_purl = v.purl OR vx.product_purl = '*'
			GROUP BY v.sbom_id, v.vuln_id, v.purl
		)
		WHERE winning_status = 'not_affected'
	`).Scan(&suppressedByVEX); err != nil {
		return nil, fmt.Errorf("failed to count vex-suppressed vulnerabilities: %w", err)
	}

	stats.SuppressedByVEX = suppressedByVEX
	if stats.TotalVulnerabilities >= suppressedByVEX {
		stats.EffectiveVulnerabilities = stats.TotalVulnerabilities - suppressedByVEX
	} else {
		stats.EffectiveVulnerabilities = stats.TotalVulnerabilities
	}

	// Last CVE refresh info.
	lastRefresh, err := c.QueryLastRefreshTime(ctx)
	if err == nil && !lastRefresh.IsZero() {
		stats.LastCVERefresh = lastRefresh.Format(time.RFC3339)
		// Count vulns found in the most recent refresh.
		_ = c.Conn.QueryRow(ctx, `
			SELECT ifNull(new_vulns_found, 0)
			FROM cve_refresh_log FINAL
			WHERE status = 'completed'
			ORDER BY finished_at DESC
			LIMIT 1
		`).Scan(&stats.NewVulnsSinceRefresh)
	}

	// Archived repos count.
	_ = c.Conn.QueryRow(ctx,
		"SELECT count() FROM github_repo_metadata FINAL WHERE archived = true").Scan(&stats.ArchivedReposCount)

	return stats, nil
}

// QuerySBOMs fetches a paginated list of SBOMs with package and vulnerability counts.
// If search is non-empty, it filters SBOMs whose document_name or source_file contains the term.
func (c *Client) QuerySBOMs(ctx context.Context, page, pageSize uint64, search string) (*dto.PaginatedResponse[dto.SBOMListItem], error) {
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	// Build WHERE clause for search.
	whereClause := ""
	var searchArgs []interface{}
	if search != "" {
		whereClause = "WHERE s.document_name ILIKE ? OR s.source_file ILIKE ?"
		pattern := "%" + search + "%"
		searchArgs = append(searchArgs, pattern, pattern)
	}

	// Count total (with search filter).
	var total uint64
	countQuery := "SELECT count() FROM (SELECT * FROM sboms FINAL) AS s " + whereClause
	if err := c.Conn.QueryRow(ctx, countQuery, searchArgs...).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count sboms: %w", err)
	}

	query := fmt.Sprintf(`
		SELECT
			s.sbom_id,
			s.source_file,
			s.spdx_version,
			s.document_name,
			s.document_version,
			s.ingested_at,
			s.source_repo,
			s.source_ref,
			s.cluster,
			s.namespace,
			s.project,
			ifNull(p.pkg_count, 0) AS package_count,
			ifNull(v.vuln_count, 0) AS vuln_count
		FROM (SELECT * FROM sboms FINAL) AS s
		LEFT JOIN (
			SELECT sbom_id, length(package_names) AS pkg_count
			FROM sbom_packages FINAL
		) AS p ON s.sbom_id = p.sbom_id
		LEFT JOIN (
			SELECT sbom_id, count() AS vuln_count
			FROM vulnerabilities FINAL
			GROUP BY sbom_id
		) AS v ON s.sbom_id = v.sbom_id
		%s
		ORDER BY s.document_name ASC, s.ingested_at DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	args := append(searchArgs, pageSize, offset)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query sboms: %w", err)
	}
	defer rows.Close()

	var items []dto.SBOMListItem
	for rows.Next() {
		var item dto.SBOMListItem
		var ingestedAt time.Time
		if err := rows.Scan(
			&item.SBOMID, &item.SourceFile, &item.SPDXVersion,
			&item.DocumentName, &item.DocumentVersion, &ingestedAt,
			&item.SourceRepo, &item.SourceRef,
			&item.Cluster, &item.Namespace, &item.Project,
			&item.PackageCount, &item.VulnCount,
		); err != nil {
			return nil, fmt.Errorf("failed to scan sbom row: %w", err)
		}
		item.IngestedAt = ingestedAt.Format(time.RFC3339)
		items = append(items, item)
	}

	if items == nil {
		items = []dto.SBOMListItem{}
	}

	return &dto.PaginatedResponse[dto.SBOMListItem]{
		Data:     items,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// QueryVulnerabilities fetches a paginated list of vulnerabilities.
//
// Every finding is returned; the VEX status is joined in for display only. There
// is deliberately no server-side "effective only" filter: hiding rows made the
// list disagree with the dashboard KPI and with the per-SBOM view, and a VEX
// status is context a reader needs to see, not a reason to drop the row.
//
// The VEX join is pre-aggregated with argMax(status, vex_timestamp) so the
// latest-wins rule (#335) applies and a finding covered by several statements
// still yields exactly one row. Scope is per SBOM (#350), and a statement
// naming a product with no subcomponents ('*') covers every component of it.
func (c *Client) QueryVulnerabilities(ctx context.Context, page, pageSize uint64) (*dto.PaginatedResponse[dto.VulnerabilityListItem], error) {
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	var total uint64
	if err := c.Conn.QueryRow(ctx, `
		SELECT count() FROM (SELECT * FROM vulnerabilities FINAL)
	`).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count vulnerabilities: %w", err)
	}

	rows, err := c.Conn.Query(ctx, `
		SELECT
			v.vuln_id, v.severity, v.purl, v.summary,
			v.fixed_version, v.source_file, v.discovered_at,
			ifNull(vx.vex_status, '') AS vex_status
		FROM (SELECT * FROM vulnerabilities FINAL) AS v
		LEFT JOIN (
			SELECT
				toString(f.sbom_id) AS sbom_id, f.vuln_id AS vuln_id, f.purl AS purl,
				argMax(s.status, s.vex_timestamp) AS vex_status
			FROM (
				SELECT DISTINCT sbom_id, vuln_id, purl,
					arrayJoin(arrayConcat([vuln_id], aliases)) AS match_id
				FROM vulnerabilities FINAL
			) AS f
			INNER JOIN (
				SELECT sbom_id, vuln_id, product_purl, status, vex_timestamp
				FROM vex_statements FINAL
				WHERE sbom_id != ''
			) AS s ON s.vuln_id = f.match_id AND s.sbom_id = toString(f.sbom_id)
			WHERE s.product_purl = f.purl OR s.product_purl = '*'
			GROUP BY f.sbom_id, f.vuln_id, f.purl
		) AS vx ON vx.vuln_id = v.vuln_id
			AND vx.purl = v.purl
			AND vx.sbom_id = toString(v.sbom_id)
		ORDER BY v.severity ASC, v.discovered_at DESC
		LIMIT ? OFFSET ?
	`, pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities: %w", err)
	}
	defer rows.Close()

	var items []dto.VulnerabilityListItem
	for rows.Next() {
		var item dto.VulnerabilityListItem
		var discoveredAt time.Time
		if err := rows.Scan(
			&item.VulnID, &item.Severity, &item.PURL,
			&item.Summary, &item.FixedVersion, &item.SourceFile,
			&discoveredAt, &item.VEXStatus,
		); err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability row: %w", err)
		}
		item.DiscoveredAt = discoveredAt.Format(time.RFC3339)
		items = append(items, item)
	}

	if items == nil {
		items = []dto.VulnerabilityListItem{}
	}

	return &dto.PaginatedResponse[dto.VulnerabilityListItem]{
		Data:     items,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// QueryLicenseCompliance fetches all license compliance records aggregated by license.
func (c *Client) QueryLicenseCompliance(ctx context.Context) ([]dto.LicenseComplianceItem, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT
			lc.license_id,
			lc.category,
			sum(lc.package_count) AS total_packages,
			arrayDistinct(groupArrayArray(lc.non_compliant_packages)) AS all_non_compliant,
			arrayDistinct(groupArrayArray(lc.exempted_packages)) AS all_exempted,
			any(lc.exemption_reason) AS exemption_reason,
			count(DISTINCT lc.sbom_id) AS sbom_count,
			groupArray(DISTINCT toString(lc.sbom_id)) AS sbom_ids,
			groupArray(DISTINCT ifNull(s.document_name, lc.source_file)) AS sbom_names
		FROM (SELECT * FROM license_compliance FINAL) AS lc
		LEFT JOIN (SELECT * FROM sboms FINAL) AS s ON s.sbom_id = lc.sbom_id
		GROUP BY lc.license_id, lc.category
		ORDER BY total_packages DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query license compliance: %w", err)
	}
	defer rows.Close()

	var items []dto.LicenseComplianceItem
	for rows.Next() {
		var item dto.LicenseComplianceItem
		var nonCompliant []string
		var exempted []string
		var exemptionReason string
		var sbomCount uint64
		var sbomIDs []string
		var sbomNames []string
		if err := rows.Scan(&item.LicenseID, &item.Category, &item.PackageCount, &nonCompliant, &exempted, &exemptionReason, &sbomCount, &sbomIDs, &sbomNames); err != nil {
			return nil, fmt.Errorf("failed to scan license row: %w", err)
		}
		item.SBOMCount = int(sbomCount)
		if len(nonCompliant) > 0 {
			item.NonCompliantPackages = nonCompliant
		}
		if len(exempted) > 0 {
			item.ExemptedPackages = exempted
			item.ExemptionReason = exemptionReason
		}
		for i, id := range sbomIDs {
			name := ""
			if i < len(sbomNames) {
				name = sbomNames[i]
			}
			item.AffectedSBOMs = append(item.AffectedSBOMs, dto.LicenseAffectedSBOM{
				SBOMID:       id,
				DocumentName: name,
			})
		}
		items = append(items, item)
	}

	if items == nil {
		items = []dto.LicenseComplianceItem{}
	}

	return items, nil
}

// QuerySBOMDependencies fetches the dependency tree for a specific SBOM.
func (c *Client) QuerySBOMDependencies(ctx context.Context, sbomID string) ([]dto.DependencyNode, error) {
	var (
		spdxIDs    []string
		names      []string
		versions   []string
		purls      []string
		licenses   []string
		relSources []uint32
		relTargets []uint32
		relTypes   []string
	)

	err := c.Conn.QueryRow(ctx, `
		SELECT
			package_spdx_ids, package_names, package_versions,
			package_purls, package_licenses,
			rel_source_indices, rel_target_indices, rel_types
		FROM sbom_packages
		WHERE sbom_id = ?
		LIMIT 1
	`, sbomID).Scan(
		&spdxIDs, &names, &versions, &purls, &licenses,
		&relSources, &relTargets, &relTypes,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query sbom_packages for %s: %w", sbomID, err)
	}

	// Build a children map from relationship arrays.
	childrenMap := make(map[uint32][]uint32)
	for i := range relSources {
		if i < len(relTargets) {
			childrenMap[relSources[i]] = append(childrenMap[relSources[i]], relTargets[i])
		}
	}

	nodes := make([]dto.DependencyNode, len(names))
	for i := range names {
		idx := uint32(i)
		lic := ""
		if i < len(licenses) {
			lic = licenses[i]
		}
		purl := ""
		if i < len(purls) {
			purl = purls[i]
		}
		spdxID := ""
		if i < len(spdxIDs) {
			spdxID = spdxIDs[i]
		}
		version := ""
		if i < len(versions) {
			version = versions[i]
		}

		children := childrenMap[idx]
		if children == nil {
			children = []uint32{}
		}

		nodes[i] = dto.DependencyNode{
			Index:    idx,
			SPDXID:   spdxID,
			Name:     names[i],
			Version:  version,
			PURL:     purl,
			License:  lic,
			Children: children,
		}
	}

	return nodes, nil
}

// QueryVEXStatements fetches a paginated list of VEX statements.
func (c *Client) QueryVEXStatements(ctx context.Context, page, pageSize uint64) (*dto.PaginatedResponse[dto.VEXStatementItem], error) {
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	var total uint64
	if err := c.Conn.QueryRow(ctx, "SELECT count() FROM vex_statements FINAL").Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count vex_statements: %w", err)
	}

	rows, err := c.Conn.Query(ctx, `
		SELECT vex_id, document_id, source_file, sbom_id, product_purl,
			   vuln_id, status, justification, impact_statement,
			   action_statement, vex_timestamp, ingested_at,
			   author, role, tooling, status_notes
		FROM vex_statements FINAL
		ORDER BY vex_timestamp DESC
		LIMIT ? OFFSET ?
	`, pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query vex_statements: %w", err)
	}
	defer rows.Close()

	var items []dto.VEXStatementItem
	for rows.Next() {
		var item dto.VEXStatementItem
		var vexTimestamp, ingestedAt time.Time
		if err := rows.Scan(
			&item.VEXID, &item.DocumentID, &item.SourceFile, &item.SBOMID, &item.ProductPURL,
			&item.VulnID, &item.Status, &item.Justification, &item.ImpactStatement,
			&item.ActionStatement, &vexTimestamp, &ingestedAt,
			&item.Author, &item.Role, &item.Tooling, &item.StatusNotes,
		); err != nil {
			return nil, fmt.Errorf("failed to scan vex row: %w", err)
		}
		item.VEXTimestamp = vexTimestamp.Format(time.RFC3339)
		item.IngestedAt = ingestedAt.Format(time.RFC3339)
		items = append(items, item)
	}

	if items == nil {
		items = []dto.VEXStatementItem{}
	}

	// Collect unique PURLs, then batch-lookup which SBOMs contain them.
	purlSet := make(map[string]struct{})
	for _, item := range items {
		if item.ProductPURL != "" {
			purlSet[item.ProductPURL] = struct{}{}
		}
	}

	// Build a map: purl -> []VEXAffectedSBOM
	purlToSBOMs := make(map[string][]dto.VEXAffectedSBOM)
	for purl := range purlSet {
		sbomRows, err := c.Conn.Query(ctx, `
			SELECT toString(p.sbom_id), ifNull(s.document_name, p.source_file)
			FROM (SELECT * FROM sbom_packages FINAL) AS p
			LEFT JOIN (SELECT * FROM sboms FINAL) AS s ON s.sbom_id = p.sbom_id
			WHERE has(p.package_purls, ?)
		`, purl)
		if err != nil {
			continue
		}
		for sbomRows.Next() {
			var sbomID, docName string
			if err := sbomRows.Scan(&sbomID, &docName); err == nil {
				purlToSBOMs[purl] = append(purlToSBOMs[purl], dto.VEXAffectedSBOM{
					SBOMID:       sbomID,
					DocumentName: docName,
				})
			}
		}
		sbomRows.Close()
	}

	// Attach affected SBOMs to each VEX item.
	for i := range items {
		if sboms, ok := purlToSBOMs[items[i].ProductPURL]; ok {
			items[i].AffectedSBOMs = sboms
		}
	}

	return &dto.PaginatedResponse[dto.VEXStatementItem]{
		Data:     items,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// QuerySBOMSourceFile returns the source_file path for a given SBOM ID.
// Returns empty string if the SBOM is not found.
func (c *Client) QuerySBOMSourceFile(ctx context.Context, sbomID string) (string, error) {
	var sourceFile string
	err := c.Conn.QueryRow(ctx,
		"SELECT source_file FROM sboms FINAL WHERE sbom_id = ? LIMIT 1", sbomID).Scan(&sourceFile)
	if err != nil {
		return "", fmt.Errorf("failed to query source file for sbom %s: %w", sbomID, err)
	}
	return sourceFile, nil
}
