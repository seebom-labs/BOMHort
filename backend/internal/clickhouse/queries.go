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

	var suppressedByVEX uint64
	_ = c.Conn.QueryRow(ctx, `
		SELECT count(DISTINCT (vuln_id, purl))
		FROM (SELECT * FROM vulnerabilities FINAL) AS v
		WHERE EXISTS (
			SELECT 1 FROM (SELECT * FROM vex_statements FINAL) AS vx
			WHERE vx.vuln_id = v.vuln_id
			AND vx.product_purl = v.purl
			AND vx.status = 'not_affected'
		)
	`).Scan(&suppressedByVEX)

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
			s.ingested_at,
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
			&item.DocumentName, &ingestedAt, &item.PackageCount, &item.VulnCount,
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

// QueryVulnerabilities fetches a paginated list of vulnerabilities with optional VEX filtering.
// If vexFilter is "effective", vulnerabilities with VEX status 'not_affected' are excluded.
func (c *Client) QueryVulnerabilities(ctx context.Context, page, pageSize uint64, vexFilter string) (*dto.PaginatedResponse[dto.VulnerabilityListItem], error) {
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	// Build WHERE clause for VEX filtering.
	// When vex_filter=effective, exclude vulns that have a VEX "not_affected" status.
	vexHaving := ""
	if vexFilter == "effective" {
		vexHaving = `WHERE (vx.status IS NULL OR vx.status != 'not_affected')`
	}

	var total uint64
	countQuery := fmt.Sprintf(`
		SELECT count() FROM (
			SELECT
				v.vuln_id,
				v.purl
			FROM (SELECT * FROM vulnerabilities FINAL) AS v
			LEFT JOIN (
				SELECT vuln_id, product_purl, status
				FROM vex_statements FINAL
			) AS vx ON vx.vuln_id = v.vuln_id AND vx.product_purl = v.purl
			%s
		)
	`, vexHaving)
	if err := c.Conn.QueryRow(ctx, countQuery).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count vulnerabilities: %w", err)
	}

	query := fmt.Sprintf(`
		SELECT
			v.vuln_id, v.severity, v.purl, v.summary,
			v.fixed_version, v.source_file, v.discovered_at,
			ifNull(vx.status, '') AS vex_status
		FROM (SELECT * FROM vulnerabilities FINAL) AS v
		LEFT JOIN (
			SELECT vuln_id, product_purl, status
			FROM vex_statements FINAL
		) AS vx ON vx.vuln_id = v.vuln_id AND vx.product_purl = v.purl
		%s
		ORDER BY v.severity ASC, v.discovered_at DESC
		LIMIT ? OFFSET ?
	`, vexHaving)

	rows, err := c.Conn.Query(ctx, query, pageSize, offset)
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
		SELECT vex_id, document_id, source_file, product_purl,
			   vuln_id, status, justification, impact_statement,
			   action_statement, vex_timestamp, ingested_at
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
			&item.VEXID, &item.DocumentID, &item.SourceFile, &item.ProductPURL,
			&item.VulnID, &item.Status, &item.Justification, &item.ImpactStatement,
			&item.ActionStatement, &vexTimestamp, &ingestedAt,
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
